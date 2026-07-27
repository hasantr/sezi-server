use super::*;

/// M1 (narrowing repeated Olm WIPE triggers): a FRESH-reconnect force-replay hands
/// out only the last 48 hours of forwards. Older orphan rows (e.g. a `delivery_failed`
/// the client never `forward_ack`ed) used to be replayed unconditionally on every
/// reconnect, re-triggering `delete_all_olm_blobs` (Olm WIPE) on the receiver. 48h is
/// a generous delivery window (cleanup retention deletes anything older anyway; this
/// constant shrinks the replay surface without waiting for retention). Milliseconds,
/// matching `created_at`.
const FORCE_REPLAY_WINDOW_MS: i64 = 48 * 3600 * 1000;

impl UserInbox {
    pub(crate) fn forward_signal(
        &self,
        kind: &str,
        from: &str,
        recipient_device_id: Option<&str>,
        ids: &[i64],
    ) {
        if ids.is_empty() {
            return;
        }
        // Sprint 8.5a: persistent forward_queue + WS push, guarded against double
        // delivery.
        // - Sender sends twice (R1 bypass + OpHub race) → a 10s dedup window skips the
        //   INSERT for the same (kind, from, recipient_device, ids).
        // - flush_forwards (replay) skips a row for 10s after it was pushed → no race
        //   between the forward_signal push and the alarm-driven flush_forwards.
        // M2-S2.2 (D3 verdict 2): recipient_device_id is now a persisted column and part
        // of the dedup key → a receipt queued while the WS was down carries its device
        // through replay (otherwise N:1 MISS). With recipient_device None (N=1 / pre-S2.3)
        // the key is NULL, i.e. identical to the previous behaviour.
        let ids_json = match serde_json::to_string(ids) {
            Ok(s) => s,
            Err(_) => return,
        };
        let now = (now_secs() * 1000) as i64;
        let storage = self.state.storage();
        let device_val = match recipient_device_id {
            Some(d) => JsValue::from_str(d),
            None => JsValue::NULL,
        };

        // Dedup: is the same receipt already queued within the last 10s and not yet
        // deleted? (forward_ack DELETEs, so a missing row means the client already
        // acked and a fresh INSERT is legitimate.) M2-S2.2: recipient_device_id is
        // part of the key — compared with `IS` because `= ?` never matches NULL.
        let dedup_window = now - 10_000;
        let recent: Option<i64> = match storage.sql().exec_raw(
            "SELECT id FROM forward_queue
             WHERE kind = ? AND from_user = ?
               AND recipient_device_id IS ? AND ids_json = ?
               AND created_at > ?
             LIMIT 1",
            Some(vec![
                JsValue::from_str(kind),
                JsValue::from_str(from),
                device_val.clone(),
                JsValue::from_str(&ids_json),
                JsValue::from_f64(dedup_window as f64),
            ]),
        ) {
            Ok(c) => match c.to_array::<ForwardIdRow>() {
                Ok(rows) => rows.first().map(|r| r.id),
                Err(_) => None,
            },
            Err(_) => None,
        };
        if recent.is_some() {
            // Sender sent twice → skip; the first INSERT already pushed.
            return;
        }

        // INSERT with pushed_at NULL; the UPDATE below stamps it if a WS push lands.
        // With no socket it stays NULL → the next alarm() flush_forwards_to_all replay
        // pushes it immediately.
        let id_opt: Option<i64> = match storage.sql().exec_raw(
            "INSERT INTO forward_queue (kind, from_user, ids_json, recipient_device_id, created_at, pushed_at)
             VALUES (?, ?, ?, ?, ?, NULL) RETURNING id",
            Some(vec![
                JsValue::from_str(kind),
                JsValue::from_str(from),
                JsValue::from_str(&ids_json),
                device_val,
                JsValue::from_f64(now as f64),
            ]),
        ) {
            Ok(c) => match c.to_array::<ForwardIdRow>() {
                Ok(rows) => rows.first().map(|r| r.id),
                Err(_) => None,
            },
            Err(_) => None,
        };
        let forward_id = match id_opt {
            Some(i) => i,
            None => return, // INSERT failed → skip the push; a fresh replay covers it later
        };
        let payload = serde_json::json!({
            "type": kind,
            "from": from,
            "recipient_device_id": recipient_device_id,
            "ids": ids,
            "forward_id": forward_id,
        })
        .to_string();
        let mut any_pushed = false;
        for ws in self.state.get_websockets() {
            // W9 ("read receipt arrives late" — same zombie-socket root cause as W1):
            // send_with_str returns Ok on a half-open socket, yet the client never RECEIVES
            // the receipt; stamping pushed_at anyway makes flush_forwards skip this row for
            // 10s, so the receipt stalls until the next 90s alarm. We still write to EVERY
            // socket (it may be hibernating but alive), but mark "pushed" ONLY for a
            // genuinely live socket (fresh last_seen) → on a zombie pushed_at stays NULL and
            // the next flush / force-reconnect replays it.
            if ws.send_with_str(payload.as_str()).is_ok() && super::message::ws_is_fresh(&ws, now) {
                any_pushed = true;
            }
        }
        if any_pushed {
            // Pushed → flush_forwards replay skips this row for the next 10s.
            let _ = storage.sql().exec_raw(
                "UPDATE forward_queue SET pushed_at = ? WHERE id = ?",
                Some(vec![
                    JsValue::from_f64(now as f64),
                    JsValue::from_f64(forward_id as f64),
                ]),
            );
        }
    }

    /// Sprint 8.5a: replay the forwards piled up in the queue, on WS reconnect or from the
    /// alarm. `force=false` (alarm): SKIP rows forward_signal just pushed (pushed_at within
    /// the last 10s) — otherwise the "INSERT+push" and "alarm flush" race would deliver
    /// twice to a LIVE socket.
    ///
    /// `force=true` (FRESH reconnect, `ws_upgrade`): IGNORE `pushed_at` → hand over EVERY
    /// forward in the queue. Rationale (field report 2026-06-02, "read receipt hugely
    /// delayed"): forward_signal stamped pushed_at whenever `send_with_str` returned Ok on a
    /// dead/zombie socket; once the client reconnected WITHOUT having received it, the 10s
    /// skip also hid the receipt from the NEW socket, so it stalled until the next alarm
    /// (90s!) or the next receipt (the "delivered+read arrive together" symptom). A new
    /// socket by definition received none of the earlier pushes → give it everything. Safe
    /// because the client dedups on `forward_id` (a repeat is idempotent).
    pub(crate) fn flush_forwards_to(&self, ws: &WebSocket, force: bool) {
        let storage = self.state.storage();
        let now = (now_secs() * 1000) as i64;
        let stale_cutoff = now - 10_000;
        let cursor = if force {
            // M1: NARROW force-replay to the last 48 hours (unconditional replay of old
            // orphan rows re-triggered an Olm WIPE on the receiver). pushed_at is still
            // IGNORED (force semantics preserved), but a created_at window now applies.
            let replay_cutoff = now - FORCE_REPLAY_WINDOW_MS;
            storage.sql().exec_raw(
                "SELECT id, kind, from_user, ids_json, recipient_device_id
                 FROM forward_queue
                 WHERE created_at > ?
                 ORDER BY id ASC LIMIT 500",
                Some(vec![JsValue::from_f64(replay_cutoff as f64)]),
            )
        } else {
            // M1/FIX-4 (CONCERN M1 — the steady-replay Olm WIPE window): the created_at window
            // added to the 48h force path was MISSING from the steady ~90s alarm path, so an
            // old un-forward_acked orphan `delivery_failed` row was re-pushed every 90s →
            // UNCONDITIONAL Olm WIPE on the receiver → a re-WIPE roughly every 90s for up to
            // 30 days. Apply the SAME created_at window (FORCE_REPLAY_WINDOW_MS) here too, so
            // old orphans are never re-pushed (the M1 forward_queue retention DELETE clears
            // them out). The pushed_at skip (fresh-INSERT vs. alarm race guard) is PRESERVED.
            // NOTE: this only narrows the worker-side surface; the real root cause (making the
            // receiver's WIPE idempotent) lives in CORE and is out of scope here.
            let replay_cutoff = now - FORCE_REPLAY_WINDOW_MS;
            storage.sql().exec_raw(
                "SELECT id, kind, from_user, ids_json, recipient_device_id
                 FROM forward_queue
                 WHERE (pushed_at IS NULL OR pushed_at < ?)
                   AND created_at > ?
                 ORDER BY id ASC LIMIT 500",
                Some(vec![
                    JsValue::from_f64(stale_cutoff as f64),
                    JsValue::from_f64(replay_cutoff as f64),
                ]),
            )
        };
        let cursor = match cursor {
            Ok(c) => c,
            Err(_) => return,
        };
        let rows: Vec<ForwardQueueRow> = match cursor.to_array() {
            Ok(r) => r,
            Err(_) => return,
        };
        if rows.is_empty() {
            return;
        }
        let mut pushed_ids: Vec<i64> = Vec::with_capacity(rows.len());
        for row in &rows {
            let ids: Vec<i64> = serde_json::from_str(&row.ids_json).unwrap_or_default();
            let payload = serde_json::json!({
                "type": row.kind,
                "from": row.from_user,
                "recipient_device_id": row.recipient_device_id,
                "ids": ids,
                "forward_id": row.id,
            })
            .to_string();
            // W9-b (Codex MED): the replay path obeys the same zombie-socket test as
            // forward_signal. Only delivery to a genuinely live socket counts as "pushed" →
            // on a zombie pushed_at stays NULL and the next flush/force replays it. With
            // force=true (fresh reconnect) the socket was stamped at accept time, so it is
            // always fresh → no regression.
            if ws.send_with_str(payload.as_str()).is_ok() && super::message::ws_is_fresh(ws, now) {
                pushed_ids.push(row.id);
            }
        }
        if !pushed_ids.is_empty() {
            let placeholders = (0..pushed_ids.len()).map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!(
                "UPDATE forward_queue SET pushed_at = ? WHERE id IN ({})",
                placeholders
            );
            let mut args: Vec<JsValue> = Vec::with_capacity(pushed_ids.len() + 1);
            args.push(JsValue::from_f64(now as f64));
            for id in &pushed_ids {
                args.push(JsValue::from_f64(*id as f64));
            }
            let _ = storage.sql().exec_raw(&sql, Some(args));
        }
    }

    /// Sprint 8: called when the sender sends a `forward_ack` frame; deletes the
    /// acknowledged forward_ids from the queue.
    pub(crate) fn forward_ack(&self, ids: &[i64]) {
        if ids.is_empty() {
            return;
        }
        let storage = self.state.storage();
        // One BATCH delete with an IN clause instead of per-id binds (SQLite is fine
        // with the ~500 placeholders a client batch can produce).
        let placeholders = (0..ids.len()).map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "DELETE FROM forward_queue WHERE id IN ({})",
            placeholders
        );
        let args: Vec<JsValue> = ids.iter().map(|i| JsValue::from_f64(*i as f64)).collect();
        let _ = storage.sql().exec_raw(&sql, Some(args));
    }

    pub(crate) fn flush_forwards_to_all(&self) {
        let websockets = self.state.get_websockets();
        if websockets.is_empty() {
            return;
        }
        // These are all sockets of the same user (multi-device) — push the queued
        // forwards to each one; the client dedups on forward_id. force=false: a
        // periodic flush to live sockets, where the 10s skip prevents double delivery
        // in the forward_signal-push vs. alarm-flush race.
        for ws in websockets {
            self.flush_forwards_to(&ws, false);
        }
    }
}
