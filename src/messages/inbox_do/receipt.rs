//! Model-B Layer-4 — account-level durable log of receipts (delivered/read).
//!
//! Fixes the sibling-race / zombie-socket / reconnect-gap defects the consume-once
//! `forward_queue` transport (push-to-all-sockets + global ack DELETE) had on
//! multi-device accounts: delivered/read now live as **durable state** (`receipt_state`)
//! in A's UserInbox DO, and every A device **syncs idempotently from its own seq
//! cursor**. The WS is only a notification channel.
//!
//! - Granularity: B's per-device `remote_id` (the id the receipt arrived for). Rolling
//!   that up to a logical message stays CLIENT-side in `mdd` (the existing proven path;
//!   only the transport changed).
//! - `seq` is an account-global monotonic high-water mark (`receipt_meta`). Even when the
//!   table is retention-purged the high-water NEVER goes backwards → cursors stay
//!   consistent (a new row can never land below an old cursor).
//! - delivered/read are SET-ONCE monotonic (`COALESCE`); read implies delivered. No
//!   change means NO seq bump (idempotent, no churn).
//!
//! delivery_failed is deliberately NOT here: it is a transient action signal (it triggers
//! a retry / Olm reset rather than a durable tick) → it stays in `forward_queue` so a
//! fresh-device replay does not re-trigger those side effects.

use super::*;

#[derive(Deserialize)]
struct ReceiptStateExisting {
    delivered_at: Option<i64>,
    read_at: Option<i64>,
    #[serde(default)]
    msg_uid: Option<String>,
}

#[derive(Deserialize)]
struct ReceiptSeqRow {
    v: i64,
}

#[derive(Deserialize)]
struct ReceiptStateRow {
    peer_id: String,
    remote_id: i64,
    #[serde(default)]
    delivered_at: Option<i64>,
    #[serde(default)]
    read_at: Option<i64>,
    seq: i64,
    /// #11 Layer-4b: the sender's local_id (the E2E msg_uid). A sibling device matches it
    /// via `oc-{msg_uid}`. Rows predating the column are NULL → None (sibling convergence
    /// is skipped for them).
    #[serde(default)]
    msg_uid: Option<String>,
}

impl UserInbox {
    /// Apply a delivered/read receipt to durable `receipt_state` (set-once monotonic).
    /// On any change it bumps the account-global seq and notifies every socket with
    /// `receipt_update` (best-effort; it carries no data, so a dropped frame cannot skip a
    /// gap — the client pulls from its cursor). `kind`: "delivered" | "read".
    /// `from_peer` = whoever produced the receipt (B). `ids` = B's device-side
    /// `remote_id`s. `ts_ms` = server receive time (precise enough to render ticks).
    pub(crate) fn apply_receipt(
        &self,
        kind: &str,
        from_peer: &str,
        ids: &[i64],
        uids: &[String],
        ts_ms: i64,
    ) {
        if ids.is_empty() {
            // uid-only receipt: an M4-restored message has no `remote_id`, so `receipt_state`'s
            // PK(peer_id, remote_id) cannot represent it and the receipt is DROPPED here. The
            // `receipt_uid_state` table exists for exactly this case and nothing reads or writes it
            // yet (see the note where it is created).
            //
            // Logged rather than left silent so the debt is MEASURED instead of argued about. If this
            // line never appears in a `wrangler tail`, the gap costs nothing in practice and the
            // table can go; if it appears often, that is the signal to finish the path. Right now
            // nobody knows which, which is why it is still open.
            if !uids.is_empty() {
                console_log!(
                    "[deliv] uid-only {kind} DUSTU peer={from_peer} uid_sayisi={} (receipt_uid_state yolu bitmedi)",
                    uids.len()
                );
            }
            return;
        }
        let is_read = kind == "read";
        let storage = self.state.storage();
        let sql = storage.sql();
        // Every CHANGED row gets an ATOMICALLY unique, strictly increasing seq: bump and read
        // the high-water with `UPDATE ... RETURNING` BEFORE writing the row (Codex HIGH-2).
        // That rules out seq reuse on a failed meta-update / DO eviction, and with it the
        // silent skip on a device whose cursor has already moved past; the worst case is an
        // unused seq gap (harmless, the cursor jumps over it). A unique seq per row also
        // guarantees that `receipt_sync`'s 500-row pagination always makes progress.
        let mut max_seq: i64 = 0;
        let mut changed = false;
        // LATENCY fast-path: collect the rows CHANGED by this call and push them directly as a
        // live `receipt_delta` at the end, so the sender paints its second tick without waiting
        // for a receipt_sync pull round-trip.
        let mut delta_rows: Vec<serde_json::Value> = Vec::new();

        for (i, &rid) in ids.iter().enumerate() {
            // #11 Layer-4b: the msg_uid for this id (the sender's local_id; the reader supplies
            // it from the E2E payload — the server is blind and cannot derive it). A sibling
            // device matches it against its `oc-{msg_uid}` row (read convergence without mdd).
            // Empty/missing → None.
            let uid: Option<&str> = uids.get(i).map(|s| s.as_str()).filter(|s| !s.is_empty());
            // Current state (for set-once). msg_uid is read too (Codex Q4: a uid arriving
            // LATER must count as a change — otherwise a read row created without a uid would
            // NEVER learn it, no seq bump would happen, and no sibling could match it).
            let existing = match sql.exec_raw(
                "SELECT delivered_at, read_at, msg_uid FROM receipt_state WHERE peer_id = ? AND remote_id = ?",
                Some(vec![
                    JsValue::from_str(from_peer),
                    JsValue::from_f64(rid as f64),
                ]),
            ) {
                Ok(c) => c
                    .to_array::<ReceiptStateExisting>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| (r.delivered_at, r.read_at, r.msg_uid)),
                Err(_) => None,
            };
            let (old_d, old_r, old_uid) = existing.unwrap_or((None, None, None));
            // BOTH delivered and read set delivered_at (read implies delivered).
            let new_d = old_d.or(Some(ts_ms));
            let new_r = if is_read { old_r.or(Some(ts_ms)) } else { old_r };
            // #11 Q4: the uid arrived for the first time (stored NULL, incoming Some) → write
            // and bump the seq even when no tick changed, so siblings see the uid on re-sync.
            let uid_newly = uid.is_some() && old_uid.is_none();
            if (new_d, new_r) == (old_d, old_r) && !uid_newly {
                continue; // nothing changed (and the uid is not new either) → idempotent skip.
            }
            // Atomic seq reservation (HIGH-2): bump and read the new value in one statement.
            let seq = match sql.exec_raw(
                "UPDATE receipt_meta SET v = v + 1 WHERE k = 'seq' RETURNING v",
                sql_no_args(),
            ) {
                Ok(c) => c
                    .to_array::<ReceiptSeqRow>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| r.v),
                Err(_) => None,
            };
            let Some(seq) = seq else {
                continue; // meta bump failed (rare DB error) → skip the row; NEVER reuse a seq.
            };
            changed = true;
            if seq > max_seq {
                max_seq = seq;
            }
            let d_val = match new_d {
                Some(v) => JsValue::from_f64(v as f64),
                None => JsValue::NULL,
            };
            let r_val = match new_r {
                Some(v) => JsValue::from_f64(v as f64),
                None => JsValue::NULL,
            };
            let uid_val = match uid {
                Some(u) => JsValue::from_str(u),
                None => JsValue::NULL,
            };
            let _ = sql.exec_raw(
                "INSERT INTO receipt_state (peer_id, remote_id, delivered_at, read_at, seq, updated_at, msg_uid)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(peer_id, remote_id) DO UPDATE SET
                   delivered_at = excluded.delivered_at,
                   read_at = excluded.read_at,
                   seq = excluded.seq,
                   updated_at = excluded.updated_at,
                   msg_uid = COALESCE(excluded.msg_uid, receipt_state.msg_uid)",
                Some(vec![
                    JsValue::from_str(from_peer),
                    JsValue::from_f64(rid as f64),
                    d_val,
                    r_val,
                    JsValue::from_f64(seq as f64),
                    JsValue::from_f64(ts_ms as f64),
                    uid_val,
                ]),
            );
            // LATENCY fast-path: collect the changed row for the live delta. Shape matches
            // receipt_sync_payload (peer/remote_id/delivered_at/read_at/seq/msg_uid) so the client
            // REUSES handle_receipt_batch. msg_uid mirrors the COALESCE result (incoming or stored).
            delta_rows.push(serde_json::json!({
                "peer": from_peer,
                "remote_id": rid,
                "delivered_at": new_d,
                "read_at": new_r,
                "seq": seq,
                "msg_uid": uid.or(old_uid.as_deref()),
            }));
        }

        if !changed {
            return;
        }
        // The high-water was already bumped atomically per row (NO separate UPDATE). Notify
        // every A device → each pulls from its own cursor.
        let payload =
            serde_json::json!({ "type": "receipt_update", "max_seq": max_seq }).to_string();
        for ws in self.state.get_websockets() {
            let _ = ws.send_with_str(payload.as_str());
        }
        // LATENCY fast-path: push the changed rows DIRECTLY to the SAME sockets (`receipt_delta`).
        // The sender applies its second tick instantly, WITHOUT the `receipt_sync` pull round-trip
        // → closes the structural "the second tick is never snappy" complaint. The durable model
        // is PRESERVED: the `receipt_update` above still goes out, so the client catches up via an
        // authoritative pull (the delta is applied NON-ROOTED and does not advance the cursor →
        // no cross-page gap-skip risk). An old client does not know `receipt_delta` and ignores it
        // (forward-compatible; it keeps working off receipt_update).
        if !delta_rows.is_empty() {
            let delta = serde_json::json!({
                "type": "receipt_delta",
                "rows": delta_rows,
                "max_seq": max_seq,
            })
            .to_string();
            for ws in self.state.get_websockets() {
                let _ = ws.send_with_str(delta.as_str());
            }
        }
    }

    // (receipt_seq_current was removed — a seq is now reserved per row with an atomic
    //  `UPDATE ... RETURNING`; there is no separate high-water read.)

    /// Serializes the `receipt_state` rows past the cursor (`seq > since ORDER BY seq ASC
    /// LIMIT 500`) into a transport-agnostic `{rows, more}` payload (NO type tag — the WS
    /// wrapper adds it). The WS frame and HTTP `GET /messages/receipt-sync` share this
    /// builder, which guarantees BIT-IDENTICAL rows. SQL error → `None` (WS: send no frame,
    /// as before; HTTP: the caller turns it into an empty batch → the cursor does not
    /// advance and the next event re-pulls).
    pub(crate) fn receipt_sync_payload(&self, since: i64) -> Option<serde_json::Value> {
        let storage = self.state.storage();
        let rows: Vec<ReceiptStateRow> = match storage.sql().exec_raw(
            "SELECT peer_id, remote_id, delivered_at, read_at, seq, msg_uid FROM receipt_state
             WHERE seq > ? ORDER BY seq ASC LIMIT 500",
            Some(vec![JsValue::from_f64(since as f64)]),
        ) {
            Ok(c) => c.to_array().unwrap_or_default(),
            Err(_) => return None,
        };
        let more = rows.len() == 500;
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "peer": r.peer_id,
                    "remote_id": r.remote_id,
                    "delivered_at": r.delivered_at,
                    "read_at": r.read_at,
                    "seq": r.seq,
                    "msg_uid": r.msg_uid,
                })
            })
            .collect();
        // Echo `since` back (shared-root #1 gap-skip fix): it lets the client tell a page
        // rooted at its cursor (since <= cursor) from a pagination continuation
        // (since = max_seq > cursor), so it advances the durable cursor only on a rooted
        // page and never skips a gap across pages.
        Some(serde_json::json!({ "rows": json_rows, "more": more, "since": since }))
    }

    /// WS `receipt_sync{since}` → `receipt_batch` frame. Same behaviour as the HTTP twin
    /// (on a SQL error no frame is sent). The client applies `receipt_batch` to mdd, advances
    /// its cursor to max(seq) and syncs again while `more=true`.
    pub(crate) fn receipt_sync(&self, ws: &WebSocket, since: i64) {
        let Some(mut payload) = self.receipt_sync_payload(since) else {
            return; // SQL error: send no frame at all, as before.
        };
        payload["type"] = serde_json::Value::String("receipt_batch".into());
        let _ = ws.send_with_str(payload.to_string().as_str());
    }
}
