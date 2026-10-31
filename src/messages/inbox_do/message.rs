use super::*;
use sha2::{Digest, Sha256};

/// For a socket to count as "genuinely live" its last CLIENT→SERVER frame must fall inside this
/// window. The client pings every 5s and reconnects after 14s of silence, so a healthy connection
/// is always under 5s fresh; 20s is 4× the ping interval, leaving room for a missed ping,
/// hibernation wake latency and clock skew. Outside it, delivery does not count as live even when
/// `send_with_str` returns Ok, and the caller sends an FCM wake instead.
const WS_LIVENESS_WINDOW_MS: i64 = 20_000;

/// A hard row-count cap on one recipient's `pending` table, the second line of defence behind TTL
/// retention: retention bounds the queue in TIME, but a flood INSIDE that window still bloats the
/// victim DO's SQLite. Past the cap the oldest surplus rows are evicted — bounded FIFO. The value
/// is generous, so reaching it means a very long offline period or a DoS, and the client's history
/// sync plus redelivery compensate for what is dropped.
///
/// KNOWN RESIDUE — eviction is GLOBAL-oldest, not per sender, so one noisy sender can push out
/// another's older undelivered messages. The free half of that attack is closed elsewhere:
/// envelopes for FABRICATED device ids no longer reach this table (`messages::recipient_devices`),
/// so what remains costs a real sender its own rate limit. A proper fix is a per-sender share
/// (evict from the largest slice first), which changes the eviction query's shape and cost — it
/// was weighed, not missed.
const PENDING_MAX_ROWS: i64 = 10_000;
/// Enforce the cap roughly every N inserts rather than on EVERY one (amortizes the hot-path
/// COUNT+DELETE; overshoot stays <= PENDING_MAX_ROWS + N). Gated on `row.id`, which is monotonic
/// thanks to AUTOINCREMENT.
const PENDING_CAP_ENFORCE_EVERY: i64 = 512;

/// The most older rows `older_queued` counts: the phone asks only whether there are any.
const OLDER_QUEUED_CAP: i64 = 100;

/// 1:1 rows older than `?4`, from the same sender device, waiting for device `?1` (or device-blind,
/// from a build that predates device addressing) — capped.
pub(crate) const OLDER_QUEUED_SQL: &str = "SELECT COUNT(*) AS n FROM (
    SELECT 1 FROM pending
    WHERE (device_id = ?1 OR device_id IS NULL) AND sender_id = ?2 AND sender_device_id IS ?3 AND group_id IS NULL
      AND id < ?4
    LIMIT 100)";

/// `last_seen_ms` from the WS attachment, if present. `None` must NOT be treated as fresh — the
/// socket may be a zombie, so let the wake fire; the field is filled in on the first ping.
pub(crate) fn ws_last_seen_ms(ws: &WebSocket) -> Option<i64> {
    ws.deserialize_attachment::<Attachment>()
        .ok()
        .flatten()
        .and_then(|a| a.last_seen_ms)
}

/// W1/W9: is the socket GENUINELY live — did its last inbound frame arrive within
/// `WS_LIVENESS_WINDOW_MS`? On a zombie/half-open socket `send_with_str` returns Ok while the
/// client receives nothing; this test stops us from counting that as a "live delivery/push".
/// `now_ms` comes from the caller (one `now_secs()` read). Missing or stale last_seen → false.
/// Shared by notify_inner (W1) and forward_signal (W9).
pub(crate) fn ws_is_fresh(ws: &WebSocket, now_ms: i64) -> bool {
    ws_last_seen_ms(ws)
        .map(|ls| now_ms - ls <= WS_LIVENESS_WINDOW_MS)
        .unwrap_or(false)
}

/// M2-S2.2: should this WS connection receive the frame for the given target device?
/// - `recipient_device` None → every socket is a target (N=1 compatibility / pre-S2.3 fan-out).
/// - WS attachment device None (pre-S1 token) → NULL tolerance, counts as a target.
/// - Both concrete → only the socket whose device matches is a target.
pub(crate) fn ws_targets_device(ws: &WebSocket, recipient_device: Option<&str>) -> bool {
    let want = match recipient_device {
        Some(d) => d,
        None => return true,
    };
    match ws_attachment_device(ws) {
        Some(have) => have == want,
        None => true, // attachment device unknown → tolerate
    }
}

/// M2-S2.2: the device_id from the WS attachment, if present.
pub(crate) fn ws_attachment_device(ws: &WebSocket) -> Option<String> {
    ws.deserialize_attachment::<Attachment>()
        .ok()
        .flatten()
        .map(|a| a.device_id)
}

/// M2-S2.2: build the recipient frame from a pending row (it carries sender_device_id).
pub(crate) fn pending_frame(r: &PendingRow) -> String {
    serde_json::json!({
        "type": "msg",
        "id": r.id,
        "sender_id": r.sender_id,
        "sender_device_id": r.sender_device_id,
        "envelope_b64": r.envelope_b64,
        "group_id": r.group_id,
        "ts": r.created_at,
    })
    .to_string()
}

/// What `notify_inner` did with one envelope.
pub(crate) struct Notified {
    /// The pending row's id.
    pub(crate) id: i64,
    pub(crate) delivered_live: bool,
    pub(crate) deduped: bool,
    /// The `msg` frame this call stored and pushed — what its wake may carry (`push::carry`).
    /// None on a dedup hit: nothing was stored this time, and the call that stored it woke.
    pub(crate) frame: Option<serde_json::Value>,
}

impl UserInbox {
    /// `silent` = the sender asked for no FCM wake (control traffic; see the core's
    /// `needs_device_wake`). It is persisted on the pending row for ONE reason: the W1 backstop
    /// ALARM would otherwise wake the device minutes later for the very message the immediate path
    /// stayed quiet about, turning a removed wake into a randomly delayed one.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn notify_inner(
        &self,
        sender_id: &str,
        sender_device_id: Option<&str>,
        recipient_device_id: Option<&str>,
        recipient_id: Option<&str>,
        envelope_b64: &str,
        group_id: Option<&str>,
        silent: bool,
    ) -> Result<Notified> {
        // Returns `Notified`. `delivered_live` answers "did the push
        // reach at least one matching, genuinely-live (W1) socket?" — false means the recipient is
        // offline and the caller must send an FCM wake. `deduped` = this envelope was already here
        // (the in-memory 60 s cache or a pending row): nothing was stored or pushed this time, and
        // the call that stored it decided the wake — `/notify-member` uses it to wake once (F4).
        let now = now_secs() as i64;

        // W1 backstop: persist the RECIPIENT user_id once (the alarm needs it to FCM-wake stuck
        // pending rows; an offline DO has no other way to learn its own user). The Cell guard
        // avoids redundant writes. Skipped when recipient_id is absent (an older body).
        if !self.uid_persisted.get() {
            if let Some(rid) = recipient_id {
                let _ = self.state.storage().put(RECIPIENT_UID_KEY, rid.to_string()).await;
                self.uid_persisted.set(true);
            }
        }

        // Idempotency: the same 4-tuple within the last 60s returns the cached msg_id instead of a
        // duplicate INSERT, so a client retry neither bloats DO storage nor pushes the frame twice.
        // Both DEVICES are part of the hash on purpose: a group's single Megolm envelope fanning
        // out to two devices of one user is byte-identical, and only the differing recipient_device
        // keeps the second row from being swallowed. Hash16 =
        //   SHA256(sender||"|"||sender_dev||"|"||recipient_dev||"|"||envelope)[0..16].
        let mut envelope_hash = [0u8; 16];
        {
            let mut hasher = Sha256::new();
            hasher.update(sender_id.as_bytes());
            hasher.update(b"|");
            hasher.update(sender_device_id.unwrap_or("").as_bytes());
            hasher.update(b"|");
            hasher.update(recipient_device_id.unwrap_or("").as_bytes());
            hasher.update(b"|");
            hasher.update(envelope_b64.as_bytes());
            envelope_hash.copy_from_slice(&hasher.finalize()[..16]);
        }
        // The hex of that same hash is the DURABLE dedup key (pending.env_hash UNIQUE).
        let env_hash_hex: String = envelope_hash.iter().map(|b| format!("{b:02x}")).collect();
        if let Some((cached_id, cached_live)) = self.dedup_lookup(sender_id, &envelope_hash, now) {
            // A dedup hit returns the FIRST delivery's REAL delivered_live, never a hard-coded
            // `true`: on an in-request retry the first attempt's cross-DO response may be lost, so
            // the caller never saw that decision, and answering `true` would silently suppress the
            // FCM wake for an offline recipient.
            return Ok(Notified { id: cached_id, delivered_live: cached_live, deduped: true, frame: None });
        }

        let storage = self.state.storage();
        let group_id_val = match group_id {
            Some(g) => JsValue::from_str(g),
            None => JsValue::NULL,
        };
        let sender_device_val = match sender_device_id {
            Some(d) => JsValue::from_str(d),
            None => JsValue::NULL,
        };
        let recipient_device_val = match recipient_device_id {
            Some(d) => JsValue::from_str(d),
            None => JsValue::NULL,
        };
        // ON CONFLICT DO NOTHING RETURNING id: a new row returns its id, while a conflict (the same
        // sender+env_hash already pending — a retry after a DO restart or TTL expiry) returns none,
        // so the existing id is looked up with a SELECT and reported delivered_live=false. That is
        // conservative: the first delivery's liveness is not stored, and one extra wake is
        // harmless. Either way no second pending row exists, so no duplicate frame or bubble.
        #[derive(Deserialize)]
        struct IdRow {
            id: i64,
        }
        let cursor = storage.sql().exec_raw(
            "INSERT INTO pending (sender_id, envelope_b64, group_id, device_id, sender_device_id, created_at, env_hash, silent)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(sender_id, env_hash) DO NOTHING
             RETURNING id",
            Some(vec![
                JsValue::from_str(sender_id),
                JsValue::from_str(envelope_b64),
                group_id_val,
                recipient_device_val,
                sender_device_val,
                JsValue::from_f64(now as f64),
                JsValue::from_str(&env_hash_hex),
                JsValue::from_f64(if silent { 1.0 } else { 0.0 }),
            ]),
        )?;
        let inserted: Option<IdRow> = cursor
            .to_array::<IdRow>()
            .ok()
            .and_then(|v| v.into_iter().next());
        let row = match inserted {
            Some(r) => r,
            None => {
                // Durable dedup hit: return the existing pending row's id (no double INSERT).
                let existing: Option<IdRow> = storage
                    .sql()
                    .exec_raw(
                        "SELECT id FROM pending WHERE sender_id = ? AND env_hash = ? LIMIT 1",
                        Some(vec![
                            JsValue::from_str(sender_id),
                            JsValue::from_str(&env_hash_hex),
                        ]),
                    )
                    .ok()
                    .and_then(|c| c.to_array::<IdRow>().ok())
                    .and_then(|v| v.into_iter().next());
                if let Some(e) = existing {
                    // Populate the in-memory dedup too, so a later retry within the same DO
                    // lifetime returns fast.
                    self.dedup_insert(sender_id.to_string(), envelope_hash, e.id, now, false);
                    return Ok(Notified { id: e.id, delivered_live: false, deduped: true, frame: None });
                }
                // Unexpected (a conflict but no row — a race or a purge in between) → fail-safe:
                // signal "not delivered" to the caller instead of attempting a fresh INSERT; the
                // next retry picks it up.
                return Err("pending durable-dedup: conflict, but the existing row was not found".into());
            }
        };

        // W2 (per-recipient pending DoS cap): an amortized hard cap. COUNT roughly every
        // PENDING_CAP_ENFORCE_EVERY inserts; if the cap is exceeded, evict the oldest surplus
        // (bounded FIFO — the row we just wrote is the newest and is kept). Running COUNT+DELETE
        // only once per interval amortizes the hot-path cost. We log ONLY on a real eviction (a
        // DoS indicator; silent in normal operation).
        if row.id % PENDING_CAP_ENFORCE_EVERY == 0 {
            #[derive(Deserialize)]
            struct CountRow {
                n: i64,
            }
            if let Ok(c) = storage
                .sql()
                .exec_raw("SELECT COUNT(*) AS n FROM pending", sql_no_args())
            {
                if let Some(cnt) = c.to_array::<CountRow>().ok().and_then(|r| r.into_iter().next()) {
                    if cnt.n > PENDING_MAX_ROWS {
                        let evict = cnt.n - PENDING_MAX_ROWS;
                        let _ = storage.sql().exec_raw(
                            "DELETE FROM pending WHERE id IN (SELECT id FROM pending ORDER BY id ASC LIMIT ?)",
                            Some(vec![JsValue::from_f64(evict as f64)]),
                        );
                        worker::console_log!(
                            "[deliv] W2 pending-cap: evicted {evict} oldest rows (recipient bloat guard, count={})",
                            cnt.n
                        );
                    }
                }
            }
        }

        let frame = serde_json::json!({
            "type": "msg",
            "id": row.id,
            "sender_id": sender_id,
            "sender_device_id": sender_device_id,
            "envelope_b64": envelope_b64,
            "group_id": group_id,
            "ts": now,
        });
        let payload = frame.to_string();
        // M2-S2.2: push only to the TARGET device's socket. With recipient_device None (S2.3
        // fan-out has not filled it yet / N=1 compatibility) push to EVERY socket, as before. An
        // Attachment.device_id of None (pre-S1 token) also counts as a target (NULL tolerance).
        // Matching rule: a concrete recipient device and a concrete attachment device that differ
        // mean the frame does NOT go to that socket.
        // `send_with_str` returning Ok does NOT mean the client received it: after a background
        // kill the TCP connection stays half-open and the CF edge accepts the write as buffered
        // while the client gets nothing. Counting that as delivered suppresses the FCM wake and the
        // message sits silently in `pending` until the alarm or a reconnect — the root of
        // "messages don't arrive". So a live delivery needs BOTH an Ok send and a client frame
        // within `WS_LIVENESS_WINDOW_MS`. A stale socket is still written to (it may be hibernating
        // but alive) without setting delivered_live: correct for a zombie, and a harmless duplicate
        // for a client that is genuinely live.
        let now_ms = now * 1000;
        let mut delivered_live = false;
        let mut zombie_seen = false;
        for ws in self.state.get_websockets() {
            if ws_targets_device(&ws, recipient_device_id) {
                let send_ok = ws.send_with_str(payload.as_str()).is_ok();
                let fresh = ws_is_fresh(&ws, now_ms);
                if send_ok && fresh {
                    delivered_live = true;
                } else if send_ok && !fresh {
                    // Write Ok but last_seen stale = zombie / half-open.
                    zombie_seen = true;
                }
            }
        }
        // A zombie was caught and no other live socket took the delivery, so the device is woken by
        // FCM (from this inbox). How often this line appears in `wrangler tail` is the only measure of how much the
        // liveness window actually catches.
        if zombie_seen && !delivered_live {
            worker::console_log!(
                "[deliv] W1 zombie socket caught (send-ok + stale) -> FCM wake path (grp={})",
                group_id.unwrap_or("1:1")
            );
        }
        // `push_wake_at` is deliberately NOT stamped here. This inbox's `/notify` or
        // `/notify-member` arm wakes an offline row immediately (`wake_gate.rs`) — or coalesces
        // that wake, or it fails — and a row stamped "pushed" from here would be skipped by the
        // backstop even when no push went out. Only the backstop stamps it, after its own push, so
        // every row gets at most one backstop wake on top of the immediate one.
        //
        // The dedup entry carries the REAL delivered_live and is written AFTER the send loop. There
        // is no await between them and the DO is single-threaded, so a retry finds the envelope
        // with the correct liveness.
        self.dedup_insert(sender_id.to_string(), envelope_hash, row.id, now, delivered_live);
        // What a wake may carry: the frame, plus — for a 1:1 frame to an offline device — how many
        // OLDER rows from the same sender device still wait for it (`push::carry`). The phone reads
        // a carried 1:1 frame only when none do: one read ahead of more than the 40 skipped keys
        // vodozemac keeps per chain would leave the oldest unreadable when `/sync` brings them —
        // ack false, `delivery_failed`, a re-pair.
        let mut carried = frame;
        if let (false, Some(device), None) = (delivered_live, recipient_device_id, group_id) {
            carried["older"] = serde_json::json!(self.older_queued(device, sender_id, sender_device_id, row.id));
        }
        Ok(Notified { id: row.id, delivered_live, deduped: false, frame: Some(carried) })
    }

    /// How many 1:1 rows older than `id`, from the same sender device, still wait for `device` —
    /// counted up to [`OLDER_QUEUED_CAP`] (the phone only asks whether it is zero). Unreadable
    /// storage reads as the cap: when in doubt, the push is not read ahead of the queue.
    fn older_queued(
        &self,
        device: &str,
        sender_id: &str,
        sender_device_id: Option<&str>,
        id: i64,
    ) -> i64 {
        #[derive(Deserialize)]
        struct CountRow {
            n: i64,
        }
        let sender_device = match sender_device_id {
            Some(d) => JsValue::from_str(d),
            None => JsValue::NULL,
        };
        self.state
            .storage()
            .sql()
            .exec_raw(
                OLDER_QUEUED_SQL,
                Some(vec![
                    JsValue::from_str(device),
                    JsValue::from_str(sender_id),
                    sender_device,
                    JsValue::from_f64(id as f64),
                ]),
            )
            .ok()
            .and_then(|c| c.to_array::<CountRow>().ok())
            .and_then(|rows| rows.into_iter().next())
            .map_or(OLDER_QUEUED_CAP, |r| r.n)
    }

    /// Is there an existing msg_id in the dedup cache for (sender, envelope_hash)?
    /// Also prunes entries older than the 60s TTL. The mutex borrow never crosses an
    /// await point — this is sync-only work.
    fn dedup_lookup(
        &self,
        sender_id: &str,
        envelope_hash: &[u8; 16],
        now: i64,
    ) -> Option<(i64, bool)> {
        let mut dedup = self.dedup.lock().ok()?;
        dedup.retain(|e| now - e.created_at < DEDUP_TTL_SECS);
        dedup
            .iter()
            .find(|e| e.sender_id == sender_id && &e.envelope_hash == envelope_hash)
            .map(|e| (e.msg_id, e.delivered_live))
    }

    fn dedup_insert(
        &self,
        sender_id: String,
        envelope_hash: [u8; 16],
        msg_id: i64,
        now: i64,
        delivered_live: bool,
    ) {
        if let Ok(mut dedup) = self.dedup.lock() {
            // Memory cap: once exceeded, drop the oldest half (roughly FIFO).
            if dedup.len() >= DEDUP_MAX_ENTRIES {
                let half = dedup.len() / 2;
                dedup.drain(0..half);
            }
            dedup.push(DedupEntry {
                sender_id,
                envelope_hash,
                msg_id,
                created_at: now,
                delivered_live,
            });
        }
    }

    pub(crate) fn flush_pending_to(&self, ws: &WebSocket) {
        // FIX-2(b) (HIGH — NULL tolerance RESTORED): rows belonging to this socket's device AND
        // NULL-device rows (`OR device_id IS NULL`, see select_pending_for_device).
        // RATIONALE: a NULL pending row is now LEGITIMATE — it means "a user who never published a
        // device list" (group fallback FIX-1: the LEFT JOIN writes `recipient_device=None` for a
        // member with no devices). Such a user is a SINGLE logical device, so delivering to the
        // device that connects is safe (no multi-device ambiguity, because NULL only arises for an
        // unpublished-single-device user; the 1:1 path REQUIRES device_id [FIX-2(a)], so NULL NEVER
        // comes from 1:1). Red-team #18's argument — "all NULLs are legacy, ws_upgrade backfill
        // stamps them, drop the tolerance" — is VOID given the FIX-1 group fallback, which keeps
        // producing new NULLs after the cut.
        // S3-TODO: if a multi-device user can ever own a NULL row (a member who has not published
        // after linking a device?) this tolerance must be revisited — NULL would no longer guarantee
        // "one logical device".
        // An unknown attachment device (pre-S1 token) takes the None branch (all rows, device-blind
        // delivery; left untouched).
        let device = ws_attachment_device(ws);
        let rows = self.select_pending_for_device(device.as_deref());
        for r in &rows {
            let _ = ws.send_with_str(pending_frame(r).as_str());
        }
        // Phase-2 step 3: the drain-idle signal, sent AFTER every `pending` frame (CF DO WS sends
        // are single-threaded and ordered, so `sync_idle` is guaranteed to arrive after the last
        // `msg` — no race). A background drain reads it as "no more pending to move this round" and
        // finishes its acks before exiting. `more=true` (the 500-row cap was hit) means there is
        // more, so keep going until the deadline. A foreground client IGNORES this frame (it is
        // only meaningful in drain mode), and an older client already swallows unknown `type`s →
        // backwards compatible.
        let flushed = rows.len();
        let idle = serde_json::json!({
            "type": "sync_idle",
            "flushed": flushed,
            "more": flushed >= 500,
        })
        .to_string();
        let _ = ws.send_with_str(idle.as_str());
    }

    /// FIX-2(b): select pending rows for the given device. The Some branch uses
    /// `device_id = ? OR device_id IS NULL` (a NULL pending row means an
    /// unpublished-single-device user via group fallback FIX-1 → delivering to the device that
    /// connects is safe). The None branch (device-blind S1 token) takes all rows, unchanged.
    fn select_pending_for_device(&self, device: Option<&str>) -> Vec<PendingRow> {
        let storage = self.state.storage();
        let cursor = match device {
            Some(d) => storage.sql().exec_raw(
                "SELECT id, sender_id, envelope_b64, group_id, sender_device_id, created_at
                 FROM pending
                 WHERE device_id = ? OR device_id IS NULL
                 ORDER BY id ASC LIMIT 500",
                Some(vec![JsValue::from_str(d)]),
            ),
            // Attachment device unknown (pre-S1 token) → all rows (today's behaviour:
            // device-blind delivery; the backfill does not run on this path).
            None => storage.sql().exec_raw(
                "SELECT id, sender_id, envelope_b64, group_id, sender_device_id, created_at
                 FROM pending ORDER BY id ASC LIMIT 500",
                sql_no_args(),
            ),
        };
        match cursor {
            Ok(c) => c.to_array().unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    pub(crate) fn flush_pending_to_all(&self) {
        let ws_list = self.state.get_websockets();
        if ws_list.is_empty() {
            return;
        }
        // M2-S2.2: flush each socket filtered by ITS OWN device — no longer pushing the same
        // row to EVERYONE, delivery is device-scoped.
        for ws in &ws_list {
            let device = ws_attachment_device(ws);
            let rows = self.select_pending_for_device(device.as_deref());
            for r in &rows {
                let _ = ws.send_with_str(pending_frame(r).as_str());
            }
        }
    }

}

#[cfg(test)]
mod dedup_sql_tests {
    //! The D-M9 durable-dedup SQL contract, verified with portable rusqlite instead of workerd's
    //! SQLite: UNIQUE(sender_id, env_hash) + ON CONFLICT DO NOTHING RETURNING id.
    use rusqlite::{params, Connection};

    fn setup() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                envelope_b64 TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                group_id TEXT, device_id TEXT, sender_device_id TEXT, env_hash TEXT
            );
            CREATE UNIQUE INDEX idx_pending_env_hash ON pending(sender_id, env_hash);",
        )
        .unwrap();
        c
    }

    /// Portable equivalent of notify_inner's INSERT — returns an id (new row) or None (conflict).
    fn insert(c: &Connection, sender: &str, env_hash: Option<&str>) -> Option<i64> {
        c.query_row(
            "INSERT INTO pending (sender_id, envelope_b64, created_at, env_hash)
             VALUES (?1, 'e', 1, ?2)
             ON CONFLICT(sender_id, env_hash) DO NOTHING
             RETURNING id",
            params![sender, env_hash],
            |r| r.get::<_, i64>(0),
        )
        .ok()
    }

    #[test]
    fn durable_dedup_second_insert_no_row_single_pending() {
        let c = setup();
        let id1 = insert(&c, "alice", Some("hh")).expect("the first INSERT returns an id");
        let id2 = insert(&c, "alice", Some("hh"));
        assert!(
            id2.is_none(),
            "D-M9: a second INSERT with the same (sender, env_hash) RETURNS NO row (DO NOTHING)"
        );
        let cnt: i64 = c
            .query_row("SELECT COUNT(*) FROM pending", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cnt, 1, "a single pending row (the double INSERT was blocked)");
        // The durable-dedup hit path: the existing id is found with a SELECT.
        let found: i64 = c
            .query_row(
                "SELECT id FROM pending WHERE sender_id=?1 AND env_hash=?2",
                params!["alice", "hh"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(found, id1, "a durable-dedup hit returns the existing id");
    }

    #[test]
    fn distinct_recipient_device_hash_both_inserted() {
        // BLOCKER #11 guard: when a group's single Megolm envelope is written for TWO devices of
        // the same member, recipient_device is part of the 4-tuple hash → a DIFFERENT env_hash →
        // the second device is NOT swallowed.
        let c = setup();
        assert!(insert(&c, "alice", Some("hh-dev1")).is_some());
        assert!(
            insert(&c, "alice", Some("hh-dev2")).is_some(),
            "a different env_hash (a different recipient_device) must not be swallowed"
        );
        let cnt: i64 = c
            .query_row("SELECT COUNT(*) FROM pending", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cnt, 2, "a sibling-device group message is NOT lost");
    }

    #[test]
    fn legacy_null_env_hash_multiple_allowed() {
        // Older rows have a NULL env_hash, and a SQLite UNIQUE index allows multiple NULLs
        // (so they never conflict).
        let c = setup();
        assert!(insert(&c, "alice", None).is_some());
        assert!(
            insert(&c, "alice", None).is_some(),
            "NULL env_hash allows multiple rows (old rows produce no UNIQUE collision)"
        );
    }

    /// What a carried 1:1 frame says of the queue ahead of it: the older rows from the SAME sender
    /// device to the SAME recipient device, never a group's, another sender's or a later one —
    /// counted up to 100.
    #[test]
    fn older_queued_counts_only_the_same_lane_ahead() {
        let c = setup();
        let row = |sender: &str, sdev: Option<&str>, dev: &str, group: Option<&str>| {
            c.execute(
                "INSERT INTO pending (sender_id, envelope_b64, created_at, group_id, device_id, sender_device_id)
                 VALUES (?1, 'e', 1, ?2, ?3, ?4)",
                params![sender, group, dev, sdev],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        let count = |dev: &str, sender: &str, sdev: Option<&str>, id: i64| -> i64 {
            c.query_row(super::OLDER_QUEUED_SQL, params![dev, sender, sdev, id], |r| r.get(0))
                .unwrap()
        };
        row("alice", Some("a1"), "b1", None); // counted
        row("alice", Some("a2"), "b1", None); // another sender device
        row("carol", Some("a1"), "b1", None); // another sender
        row("alice", Some("a1"), "b2", None); // another recipient device
        row("alice", Some("a1"), "b1", Some("room")); // a group row: Megolm, no Olm chain
        let me = row("alice", Some("a1"), "b1", None);
        row("alice", Some("a1"), "b1", None); // later: not ahead of it
        assert_eq!(count("b1", "alice", Some("a1"), me), 1);
        assert_eq!(count("b1", "alice", Some("a2"), me), 1);
        assert_eq!(count("b1", "dave", Some("a1"), me), 0);
        for _ in 0..150 {
            row("eve", None, "b9", None);
        }
        let last = row("eve", None, "b9", None);
        assert_eq!(count("b9", "eve", None, last), 100, "a NULL device matches, capped at 100");
    }
}
