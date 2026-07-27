//! Sibling-read durable cursor (2026-06-28, Codex-approved) — a MIRROR of `receipt.rs`, but for
//! converging `viewed_at` (read state) across U's OWN devices. PK = `msg_uid` (a global UUID, so
//! peer-agnostic). `seq` lives in a SEPARATE space (`self_read_meta`), so a self-read gap can never
//! BLOCK the receipt cursor (Codex Q1). The old brittle ReadSelfSync (live Olm self-message: dies on a
//! wedged session, covers only fresh reads) REMAINS as a latency fast-path; this durable path is the
//! AUTHORITATIVE backstop: wedge-immune (WS/HTTP pull, not Olm), full-pull from cursor=0 on a new
//! device, set-once monotonic.
//! Retention (UPDATE 2026-07-03, server-lean audit — Codex-Q8 REVERSED): this table IS now purged at
//! retention parity (`mod.rs` alarm cleanup, the receipt_state pattern). The Q8 fear (losing full-pull)
//! proved unfounded: a new device gets read state ATTACHED TO THE MESSAGE via M4 sibling sync
//! (`viewed_at` travels inside MessageRow).

use super::*;

/// W3 (self-read DoS hardening, 2026-07-02): per-uid length cap — a legitimate msg_uid is a UUID
/// (~36 chars), so anything longer is anomaly/bloat → skip it. The uid COUNT per request is not capped
/// separately: the handler's 32KB body cap already bounds a request (~800 uids) and the `/self-read` DO
/// route is reachable ONLY through that handler (not public) → one entry point, one limit. (The old
/// uid-count truncation was REMOVED — Codex flag: `&uids[..500]` dropped the excess SILENTLY and still
/// answered 204, while the client drops self-read on error → silent loss of read state. The body cap
/// already rejects an over-legitimate request EXPLICITLY with 400.)
const MAX_SELF_READ_UID_LEN: usize = 64;

#[derive(Deserialize)]
struct SelfReadExisting {
    read_at: Option<i64>,
}

#[derive(Deserialize)]
struct SelfReadSeqRow {
    v: i64,
}

#[derive(Deserialize)]
struct SelfReadStateRow {
    msg_uid: String,
    read_at: i64,
    seq: i64,
}

impl UserInbox {
    /// One of U's devices reported "I read these `msg_uid`s" → SET-ONCE write into durable
    /// `self_read_state` (idempotent skip when read_at is already set); every CHANGED row gets an
    /// ATOMICALLY unique seq (`UPDATE self_read_meta RETURNING` — the receipt.rs pattern), then push
    /// `self_read_update` (cursor poke) + `self_read_delta` (latency fast-path) to the other sockets.
    /// `ts_ms` = server receive time (the stored read_at is bookkeeping only; each client sets its own
    /// viewed_at when applying).
    pub(crate) fn apply_self_read(&self, uids: &[String], ts_ms: i64) {
        if uids.is_empty() {
            return;
        }
        let storage = self.state.storage();
        let sql = storage.sql();
        let mut max_seq: i64 = 0;
        let mut changed = false;
        let mut delta_rows: Vec<serde_json::Value> = Vec::new();
        for uid in uids {
            // W3: skip an empty OR over-long uid (legit msg_uid = ~36-char UUID; >MAX = anomaly/bloat).
            if uid.is_empty() || uid.len() > MAX_SELF_READ_UID_LEN {
                continue;
            }
            // Set-once: already flagged read (read_at NOT NULL) → idempotent skip (no seq bump).
            let existing = match sql.exec_raw(
                "SELECT read_at FROM self_read_state WHERE msg_uid = ?",
                Some(vec![JsValue::from_str(uid)]),
            ) {
                Ok(c) => c
                    .to_array::<SelfReadExisting>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .and_then(|r| r.read_at),
                Err(_) => None,
            };
            if existing.is_some() {
                continue;
            }
            // Atomic seq reservation (bump + read in one statement; no seq reuse, no silent skip).
            let seq = match sql.exec_raw(
                "UPDATE self_read_meta SET v = v + 1 WHERE k = 'seq' RETURNING v",
                sql_no_args(),
            ) {
                Ok(c) => c
                    .to_array::<SelfReadSeqRow>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| r.v),
                Err(_) => None,
            };
            let Some(seq) = seq else {
                continue; // meta bump failed (rare) → skip this uid; NEVER reuse a seq.
            };
            changed = true;
            if seq > max_seq {
                max_seq = seq;
            }
            let _ = sql.exec_raw(
                "INSERT INTO self_read_state (msg_uid, read_at, seq, updated_at)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT(msg_uid) DO UPDATE SET seq = excluded.seq, updated_at = excluded.updated_at",
                Some(vec![
                    JsValue::from_str(uid),
                    JsValue::from_f64(ts_ms as f64),
                    JsValue::from_f64(seq as f64),
                    JsValue::from_f64(ts_ms as f64),
                ]),
            );
            delta_rows.push(serde_json::json!({ "msg_uid": uid, "read_at": ts_ms, "seq": seq }));
        }
        if !changed {
            return;
        }
        // Notify all of U's devices → each one pulls from its own cursor (authoritative).
        let payload =
            serde_json::json!({ "type": "self_read_update", "max_seq": max_seq }).to_string();
        for ws in self.state.get_websockets() {
            let _ = ws.send_with_str(payload.as_str());
        }
        // LATENCY fast-path: push the changed rows straight to the SAME sockets so they can apply
        // without waiting for a cursor pull round-trip. Row shape == self_read_sync_payload's, so the
        // client REUSES handle_self_read_batch.
        if !delta_rows.is_empty() {
            let delta = serde_json::json!({
                "type": "self_read_delta",
                "rows": delta_rows,
                "max_seq": max_seq,
            })
            .to_string();
            for ws in self.state.get_websockets() {
                let _ = ws.send_with_str(delta.as_str());
            }
        }
    }

    /// `self_read_state` rows past the cursor (`seq > since ORDER BY seq ASC LIMIT 500`) as a
    /// transport-agnostic `{rows, more, since}` (the receipt_sync_payload pattern; no type tag).
    /// The WS frame and HTTP `GET /self-read-sync` share this builder → bit-identical rows.
    /// SQL error → None.
    pub(crate) fn self_read_sync_payload(&self, since: i64) -> Option<serde_json::Value> {
        let storage = self.state.storage();
        let rows: Vec<SelfReadStateRow> = match storage.sql().exec_raw(
            "SELECT msg_uid, read_at, seq FROM self_read_state
             WHERE seq > ? ORDER BY seq ASC LIMIT 500",
            Some(vec![JsValue::from_f64(since as f64)]),
        ) {
            Ok(c) => c.to_array().unwrap_or_default(),
            Err(_) => return None,
        };
        let more = rows.len() == 500;
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| serde_json::json!({ "msg_uid": r.msg_uid, "read_at": r.read_at, "seq": r.seq }))
            .collect();
        Some(serde_json::json!({ "rows": json_rows, "more": more, "since": since }))
    }

    /// WS `self_read_sync{since}` → `self_read_batch` frame (receipt_sync pattern; silent on SQL error).
    pub(crate) fn self_read_sync(&self, ws: &WebSocket, since: i64) {
        let Some(mut payload) = self.self_read_sync_payload(since) else {
            return;
        };
        payload["type"] = serde_json::Value::String("self_read_batch".into());
        let _ = ws.send_with_str(payload.to_string().as_str());
    }
}
