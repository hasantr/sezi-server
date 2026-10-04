use crate::utils::now_secs;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::*;

mod alarm_ops;
mod alarm_policy;
mod forward;
mod message;
mod receipt;
mod self_read;
mod ws;

use alarm_policy::next_alarm_delay_ms;

const FLUSH_INTERVAL_MS: i64 = 90 * 1000;
/// Alarm interval for a DO with nothing to deliver that still holds retention-eligible rows.
/// Four wakes a day covers a 24 h purge and is the difference between ~4 and ~960 billed wakes
/// per idle inbox per day. See `alarm_policy`.
const IDLE_INTERVAL_MS: i64 = 6 * 3600 * 1000;
const CLEANUP_INTERVAL_MS: i64 = 24 * 3600 * 1000;
const LAST_CLEANUP_KEY: &str = "last_cleanup_at";
const REMOVED_ACCOUNT_KEY: &str = "membership_removed";

/// DO storage key holding the recipient user_id that owns this inbox. An offline DO (no WS
/// attachment) has no other way to learn its own user, which the alarm's FCM wake needs.
const RECIPIENT_UID_KEY: &str = "recipient_uid";

/// A `pending` row older than this, still unacked and with a NULL `push_wake_at`, is treated as a
/// failed live delivery and gets one FCM wake. The grace period preserves the client's chance to
/// ack; the alarm scans every 90s, so a stuck row is woken within 30-120s.
const PUSH_BACKSTOP_GRACE_SECS: i64 = 30;

/// One-shot NULL-device backfill flag (DO storage). On the first device-aware WS connection every
/// `pending.device_id IS NULL` row is stamped with that device; the flag stops later reconnects
/// from re-stamping, which would be racy since every reconnect stale-closes the previous socket.
const DEVICE_BACKFILL_DONE_KEY: &str = "m2_device_backfill_done";

/// Idempotency window: the same (sender_id, envelope_b64) arriving again returns the existing
/// msg_id instead of INSERTing a duplicate, so a client retry after a network glitch neither
/// writes a second row nor delivers the WS frame twice. 60s covers a 15s timeout plus retries.
const DEDUP_TTL_SECS: i64 = 60;

/// Memory ceiling for the dedup vector. The DO is long-lived, so this guards against spam.
const DEDUP_MAX_ENTRIES: usize = 256;

/// Per-user inbox + WebSocket gateway. Owns the pending message queue in SQL storage, WS
/// hibernation, the periodic alarm flush + cleanup, and the ack/delivered/read RPC bridge.
/// (No typing arm: typing rides E2E-encrypted inside an ordinary `send`.)
#[durable_object]
pub struct UserInbox {
    pub(crate) state: State,
    pub(crate) env: Env,
    pub(crate) initialized: std::cell::Cell<bool>,
    /// (sender, envelope-hash) pairs handled within the last DEDUP_TTL_SECS. In memory
    /// deliberately: it costs no storage writes and a DO lives for hours. The duplicate window
    /// across a restart is covered by the client-side `hasIncomingRemoteId` dedup.
    pub(crate) dedup: std::sync::Mutex<Vec<DedupEntry>>,
    /// Has the recipient user_id been written to storage in this DO instance? Avoids a redundant
    /// write per notify; resets on a DO restart, so the first notify after one writes it again.
    pub(crate) uid_persisted: std::cell::Cell<bool>,
}

#[derive(Clone)]
pub(crate) struct DedupEntry {
    pub(crate) sender_id: String,
    /// First 16 bytes of the SHA256 — collision probability is negligible (2^64 birthday bound).
    pub(crate) envelope_hash: [u8; 16],
    pub(crate) msg_id: i64,
    pub(crate) created_at: i64,
    /// The FIRST delivery's real `delivered_live` result, replayed on a dedup hit. A hard-coded
    /// `true` here would silently suppress the offline wake.
    pub(crate) delivered_live: bool,
}

#[derive(Deserialize)]
struct NotifyBody {
    sender_id: String,
    envelope_b64: String,
    /// The recipient user_id (this DO's owner), which the caller already knows. `notify_inner`
    /// persists it so the alarm can send the stuck-pending FCM wake. `None` on an older body
    /// skips the persist: the backstop becomes a no-op while the immediate push still works.
    #[serde(default)]
    recipient_id: Option<String>,
    /// The group this message belongs to during a group fan-out; absent for 1:1.
    #[serde(default)]
    group_id: Option<String>,
    /// The sender's device.
    #[serde(default)]
    sender_device_id: Option<String>,
    /// The target recipient device. `None` means the single-primary / compatibility path.
    #[serde(default)]
    recipient_device_id: Option<String>,
    /// The sender asked for no FCM wake (control traffic). Absent reads as false, i.e. wake.
    #[serde(default)]
    silent: bool,
}

#[derive(Deserialize)]
struct ForwardIdsBody {
    from: String,
    ids: Vec<i64>,
    /// The device this receipt is scoped to. In the delivered/failed direction it is the recipient
    /// device; in the read direction the sender sends the same thing under `sender_device_id`.
    /// `device_for_forward` picks whichever arrived.
    #[serde(default)]
    recipient_device_id: Option<String>,
    #[serde(default)]
    sender_device_id: Option<String>,
    /// msg_uids PARALLEL to `ids` (the sender's local_id, taken by the reader from the E2E
    /// payload). `apply_receipt` stores it in `receipt_state.msg_uid` so a sibling device can match
    /// the read via `oc-{msg_uid}`. An old client or the delivered path sends an empty Vec.
    #[serde(default)]
    uids: Vec<String>,
}

/// Sibling-read durable cursor: a device of U reports the `msg_uid`s of the incoming messages it
/// read (peer- and group-agnostic — one global list). `read_at` is the server's now.
#[derive(Deserialize)]
struct SelfReadBody {
    uids: Vec<String>,
}

impl ForwardIdsBody {
    /// The device to hand to forward_signal: recipient_device_id first (delivered/failed),
    /// otherwise sender_device_id (the reverse read direction).
    fn device_for_forward(&self) -> Option<&str> {
        self.recipient_device_id
            .as_deref()
            .or(self.sender_device_id.as_deref())
    }
}

#[derive(Deserialize)]
pub(crate) struct PendingRow {
    pub(crate) id: i64,
    pub(crate) sender_id: String,
    pub(crate) envelope_b64: String,
    #[serde(default)]
    pub(crate) group_id: Option<String>,
    /// The sender's device (needed for the flush replay frame).
    #[serde(default)]
    pub(crate) sender_device_id: Option<String>,
    pub(crate) created_at: i64,
}

#[derive(Deserialize)]
pub(crate) struct ForwardIdRow {
    pub(crate) id: i64,
}

#[derive(Deserialize)]
pub(crate) struct ForwardQueueRow {
    pub(crate) id: i64,
    pub(crate) kind: String,
    pub(crate) from_user: String,
    pub(crate) ids_json: String,
    /// The recipient device that produced the receipt (needed to reconstruct the replay payload).
    #[serde(default)]
    pub(crate) recipient_device_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Attachment {
    #[serde(rename = "userId")]
    pub(crate) user_id: String,
    /// The DEVICE behind this WS connection (from the JWT's mandatory device_id claim), so a
    /// socket either has a device or was never attached. This is the SOCKET's own device —
    /// distinct from `pending.device_id`, which is still nullable and must stay that way (see the
    /// ack arm in `ws.rs`).
    #[serde(rename = "deviceId")]
    pub(crate) device_id: String,
    /// When the last CLIENT→SERVER frame (ping/ack/read; the client text-pings every 5s) was
    /// received on this socket, in ms. `notify_inner` uses it as its LIVENESS TEST: only a socket
    /// that produced a frame within `WS_LIVENESS_WINDOW_MS` counts as genuinely live. On a
    /// half-open socket `send_with_str` returns Ok while the client receives nothing, so a stale
    /// stamp is what makes the FCM wake fire instead of a silent delivery loss.
    #[serde(rename = "lastSeenMs", default)]
    pub(crate) last_seen_ms: Option<i64>,
}

pub(crate) fn sql_no_args() -> Option<Vec<JsValue>> {
    None
}

impl DurableObject for UserInbox {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            initialized: std::cell::Cell::new(false),
            dedup: std::sync::Mutex::new(Vec::new()),
            uid_persisted: std::cell::Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();
        let method = req.method();

        // POST /purge-account → 204. Called after the D1 membership-deletion batch commits the
        // purge outbox: a final status frame to the open sockets, then all SQL/KV/alarm storage
        // deleted, then a permanent tombstone. Idempotent, so replaying it is safe.
        if method == Method::Post && path == "/purge-account" {
            let sockets = self.state.get_websockets();
            for socket in sockets {
                let _ = socket.send_with_str(r#"{"type":"membership_removed"}"#);
                let _ = socket.close(Some(1008), Some("membership_removed"));
            }
            let storage = self.state.storage();
            storage.delete_all().await?;
            // `delete_all()` does NOT clear the alarm, so without this a purged inbox goes on
            // waking every 90s forever. Best-effort: if the delete fails, `alarm()`'s own
            // removed-account check refuses to re-arm, so the chain ends after one more wake.
            let _ = storage.delete_alarm().await;
            storage.put(REMOVED_ACCOUNT_KEY, true).await?;
            self.initialized.set(false);
            self.uid_persisted.set(false);
            if let Ok(mut dedup) = self.dedup.lock() {
                dedup.clear();
            }
            return Response::empty().map(|r| r.with_status(204));
        }

        if self
            .state
            .storage()
            .get::<bool>(REMOVED_ACCOUNT_KEY)
            .await?
            .unwrap_or(false)
        {
            return Response::error("membership_removed", 410);
        }

        // POST /contact-update {revision} → 204. An ephemeral nudge: no storage, no SQL. An
        // offline user does its authoritative pull on boot/resume; an open socket is merely poked.
        if method == Method::Post && path == "/contact-update" {
            #[derive(Deserialize)]
            struct ContactUpdateBody {
                revision: i64,
            }
            let body: ContactUpdateBody = req.json().await?;
            let frame = serde_json::json!({
                "type": "contact_update",
                "revision": body.revision,
            })
            .to_string();
            for socket in self.state.get_websockets() {
                let _ = socket.send_with_str(&frame);
            }
            return Response::empty().map(|r| r.with_status(204));
        }
        if method == Method::Post && path == "/group-update" {
            for socket in self.state.get_websockets() {
                let _ = socket.send_with_str(r#"{"type":"group_update"}"#);
            }
            return Response::empty().map(|r| r.with_status(204));
        }
        self.ensure_init().await?;

        // WS upgrade (the worker proxies /sync here).
        if req
            .headers()
            .get("upgrade")
            .ok()
            .flatten()
            .as_deref()
            .map(|s| s.to_lowercase())
            == Some("websocket".into())
        {
            return self.ws_upgrade(req).await;
        }

        match (method, path.as_str()) {
            (Method::Post, "/notify") => {
                let body: NotifyBody = req.json().await?;
                let (id, delivered_live) = self
                    .notify_inner(
                        &body.sender_id,
                        body.sender_device_id.as_deref(),
                        body.recipient_device_id.as_deref(),
                        body.recipient_id.as_deref(),
                        &body.envelope_b64,
                        body.group_id.as_deref(),
                        body.silent,
                    )
                    .await?;
                // Cheap (a no-op get_alarm when already armed) and revives a chain broken by an
                // earlier transient error, so a recipient who never reconnects over WS still
                // gets the FCM backstop.
                self.ensure_alarm().await;
                Response::from_json(
                    &serde_json::json!({ "id": id, "delivered_live": delivered_live }),
                )
            }
            // POST /forward-delivered, /forward-read {from, ids, uids} → 204. Both land in the
            // durable `receipt_state` plus a per-device cursor sync, NOT the consume-once
            // forward_queue, and both ignore recipient_device_id: the tick goes to ALL of A's
            // devices and the aggregation happens client-side, keyed by remote_id.
            (Method::Post, "/forward-delivered") => {
                let body: ForwardIdsBody = req.json().await?;
                self.apply_receipt(
                    "delivered",
                    &body.from,
                    &body.ids,
                    &body.uids,
                    (now_secs() * 1000) as i64,
                );
                Response::empty().map(|r| r.with_status(204))
            }
            (Method::Post, "/forward-read") => {
                let body: ForwardIdsBody = req.json().await?;
                self.apply_receipt(
                    "read",
                    &body.from,
                    &body.ids,
                    &body.uids,
                    (now_secs() * 1000) as i64,
                );
                Response::empty().map(|r| r.with_status(204))
            }
            // POST /forward-delivery-failed {from, ids} → 204. The receiver could not decrypt
            // (MAC mismatch); on the sender the message moves to failedDelivery and an auto-retry
            // fires once the session has self-healed.
            (Method::Post, "/forward-delivery-failed") => {
                let body: ForwardIdsBody = req.json().await?;
                self.forward_signal(
                    "delivery_failed",
                    &body.from,
                    body.device_for_forward(),
                    &body.ids,
                );
                // The ONLY arm that still enqueues into `forward_queue`, so it is the third door
                // (with `/notify` and `ws_upgrade`) that has to restart an idle inbox's alarm
                // chain — whatever creates work must be able to restart it.
                self.ensure_alarm().await;
                Response::empty().map(|r| r.with_status(204))
            }
            // GET /receipt-sync?since=<seq> → {rows, more}. The HTTP twin of the WS `receipt_sync`
            // frame, sharing the `receipt_sync_payload` builder so both are bit-identical; a
            // device on the HTTP send fallback cursor-pulls its tick from here. A SQL error
            // becomes an empty batch — the cursor does not advance and the next event re-pulls.
            (Method::Get, "/receipt-sync") => {
                let since = url
                    .query_pairs()
                    .find(|(k, _)| k == "since")
                    .and_then(|(_, v)| v.parse::<i64>().ok())
                    .unwrap_or(0);
                let payload = self
                    .receipt_sync_payload(since)
                    .unwrap_or_else(|| serde_json::json!({ "rows": [], "more": false }));
                Response::from_json(&payload)
            }
            // POST /self-read {uids} → 204. A device of U reports the msg_uids it read →
            // self_read_state set-once + seq bump + a delta to U's other devices.
            (Method::Post, "/self-read") => {
                let body: SelfReadBody = req.json().await?;
                self.apply_self_read(&body.uids, (now_secs() * 1000) as i64);
                Response::empty().map(|r| r.with_status(204))
            }
            // GET /self-read-sync?since=<seq> → {rows, more}. The HTTP twin of the WS
            // `self_read_sync` frame; a new device pulls from since=0 to converge its backlog.
            (Method::Get, "/self-read-sync") => {
                let since = url
                    .query_pairs()
                    .find(|(k, _)| k == "since")
                    .and_then(|(_, v)| v.parse::<i64>().ok())
                    .unwrap_or(0);
                let payload = self
                    .self_read_sync_payload(since)
                    .unwrap_or_else(|| serde_json::json!({ "rows": [], "more": false }));
                Response::from_json(&payload)
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        self.handle_ws_message(ws, message).await
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let _ = ws.close(Some(code as u16), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        // Read BEFORE `ensure_init`, which re-creates the tables and re-arms the alarm. A purged
        // inbox must leave here without arming anything; running init first is exactly how one
        // kept its 90s heartbeat alive.
        let account_removed = self
            .state
            .storage()
            .get::<bool>(REMOVED_ACCOUNT_KEY)
            .await?
            .unwrap_or(false);
        if account_removed {
            return Response::empty();
        }
        self.ensure_init().await?;
        self.flush_pending_to_all();
        // If the sender misses the reconnect, the periodic alarm pushes anyway (idempotent: a
        // repeat is removed by the client's `forward_ack` and the sender side dedups it).
        self.flush_forwards_to_all();
        // Ground truth for delivery: the liveness test narrows the delivered_live false-positive
        // window but cannot close it (a socket that dies right after a ping). Still sitting in
        // pending means unacked means undelivered → wake once the grace period is over.
        self.backstop_push_stale_pending().await;
        let now_ms_val = (now_secs() * 1000) as i64;
        let last: Option<i64> = self
            .state
            .storage()
            .get::<i64>(LAST_CLEANUP_KEY)
            .await
            .ok()
            .flatten();
        let last_val = last.unwrap_or(0);
        if now_ms_val - last_val >= CLEANUP_INTERVAL_MS {
            // Admin-configurable (D1 server_settings), one SELECT per cleanup and therefore at
            // most once per 24h; the helper falls back to 30 days on an error or a missing row.
            let days = crate::server::handlers::fetch_message_retention_days(&self.env).await;
            let cutoff = (now_secs() as i64) - days * 24 * 3600;
            let storage = self.state.storage();
            // BEST-EFFORT, like its siblings: a bare `?` here would abort the handler and skip
            // the `ensure_alarm` re-arm below, killing the alarm chain. The watermark advances
            // ONLY on success, so a transient error is retried on the next alarm rather than
            // skipping retention for 24h.
            let purge_ok = storage
                .sql()
                .exec_raw(
                    "DELETE FROM pending WHERE created_at < ?",
                    Some(vec![JsValue::from_f64(cutoff as f64)]),
                )
                .is_ok();
            // `updated_at` is in ms, hence cutoff*1000. The high-water mark (`receipt_meta`) is
            // never purged → seq stays monotonic and cursors stay consistent.
            let _ = storage.sql().exec_raw(
                "DELETE FROM receipt_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // self_read_state is purged at retention parity, not exempt: it is the live
            // incremental convergence cursor, and a row beyond retention is dead metadata. A new
            // device gets old messages via M4 sibling sync, whose package carries `viewed_at`
            // alongside the message, so read state flows independently of this table. As with
            // receipt_state, the high-water mark (self_read_meta) is never purged. updated_at is ms.
            let _ = storage.sql().exec_raw(
                "DELETE FROM self_read_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // Orphan receipt rows — especially delivery_failed ones the client never
            // forward_acked — otherwise accumulate forever and are replayed unconditionally on a
            // fresh reconnect, re-triggering `delete_all_olm_blobs` on the receiver. `created_at`
            // is in MS here, unlike pending's seconds-based cutoff.
            let _ = storage.sql().exec_raw(
                "DELETE FROM forward_queue WHERE created_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            if purge_ok {
                let _ = storage.put(LAST_CLEANUP_KEY, now_ms_val).await;
            }
        }
        // Re-arm robustly (a blind `let _ = set_alarm` lets one transient error break the chain
        // for the life of this DO instance), and CONDITIONALLY: an inbox with nothing queued and
        // nobody connected stops rather than waking ~960 times a day (see `alarm_policy`). Both
        // events that create work — `/notify` and `ws_upgrade` — call `ensure_alarm`.
        let work = self.measure_alarm_work(account_removed);
        if let Some(delay) = next_alarm_delay_ms(work, FLUSH_INTERVAL_MS, IDLE_INTERVAL_MS) {
            self.arm_alarm_within(delay).await;
        }
        Response::empty()
    }
}

impl UserInbox {
    async fn ensure_init(&self) -> Result<()> {
        if self.initialized.get() {
            return Ok(());
        }
        let storage = self.state.storage();
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                envelope_b64 TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_pending_created ON pending(created_at)",
            sql_no_args(),
        )?;
        // Durable dedup, since the in-memory one is lost on a DO restart and a retry would then
        // create a SECOND pending row. env_hash is the 4-tuple
        // SHA256(sender|sender_dev|recipient_dev|envelope), so a group's single Megolm envelope
        // written for two devices of the same member hashes differently per device and the
        // sibling's row is not swallowed. Older rows have NULL, which a UNIQUE index permits.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN env_hash TEXT",
            sql_no_args(),
        );
        let _ = storage.sql().exec_raw(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_env_hash ON pending(sender_id, env_hash)",
            sql_no_args(),
        );
        // Every ADD COLUMN below is an ALTER-and-ignore: the error is swallowed when the column
        // already exists, because `CREATE TABLE IF NOT EXISTS` never widens an existing table.
        //
        // group_id — the group a message belongs to, so the recipient picks the Megolm decrypt
        // path; NULL for 1:1.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN group_id TEXT",
            sql_no_args(),
        );
        // device_id — which RECIPIENT DEVICE the row belongs to (per-device queue + ack
        // isolation). Older NULL rows are stamped by the first-WS backfill in `ws_upgrade`.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN device_id TEXT",
            sql_no_args(),
        );
        // sender_device_id — the recipient's frame must carry it so 1:1 can pick the right Olm
        // device session. A live push takes it from the notify_inner parameter, but a flush replay
        // has to read it back, hence a column. NULL means unknown.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN sender_device_id TEXT",
            sql_no_args(),
        );
        // push_wake_at (ms) — NULL means no backstop wake has fired for this row yet. Written
        // ONLY by the backstop after its own push (notify_inner deliberately leaves it NULL), so
        // every row gets at most one backstop wake.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN push_wake_at INTEGER",
            sql_no_args(),
        );
        // silent — the sender declined an FCM wake for this envelope (control traffic). Stored so
        // the backstop skips the row: a wake the immediate path declined must not reappear
        // minutes later. NULL reads as "wake".
        let _ = storage
            .sql()
            .exec_raw("ALTER TABLE pending ADD COLUMN silent INTEGER", sql_no_args());
        // forward_queue — receipt forwards (delivered / read / delivery_failed) are persistent
        // rather than fire-and-forget WS pushes: pushed immediately to whatever sockets exist AND
        // written here, replayed by flush_forwards on reconnect, cleared by the sender's
        // `forward_ack` frame.
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS forward_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                from_user TEXT NOT NULL,
                ids_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                pushed_at INTEGER
            )",
            sql_no_args(),
        )?;
        let _ = storage.sql().exec_raw(
            "ALTER TABLE forward_queue ADD COLUMN pushed_at INTEGER",
            sql_no_args(),
        );
        // recipient_device_id — which recipient device produced the forward. It makes the replay
        // device-accurate and is part of the dedup key: without it, a receipt queued while the WS
        // was down replayed device-less and missed.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE forward_queue ADD COLUMN recipient_device_id TEXT",
            sql_no_args(),
        );
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_fwd_created ON forward_queue(created_at)",
            sql_no_args(),
        )?;
        // The dedup lookup: (kind, from_user, recipient_device_id, ids_json).
        let _ = storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_fwd_dedup_dev ON forward_queue(kind, from_user, recipient_device_id, ids_json, created_at)",
            sql_no_args(),
        );
        // The account-level durable receipt log (delivered/read), in place of the consume-once
        // forward_queue: every A device syncs idempotently from its own `seq` cursor, which is
        // what survives the sibling race, zombie sockets and reconnect gaps. PK(peer_id,
        // remote_id) is B's per-device receipt id; rolling ticks up to a logical message happens
        // client-side. `seq` is account-global and monotonic — the `receipt_meta` high-water never
        // goes backwards even if the table is purged. See receipt.rs.
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS receipt_state (
                peer_id TEXT NOT NULL,
                remote_id INTEGER NOT NULL,
                delivered_at INTEGER,
                read_at INTEGER,
                seq INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, remote_id)
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_receipt_seq ON receipt_state(seq)",
            sql_no_args(),
        )?;
        // msg_uid — lets a sibling device correlate its `oc-{msg_uid}` row with the read.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE receipt_state ADD COLUMN msg_uid TEXT",
            sql_no_args(),
        );
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS receipt_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "INSERT OR IGNORE INTO receipt_meta (k, v) VALUES ('seq', 0)",
            sql_no_args(),
        )?;
        // The sibling-read durable cursor: a mirror of receipt_state on a separate axis,
        // converging `viewed_at` across U's OWN devices. Durable and cursor-based rather than a
        // live Olm self-message, which dies on a wedged session, covers only fresh reads and gets
        // a new device's backlog wrong. PK = msg_uid (a global UUID, hence peer-agnostic). `seq`
        // lives in its own space (`self_read_meta`) so a self-read gap cannot block the receipt
        // cursor. Purged at retention parity — see the alarm cleanup above and self_read.rs.
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS self_read_state (
                msg_uid TEXT PRIMARY KEY,
                read_at INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_self_read_seq ON self_read_state(seq)",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS self_read_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "INSERT OR IGNORE INTO self_read_meta (k, v) VALUES ('seq', 0)",
            sql_no_args(),
        )?;
        // msg_uid-only read receipts, for a message pulled by M4 link-time sync: msg_id is NULL
        // there, which receipt_state's PK(peer_id, remote_id) cannot represent. A separate
        // uid-keyed table rather than a synthetic remote_id (semantic debt and collision risk),
        // sharing the `receipt_meta` seq space so one cursor covers both.
        //
        // NEVER WRITTEN, deliberately: core skips the receipt entirely when it has no remote_id,
        // so nothing reaches the uid branch, and the client closed the user-visible half instead
        // (a sibling holding a remote_id relays the receipt). What is left uncovered is the case
        // where NO device of the account holds a remote_id — narrow and self-limiting. Kept as
        // groundwork; finish it only if that case is ever reported.
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS receipt_uid_state (
                peer_id TEXT NOT NULL,
                msg_uid TEXT NOT NULL,
                delivered_at INTEGER,
                read_at INTEGER,
                seq INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, msg_uid)
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_receipt_uid_seq ON receipt_uid_state(seq)",
            sql_no_args(),
        )?;
        // delivered/read live in receipt_state; any left in forward_queue are exposed to the
        // consume-once + global-ack-DELETE sibling-steal race, so drain them. Anything in flight
        // is repaired by StateDigest reconciliation and the next receipt. delivery_failed stays
        // (still on the forward_queue path), and new delivered/read never enter it, so this
        // DELETE is idempotent.
        let _ = storage.sql().exec_raw(
            "DELETE FROM forward_queue WHERE kind IN ('delivered', 'read')",
            sql_no_args(),
        );
        // The initial arm goes through `ensure_alarm` (3 bounded retries, logs on failure) rather
        // than a single swallowed `set_alarm`: if the first arm fails and no WS reconnect ever
        // happens, the backstop never runs.
        self.ensure_alarm().await;
        self.initialized.set(true);
        Ok(())
    }

    async fn ws_upgrade(&self, req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;

        // A DO fetch does NOT pass through the lib.rs `#[event(fetch)]` boot guard (it may run in
        // a different isolate), so prepare the JWT key here too — from the env secret, or from the
        // D1 self-provision cache when there is none. Memoized, so an installation with the env
        // secret set never touches D1.
        crate::self_provision::ensure_keys(&self.env).await;

        // The token and device_id are parsed BEFORE accept_web_socket and the stale close,
        // because the backfill below has to know the device first. (The token arrives as
        // Sec-WebSocket-Protocol "sezgi.bearer.v1, <token>"; lib.rs sync_ws already verified it
        // before proxying, so this re-parse only builds the attachment.) The `device_id` claim is
        // mandatory, so either both are known or the token was not ours.
        let attached: Option<(String, String)> = crate::extract_bearer_subprotocol(&req)
            .ok()
            .and_then(|t| crate::auth::jwt::token_identity(&self.env, &t).ok());
        let attach_device: Option<&str> = attached.as_ref().map(|(_, d)| d.as_str());

        // The stale close is DEVICE-AWARE: only the previous socket of the SAME device is closed
        // as superseded (reconnect/zombie cleanup). Closing them all would have two devices of one
        // user constantly tearing down each other's socket, breaking the linking flow and
        // dual-device delivery — and it is unnecessary, because each socket flushes and acks only
        // its own pending rows. Option equality gives exactly the right semantics: a device-less
        // socket is kept when a device-aware one connects, and flush/ack tolerate
        // "OR device_id IS NULL", so it still gets its queue.
        let stale = self.state.get_websockets();
        self.state.accept_web_socket(&server);
        for old in stale {
            let old_dev = old
                .deserialize_attachment::<Attachment>()
                .ok()
                .flatten()
                .map(|a| a.device_id);
            if old_dev.as_deref() == attach_device {
                let _ = old.close(Some(1000), Some("superseded"));
            }
        }

        if let Some((uid, dev)) = attached.clone() {
            let _ = server.serialize_attachment(Attachment {
                user_id: uid,
                device_id: dev,
                // A freshly accepted socket counts as live for one `WS_LIVENESS_WINDOW_MS`, so no
                // spurious push happens before the client sends its first ping.
                last_seen_ms: Some((now_secs() * 1000) as i64),
            });
        }

        // The device comes straight from the claim and is NEVER derived.
        if let Some(dev) = attach_device {
            self.backfill_null_device_once(dev).await;
        }

        self.flush_pending_to(&server);
        // force=true: a FRESH socket by definition never received what was pushed to the old
        // (dead/zombie) one, so ignore pushed_at and replay the whole queue. Without this a read
        // receipt could be delayed for hours; the client dedups on forward_id.
        self.flush_forwards_to(&server, true);
        // Self-heal an alarm chain broken by a transient set_alarm error. A no-op when armed.
        self.ensure_alarm().await;

        // Echo back the subprotocol the client offered: the tokio-tungstenite client validates
        // the server's selection and fails with "no subprotocol selected" if it is not echoed.
        let resp = Response::from_websocket(pair.client)?;
        let headers = resp.headers().clone();
        headers.set("Sec-WebSocket-Protocol", "sezgi.bearer.v1")?;
        Ok(resp.with_headers(headers))
    }

    /// Stamp every `pending.device_id IS NULL` row with the given device exactly ONCE, behind the
    /// DEVICE_BACKFILL_DONE_KEY flag, so a reconnect never re-stamps.
    ///
    /// It only catches the NULLs present at the FIRST device-aware connection. A NULL row created
    /// later (the group fallback, for a member who published no devices) is skipped here and
    /// reaches the right device through the complementary `OR device_id IS NULL` tolerance in
    /// flush/ack. Both rest on NULL occurring only for a user with one unpublished device — if a
    /// multi-device user can ever own a NULL row, revisit them together.
    async fn backfill_null_device_once(&self, device_id: &str) {
        let storage = self.state.storage();
        let done: Option<bool> = storage
            .get::<bool>(DEVICE_BACKFILL_DONE_KEY)
            .await
            .ok()
            .flatten();
        if done == Some(true) {
            return;
        }
        let _ = storage.sql().exec_raw(
            "UPDATE pending SET device_id = ? WHERE device_id IS NULL",
            Some(vec![JsValue::from_str(device_id)]),
        );
        let _ = storage.put(DEVICE_BACKFILL_DONE_KEY, true).await;
    }
}
