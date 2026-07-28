use crate::auth::jwt::{device_id_from_token, verify_access_token};
use crate::utils::now_secs;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::*;

mod forward;
mod message;
mod receipt;
mod self_read;
mod ws;

const FLUSH_INTERVAL_MS: i64 = 90 * 1000;
const CLEANUP_INTERVAL_MS: i64 = 24 * 3600 * 1000;
const LAST_CLEANUP_KEY: &str = "last_cleanup_at";
const REMOVED_ACCOUNT_KEY: &str = "membership_removed";

/// W1 backstop: DO storage key holding the RECIPIENT user_id that owns this inbox (needed for the
/// alarm's stuck-pending FCM wake; an offline DO has no other way to learn its own user).
const RECIPIENT_UID_KEY: &str = "recipient_uid";

/// W1 backstop: once a `pending` row is older than this many seconds AND is still unacked AND its
/// `push_wake_at` is NULL (no backstop wake has fired for it yet), treat the live delivery as
/// failed and send an FCM wake. The grace period preserves the client's chance to ack (we do not
/// push a freshly inserted row immediately); the alarm scans every 90s, so a stuck row gets its
/// wake within 30-120s. This is the rare false-positive edge — the common offline case already
/// gets the caller-side immediate push.
const PUSH_BACKSTOP_GRACE_SECS: i64 = 30;

/// M2-S2.2 — one-shot NULL-device backfill flag (DO storage).
/// On the first device-aware WS connection it stamps every `pending.device_id IS NULL` row with
/// THAT device; once the flag is SET later reconnects do NOT RE-STAMP (red-team HIGH #3: every
/// reconnect stale-closes the previous socket → frequent reconnects → without the flag the
/// backfill would be racy). With N=1 the DO belongs to a single device so the backfill is correct;
/// multi-device is S3.
const DEVICE_BACKFILL_DONE_KEY: &str = "m2_device_backfill_done";

/// Idempotency: if the same (sender_id, envelope_b64) arrives again within this window, return the
/// existing msg_id instead of INSERTing a duplicate, so a client retry after a network glitch
/// neither writes a second row into DO storage nor makes the recipient receive the WS frame twice.
/// 60s is plenty (a 15s HTTP timeout plus one or two retries).
const DEDUP_TTL_SECS: i64 = 60;

/// Memory ceiling for the dedup vector. The DO is long-lived, so this guards against spam.
const DEDUP_MAX_ENTRIES: usize = 256;

/// Per-user inbox + WebSocket gateway; a faithful port of the UserInbox from the TypeScript
/// worker. Owns the pending message queue in SQL storage, WS hibernation, the periodic alarm
/// flush + cleanup, and the ack/typing/delivered/read RPC bridge.
#[durable_object]
pub struct UserInbox {
    pub(crate) state: State,
    pub(crate) env: Env,
    pub(crate) initialized: std::cell::Cell<bool>,
    /// (sender, envelope-hash) pairs handled within the last DEDUP_TTL_SECS.
    /// Reset on a DO restart; keeping it in memory is deliberate (it costs no storage writes and a
    /// DO lives for hours or days anyway). That leaves a brief duplicate window across a restart,
    /// for which the client-side `hasIncomingRemoteId` dedup is the safety net.
    pub(crate) dedup: std::sync::Mutex<Vec<DedupEntry>>,
    /// W1 backstop: has the RECIPIENT user_id been written to storage in this DO instance? The
    /// alarm needs the user_id to call `maybe_push_wake` for stuck pending rows, but while offline
    /// (no WS attachment) the DO cannot learn its own user any other way, so we persist the
    /// `recipient_id` from the notify body once. The Cell avoids redundant writes; it resets on a
    /// DO restart, so the first notify after a restart writes it again.
    pub(crate) uid_persisted: std::cell::Cell<bool>,
}

#[derive(Clone)]
pub(crate) struct DedupEntry {
    pub(crate) sender_id: String,
    /// First 16 bytes of the SHA256 — collision probability is negligible (2^64 birthday bound).
    pub(crate) envelope_hash: [u8; 16],
    pub(crate) msg_id: i64,
    pub(crate) created_at: i64,
    /// W4-a (Codex HIGH): the FIRST delivery's real `delivered_live` result. A dedup hit (a W4
    /// in-request retry or a client retry) returns this, which stops a hard-coded `true` from
    /// silently suppressing the offline wake.
    pub(crate) delivered_live: bool,
}

#[derive(Deserialize)]
struct NotifyBody {
    sender_id: String,
    envelope_b64: String,
    /// W1 backstop: the RECIPIENT user_id (this DO's owner). The caller (notify_recipient /
    /// WS-send) already knows it, so it rides in the body, notify_inner persists it, and the alarm
    /// uses it for the stuck-pending FCM wake. `#[serde(default)]` makes older bodies (without the
    /// field) `None`, in which case the persist is skipped — the backstop becomes a no-op while the
    /// caller-side immediate push still works, so there is no regression.
    #[serde(default)]
    recipient_id: Option<String>,
    /// The group this message belongs to during a group fan-out (phase 2); absent for 1:1 (serde
    /// defaults it to None).
    #[serde(default)]
    group_id: Option<String>,
    /// M2-S2.2: the sender's device. `#[serde(default)]` yields `None` while the S2.3 fan-out does
    /// not populate it yet, and for pre-S2 /notify bodies.
    #[serde(default)]
    sender_device_id: Option<String>,
    /// M2-S2.2: the target RECIPIENT device. In S2.2 the body does NOT carry it yet (S2.3 adds it
    /// to the `notify_recipient` body), so for now `None` means the N=1 primary / compatibility
    /// path; notify_inner already takes the parameter today, which is what separates S2.2 from S2.3.
    #[serde(default)]
    recipient_device_id: Option<String>,
    /// The sender asked for no FCM wake (control traffic). `#[serde(default)]` → a body from a
    /// worker version that does not send it reads as false, i.e. today's behaviour.
    #[serde(default)]
    silent: bool,
}

#[derive(Deserialize)]
struct ForwardTypingBody {
    sender_id: String,
}

#[derive(Deserialize)]
struct ForwardIdsBody {
    from: String,
    ids: Vec<i64>,
    /// M2-S2.2 — the device this receipt is scoped to. In the delivered/failed direction it is the
    /// `recipient_device_id` (which recipient device received it, or failed to decrypt it); in the
    /// read direction the sender sends it under the name `sender_device_id` (the reverse-direction
    /// self-heal device pair). Whichever arrives, `device_for_forward` picks it.
    /// `#[serde(default)]` keeps it `None` until S2.3 populates it (N=1 compatibility).
    #[serde(default)]
    recipient_device_id: Option<String>,
    #[serde(default)]
    sender_device_id: Option<String>,
    /// #11 Layer-4b: msg_uids PARALLEL to `ids` (the sender's local_id, supplied by the reader from
    /// the E2E payload). `apply_receipt` writes it into `receipt_state.msg_uid` so a sibling device
    /// can match the read via `oc-{msg_uid}`. An old client or the delivered path sends an empty Vec.
    #[serde(default)]
    uids: Vec<String>,
}

/// Sibling-read durable cursor (2026-06-28): a device of U reports the `msg_uid`s of the incoming
/// messages it read (peer- and group-agnostic — one global list). `read_at` is the server's now.
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
    /// M2-S2.2: the sender's device (needed for the flush replay frame).
    #[serde(default)]
    pub(crate) sender_device_id: Option<String>,
    pub(crate) created_at: i64,
}

// Sprint 8: forward_queue rows
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
    /// M2-S2.2: the recipient device that produced the receipt (needed to reconstruct the replay
    /// payload).
    #[serde(default)]
    pub(crate) recipient_device_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Attachment {
    #[serde(rename = "userId")]
    pub(crate) user_id: String,
    /// M2-S2.2: the DEVICE behind this WS connection (from the JWT's device_id claim).
    /// A pre-S1 token (no claim) yields `None`, and per-device flush/ack then falls back to NULL
    /// tolerance. `#[serde(default)]` lets attachments serialized earlier (pre-S2 WS hibernation)
    /// parse without error.
    #[serde(rename = "deviceId", default)]
    pub(crate) device_id: Option<String>,
    /// W1 (delivered_live false-positive fix): when the last CLIENT→SERVER frame (ping/ack/read;
    /// the client text-pings every 5s, see ws_conn.rs) was received on this socket, in ms.
    /// `notify_inner` uses it as its LIVENESS TEST: only a socket that produced a frame within the
    /// last `WS_LIVENESS_WINDOW_MS` counts as "genuinely live". On a zombie/half-open socket (TCP
    /// left half-open by a MIUI background kill) `send_with_str` returns Ok while the client
    /// receives NOTHING → last_seen goes stale → delivered_live is NOT set → an FCM wake fires,
    /// which closes the root cause of silent delivery delays and lost notifications.
    /// `#[serde(default)]` lets pre-W1 serialized attachments parse as `None` (the field fills in
    /// on the first ping).
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

        // Called after the D1 membership-deletion batch has committed the purge outbox.
        // First a final status frame goes to the open sockets, then all SQL/KV/alarm storage is
        // deleted, and finally a permanent DO tombstone is left behind. Calling it again is
        // idempotent, so replaying it after a lost outbox response is safe.
        if method == Method::Post && path == "/purge-account" {
            let sockets = self.state.get_websockets();
            for socket in sockets {
                let _ = socket.send_with_str(r#"{"type":"membership_removed"}"#);
                let _ = socket.close(Some(1008), Some("membership_removed"));
            }
            let storage = self.state.storage();
            storage.delete_all().await?;
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

        // An ephemeral nudge creates no storage and no SQL. An offline user does its
        // authoritative pull on boot/resume; if a socket is open we merely poke it.
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
                // D-M10: a cheap `ensure_alarm` on the warm /notify path (a no-op get_alarm when
                // already armed). If the recipient is OFFLINE and never reconnects over WS — and
                // the alarm chain was broken earlier by a transient error — stuck pending messages
                // must still get the FCM backstop, so a dead alarm is revived here on /notify.
                self.ensure_alarm().await;
                Response::from_json(
                    &serde_json::json!({ "id": id, "delivered_live": delivered_live }),
                )
            }
            (Method::Post, "/forward-typing") => {
                let body: ForwardTypingBody = req.json().await?;
                self.forward_typing_inner(&body.sender_id);
                Response::empty().map(|r| r.with_status(204))
            }
            // Layer-4: delivered/read are now durable `receipt_state` plus a per-device cursor
            // sync, NOT the consume-once forward_queue. recipient_device_id is NO LONGER used for
            // delivered/read: the tick goes to ALL of A's devices and the aggregation happens
            // client-side in mdd (keyed by remote_id). ts is the server receive time.
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
            (Method::Post, "/forward-delivery-failed") => {
                // The receiver failed to decrypt (MAC mismatch) → tell the sender. On the sender
                // the message moves to failedDelivery, so the UI shows something like a 1.5 tick
                // and an auto-retry is triggered once the session has self-healed.
                let body: ForwardIdsBody = req.json().await?;
                self.forward_signal(
                    "delivery_failed",
                    &body.from,
                    body.device_for_forward(),
                    &body.ids,
                );
                Response::empty().map(|r| r.with_status(204))
            }
            // Shared-root #1: the HTTP twin of receipt-sync. It uses the SAME
            // `receipt_sync_payload` builder as the WS `receipt_sync` frame → BIT-IDENTICAL
            // {rows, more}. A device that is not WS-connected (on the HTTP send fallback)
            // cursor-pulls its own tick from here, which self-heals a stuck tick. A SQL error
            // becomes an empty batch (the cursor does not advance and the next event re-pulls).
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
            // Sibling-read durable cursor (2026-06-28): a device of U reports the msg_uids it read
            // → self_read_state set-once + seq bump + self_read_update/delta to U's other devices.
            (Method::Post, "/self-read") => {
                let body: SelfReadBody = req.json().await?;
                self.apply_self_read(&body.uids, (now_secs() * 1000) as i64);
                Response::empty().map(|r| r.with_status(204))
            }
            // The HTTP twin of self-read-sync (the SAME builder as the WS `self_read_sync` frame).
            // A new device pulls the whole read state from cursor=0 so its backlog converges.
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
        self.ensure_init().await?;
        self.flush_pending_to_all();
        // Sprint 8: forward-queue alarm flush — if the sender misses the reconnect, the periodic
        // alarm will attempt the push anyway (idempotent: a repeat is removed by the client's
        // `forward_ack` and the sender side dedups it).
        self.flush_forwards_to_all();
        // W1 backstop (Codex HIGH — the definitive closure of W1): FCM-wake the pending rows that
        // were believed delivered_live=true but were never acked, i.e. were in fact not delivered.
        // W1's liveness test narrows the false-positive window but cannot close it (a socket that
        // dies right after a ping); this ground-truth backstop does: still sitting in pending means
        // unacked means undelivered → push once the grace period is over.
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
            // The message retention period is now admin-configurable (D1 server_settings).
            // Instead of a hard-coded 30 days it is read with a single SELECT per cleanup; on an
            // error or a missing row the helper falls back to 30. Thanks to CLEANUP_INTERVAL_MS
            // (24h) it is queried at most once per alarm.
            let days = crate::server::handlers::fetch_message_retention_days(&self.env).await;
            let cutoff = (now_secs() as i64) - days * 24 * 3600;
            let storage = self.state.storage();
            // D-M10: the pending purge is BEST-EFFORT (the same `let _ =` pattern as its siblings).
            // It used to be a bare `?`, so a transient storage error aborted the alarm handler and
            // SKIPPED the `ensure_alarm` re-arm at the end → a dead alarm chain, stopping the
            // offline flush, the forward replay and the stuck-pending FCM backstop. The watermark
            // (LAST_CLEANUP_KEY) advances ONLY on a successful purge, so a transient error does not
            // skip retention for 24h — it is retried on the next alarm.
            let purge_ok = storage
                .sql()
                .exec_raw(
                    "DELETE FROM pending WHERE created_at < ?",
                    Some(vec![JsValue::from_f64(cutoff as f64)]),
                )
                .is_ok();
            // Layer-4: receipt_state retention (updated_at is in ms, hence cutoff*1000).
            // An old tick has already been displayed, and the high-water mark (`receipt_meta`) is
            // never purged → seq stays monotonic and cursors stay consistent.
            let _ = storage.sql().exec_raw(
                "DELETE FROM receipt_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // server-lean audit (2026-07-03): purge self_read_state at RETENTION PARITY. It used to
            // be exempt ("never purged", out of the Codex-Q8 fear of breaking full-pull), the ONLY
            // exception to the "the server does not grow" principle. That fear turned out to be
            // UNFOUNDED (Fable handover + Opus verification): a new device receives old messages via
            // M4 sibling sync, and the M4 package (state_transfer.rs `Vec<MessageRow>`) carries
            // `viewed_at` ALONGSIDE THE MESSAGE → read state flows INDEPENDENTLY of
            // self_read_state. self_read_state is the live incremental convergence cursor; a row
            // beyond retention is dead metadata (that message was already deleted from pending and
            // M4 carries its read state). Exactly the receipt_state pattern: the high-water mark
            // (self_read_meta) is NEVER purged → seq stays monotonic and cursors consistent.
            // updated_at is in ms.
            let _ = storage.sql().exec_raw(
                "DELETE FROM self_read_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // M1 (repeated Olm WIPE triggers): forward_queue retention. Old orphan receipt rows —
            // especially delivery_failed ones the client never forward_acked — accumulated forever
            // and were replayed unconditionally on a FRESH reconnect, re-triggering
            // `delete_all_olm_blobs` (Olm WIPE) on the receiver. Clean them with the same retention
            // window. `created_at` is in MS here (forward_signal writes `now_secs()*1000`), so the
            // cutoff is in ms too — same as receipt_state, and DIFFERENT from pending's
            // seconds-based cutoff.
            let _ = storage.sql().exec_raw(
                "DELETE FROM forward_queue WHERE created_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            if purge_ok {
                let _ = storage.put(LAST_CLEANUP_KEY, now_ms_val).await;
            }
        }
        // W11: re-arm the alarm chain ROBUSTLY. The old blind `let _ = set_alarm` let a single
        // transient storage error break the chain for the entire lifetime of this DO instance,
        // silently stopping the offline flush, the forward replay and the cleanup.
        self.ensure_alarm().await;
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
        // D-M9 (durable dedup): an env_hash column on pending + UNIQUE(sender_id, env_hash).
        // The in-memory dedup (60s) is lost on a DO restart or once its TTL expires, so a retry of
        // the same envelope would create a SECOND pending row (duplicate WS frame, notification and
        // bubble). env_hash is the hex of the EXISTING 4-tuple hash
        // (SHA256(sender|sender_dev|recipient_dev|envelope)), so when a group's single Megolm
        // envelope is written for TWO devices of the same member the differing recipient_dev yields
        // a DIFFERENT hash → the second device's row is NOT swallowed, i.e. no lost group message on
        // a sibling device. Older rows have a NULL env_hash, and a SQLite UNIQUE index permits
        // multiple NULLs (safe).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN env_hash TEXT",
            sql_no_args(),
        );
        let _ = storage.sql().exec_raw(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_env_hash ON pending(sender_id, env_hash)",
            sql_no_args(),
        );
        // Phase 2 (group fan-out): a group_id column on pending, naming the group a message belongs
        // to so the recipient picks the Megolm decrypt path; NULL for 1:1. ALTER for older DOs, with
        // the error IGNORED if the column already exists (the forward_queue.pushed_at pattern).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN group_id TEXT",
            sql_no_args(),
        );
        // M2-S2.2 (multi-device): a device_id column on pending, naming which RECIPIENT DEVICE the
        // row belongs to (per-device queue + ack isolation). ALTER for rows written before the
        // backfill and for pre-S2 DOs, with the error IGNORED if it already exists (the group_id
        // ALTER pattern). With N=1 there is a single primary; older NULL rows are stamped by the
        // first-WS backfill (see the NULL-backfill flag in ws_upgrade).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN device_id TEXT",
            sql_no_args(),
        );
        // M2-S2.2: the SENDER's device. The recipient's frame must carry `sender_device_id` (for
        // 1:1 the recipient uses it to pick the right Olm device session; a group has a single
        // Megolm envelope). A live push gets it from the notify_inner parameter while a flush replay
        // reads it back from the DB, hence a dedicated column. NULL means the sender device is
        // unknown (older rows / compatibility).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN sender_device_id TEXT",
            sql_no_args(),
        );
        // W1 backstop: a push_wake_at column on pending (ms). NULL means no backstop FCM wake has
        // been sent for this row yet, so once the grace period passes the alarm backstop pushes one.
        // The column is written ONLY by the backstop itself, after its own push — notify_inner
        // deliberately leaves it NULL (see the "W1 backstop NOTE" in message.rs), so every row gets
        // at most one backstop wake. ALTER for older DOs, with the error IGNORED if it already
        // exists (the group_id pattern).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN push_wake_at INTEGER",
            sql_no_args(),
        );
        // `silent` = the sender declined an FCM wake for this envelope (control traffic). Stored so
        // the W1 backstop alarm below skips the row: a wake the immediate path declined must not
        // reappear minutes later. NULL on rows written before this column existed → treated as
        // "wake", the old behaviour. ALTER-and-ignore, the push_wake_at pattern.
        let _ = storage
            .sql()
            .exec_raw("ALTER TABLE pending ADD COLUMN silent INTEGER", sql_no_args());
        // Sprint 8: forward_queue — receipt forwards (delivered / read / delivery_failed) live in a
        // persistent queue instead of being fire-and-forget WS pushes. Each one is pushed
        // immediately to however many connected sockets exist AND written to this table; when the
        // sender reconnects, flush_forwards replays it, and the sender's `forward_ack` frame clears
        // the queue.
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
        // Sprint 8.5a: the pushed_at column — an ALTER TABLE ADD COLUMN for DOs where the table was
        // first created back in Sprint 8. The error is IGNORED if it already exists.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE forward_queue ADD COLUMN pushed_at INTEGER",
            sql_no_args(),
        );
        // M2-S2.2 (multi-device): a recipient_device_id column on forward_queue, recording WHICH
        // RECIPIENT DEVICE produced a receipt forward (delivered / read / delivery_failed). It makes
        // the replay device-accurate and becomes part of the dedup key (D3 verdict 2: a receipt
        // queued while the WS was down replayed without a device → N:1 MISS). ALTER for older DOs,
        // with the error IGNORED if it already exists.
        let _ = storage.sql().exec_raw(
            "ALTER TABLE forward_queue ADD COLUMN recipient_device_id TEXT",
            sql_no_args(),
        );
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_fwd_created ON forward_queue(created_at)",
            sql_no_args(),
        )?;
        // Sprint 8.5a: speed up the (kind, from_user, ids_json) lookup used by the dedup.
        // M2-S2.2: the dedup key now also includes recipient_device_id, so widen the index with
        // that column too (the old index stays harmlessly in place; the new query uses this one).
        let _ = storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_fwd_dedup_dev ON forward_queue(kind, from_user, recipient_device_id, ids_json, created_at)",
            sql_no_args(),
        );
        // Model-B Layer-4: the account-level durable receipt log (delivered/read). It replaces the
        // consume-once forward_queue — every A device syncs idempotently from its own `seq` cursor
        // (the fix for the sibling race, zombie sockets and reconnect gaps).
        // PK(peer_id, remote_id) is B's per-device receipt id; rolling ticks up to a logical message
        // happens client-side in mdd. `seq` is an account-global monotonic counter, and the
        // `receipt_meta` high-water never goes backwards even if the table is purged → cursors stay
        // consistent. (See receipt.rs.)
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
        // #11 Layer-4b: the msg_uid column, which lets a sibling device correlate its `oc-{msg_uid}`
        // row with the read. ADD COLUMN for existing DOs (idempotent: the error is SWALLOWED if it
        // already exists). `CREATE TABLE IF NOT EXISTS` does not add columns to an existing table,
        // so the separate ALTER is required.
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
        // ── SIBLING-READ durable cursor (2026-06-28, Codex-approved design) ──────────────
        // A mirror image of receipt_state (sender <-> recipient delivered/read) but on a SEPARATE
        // axis for sibling reads: converging `viewed_at` across U's OWN devices. It replaces the old
        // brittle ReadSelfSync (a live Olm self-message: dies on a wedged session, covers only fresh
        // reads, gets a new device's backlog wrong) with something durable, monotonic and
        // cursor-based. PK = msg_uid (a global UUID, hence peer-agnostic). `seq` lives in a SEPARATE
        // space (`self_read_meta`) so a self-read gap cannot block the receipt cursor (Codex Q1).
        // Retention: this table IS purged at retention parity — see the 2026-07-03 reversal of
        // Codex Q8 in the alarm cleanup above and in self_read.rs.
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
        // ── Codex#5: M4 / msg_uid-only read receipts (sender <-> recipient, without a remote_id) ──
        // When an M4-restored message (msg_id = NULL) is read, core sends `msg_uids` with an empty
        // `ids`, which receipt_state's PK(peer_id, remote_id) cannot represent, so it would be
        // dropped. Hence a SEPARATE uid-keyed table rather than a synthetic remote_id (which would
        // create semantic debt and collision risk; Codex Q6). It is designed to share the same
        // `receipt_meta` seq space — the same axis as the receipt flow, a tick for the sender — so a
        // single cursor covers both.
        // STATUS: the table and index are created here, but nothing in the worker reads or writes
        // `receipt_uid_state` yet, and apply_receipt still returns early on an empty `ids`, so
        // uid-only receipts are still dropped. Schema groundwork only.
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
        // Layer-4 cutover (Codex HIGH-3): delivered/read now live in receipt_state. The OLD
        // (pre-cutover) delivered/read rows still sitting in forward_queue are exposed to the
        // consume-once + global-ack-DELETE sibling-steal race, so DRAIN them for a clean cut;
        // anything in flight is repaired by StateDigest reconciliation and the next receipt.
        // delivery_failed STAYS (it is still on the forward_queue path). New delivered/read never
        // ENTER forward_queue (they go to apply_receipt), which makes this DELETE idempotent.
        let _ = storage.sql().exec_raw(
            "DELETE FROM forward_queue WHERE kind IN ('delivered', 'read')",
            sql_no_args(),
        );
        // W11 HARDENING (2026-07-02, Codex flag): route the initial arm through `ensure_alarm`. It
        // used to be `let _ = set_alarm` — one attempt whose result was SWALLOWED — so if the first
        // arm failed and no WS reconnect ever happened, the backstop NEVER ran. `ensure_alarm` does
        // 3 bounded retries and logs visibly on failure (get_alarm is idempotent, so an
        // already-armed alarm is a no-op).
        self.ensure_alarm().await;
        self.initialized.set(true);
        Ok(())
    }

    async fn ws_upgrade(&self, req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;

        // M2-S2.2: parse the token and device_id BEFORE accept_web_socket and the stale close. The
        // socket is accepted once Attachment{user_id, device_id} is ready, because the backfill has
        // to know the device FIRST. (The token arrives as Sec-WebSocket-Protocol
        // "sezgi.bearer.v1, <token>"; lib.rs sync_ws already verified it before proxying, and we
        // re-parse it here only to build the attachment.)
        // Self-host phase A: a DO fetch does NOT pass through the lib.rs `#[event(fetch)]` boot
        // guard (it may run in a different isolate), so prepare the JWT key in this isolate too —
        // from the env secret, or from the D1 self-provision cache when there is none. It is
        // memoized, so on an installation with the env secret set it returns without touching D1
        // (bit-identical to today's behaviour).
        crate::self_provision::ensure_keys(&self.env).await;

        let mut attach_user: Option<String> = None;
        let mut attach_device: Option<String> = None;
        if let Ok(t) = crate::extract_bearer_subprotocol(&req) {
            if let Ok(uid) = verify_access_token(&self.env, &t) {
                attach_user = Some(uid);
                // The device_id claim is ABSENT from a pre-S1 token → None (NULL tolerance).
                attach_device = device_id_from_token(&self.env, &t).ok().flatten();
            }
        }

        // M2-S3.0 (B3): the stale close is now DEVICE-AWARE. Two devices of the same user (primary +
        // linked) hold sockets at the same time, and each one flushes/acks ONLY its own pending rows
        // (S2.2 per-device isolation), so the old single-queue race — whoever acks first deletes the
        // row — is structurally gone. That means we can no longer close old sockets
        // UNCONDITIONALLY: doing so would have the two devices constantly tearing down each other's
        // socket, breaking the linking flow and dual-device delivery. So only the previous socket of
        // the SAME device_id is closed as "superseded" (reconnect/zombie cleanup, avoiding double
        // pushes). Option<String> equality is exactly the right semantics here: None == None (a
        // pre-S1 device-less reconnect of the same device → close), Some == Some (the same device
        // reconnecting → close), None != Some (a new device-aware connection KEEPS the device-less
        // old socket — flush/ack tolerate "OR device_id IS NULL", so that socket still gets its
        // queue). With N=1 there is one device, so all old sockets share it and the "close them all"
        // behaviour is preserved exactly. (Rejecting a socket at revoke time is S3.5.)
        let stale = self.state.get_websockets();
        self.state.accept_web_socket(&server);
        for old in stale {
            let old_dev = old
                .deserialize_attachment::<Attachment>()
                .ok()
                .flatten()
                .and_then(|a| a.device_id);
            if old_dev == attach_device {
                let _ = old.close(Some(1000), Some("superseded"));
            }
        }

        if let Some(uid) = attach_user {
            let _ = server.serialize_attachment(Attachment {
                user_id: uid,
                device_id: attach_device.clone(),
                // W1: a freshly accepted socket counts as "live" for one `WS_LIVENESS_WINDOW_MS`,
                // so no spurious push happens before the client sends its first ping.
                // handle_ws_message refreshes the stamp on the first inbound frame.
                last_seen_ms: Some((now_secs() * 1000) as i64),
            });
        }

        // M2-S2.2 IDEMPOTENT NULL backfill (red-team HIGH #3, #18): stamp the pre-S2 (device-less)
        // pending rows with the device of this first device-aware socket. A one-shot flag in DO
        // storage means a reconnect does NOT RE-STAMP. The value comes from Attachment.device_id,
        // i.e. straight from the claim and NEVER derived.
        if let Some(dev) = attach_device.as_deref() {
            self.backfill_null_device_once(dev).await;
        }

        self.flush_pending_to(&server);
        // Sprint 8: WS reconnect replay — the sender receives the queued receipt forwards over this
        // new socket. force=true because a FRESH socket by definition never received what was pushed
        // to the old (dead/zombie) socket → ignore pushed_at and hand over EVERYTHING in the queue
        // (the root-cause fix for the 2026-06-02 field report "read receipt hugely delayed"; the
        // client dedups on forward_id).
        self.flush_forwards_to(&server, true);
        // W11: if the periodic alarm chain was broken by a transient set_alarm error, SELF-HEAL it on
        // a client reconnect → the offline flush, forward replay and cleanup come back to life.
        // A no-op when already armed (a cheap get_alarm).
        self.ensure_alarm().await;

        // WS upgrade response: echo back the subprotocol the client offered. The tokio-tungstenite
        // client validates the subprotocol the server selected and fails with
        // "no subprotocol selected" if it is not echoed.
        let resp = Response::from_websocket(pair.client)?;
        let headers = resp.headers().clone();
        headers.set("Sec-WebSocket-Protocol", "sezgi.bearer.v1")?;
        Ok(resp.with_headers(headers))
    }

    /// W11: keep the periodic alarm chain robust. The result of `set_alarm` used to be swallowed
    /// (`let _ =`), so a single transient storage error broke the chain and silently stopped the
    /// offline flush, forward replay and cleanup for the whole lifetime of that DO instance (until
    /// it was evicted and re-initialised). A no-op when already armed; otherwise arm it with a
    /// bounded retry. Called at the end of alarm() (after firing, get_alarm is None so it re-arms)
    /// and from every ws_upgrade, since a client reconnect is the natural self-heal point.
    async fn ensure_alarm(&self) {
        let storage = self.state.storage();
        if storage.get_alarm().await.ok().flatten().is_some() {
            return;
        }
        let next = (now_secs() * 1000) as i64 + FLUSH_INTERVAL_MS;
        for _ in 0..3 {
            if storage.set_alarm(next).await.is_ok() {
                return;
            }
        }
        console_log!(
            "UserInbox: set_alarm 3x fail — alarm zinciri risk (sonraki ws_upgrade re-dener)"
        );
    }

    /// W1 backstop (Codex HIGH — the definitive closure of W1). Ground truth: a row still sitting in
    /// `pending` is unacked, therefore undelivered. Send an FCM wake for rows whose `push_wake_at` is
    /// NULL (no backstop wake has fired for them yet) and whose grace period has elapsed → this
    /// closes the false-positive window W1 narrowed but could not eliminate (a socket dying right
    /// after a ping). One push per distinct device_id (maybe_push_wake with None means all devices),
    /// then push_wake_at is stamped so the next alarm does not re-push. Idempotent and best-effort.
    ///
    /// `silent` rows are EXCLUDED from the device scan. A control message the sender declined a wake
    /// for is still legitimately unacked while the recipient sleeps, so without this filter the
    /// backstop would wake the device for it after the grace period — converting the removed wake
    /// into a delayed one, which is harder to explain than the original bug. The rows are still
    /// stamped below (the UPDATE is deliberately unfiltered) so a silent row cannot keep the scan
    /// returning it forever.
    async fn backstop_push_stale_pending(&self) {
        let storage = self.state.storage();
        let uid: Option<String> = storage.get(RECIPIENT_UID_KEY).await.ok().flatten();
        let uid = match uid {
            Some(u) => u,
            None => return, // RECIPIENT user_id not known yet (no notify has arrived) → no-op
        };
        let db = match self.env.d1("DB") {
            Ok(d) => d,
            Err(_) => return,
        };
        let now = now_secs() as i64;
        let cutoff = now - PUSH_BACKSTOP_GRACE_SECS; // pending.created_at is in SECONDS
                                                     // Distinct recipient devices of the stuck rows (None = device-blind → all devices).
        let cursor = match storage.sql().exec_raw(
            "SELECT DISTINCT device_id FROM pending
             WHERE push_wake_at IS NULL AND created_at < ? AND (silent IS NULL OR silent = 0)",
            Some(vec![JsValue::from_f64(cutoff as f64)]),
        ) {
            Ok(c) => c,
            Err(_) => return,
        };
        #[derive(Deserialize)]
        struct DevRow {
            #[serde(default)]
            device_id: Option<String>,
        }
        let rows: Vec<DevRow> = match cursor.to_array() {
            Ok(r) => r,
            Err(_) => return,
        };
        if rows.is_empty() {
            return;
        }
        // [deliv-telemetry] The W1 backstop fired = it caught a stuck pending row that W1's liveness
        // test missed (a socket dying just after a ping, or a lost ws.rs response). How OFTEN this
        // line appears in `wrangler tail` measures the field impact of W1's residual gap (per Codex,
        // without a counter it cannot be proven). High signal and low frequency, so a per-event log
        // is acceptable.
        console_log!(
            "[deliv] W1-backstop wake: {} device stale-unacked (uid={})",
            rows.len(),
            uid
        );
        for r in &rows {
            crate::push::fcm::maybe_push_wake(&self.env, &db, &uid, r.device_id.as_deref()).await;
        }
        // Stamp the rows so the next alarm does not re-push them (best-effort; if the error is
        // swallowed the worst case is another wake on the next alarm = a harmless extra push).
        let _ = storage.sql().exec_raw(
            "UPDATE pending SET push_wake_at = ? WHERE push_wake_at IS NULL AND created_at < ?",
            Some(vec![
                JsValue::from_f64((now * 1000) as f64),
                JsValue::from_f64(cutoff as f64),
            ]),
        );
    }

    /// M2-S2.2: stamp every `pending.device_id IS NULL` row with the given device exactly ONCE,
    /// behind the DEVICE_BACKFILL_DONE_KEY flag. Once the flag is set this is a no-op, so a
    /// reconnect never re-stamps (red-team HIGH #3). With N=1 the DO belongs to a single device, so
    /// every historical device-less row correctly belongs to it.
    /// FIX-2(b) NOTE: the backfill only stamps the historical NULLs present at the FIRST
    /// device-aware connection. A NULL pending row created later (group fallback FIX-1 → a member
    /// who published no devices) arrives after the flag is set and is therefore SKIPPED by the
    /// backfill, but flush/ack still deliver it to the right device through the
    /// `OR device_id IS NULL` tolerance (FIX-2(b)). The two mechanisms are complementary: NULL only
    /// occurs for an unpublished-single-device user, so "the one logical device" is the device that
    /// connects. S3-TODO: if a multi-device user can ever own a NULL row, both the backfill and the
    /// tolerance must be revisited.
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
