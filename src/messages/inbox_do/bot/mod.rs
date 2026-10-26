//! Bot mode: a bot's end of the encryption, in the bot's own `UserInbox` (docs/BOTS_BUILD.md §2.3).
//!
//! Every path the kernel already takes to a user — the 1:1 notify, the `delivered` and
//! `delivery_failed` forwards, `forward-read` — reaches `USER_INBOX.id_from_name(bot)` with no
//! routing change; in bot mode, this inbox answers them with the engine instead of a socket.
//!
//! | File | What |
//! |---|---|
//! | `store.rs` | the bot tables (created lazily, only here) and the engine's `BotStore` over them |
//! | `ingest.rs` | the alarm's tick: open stored frames in one synchronous block, ack, queue |
//! | `send.rs` | `sendMessage`, pair-acks (repair and reply), resends after a re-pair |
//! | `send_guard.rs` | what a program's sends are held to: 60 a minute, 30 into one chat |
//! | `send_replay.rs` | idempotent sending: a repeated `client_id` answers the first `message_id` |
//! | `outbox.rs` | what the tick owes the network, drained under a subrequest budget |
//! | `updates.rs` | the update JSON and `getUpdates`' long poll |
//! | `deliver.rs` | the webhook round, the owner's ping, and "taken" → the member's `forward-read` |
//! | `builtin.rs` | a built-in bot (sheet, AI): its configuration and secrets, the owner's test |
//! | `builtin_run.rs` · `builtin_jobs.rs` | the built-in runner's round: members' updates · rows owed to the sheet |
//! | `builtin_room.rs` | a built-in bot called in a room: answers into the room, proposals 1:1 |
//! | `builtin_policy.rs` | the round's pure decisions: budget, a pending row, a proposal's text |
//! | `builtin_ai.rs` · `builtin_sheet.rs` | the model call (two dialects) · the sheet's POST |
//! | `builtin_store.rs` · `builtin_copy.rs` | the built-in tables · every line the bot says itself |
//! | `room.rs` · `room_send.rs` · `room_asks.rs` | the bot in its rooms: calls it believes, posts and their key shares · a post's chunks · key requests |
//! | `room_plan.rs` · `room_store.rs` | the room round's pure decisions · the room tables |
//!
//! Internal routes (a DO stub is not public; only the Worker calls them):
//! `/bot/init`, `/bot/updates`, `/bot/api`, `/bot/state`, `/bot/webhook`, `/bot/webhook-secret`,
//! `/bot/ping`, `/bot/builtin`, `/bot/builtin-test`, `/bot/wake`, `/bot/room-event`.

use super::*;

mod builtin;
mod builtin_ai;
mod builtin_copy;
mod builtin_jobs;
mod builtin_policy;
mod builtin_room;
mod builtin_run;
mod builtin_sheet;
mod builtin_store;
mod deliver;
mod ingest;
mod outbox;
mod room;
mod room_asks;
mod room_plan;
mod room_send;
mod room_store;
mod send;
mod send_guard;
mod send_replay;
mod store;
mod updates;

/// DO storage key: this inbox belongs to a bot.
const BOT_MODE_KEY: &str = "bot_mode";

/// What every engine call needs, read from `bot_kv`.
pub(super) struct BotCtx {
    pub(super) bot_id: String,
    pub(super) device_id: String,
    pub(super) key: [u8; 32],
}

#[derive(Deserialize)]
struct InitBody {
    bot_id: String,
    device_id: String,
    account_pickle: String,
    pickle_key_b64: String,
}

impl UserInbox {
    /// Is this a bot's inbox? Memoized for the life of the instance (`/purge-account` resets it).
    pub(super) async fn is_bot(&self) -> bool {
        if let Some(b) = self.bot_mode.get() {
            return b;
        }
        let b = self
            .state
            .storage()
            .get::<bool>(BOT_MODE_KEY)
            .await
            .ok()
            .flatten()
            .unwrap_or(false);
        self.bot_mode.set(Some(b));
        b
    }

    /// The bot tables; idempotent and synchronous.
    fn bot_tables(&self) -> Result<()> {
        let sql = self.state.storage().sql();
        let tables = store::TABLES.iter().chain(builtin_store::TABLES.iter()).chain(room_store::TABLES.iter());
        for t in tables.chain(send_guard::TABLES.iter()).chain(send_replay::TABLES.iter()) {
            sql.exec_raw(t, sql_no_args())?;
        }
        // Columns added since an older inbox made its tables: each once, its failure on a table
        // that already has the column ignored.
        let s = self.bot_store();
        let ran: usize = s.kv_get("builtin_schema").and_then(|v| v.parse().ok()).unwrap_or(0);
        if ran < builtin_store::UPGRADES.len() {
            for u in &builtin_store::UPGRADES[ran..] {
                let _ = sql.exec_raw(u, sql_no_args());
            }
            s.kv_put("builtin_schema", &builtin_store::UPGRADES.len().to_string());
        }
        Ok(())
    }

    fn bot_store(&self) -> store::SqlBotStore<store::DoSql> {
        store::do_store(self.state.storage().sql())
    }

    pub(super) fn bot_ctx(&self) -> Result<BotCtx> {
        let s = self.bot_store();
        let missing = || Error::RustError("bot inbox not initialized".into());
        let key_b64 = s.kv_get("pickle_key").ok_or_else(missing)?;
        let key: [u8; 32] = crate::utils::b64_decode(&key_b64)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(missing)?;
        Ok(BotCtx {
            bot_id: s.kv_get("bot_id").ok_or_else(missing)?,
            device_id: s.kv_get("device_id").ok_or_else(missing)?,
            key,
        })
    }

    /// The `/bot/*` routes. `/bot/init` is the one that may run before bot mode.
    pub(super) async fn bot_fetch(&self, mut req: Request, path: &str) -> Result<Response> {
        if path == "/bot/init" && req.method() == Method::Post {
            let body: InitBody = req.json().await?;
            return self.bot_init(body).await;
        }
        if !self.is_bot().await {
            return Response::error("not found", 404);
        }
        self.bot_tables()?;
        match (req.method(), path) {
            (Method::Post, "/bot/updates") => {
                let body: serde_json::Value = req.json().await?;
                self.bot_get_updates(&body).await
            }
            (Method::Post, "/bot/api") => {
                let body: serde_json::Value = req.json().await?;
                self.bot_api(&body).await
            }
            (Method::Get, "/bot/state") => self.bot_state(),
            (Method::Post, "/bot/webhook") => self.bot_set_webhook(req.json().await?),
            (Method::Post, "/bot/webhook-secret") => self.bot_set_webhook_secret(req.json().await?),
            (Method::Post, "/bot/ping") => {
                let body: serde_json::Value = req.json().await?;
                self.bot_ping(body.get("who").cloned().unwrap_or_default()).await
            }
            (Method::Post, "/bot/builtin") => self.bot_builtin_set(req.json().await?).await,
            (Method::Get, "/bot/builtin") => self.bot_builtin_get(),
            (Method::Post, "/bot/builtin-test") => {
                let body: serde_json::Value = req.json().await?;
                self.bot_builtin_test(body.get("who").cloned().unwrap_or_default()).await
            }
            (Method::Post, "/bot/wake") => self.bot_wake().await,
            (Method::Post, "/bot/room-event") => self.bot_room_event(req.json().await?).await,
            _ => Response::error("not found", 404),
        }
    }

    /// Bot mode on, with the identity the Worker just made. Refused once an account is here: a
    /// bot's identity is never replaced (a new key behind the same user id reads as
    /// `key_changed` at every member).
    async fn bot_init(&self, body: InitBody) -> Result<Response> {
        self.bot_tables()?;
        let s = self.bot_store();
        if s.kv_get("account_pickle").is_some() {
            return Response::error("already_initialized", 409);
        }
        s.kv_put("bot_id", &body.bot_id);
        s.kv_put("device_id", &body.device_id);
        s.kv_put("pickle_key", &body.pickle_key_b64);
        s.kv_put("account_pickle", &body.account_pickle);
        self.state.storage().put(BOT_MODE_KEY, true).await?;
        // notify_inner persists this on the first frame anyway; writing it now names the inbox.
        self.state.storage().put(RECIPIENT_UID_KEY, body.bot_id.as_str()).await?;
        self.bot_mode.set(Some(true));
        Response::empty().map(|r| r.with_status(204))
    }

    /// A program's `sendMessage`, after the Worker's checks: a repeated `client_id`
    /// (`send_replay.rs`), the send limits (`send_guard.rs`), then the send. A send that did not
    /// happen gives its slot and its `client_id` back.
    async fn bot_api(&self, body: &serde_json::Value) -> Result<Response> {
        let ctx = self.bot_ctx()?;
        let s = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let method = s("method");
        if !matches!(method, "sendMessage" | "sendRoom") {
            return crate::bots::api::bot_err(404, "unknown-method");
        }
        let room = (method == "sendRoom").then(|| s("room_id"));
        let reply_to = body.get("reply_to").and_then(|v| v.as_str());
        let client_id = body.get("client_id").and_then(|v| v.as_str());
        let chat = send_guard::chat_key(Some(s("to")), room);
        let fp = send_replay::fingerprint(&chat, s("text"), reply_to);
        if let Some(cid) = client_id {
            match self.bot_client_replay(cid, &fp).await {
                send_replay::Replay::New => {}
                send_replay::Replay::Sent(message_id) => return send_replay::duplicate(&message_id),
                send_replay::Replay::Conflict => return crate::bots::api::bot_err(409, "client-id-reused"),
                send_replay::Replay::InFlight => return crate::bots::api::bot_err(409, "in-progress"),
            }
        }
        // From the replay's last read to the reservation: no `await`, so no second call of the
        // same `client_id` can slip in between.
        let db = self.bot_store().db;
        let now = crate::utils::now_ms() as i64;
        let slot = match send_guard::take_slot(&db, &chat, now) {
            Ok(slot) => slot,
            Err(retry_after_s) => return send_guard::rate_limited(retry_after_s),
        };
        let msg_uid = send::new_msg_uid();
        if let Some(cid) = client_id {
            send_replay::reserve(&db, cid, &fp, &msg_uid, now);
        }
        let sent = match room {
            None => self.bot_send_text(&ctx, s("to"), s("text"), &msg_uid).await,
            // The Worker checked `group_bots`; the room round checks it again before sending.
            Some(room_id) => self.bot_send_room_text(room_id, s("text"), reply_to, &msg_uid).await,
        };
        if !matches!(&sent, Ok(r) if r.status_code() == 200) {
            send_guard::refund(&db, slot);
            if let Some(cid) = client_id {
                send_replay::release(&db, cid);
            }
        }
        sent
    }

    /// Counts, for diagnosis and the owner's page. No content.
    fn bot_state(&self) -> Result<Response> {
        use store::Exec;
        let s = self.bot_store();
        let count = |t: &str| s.db.int(&format!("SELECT COUNT(*) AS n FROM {t}"), &[]).unwrap_or(-1);
        let count_opt = |q: &str| s.db.int(q, &[]);
        let mut state = serde_json::json!({
            "bot_id": s.kv_get("bot_id"),
            "pending": count("pending"),
            "updates": count("bot_updates"),
            "outbox": count("bot_outbox"),
            "sent": count("bot_sent"),
            "sheet_jobs": count("bot_sheet_jobs"),
            "room_posts": count("bot_room_posts"),
            "rooms_keyed": count("bot_megolm"),
            "waiting_since": count_opt(deliver::WAITING_SINCE),
            "webhook": s.kv_get("webhook_url").is_some(),
            // Set, but its URL fails the outbound rule now: delivered nothing (`deliver::Hook`).
            "webhook_refused": self.bot_webhook() == deliver::Hook::Refused,
        });
        if let (Some(m), serde_json::Value::Object(b)) = (state.as_object_mut(), self.builtin_state()) {
            m.extend(b);
        }
        Response::from_json(&state)
    }

    /// `/notify` in bot mode: the frame is stored (by the caller, as for anyone); the bot is
    /// "live" by definition, so no push is attempted, and the tick runs now.
    pub(super) async fn bot_notified(&self, id: i64) -> Result<Response> {
        self.arm_alarm_within(0).await;
        Response::from_json(&serde_json::json!({ "id": id, "delivered_live": true }))
    }
}
