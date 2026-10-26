//! `POST /bot/v1/:method` — what a bot's program calls (docs/BOTS_BUILD.md §2.5).
//!
//! | method | body | answer |
//! |---|---|---|
//! | `getMe` | `{}` | `{ok, bot:{bot_id, name, about}}` |
//! | `getUpdates` | `{offset?, timeout? 0..25, limit? 1..100}` | `{ok, updates:[…]}`; below `offset` is confirmed and deleted |
//! | `sendMessage` | `{chat:{user_id}\|{room_id}, text ≤4000, reply_to?}` | `{ok, message_id}` (`b-<uuid>`) |
//! | `setWebhook` | `{url}` (https; `""` or `null` clears) | `{ok, webhook_secret}` |
//! | `deleteWebhook` | `{}` | `{ok}` |
//!
//! With a webhook set, `getUpdates` answers `bot/webhook-active` (409): one queue, one reader.
//! A built-in bot (`builtin.rs`) is that reader: `getUpdates` and `setWebhook` answer
//! `bot/builtin-active` (409) until the owner returns it to program mode.
//!
//! Into a room (Phase 3): only one whose admins added the bot (`group_bots`, else
//! `bot/not-in-room`), sent by the bot's inbox under its own Megolm session. `reply_to` is the
//! `message_id` of a call the bot was handed in that room (`bot/unknown-reply` otherwise); a 1:1
//! `reply_to` and `buttons` answer `bot/unsupported` rather than being dropped in silence.
//! Errors are `{ok:false, error:"bot/<code>"}`.
//!
//! The Worker checks the key and who the bot may write to; the bot's inbox does the encryption.
//! A bot may write to an active human of this server who has not blocked it, and to nobody else.

use super::token::{self, BotAuth};
use crate::d1util::d1_text;
use serde::Deserialize;
use worker::*;

const MAX_TEXT_CHARS: usize = 4000;
const SENDS_PER_MINUTE: usize = 60;
const MAX_POLL_SECS: i64 = 25;
const MAX_LIMIT: i64 = 100;

/// Is the target an active human, and is there a block between them? Bind: target, bot.
pub(crate) const SEND_TARGET_SQL: &str = "SELECT
       EXISTS(SELECT 1 FROM users WHERE id = ?1 AND kind = 'human') AS human,
       EXISTS(SELECT 1 FROM contact_blocks
               WHERE (blocker_user_id = ?1 AND blocked_user_id = ?2)
                  OR (blocker_user_id = ?2 AND blocked_user_id = ?1)) AS blocked";

pub(crate) fn bot_err(status: u16, code: &str) -> Result<Response> {
    let body = serde_json::json!({ "ok": false, "error": format!("bot/{code}") });
    Ok(Response::from_json(&body)?.with_status(status))
}

pub async fn dispatch(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let method = ctx.param("method").cloned().unwrap_or_default();
    let db = ctx.env.d1("DB")?;
    let Some(bot) = token::authenticate(&req, &db).await? else {
        return bot_err(401, "unauthorized");
    };
    if bot.disabled_at.is_some() {
        return bot_err(403, "disabled");
    }
    // "When did the program last show up" (the owner's "no word from it" line).
    super::mark_program_seen(&ctx.env, &bot.bot_id).await;
    let body: serde_json::Value = req.json().await.unwrap_or(serde_json::json!({}));
    match method.as_str() {
        "getMe" => Response::from_json(&serde_json::json!({
            "ok": true,
            "bot": { "bot_id": bot.bot_id, "name": bot.name, "about": bot.about },
        })),
        "getUpdates" => get_updates(&ctx.env, &bot, &body).await,
        "sendMessage" => send_message(&ctx.env, &db, &bot, body).await,
        "setWebhook" => {
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            // authenticate() just read this very header.
            let token = crate::auth::middleware::extract_bearer(&req).unwrap_or_default();
            set_webhook(&ctx.env, &db, &bot, url, &token).await
        }
        "deleteWebhook" => set_webhook(&ctx.env, &db, &bot, "", "").await,
        _ => bot_err(404, "unknown-method"),
    }
}

async fn get_updates(env: &Env, bot: &BotAuth, body: &serde_json::Value) -> Result<Response> {
    let int = |k: &str| body.get(k).and_then(|v| v.as_i64());
    let offset = int("offset").unwrap_or(0);
    let timeout = int("timeout").unwrap_or(0);
    let limit = int("limit").unwrap_or(MAX_LIMIT);
    if offset < 0 || !(0..=MAX_POLL_SECS).contains(&timeout) || !(1..=MAX_LIMIT).contains(&limit) {
        return bot_err(400, "bad-request");
    }
    let q = serde_json::json!({ "offset": offset, "timeout": timeout, "limit": limit });
    let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/updates", Some(q.to_string())).await?;
    crate::respond::passthrough(resp).await
}

/// Set (`url` non-empty) or clear the webhook. The secret is derived from the key the program
/// called with, so the program can compute it itself; it is also answered, once, for convenience.
async fn set_webhook(env: &Env, db: &D1Database, bot: &BotAuth, url: &str, token: &str) -> Result<Response> {
    let (url, secret) = if url.trim().is_empty() {
        (None, None)
    } else {
        let Some(url) = super::webhook::clean_url(url, super::builtin_rules::allow_lan(env)) else {
            return bot_err(400, "bad-url");
        };
        (Some(url), Some(super::webhook::derive_secret(token)))
    };
    let call = serde_json::json!({ "url": url, "secret": secret });
    let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/webhook", Some(call.to_string())).await?;
    if resp.status_code() == 409 {
        return crate::respond::passthrough(resp).await; // `bot/builtin-active`
    }
    if resp.status_code() != 204 {
        return bot_err(502, "inbox-unavailable");
    }
    db.prepare("UPDATE bots SET webhook_url = ?2 WHERE bot_id = ?1")
        .bind(&[d1_text(&bot.bot_id), crate::d1util::d1_opt_text(url.as_deref())])?
        .run()
        .await?;
    match secret {
        Some(s) => Response::from_json(&serde_json::json!({ "ok": true, "webhook_secret": s })),
        None => Response::from_json(&serde_json::json!({ "ok": true })),
    }
}

#[derive(Deserialize)]
struct Chat {
    user_id: Option<String>,
    room_id: Option<String>,
}

#[derive(Deserialize)]
struct SendBody {
    chat: Chat,
    text: String,
    #[serde(default)]
    reply_to: Option<String>,
    #[serde(default)]
    buttons: Option<serde_json::Value>,
}

async fn send_message(
    env: &Env,
    db: &D1Database,
    bot: &BotAuth,
    body: serde_json::Value,
) -> Result<Response> {
    let Ok(body) = serde_json::from_value::<SendBody>(body) else {
        return bot_err(400, "bad-request");
    };
    if body.buttons.is_some() {
        return bot_err(400, "unsupported");
    }
    let text = body.text.trim_end();
    if text.trim().is_empty() || text.chars().count() > MAX_TEXT_CHARS {
        return bot_err(400, "bad-text");
    }
    let room = match (body.chat.room_id, body.chat.user_id.as_deref()) {
        (Some(room), None) if !room.is_empty() && room.len() <= 64 => Some(room),
        (None, Some(_)) => None,
        _ => return bot_err(400, "bad-request"),
    };
    // A reply names a room call (`update.message.message_id`); 1:1 replies are not built yet.
    if room.is_none() && body.reply_to.is_some() {
        return bot_err(400, "unsupported");
    }
    if !crate::ratelimit::check_rate_limit_env(
        env,
        &format!("bot_send:{}", bot.bot_id),
        SENDS_PER_MINUTE,
        60,
    )
    .await
    {
        return bot_err(429, "rate-limited");
    }
    if let Some(room_id) = room {
        // Only into a room whose admins added this bot (`group_bots`); the bot's inbox asks again
        // before anything leaves, so a removal in between still stops the post.
        if !crate::groups::bots::is_room_bot(db, &room_id, &bot.bot_id).await? {
            return bot_err(403, "not-in-room");
        }
        let call = serde_json::json!({
            "method": "sendRoom", "room_id": room_id, "text": text, "reply_to": body.reply_to,
        });
        let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/api", Some(call.to_string())).await?;
        return crate::respond::passthrough(resp).await;
    }
    let Some(to) = body.chat.user_id.filter(|u| u.len() == 36) else {
        return bot_err(400, "bad-request");
    };
    #[derive(Deserialize)]
    struct Target {
        human: i64,
        blocked: i64,
    }
    let target: Option<Target> = db
        .prepare(SEND_TARGET_SQL)
        .bind(&[d1_text(&to), d1_text(&bot.bot_id)])?
        .first(None)
        .await?;
    match target {
        Some(t) if t.human == 1 && t.blocked == 0 => {}
        Some(t) if t.human == 1 => return bot_err(403, "blocked"),
        _ => return bot_err(403, "not-a-member"),
    }
    let call = serde_json::json!({ "method": "sendMessage", "to": to, "text": text });
    let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/api", Some(call.to_string())).await?;
    crate::respond::passthrough(resp).await
}
