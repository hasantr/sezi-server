//! `POST /bot/v1/:method` — what a bot's program calls (docs/BOTS_BUILD.md §2.5).
//!
//! | method | body | answer |
//! |---|---|---|
//! | `getMe` | `{}` | `{ok, bot:{bot_id, name, about}}` |
//! | `getUpdates` | `{offset?, timeout? 0..25, limit? 1..100}` | `{ok, updates:[…]}`; below `offset` is confirmed and deleted |
//! | `sendMessage` | `{chat:{user_id}, text ≤4000}` | `{ok, message_id}` (`b-<uuid>`) |
//!
//! Phase 1 writes 1:1 text only: a `room_id`, `reply_to` or `buttons` answers `bot/unsupported`
//! rather than being dropped in silence. Errors are `{ok:false, error:"bot/<code>"}`.
//!
//! The Worker checks the key and who the bot may write to; the bot's inbox does the encryption.
//! A bot may write to an active human of this server who has not blocked it, and to nobody else.

use super::token::{self, BotAuth};
use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;
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
    // Best effort: "when did the program last show up" (the Phase 2 "no word from it" line).
    if let Ok(stmt) = db
        .prepare("UPDATE bots SET program_seen_at = ?2 WHERE bot_id = ?1")
        .bind(&[d1_text(&bot.bot_id), d1_int(now_secs() as i64)])
    {
        let _ = stmt.run().await;
    }
    let body: serde_json::Value = req.json().await.unwrap_or(serde_json::json!({}));
    match method.as_str() {
        "getMe" => Response::from_json(&serde_json::json!({
            "ok": true,
            "bot": { "bot_id": bot.bot_id, "name": bot.name, "about": bot.about },
        })),
        "getUpdates" => get_updates(&ctx.env, &bot, &body).await,
        "sendMessage" => send_message(&ctx.env, &db, &bot, body).await,
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
    if body.chat.room_id.is_some() || body.reply_to.is_some() || body.buttons.is_some() {
        return bot_err(400, "unsupported");
    }
    let Some(to) = body.chat.user_id.filter(|u| u.len() == 36) else {
        return bot_err(400, "bad-request");
    };
    let text = body.text.trim_end();
    if text.trim().is_empty() || text.chars().count() > MAX_TEXT_CHARS {
        return bot_err(400, "bad-text");
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
