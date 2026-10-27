//! `POST /bot/v1/:method` — what a bot's program calls (docs/BOTS_BUILD.md §2.5).
//!
//! | method | body | answer |
//! |---|---|---|
//! | `getMe` | `{}` | `{ok, bot:{bot_id, name, about}}` |
//! | `getUpdates` | `{offset?, timeout? 0..25, limit? 1..100}` | `{ok, updates:[…]}`; below `offset`, what a poll handed out is confirmed and deleted |
//! | `sendMessage` | `{chat:{user_id}\|{room_id}, text ≤4000, reply_to?, client_id?}` | `{ok, message_id}` (`b-<uuid>`); a repeated `client_id` answers the first send's `message_id` with `duplicate: true` |
//! | `setWebhook` | `{url}` (https; `""` or `null` clears) | `{ok, webhook_secret}` |
//! | `deleteWebhook` | `{}` | `{ok}` |
//! | `getFile` | `{file_id}` | the file's DECRYPTED bytes (`application/octet-stream`); an error is the usual JSON |
//!
//! Every body is a JSON object of at most 64 KiB whose fields have their documented types
//! (`api_input.rs`); anything else is refused before a lookup.
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

use super::api_input::{self as input, Chat, SendReq};
use super::token::{self, BotAuth};
use crate::d1util::d1_text;
use serde::Deserialize;
use worker::*;

/// Is the target an active human, and is there a block between them? Bind: target, bot.
pub(crate) const SEND_TARGET_SQL: &str = "SELECT
       EXISTS(SELECT 1 FROM users WHERE id = ?1 AND kind = 'human') AS human,
       EXISTS(SELECT 1 FROM contact_blocks
               WHERE (blocker_user_id = ?1 AND blocked_user_id = ?2)
                  OR (blocker_user_id = ?2 AND blocked_user_id = ?1)) AS blocked";

/// The owner's copy of the webhook (`GET /admin/bots`), written only when it changes: a program
/// calling `setWebhook` with the same URL on every start (or in a loop) writes no D1 row.
/// Bind: bot_id, url (NULL clears).
pub(crate) const SET_WEBHOOK_SQL: &str =
    "UPDATE bots SET webhook_url = ?2 WHERE bot_id = ?1 AND webhook_url IS NOT ?2";

pub(crate) fn bot_err(status: u16, code: &str) -> Result<Response> {
    Ok(Response::from_json(&super::api_answer::error(code))?.with_status(status))
}

/// `bot/rate-limited`, with `retry_after` in the body (an Apps Script program reads no headers)
/// and in `Retry-After` — the send limits', the call budget's and the wrong-key brake's answer.
pub(crate) fn rate_limited(retry_after_s: u64) -> Result<Response> {
    let mut resp = Response::from_json(&super::api_answer::rate_limited(retry_after_s))?.with_status(429);
    resp.headers_mut().set("Retry-After", &retry_after_s.to_string())?;
    Ok(resp)
}

pub async fn dispatch(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let method = ctx.param("method").cloned().unwrap_or_default();
    // An address that keeps sending keys that open no bot waits before its next lookup
    // (`key_brake.rs`): no D1 read for it, and no write anywhere. Only a well-formed key costs a
    // lookup, so only one is braked or counted; a key this isolate saw open a bot passes.
    let addr = crate::ratelimit::door_address(&crate::ratelimit::client_ip(&req, &ctx.env));
    let now_s = crate::utils::now_secs() as i64;
    let key_hash = crate::auth::middleware::extract_bearer(&req)
        .filter(|k| token::parse(k).is_some())
        .map(|k| token::hash(&k));
    if let Some(h) = &key_hash {
        if let Err(retry_after_s) = super::key_brake::check(&addr, h, now_s) {
            return rate_limited(retry_after_s);
        }
    }
    let db = ctx.env.d1("DB")?;
    let Some(bot) = token::authenticate(&req, &db).await? else {
        if let Some(h) = &key_hash {
            super::key_brake::miss(&addr, h, now_s);
        }
        return bot_err(401, "unauthorized");
    };
    if let Some(h) = &key_hash {
        super::key_brake::good(h, now_s);
    }
    if bot.disabled_at.is_some() {
        return bot_err(403, "disabled");
    }
    // Every call, whatever its method, takes one from the bot's budget before any of its work
    // (`inbox_do/bot/api_budget.rs`: 300 a minute, a burst of 60).
    if let Some(refused) = take_call(&ctx.env, &bot.bot_id).await {
        return refused;
    }
    // "When did the program last show up" (the owner's "no word from it" line).
    super::mark_program_seen(&ctx.env, &bot.bot_id).await;
    let body = match read_body(&mut req).await? {
        Ok(b) => b,
        Err((status, code)) => return bot_err(status, code),
    };
    match method.as_str() {
        "getMe" => Response::from_json(&super::api_answer::me(&bot.bot_id, &bot.name, bot.about.as_deref())),
        "getUpdates" => get_updates(&ctx.env, &bot, &body).await,
        "sendMessage" => match input::parse_send(&body) {
            Ok(send) => send_message(&ctx.env, &db, &bot, send).await,
            Err((status, code)) => bot_err(status, code),
        },
        "setWebhook" => {
            let url = match input::parse_webhook(&body) {
                Ok(u) => u.unwrap_or(""),
                Err((status, code)) => return bot_err(status, code),
            };
            // authenticate() just read this very header.
            let token = crate::auth::middleware::extract_bearer(&req).unwrap_or_default();
            set_webhook(&ctx.env, &db, &bot, url, &token).await
        }
        "deleteWebhook" => set_webhook(&ctx.env, &db, &bot, "", "").await,
        "getFile" => match input::parse_get_file(&body) {
            Ok(file_id) => get_file(&ctx.env, &bot, file_id).await,
            Err((status, code)) => bot_err(status, code),
        },
        _ => bot_err(404, "unknown-method"),
    }
}

/// One call from the bot's budget, counted in its inbox: `Some(answer)` when it is refused. An
/// inbox that does not answer lets the call through — the budget bounds a program, not the
/// inbox's own availability, and the call that follows meets the same inbox anyway.
async fn take_call(env: &Env, bot_id: &str) -> Option<Result<Response>> {
    match super::bot_inbox(env, bot_id, Method::Post, "/bot/budget", None).await {
        Ok(r) if r.status_code() == 204 => None,
        Ok(r) if r.status_code() == 429 => Some(inbox_answer(Ok(r)).await),
        other => {
            console_log!("[bot] call budget not counted: {:?}", other.map(|r| r.status_code()).map_err(|e| e.to_string()));
            None
        }
    }
}

/// The body, at most `api_input::MAX_BODY_BYTES`: refused unread when its `content-length` says
/// it is bigger, and again by what was actually read (a length can lie, or be absent).
async fn read_body(req: &mut Request) -> Result<std::result::Result<serde_json::Value, input::Refusal>> {
    let declared = req
        .headers()
        .get("content-length")?
        .and_then(|v| v.trim().parse::<u64>().ok());
    if input::body_too_large(declared) {
        return Ok(Err((413, "too-large")));
    }
    let bytes = req.bytes().await.unwrap_or_default();
    Ok(input::parse_body(&bytes))
}

/// The bot inbox's answer as the program gets it: as it is when it is the documented `{ok, …}`
/// JSON below 500 (`api_input::is_program_answer`), with its `Retry-After`; anything else —
/// the inbox threw, was purged under the call, answered plain text — is `bot/inbox-unavailable`.
async fn inbox_answer(resp: Result<Response>) -> Result<Response> {
    let Ok(mut resp) = resp else {
        return bot_err(502, "inbox-unavailable");
    };
    let status = resp.status_code();
    let body = resp.bytes().await.unwrap_or_default();
    if !input::is_program_answer(status, &body) {
        return bot_err(502, "inbox-unavailable");
    }
    // A fresh response: one that came out of `fetch` has immutable headers (`respond::passthrough`).
    let mut out = Response::from_bytes(body)?.with_status(status);
    out.headers_mut().set("content-type", "application/json")?;
    if let Some(wait) = resp.headers().get("retry-after")? {
        out.headers_mut().set("Retry-After", &wait)?;
    }
    Ok(out)
}

async fn get_updates(env: &Env, bot: &BotAuth, body: &serde_json::Value) -> Result<Response> {
    let q = match input::parse_updates(body) {
        Ok(q) => q,
        Err((status, code)) => return bot_err(status, code),
    };
    let q = serde_json::json!({ "offset": q.offset, "timeout": q.timeout, "limit": q.limit });
    inbox_answer(super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/updates", Some(q.to_string())).await).await
}

/// `getFile`: a member's file, opened by the bot's inbox (`inbox_do/bot/files.rs`) after the
/// relay's record of its blob said the member uploaded it for this bot — the bytes, decrypted, or
/// the inbox's `{ok:false}` answer. The program never sees a key or a `media_id`, and a `file_id`
/// is looked up in this bot's own inbox, so no other bot's key reaches it.
async fn get_file(env: &Env, bot: &BotAuth, file_id: &str) -> Result<Response> {
    let call = serde_json::json!({ "file_id": file_id });
    let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/file", Some(call.to_string())).await;
    let mut resp = match resp {
        Ok(r) if r.status_code() == 200 => r,
        other => return inbox_answer(other).await,
    };
    let bytes = resp.bytes().await?;
    // A fresh response: one that came out of `fetch` has immutable headers.
    let mut out = Response::from_bytes(bytes)?;
    let h = out.headers_mut();
    h.set("content-type", "application/octet-stream")?;
    h.set("cache-control", "private, no-store")?;
    h.set("x-content-type-options", "nosniff")?;
    Ok(out)
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
    let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/webhook", Some(call.to_string())).await;
    match resp.as_ref().map(Response::status_code) {
        Ok(204) => {}
        Ok(409) => return inbox_answer(resp).await, // `bot/builtin-active`
        _ => return bot_err(502, "inbox-unavailable"),
    }
    db.prepare(SET_WEBHOOK_SQL)
        .bind(&[d1_text(&bot.bot_id), crate::d1util::d1_opt_text(url.as_deref())])?
        .run()
        .await?;
    Response::from_json(&super::api_answer::webhook(secret.as_deref()))
}

/// A `sendMessage` that `api_input::parse_send` accepted: who it may go to, then the bot's inbox,
/// which counts the send limits (`inbox_do/bot/send_guard.rs`: 60 a minute, 30 into one chat,
/// `bot/rate-limited` with `retry_after`) — exactly, and without the KV put per send the
/// server's shared limiter cannot afford.
async fn send_message(env: &Env, db: &D1Database, bot: &BotAuth, send: SendReq) -> Result<Response> {
    let to = match send.chat {
        Chat::Room(room_id) => {
            // Only into a room whose admins added this bot (`group_bots`); the bot's inbox asks
            // again before anything leaves, so a removal in between still stops the post.
            if !crate::groups::bots::is_room_bot(db, &room_id, &bot.bot_id).await? {
                return bot_err(403, "not-in-room");
            }
            let call = serde_json::json!({
                "method": "sendRoom", "room_id": room_id, "text": send.text, "reply_to": send.reply_to,
                "client_id": send.client_id,
            });
            let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/api", Some(call.to_string())).await;
            return inbox_answer(resp).await;
        }
        Chat::User(to) => to,
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
    let call = serde_json::json!({
        "method": "sendMessage", "to": to, "text": send.text, "client_id": send.client_id,
    });
    inbox_answer(super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/api", Some(call.to_string())).await).await
}
