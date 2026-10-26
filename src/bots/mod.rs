//! Bots (docs/BOTS_PLAN.md, docs/BOTS_BUILD.md).
//!
//! A bot is an account of `kind='bot'` whose end of the encryption runs inside the relay, in its
//! OWN `UserInbox` Durable Object ("bot mode", `messages/inbox_do/bot/`). Members reach it 1:1
//! as a server-asserted contact; its program talks to it over `/bot/v1/:method` with a bearer
//! key. What lives here is the Worker half:
//!
//! | File | What |
//! |---|---|
//! | `admin.rs` | the owner's `/admin/bots` surface: create (key shown once), list, change, renew, delete |
//! | `builtin.rs` · `builtin_rules.rs` | a built-in bot (sheet, AI): the owner's routes · its rules, limits and URL rule |
//! | `api.rs` | `/bot/v1/:method` — `getMe`, `getUpdates`, `sendMessage`, `setWebhook`, `deleteWebhook` |
//! | `api_input.rs` | what a program may send it: body size, JSON shape, every field's type and bound |
//! | `api_answer.rs` | every answer body it can read, Worker's and inbox's alike |
//! | `conformance_tests.rs` | §2.5's tables (methods, errors) held against the code and the program's README |
//! | `webhook.rs` | the webhook's derived secret, its signature and envelope, one POST |
//! | `listing.rs` | `GET /bots` — the enabled bots, for any active member |
//! | `token.rs` | the key's shape, its hash, the lookup |
//! | `provision.rs` | every D1 statement a bot's account, device, keys and grants take |
//!
//! A bot is never a group member (`groups.rs` refuses it), never in the directory, never in the
//! owner's member list or counts, and never removed as a member — it is deleted as a bot.

pub mod admin;
pub mod api;
pub(crate) mod api_answer;
pub(crate) mod api_input;
pub mod builtin;
pub(crate) mod builtin_rules;
pub mod listing;
pub(crate) mod provision;
pub(crate) mod token;
pub(crate) mod webhook;

use crate::d1util::d1_text;
use serde::Deserialize;
use worker::*;

/// The relay's answer when a bot is named where only a human may stand (a group's members).
pub(crate) const BOT_NOT_MEMBER: &str = "bot_not_member";

/// Which of a set of user ids are bots. Bind: a JSON array of ids.
pub(crate) const BOTS_AMONG_SQL: &str =
    "SELECT COUNT(*) AS n FROM users WHERE kind = 'bot' AND id IN (SELECT value FROM json_each(?1))";

/// Is any of `ids` a bot? An empty list answers false without a query.
pub(crate) async fn any_bot(db: &D1Database, ids: &[String]) -> Result<bool> {
    if ids.is_empty() {
        return Ok(false);
    }
    #[derive(Deserialize)]
    struct N {
        n: i64,
    }
    let list = serde_json::to_string(ids).map_err(|e| Error::RustError(e.to_string()))?;
    let row: Option<N> = db
        .prepare(BOTS_AMONG_SQL)
        .bind(&[d1_text(&list)])?
        .first(None)
        .await?;
    Ok(row.is_some_and(|r| r.n > 0))
}

/// The stamp, written at most once a minute: every API call stamps, and a stamp per call was a D1
/// row written per call — a program polling with `timeout: 0` in a loop spent the daily write
/// allowance the whole server shares (2.1, 2026-10-26). An UPDATE its WHERE excludes writes no
/// row. Bind: bot_id, now (s).
pub(crate) const PROGRAM_SEEN_SQL: &str = "UPDATE bots SET program_seen_at = ?2
      WHERE bot_id = ?1 AND (program_seen_at IS NULL OR program_seen_at <= ?2 - 60)";

/// "The program showed up": an API call, or a webhook it took (`bots.program_seen_at`, seconds).
/// Best effort — a missed stamp only makes the owner's "no word from it" line early.
pub(crate) async fn mark_program_seen(env: &Env, bot_id: &str) {
    let Ok(db) = env.d1("DB") else {
        return;
    };
    if let Ok(stmt) = db
        .prepare(PROGRAM_SEEN_SQL)
        .bind(&[d1_text(bot_id), crate::d1util::d1_int(crate::utils::now_secs() as i64)])
    {
        let _ = stmt.run().await;
    }
}

/// One internal call to a bot's inbox. DO stubs are not public: only this Worker reaches them,
/// so a `/bot/*` path there needs no authentication of its own.
pub(crate) async fn bot_inbox(
    env: &Env,
    bot_id: &str,
    method: Method,
    path: &str,
    body: Option<String>,
) -> Result<Response> {
    let stub = env
        .durable_object("USER_INBOX")?
        .id_from_name(bot_id)?
        .get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(method);
    if let Some(b) = body {
        init.with_body(Some(b.into()));
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        init.with_headers(headers);
    }
    let req = Request::new_with_init(&format!("https://do.sezgi{path}"), &init)?;
    stub.fetch_with_request(req).await
}

#[cfg(test)]
#[path = "seen_tests.rs"]
mod seen_tests;

#[cfg(test)]
#[path = "conformance_tests.rs"]
mod conformance_tests;
