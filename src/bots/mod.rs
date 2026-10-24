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
//! | `api.rs` | `/bot/v1/:method` — `getMe`, `getUpdates`, `sendMessage` |
//! | `token.rs` | the key's shape, its hash, the lookup |
//! | `provision.rs` | every D1 statement a bot's account, device, keys and grants take |
//!
//! A bot is never a group member (`groups.rs` refuses it), never in the directory, never in the
//! owner's member list or counts, and never removed as a member — it is deleted as a bot.

pub mod admin;
pub mod api;
pub(crate) mod provision;
pub(crate) mod token;

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
