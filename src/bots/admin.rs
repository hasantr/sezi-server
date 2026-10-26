//! The owner's bot surface (docs/BOTS_BUILD.md §2.5, board R9-Bots-Server).
//!
//! | Route | What |
//! |---|---|
//! | `POST /admin/bots {name, about?}` | create → `{bot_id, token}`; the token is shown ONCE |
//! | `GET /admin/bots` | every bot not deleted, with how its program is doing (below) |
//! | `PATCH /admin/bots/:id {name?, about?, disabled?}` | change, turn off, turn back on |
//! | `POST /admin/bots/:id/token` | a new key; the old one stops at once |
//! | `DELETE /admin/bots/:id` | soft delete: the account and its name stay for old messages |
//! | `POST /admin/bots/:id/test` | "Dene": a `ping` update to the program → `{ok, update_id}`; a built-in bot runs NOW → `{ok, kind, outcome, answer?}` |
//! | `PUT`/`GET /admin/bots/:id/builtin` | a built-in bot's configuration (`builtin.rs`) |
//!
//! Each listed bot carries `program_seen_at` (seconds: its last API call or taken webhook),
//! `waiting_since` (ms: the oldest update its program has not been handed), `webhook` (set or
//! not), `webhook_refused` (set, but its URL fails the outbound rule at delivery, so nothing is
//! sent to it — one stored before the rule existed) and `program_silent` — "Programından haber yok": an update has waited 10 minutes and
//! the program has not been seen in that time (BOTS_BUILD §5, R9 decision 4). Otherwise the
//! page shows "last seen". A built-in bot (`builtin` = `sheet` / `ai`) is never silent — the relay
//! is its program — and carries `ai_provider`, `ai_model`, `last_ok_at` (ms) and `last_error`
//! (a typed code) instead; no secret and no instructions are listed. Every bot also carries
//! `rooms` (`[{room_id, name}]`), the rooms it is in — read-only here, since a room's admins
//! decide its bots and the owner never does.
//!
//! OWNER-only, through `require_active_auth` (a revoked device's access token is refused at
//! once — the `admin/mod.rs` guard explains why `require_auth` is never enough here).
//!
//! "A new key" is a new TOKEN, never new crypto: a bot's identity is made once, and a new key
//! behind the same user id would read as `key_changed` at every member (BOTS_BUILD §5).

use super::{provision, token};
use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::{b64_encode, now_ms, now_secs, random_bytes};
use serde::Deserialize;
use worker::*;

const MAX_NAME_CHARS: usize = 64;
const MAX_ABOUT_CHARS: usize = 280;
/// How long an update waits before the program counts as silent.
const SILENT_AFTER_MS: i64 = 10 * 60 * 1000;

/// "No word from the program": an update has waited `SILENT_AFTER_MS`, and the program was not
/// seen within that window. `seen_at_s` is in seconds (`bots.program_seen_at`), the rest in ms.
pub(crate) fn program_silent(waiting_since_ms: Option<i64>, seen_at_s: Option<i64>, now_ms: i64) -> bool {
    let Some(since) = waiting_since_ms else {
        return false;
    };
    let window_start = now_ms - SILENT_AFTER_MS;
    since <= window_start && seen_at_s.is_none_or(|s| s * 1000 < window_start)
}

/// The owner's user id, or the refusal to send.
pub(crate) async fn owner(req: &Request, env: &Env) -> std::result::Result<String, Response> {
    let user_id = require_active_auth(req, env).await?.user_id;
    require_owner(&user_id, env).await?;
    Ok(user_id)
}

/// A trimmed name of 1..=64 characters, or `None`.
fn clean_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    (!name.is_empty() && name.chars().count() <= MAX_NAME_CHARS).then(|| name.to_string())
}

/// A trimmed description of at most 280 characters; empty reads as none.
fn clean_about(raw: &str) -> std::result::Result<Option<String>, ()> {
    let about = raw.trim();
    if about.chars().count() > MAX_ABOUT_CHARS {
        return Err(());
    }
    Ok((!about.is_empty()).then(|| about.to_string()))
}

#[derive(Deserialize, Default)]
struct CreateBody {
    name: String,
    #[serde(default)]
    about: Option<String>,
}

pub async fn create(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let owner_id = match owner(&req, &ctx.env).await {
        Ok(u) => u,
        Err(resp) => return Ok(resp),
    };
    let body: CreateBody = req.json().await.unwrap_or_default();
    let Some(name) = clean_name(&body.name) else {
        return json_err(400, "bad_name");
    };
    let Ok(about) = clean_about(body.about.as_deref().unwrap_or("")) else {
        return json_err(400, "bad_about");
    };
    let db = ctx.env.d1("DB")?;
    #[derive(Deserialize)]
    struct N {
        n: i64,
    }
    let count: Option<N> = db
        .prepare("SELECT COUNT(*) AS n FROM bots WHERE deleted_at IS NULL")
        .first(None)
        .await?;
    if count.is_some_and(|c| c.n >= provision::MAX_BOTS) {
        return json_err(409, "too_many_bots");
    }

    let bot_id = uuid::Uuid::new_v4().to_string();
    let pickle_key: [u8; 32] = random_bytes(32).try_into().expect("32 random bytes");
    let reg = sezi_bot_engine::create_identity(
        &bot_id,
        &pickle_key,
        provision::OTK_POOL_TARGET,
        now_ms() as i64,
    )
    .map_err(|e| Error::RustError(format!("bot identity: {e}")))?;

    // The inbox first: a D1 account whose crypto state never landed would be a contact nobody
    // can talk to. The reverse leftover — an initialized inbox with no account — is purged below.
    let init = serde_json::json!({
        "bot_id": bot_id,
        "device_id": reg.device_id,
        "account_pickle": reg.account_pickle,
        "pickle_key_b64": b64_encode(&pickle_key),
    });
    let resp = super::bot_inbox(&ctx.env, &bot_id, Method::Post, "/bot/init", Some(init.to_string())).await?;
    if resp.status_code() != 204 {
        return json_err(502, "bot_inbox_init_failed");
    }

    let secret = token::mint(&bot_id);
    let nb = provision::NewBot {
        bot_id: &bot_id,
        name: &name,
        about: about.as_deref(),
        owner: &owner_id,
        token_hash: &token::hash(&secret),
        now_s: now_secs() as i64,
        reg: &reg,
    };
    let written = match provision::creation_statements(&db, &nb) {
        Ok(stmts) => db.batch(stmts).await.map(|_| ()),
        Err(e) => Err(e),
    };
    if let Err(e) = written {
        let _ = crate::realtime::purge_account_inbox(&ctx.env, &bot_id).await;
        return Err(e);
    }
    provision::nudge_humans(&ctx.env, &db).await;
    Response::from_json(&serde_json::json!({ "bot_id": bot_id, "token": secret }))
}

#[derive(Deserialize, serde::Serialize)]
struct BotRow {
    bot_id: String,
    name: String,
    #[serde(default)]
    about: Option<String>,
    #[serde(default)]
    builtin: Option<String>,
    #[serde(default)]
    ai_provider: Option<String>,
    created_at: i64,
    #[serde(default)]
    disabled_at: Option<i64>,
    #[serde(default)]
    program_seen_at: Option<i64>,
}

pub async fn list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let rows: Vec<BotRow> = db
        .prepare(
            "SELECT bot_id, name, about, builtin, ai_provider, created_at, disabled_at, program_seen_at
               FROM bots WHERE deleted_at IS NULL ORDER BY created_at, bot_id",
        )
        .all()
        .await?
        .results()?;
    #[derive(Deserialize, Default)]
    struct State {
        #[serde(default)]
        waiting_since: Option<i64>,
        #[serde(default)]
        webhook: bool,
        #[serde(default)]
        webhook_refused: bool,
        #[serde(default)]
        ai_model: Option<String>,
        #[serde(default)]
        last_ok_at: Option<i64>,
        #[serde(default)]
        last_error: Option<String>,
    }
    let now = now_ms() as i64;
    let mut out = Vec::with_capacity(rows.len());
    // One inbox read per bot; `provision::MAX_BOTS` bounds the count.
    for row in rows {
        let state: State = match super::bot_inbox(&ctx.env, &row.bot_id, Method::Get, "/bot/state", None).await {
            Ok(mut r) if r.status_code() == 200 => r.json().await.unwrap_or_default(),
            _ => State::default(),
        };
        let mut v = serde_json::to_value(&row).map_err(|e| Error::RustError(e.to_string()))?;
        v["waiting_since"] = state.waiting_since.into();
        v["webhook"] = state.webhook.into();
        v["webhook_refused"] = state.webhook_refused.into();
        let silent = row.builtin.is_none() && program_silent(state.waiting_since, row.program_seen_at, now);
        v["program_silent"] = silent.into();
        v["ai_model"] = state.ai_model.into();
        v["last_ok_at"] = state.last_ok_at.into();
        v["last_error"] = state.last_error.into();
        v["rooms"] = bot_rooms(&db, &row.bot_id).await?.into();
        out.push(v);
    }
    Response::from_json(&serde_json::json!({ "bots": out }))
}

/// The rooms a bot is in, `[{room_id, name}]` — shown to the owner READ-ONLY: a room's admins
/// add and remove its bots (`groups_bots.rs`, R9 decision 6), the owner only sees where it is.
async fn bot_rooms(db: &D1Database, bot_id: &str) -> Result<Vec<serde_json::Value>> {
    #[derive(Deserialize)]
    struct Room {
        group_id: String,
        name: String,
    }
    let rooms: Vec<Room> = db
        .prepare(crate::groups::bots::BOT_ROOMS_SQL)
        .bind(&[d1_text(bot_id)])?
        .all()
        .await?
        .results()?;
    Ok(rooms
        .into_iter()
        .map(|r| serde_json::json!({ "room_id": r.group_id, "name": r.name }))
        .collect())
}

#[derive(Deserialize, Default)]
struct PatchBody {
    name: Option<String>,
    about: Option<String>,
    disabled: Option<bool>,
}

/// A bot that exists and is not deleted.
pub(crate) async fn live_bot(db: &D1Database, bot_id: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct R {
        #[allow(dead_code)] // an existence check; the value is never read
        bot_id: String,
    }
    let row: Option<R> = db
        .prepare("SELECT bot_id FROM bots WHERE bot_id = ?1 AND deleted_at IS NULL")
        .bind(&[d1_text(bot_id)])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

pub async fn update(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let Some(bot_id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request");
    };
    let body: PatchBody = req.json().await.unwrap_or_default();
    if body.name.is_none() && body.about.is_none() && body.disabled.is_none() {
        return json_err(400, "bad_request");
    }
    let name = match body.name.as_deref().map(clean_name) {
        Some(None) => return json_err(400, "bad_name"),
        other => other.flatten(),
    };
    let about = match body.about.as_deref().map(clean_about) {
        Some(Err(())) => return json_err(400, "bad_about"),
        Some(Ok(a)) => Some(a),
        None => None,
    };
    let db = ctx.env.d1("DB")?;
    if !live_bot(&db, &bot_id).await? {
        return json_err(404, "not_found");
    }
    let now = d1_int(now_secs() as i64);
    let mut stmts = Vec::new();
    if let Some(n) = &name {
        stmts.push(
            db.prepare("UPDATE bots SET name = ?2 WHERE bot_id = ?1")
                .bind(&[d1_text(&bot_id), d1_text(n)])?,
        );
        // The name members see is the account's display name; the revision bump is what a
        // grant sync compares to refresh a profile.
        stmts.push(
            db.prepare(
                "UPDATE users SET display_name = ?2, profile_revision = profile_revision + 1
                  WHERE id = ?1 AND kind = 'bot'",
            )
            .bind(&[d1_text(&bot_id), d1_text(n)])?,
        );
    }
    if let Some(a) = &about {
        stmts.push(
            db.prepare("UPDATE bots SET about = ?2 WHERE bot_id = ?1")
                .bind(&[d1_text(&bot_id), d1_opt_text(a.as_deref())])?,
        );
    }
    match body.disabled {
        Some(true) => stmts.push(
            db.prepare("UPDATE bots SET disabled_at = COALESCE(disabled_at, ?2) WHERE bot_id = ?1")
                .bind(&[d1_text(&bot_id), now])?,
        ),
        Some(false) => stmts.push(
            db.prepare("UPDATE bots SET disabled_at = NULL WHERE bot_id = ?1")
                .bind(&[d1_text(&bot_id)])?,
        ),
        None => {}
    }
    db.batch(stmts).await?;
    // A built-in bot held its queue while it was off; back on, it runs now.
    if body.disabled == Some(false) {
        let _ = super::bot_inbox(&ctx.env, &bot_id, Method::Post, "/bot/wake", None).await;
    }
    // Members read a bot's name, line and on/off state from `GET /bots`, which their kernel
    // re-reads on a `contact_update`. Without this nudge a turned-off bot still looked on to them
    // until their app restarted (lab, 2026-10-26).
    provision::nudge_humans(&ctx.env, &db).await;
    no_content()
}

pub async fn renew_token(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let Some(bot_id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request");
    };
    let db = ctx.env.d1("DB")?;
    if !live_bot(&db, &bot_id).await? {
        return json_err(404, "not_found");
    }
    let secret = token::mint(&bot_id);
    // A webhook in force is signed with the NEW key's secret from now on; the old one stops
    // verifying, as the old key stops working. The inbox hears the new secret FIRST, and a renewal
    // it did not take is refused with nothing changed: until 2026-10-26 a failed push was only
    // logged, so the program held a new key while every webhook came signed with the old one's
    // secret and failed its check. Should the token write below fail after the push, the webhooks
    // signed meanwhile fail and wait on their retries, and the owner's next renewal heals both.
    let push = serde_json::json!({ "secret": super::webhook::derive_secret(&secret) });
    let pushed =
        super::bot_inbox(&ctx.env, &bot_id, Method::Post, "/bot/webhook-secret", Some(push.to_string())).await;
    if !renewal_reached_inbox(pushed.as_ref().map(|r| r.status_code())) {
        console_warn!("bot key renewal refused bot={bot_id}: the inbox did not take the webhook secret");
        return json_err(502, "inbox_unavailable");
    }
    let now = d1_int(now_secs() as i64);
    db.batch(vec![
        db.prepare(token::REVOKE_TOKENS_SQL)
            .bind(&[d1_text(&bot_id), now.clone()])?,
        db.prepare(token::INSERT_TOKEN_SQL)
            .bind(&[d1_text(&token::hash(&secret)), d1_text(&bot_id), now])?,
    ])
    .await?;
    Response::from_json(&serde_json::json!({ "bot_id": bot_id, "token": secret }))
}

/// Whether the inbox took a renewed key's webhook secret: the call went through and answered 2xx.
/// A DO that threw answers 500 as an `Ok` response, which is not taken.
pub(crate) fn renewal_reached_inbox<E>(status: std::result::Result<u16, E>) -> bool {
    matches!(status, Ok(s) if (200..300).contains(&s))
}

/// "Dene": a `ping` update, carrying the owner as `who`, that the program receives like any
/// other — by poll or webhook. A program that answers it shows the owner the whole loop works.
/// A built-in bot is run NOW instead, and the answer is its measured outcome
/// (`{ok, kind, outcome: "ok" | "<code>", answer?}`).
pub async fn test(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let owner_id = match owner(&req, &ctx.env).await {
        Ok(u) => u,
        Err(resp) => return Ok(resp),
    };
    let Some(bot_id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request");
    };
    let db = ctx.env.d1("DB")?;
    if !live_bot(&db, &bot_id).await? {
        return json_err(404, "not_found");
    }
    #[derive(Deserialize, serde::Serialize)]
    struct Who {
        user_id: String,
        #[serde(default)]
        display_name: Option<String>,
        server_role: String,
    }
    let who: Option<Who> = db
        .prepare("SELECT id AS user_id, display_name, role AS server_role FROM users WHERE id = ?1")
        .bind(&[d1_text(&owner_id)])?
        .first(None)
        .await?;
    #[derive(Deserialize)]
    struct Builtin {
        #[serde(default)]
        builtin: Option<String>,
    }
    let builtin: Option<Builtin> = db
        .prepare("SELECT builtin FROM bots WHERE bot_id = ?1")
        .bind(&[d1_text(&bot_id)])?
        .first(None)
        .await?;
    let path = match builtin.and_then(|b| b.builtin).as_deref() {
        Some("sheet" | "ai") => "/bot/builtin-test",
        _ => "/bot/ping",
    };
    let call = serde_json::json!({ "who": who });
    let resp = super::bot_inbox(&ctx.env, &bot_id, Method::Post, path, Some(call.to_string())).await?;
    crate::respond::passthrough(resp).await
}

pub async fn delete(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let owner_id = match owner(&req, &ctx.env).await {
        Ok(u) => u,
        Err(resp) => return Ok(resp),
    };
    let Some(bot_id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request");
    };
    let db = ctx.env.d1("DB")?;
    if !live_bot(&db, &bot_id).await? {
        return json_err(404, "not_found");
    }
    db.batch(provision::deletion_statements(
        &db,
        &bot_id,
        &owner_id,
        now_secs() as i64,
    )?)
    .await?;
    // Its sessions, updates, secrets and outbox go with the inbox. A failure here is retried by
    // the cron's purge drain: the batch above queued it (`provision::QUEUE_PURGE_SQL`).
    if let Err(e) = crate::realtime::purge_account_inbox(&ctx.env, &bot_id).await {
        console_warn!("bot inbox purge failed bot={bot_id}: {e:?}");
    }
    provision::nudge_humans(&ctx.env, &db).await;
    no_content()
}

#[cfg(test)]
mod tests {
    use super::program_silent;

    const MIN: i64 = 60_000;

    /// The body of `pub async fn <name>` in `src`, up to the next top-level `fn`.
    fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
        let start = src.find(&format!("pub async fn {name}(")).expect(name);
        let rest = &src[start..];
        let end = rest[1..].find("\npub async fn ").map_or(rest.len(), |i| i + 1);
        &rest[..end]
    }

    #[test]
    fn every_owner_change_members_see_nudges_them() {
        // What members are shown of a bot (name, line, on/off, the AI chip) is `GET /bots`, which
        // their kernel re-reads on a `contact_update` only. Measured in the lab: a bot turned off
        // or made an AI bot looked unchanged to members until their app restarted.
        let admin = include_str!("admin.rs");
        for f in ["create", "update", "delete"] {
            assert!(fn_body(admin, f).contains("nudge_humans("), "admin::{f}");
        }
        assert!(fn_body(include_str!("builtin.rs"), "put").contains("nudge_humans("), "builtin::put");
    }

    #[test]
    fn a_key_renewal_the_inbox_did_not_take_changes_nothing() {
        use super::renewal_reached_inbox as taken;
        assert!(taken::<()>(Ok(204)));
        assert!(!taken::<()>(Ok(500)), "a DO that threw answers 500 as an Ok response");
        assert!(!taken(Err("no stub")));
        // The order is the point: the inbox is asked before the old key is revoked, and a refusal
        // returns before the token batch.
        let body = fn_body(include_str!("admin.rs"), "renew_token");
        let push = body.find("/bot/webhook-secret").expect("push");
        let refuse = body.find("inbox_unavailable").expect("refusal");
        let revoke = body.find("REVOKE_TOKENS_SQL").expect("revoke");
        assert!(push < refuse && refuse < revoke, "push, refuse, then revoke");
    }

    #[test]
    fn silent_only_after_an_update_waited_ten_minutes_unseen() {
        let now = 100 * MIN;
        assert!(!program_silent(None, None, now), "nothing waits");
        assert!(!program_silent(Some(now - 9 * MIN), None, now), "not ten minutes yet");
        assert!(program_silent(Some(now - 10 * MIN), None, now), "never seen");
        assert!(program_silent(Some(now - 30 * MIN), Some((now - 11 * MIN) / 1000), now));
        assert!(
            !program_silent(Some(now - 30 * MIN), Some((now - 2 * MIN) / 1000), now),
            "seen within the window: last seen, not silent"
        );
    }
}
