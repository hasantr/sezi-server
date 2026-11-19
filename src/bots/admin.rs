//! The owner's bot surface (docs/BOTS_BUILD.md §2.5, board R9-Bots-Server).
//!
//! | Route | What |
//! |---|---|
//! | `POST /admin/bots {name, about?}` | create → `{bot_id, token}`; the token is shown ONCE |
//! | `GET /admin/bots` | every bot not deleted, with how its program is doing (below) |
//! | `PATCH /admin/bots/:id {name?, about?, disabled?, clear_webhook?, dm_scope?}` | change, turn off, turn back on; end the program's webhook; `dm_scope` `reply` / `anyone` (D4) |
//! | `POST /admin/bots/:id/token` | a new key; the old one stops at once, and so does its webhook |
//! | `DELETE /admin/bots/:id` | soft delete: the account and its name stay for old messages |
//! | `POST /admin/bots/:id/test` | "Dene": a `ping` update to the program → `{ok, update_id}`; a built-in bot runs NOW → `{ok, kind, outcome, answer?}` |
//! | `PUT`/`GET /admin/bots/:id/builtin` | a built-in bot's configuration (`builtin.rs`) |
//!
//! Each listed bot carries `program_seen_at` (seconds: its last API call or taken webhook),
//! `waiting_since` (ms: the oldest update its program has not been handed), `webhook` (set or
//! not), `webhook_host` (its host alone, never the path or query — decision D5: the owner sees
//! where members' messages go), `dm_scope` (`reply` / `anyone`, decision D4),
//! `webhook_refused` (set, but its URL fails the outbound rule at delivery, so nothing is
//! sent to it — one stored before the rule existed) and `program_silent` — "Programından haber yok": an update has waited 10 minutes and
//! the program has not been seen in that time (BOTS_BUILD §5, R9 decision 4). Otherwise the
//! page shows "last seen". `backlog_full` says the bot holds its 2,000 updates, so nobody's new
//! message is queued and members are told the program is busy, and `unconfirmed` how many of
//! them the program was handed by a poll and never confirmed with `offset` — a program that
//! polls and never confirms is alive, so `program_silent` cannot say it. A built-in bot (`builtin` = `sheet` / `ai`) is never silent — the relay
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
    /// The interface linked to it (`docs/BOT_APP_PLAN.md`): a catalog entry, or none.
    #[serde(default)]
    app_entry: Option<String>,
}

pub async fn list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let rows: Vec<BotRow> = db
        .prepare(
            "SELECT bot_id, name, about, builtin, ai_provider, created_at, disabled_at, program_seen_at,
                    app_entry
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
        webhook_host: Option<String>,
        #[serde(default)]
        dm_scope: Option<String>,
        #[serde(default)]
        backlog_full: bool,
        #[serde(default)]
        unconfirmed: Option<i64>,
        #[serde(default)]
        ai_model: Option<String>,
        #[serde(default)]
        last_ok_at: Option<i64>,
        #[serde(default)]
        last_error: Option<String>,
        /// A hearings bot's audit as counts (`inbox_do/bot/hearings_audit.rs`).
        #[serde(default)]
        hearings: Option<serde_json::Value>,
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
        v["webhook_host"] = state.webhook_host.into();
        v["dm_scope"] = state.dm_scope.into();
        v["backlog_full"] = state.backlog_full.into();
        v["unconfirmed"] = state.unconfirmed.into();
        let silent = row.builtin.is_none() && program_silent(state.waiting_since, row.program_seen_at, now);
        v["program_silent"] = silent.into();
        v["ai_model"] = state.ai_model.into();
        v["last_ok_at"] = state.last_ok_at.into();
        v["last_error"] = state.last_error.into();
        if let Some(h) = state.hearings {
            v["hearings"] = h;
        }
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
    /// `true` ends the program's webhook (D5: the owner sees its host and may end it); the
    /// program's key sets one again. Absent or `false`: unchanged.
    #[serde(default)]
    clear_webhook: bool,
    /// `"reply"` (the default: 1:1 only to a member who wrote lately) or `"anyone"` (D4).
    dm_scope: Option<String>,
    /// The bot's interface (`docs/BOT_APP_PLAN.md`): an app catalog entry id, or `""` to take it
    /// off. Absent: unchanged.
    app_entry: Option<String>,
}

/// The owner's changes the bot's inbox holds: the DM scope set, the webhook ended. Asked before
/// any D1 write, so a change the inbox did not take is refused with the bot's row unchanged;
/// false when one was not taken.
async fn patch_inbox(env: &Env, bot_id: &str, body: &PatchBody) -> bool {
    let mut calls = Vec::new();
    if let Some(scope) = &body.dm_scope {
        calls.push(("/bot/dm-scope", serde_json::json!({ "scope": scope })));
    }
    if body.clear_webhook {
        calls.push(("/bot/webhook", serde_json::json!({ "url": null })));
    }
    for (path, call) in calls {
        let r = super::bot_inbox(env, bot_id, Method::Post, path, Some(call.to_string())).await;
        if !renewal_reached_inbox(r.as_ref().map(|r| r.status_code())) {
            console_warn!("bot change refused bot={bot_id}: the inbox did not take {path}");
            return false;
        }
    }
    true
}

/// An app catalog entry id: the BLAKE3 of a bundle, 64 lowercase hex.
pub(crate) fn is_entry_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Is the catalog keeping entry `id`?
async fn catalog_has(db: &D1Database, id: &str) -> Result<bool> {
    let row: Option<serde_json::Value> = db
        .prepare("SELECT id FROM app_catalog WHERE id = ?1")
        .bind(&[d1_text(id)])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

/// Is this a built-in bot (the relay runs it)?
async fn is_builtin(db: &D1Database, bot_id: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct R {
        builtin: Option<String>,
    }
    let row: Option<R> = db
        .prepare("SELECT builtin FROM bots WHERE bot_id = ?1")
        .bind(&[d1_text(bot_id)])?
        .first(None)
        .await?;
    Ok(row.and_then(|r| r.builtin).is_some())
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
    let nothing = body.name.is_none() && body.about.is_none() && body.disabled.is_none();
    if nothing && !body.clear_webhook && body.dm_scope.is_none() && body.app_entry.is_none() {
        return json_err(400, "bad_request");
    }
    if body.dm_scope.as_deref().is_some_and(|s| !matches!(s, "reply" | "anyone")) {
        return json_err(400, "bad_dm_scope");
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
    if body.app_entry.as_deref().is_some_and(|e| !e.is_empty() && !is_entry_id(e)) {
        return json_err(400, "bad_app");
    }
    let db = ctx.env.d1("DB")?;
    if !live_bot(&db, &bot_id).await? {
        return json_err(404, "not_found");
    }
    if let Some(entry) = body.app_entry.as_deref().filter(|e| !e.is_empty()) {
        // A built-in bot answers by the relay's own rules; it reads no `app` update.
        if is_builtin(&db, &bot_id).await? {
            return json_err(409, "builtin_no_app");
        }
        if !catalog_has(&db, entry).await? {
            return json_err(404, "app_not_in_catalog");
        }
    }
    if !patch_inbox(&ctx.env, &bot_id, &body).await {
        return json_err(502, "inbox_unavailable");
    }
    let now = d1_int(now_secs() as i64);
    let mut stmts = Vec::new();
    if body.clear_webhook {
        stmts.push(db.prepare(super::api::SET_WEBHOOK_SQL).bind(&[d1_text(&bot_id), d1_opt_text(None)])?);
    }
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
    if let Some(entry) = &body.app_entry {
        let entry = (!entry.is_empty()).then_some(entry.as_str());
        stmts.push(
            db.prepare("UPDATE bots SET app_entry = ?2 WHERE bot_id = ?1")
                .bind(&[d1_text(&bot_id), d1_opt_text(entry)])?,
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
    if !stmts.is_empty() {
        db.batch(stmts).await?; // a DM scope alone is the inbox's, written above
    }
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
    // A key is renewed because it leaked, and whoever holds the old one may have pointed the
    // webhook at themselves: members' words would go on being POSTed there, signed with the new
    // key's secret, after the old key stopped working (until 2026-11-18 the renewal only re-signed
    // it). So a renewal ENDS the webhook, in the inbox and in the owner's copy; the program that
    // holds the new key sets it again, and until then updates wait for a poll. The inbox is asked
    // FIRST, and a renewal it did not take is refused with nothing changed — the old key working
    // and its webhook in place, so the owner's next try is a clean one.
    let clear = serde_json::json!({ "url": null });
    let cleared = super::bot_inbox(&ctx.env, &bot_id, Method::Post, "/bot/webhook", Some(clear.to_string())).await;
    if !renewal_reached_inbox(cleared.as_ref().map(|r| r.status_code())) {
        console_warn!("bot key renewal refused bot={bot_id}: the inbox did not clear the webhook");
        return json_err(502, "inbox_unavailable");
    }
    let now = d1_int(now_secs() as i64);
    db.batch(vec![
        db.prepare(token::REVOKE_TOKENS_SQL)
            .bind(&[d1_text(&bot_id), now.clone()])?,
        db.prepare(token::INSERT_TOKEN_SQL)
            .bind(&[d1_text(&token::hash(&secret)), d1_text(&bot_id), now])?,
        db.prepare(super::api::SET_WEBHOOK_SQL)
            .bind(&[d1_text(&bot_id), d1_opt_text(None)])?,
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
    let path = test_path(builtin.and_then(|b| b.builtin).as_deref());
    let call = serde_json::json!({ "who": who });
    let resp = super::bot_inbox(&ctx.env, &bot_id, Method::Post, path, Some(call.to_string())).await?;
    crate::respond::passthrough(resp).await
}

/// Where "Dene" goes for a bot whose `bots.builtin` is `builtin`: every built-in kind to its
/// runner's measured test, a program bot a `ping`. The kind is read by `Kind`'s own
/// deserializer, so a kind added there is routed here without a second list to forget.
pub(crate) fn test_path(builtin: Option<&str>) -> &'static str {
    let builtin_kind = builtin.is_some_and(|b| {
        serde_json::from_value::<super::builtin_rules::Kind>(serde_json::Value::String(b.to_owned())).is_ok()
    });
    if builtin_kind {
        "/bot/builtin-test"
    } else {
        "/bot/ping"
    }
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
        let push = body.find("\"/bot/webhook\"").expect("push");
        let refuse = body.find("inbox_unavailable").expect("refusal");
        let revoke = body.find("REVOKE_TOKENS_SQL").expect("revoke");
        assert!(push < refuse && refuse < revoke, "push, refuse, then revoke");
    }

    /// A renewed key is a leaked one: the webhook whoever held the old key may have set ends with
    /// it, in the inbox (which POSTs) and in the owner's copy (which the list shows), in the same
    /// step — never re-signed and kept, as it was until 2026-11-18.
    #[test]
    fn renewing_a_key_ends_its_webhook_everywhere() {
        let body = fn_body(include_str!("admin.rs"), "renew_token");
        assert!(body.contains("json!({ \"url\": null })"), "the inbox's webhook is cleared");
        assert!(!body.contains("\"secret\""), "nothing is re-signed");
        let batch = &body[body.find("db.batch(").expect("one batch")..];
        for stmt in ["REVOKE_TOKENS_SQL", "INSERT_TOKEN_SQL", "SET_WEBHOOK_SQL"] {
            assert!(batch.contains(stmt), "{stmt} is not in the renewal's batch");
        }
        assert!(batch.contains("d1_opt_text(None)"), "the owner's copy is set to NULL");
        // What the inbox does with it: `deliver_tests.rs`, a_cleared_webhook_is_posted_nothing.
    }

    /// D5: the owner ends a webhook with `clear_webhook: true`; absent, nothing changes. The
    /// listing shows its host, never its path.
    #[test]
    fn the_owner_sees_the_webhooks_host_and_can_end_it() {
        let parse = |s: &str| serde_json::from_str::<super::PatchBody>(s).unwrap();
        assert!(parse(r#"{"clear_webhook": true}"#).clear_webhook);
        assert!(!parse(r#"{"name": "x"}"#).clear_webhook, "an older app's PATCH changes no webhook");
        assert_eq!(parse(r#"{"dm_scope": "anyone"}"#).dm_scope.as_deref(), Some("anyone"));
        let src = include_str!("admin.rs");
        let update = fn_body(src, "update");
        let ask = update.find("patch_inbox(").expect("the inbox is asked");
        let write = update.find("db.batch(stmts)").expect("the D1 write");
        assert!(ask < write, "the inbox first, so a refusal changes nothing");
        assert!(update.contains("SET_WEBHOOK_SQL"), "the owner's copy is cleared too");
        let list = fn_body(src, "list");
        assert!(list.contains("v[\"webhook_host\"]") && list.contains("v[\"dm_scope\"]"));
        let state = include_str!("../messages/inbox_do/bot/mod.rs");
        assert!(state.contains("\"webhook_host\": s.kv_get(\"webhook_url\").and_then(|u| crate::bots::webhook::host_of(&u))"));
    }

    #[test]
    fn every_builtin_kind_is_tested_by_its_runner_and_a_program_is_pinged() {
        // Until 2026-10-27 the hearings kind was pinged: its own test was unreachable, and the
        // core read the ping's answer as `outcome: "sent"`, so the app never marked the rung tried.
        use super::super::builtin_rules::Kind;
        for kind in [Kind::Sheet, Kind::Ai, Kind::Hearings] {
            // Exhaustive on purpose: a new kind does not compile until it is in the list above.
            match kind {
                Kind::Sheet | Kind::Ai | Kind::Hearings => {}
            }
            assert_eq!(super::test_path(Some(kind.as_str())), "/bot/builtin-test", "{kind:?}");
        }
        assert_eq!(super::test_path(None), "/bot/ping", "a program bot");
        assert_eq!(super::test_path(Some("gone")), "/bot/ping", "a kind this relay does not know");
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
