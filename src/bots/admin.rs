//! The owner's bot surface (docs/BOTS_BUILD.md §2.5, board R9-Bots-Server).
//!
//! | Route | What |
//! |---|---|
//! | `POST /admin/bots {name, about?}` | create → `{bot_id, token}`; the token is shown ONCE |
//! | `GET /admin/bots` | every bot not deleted |
//! | `PATCH /admin/bots/:id {name?, about?, disabled?}` | change, turn off, turn back on |
//! | `POST /admin/bots/:id/token` | a new key; the old one stops at once |
//! | `DELETE /admin/bots/:id` | soft delete: the account and its name stay for old messages |
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

/// The owner's user id, or the refusal to send.
async fn owner(req: &Request, env: &Env) -> std::result::Result<String, Response> {
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
            "SELECT bot_id, name, about, builtin, created_at, disabled_at, program_seen_at
               FROM bots WHERE deleted_at IS NULL ORDER BY created_at, bot_id",
        )
        .all()
        .await?
        .results()?;
    Response::from_json(&serde_json::json!({ "bots": rows }))
}

#[derive(Deserialize, Default)]
struct PatchBody {
    name: Option<String>,
    about: Option<String>,
    disabled: Option<bool>,
}

/// A bot that exists and is not deleted.
async fn live_bot(db: &D1Database, bot_id: &str) -> Result<bool> {
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
    // Its sessions, updates and outbox go with the inbox; a failure here leaves an inbox no
    // token can reach any more, which the next delete attempt (404) cannot retry — so log it.
    if let Err(e) = crate::realtime::purge_account_inbox(&ctx.env, &bot_id).await {
        console_warn!("bot inbox purge failed bot={bot_id}: {e:?}");
    }
    provision::nudge_humans(&ctx.env, &db).await;
    no_content()
}
