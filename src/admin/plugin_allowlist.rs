//! The OWNER's writes to the plugin allowlist (Wave C3, `crate::plugin_allowlist`). Every member
//! reads the result on `GET /plugin-policy`; each answer here is that same body, so the owner's
//! screen refreshes in one round trip.
//!
//! - **PUT /admin/plugin-policy/mode** `{"mode":"open"|"allowlist"}` — `400
//!   plugin/policy-bad-mode` for any other word. `open` deletes the key (the default).
//! - **POST /admin/plugin-allowlist** `{publisher_key, app_id?, max_caps:[…], label}` or
//!   `{code_hash, max_caps:[…], label}` — checked by `sezi_plugin_fmt::allowlist::check_new_row`
//!   (`400 plugin/allowlist-bad-row`), at most `MAX_ROWS` (`400 plugin/allowlist-full`). The same
//!   rule again refreshes its ceiling and label.
//! - **DELETE /admin/plugin-allowlist/:id** — a missing id is a no-op.
//!
//! Owner only (`require_owner`): which third-party code may run on a server is the owner's call
//! (decision D1); an admin keeps the per-plugin switch (`POST /admin/plugin-policy`).

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::plugin_allowlist::{COUNT_SQL, DELETE_SQL, MODE_KEY, UPSERT_SQL};
use crate::respond::json_err;
use sezi_plugin_fmt::allowlist::{self as rule, AllowRule, Mode};
use worker::*;

/// The owner's id, or the refusal to answer with.
async fn owner(req: &Request, env: &Env) -> std::result::Result<String, Response> {
    let user_id = require_active_auth(req, env).await?.user_id;
    require_owner(&user_id, env).await?;
    Ok(user_id)
}

async fn answer(db: &D1Database) -> Result<Response> {
    Response::from_json(&super::plugin_policy::policy_body(db).await)
}

pub async fn set_mode(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let body: serde_json::Value = req.json().await.unwrap_or_default();
    let mode = match body.get("mode").and_then(|m| m.as_str()).map(Mode::parse_write) {
        Some(Ok(m)) => m,
        _ => return json_err(400, rule::BAD_MODE),
    };
    let db = ctx.env.d1("DB")?;
    // Both words are stored (until 2026-11-08 `open` deleted the key): the owner's `open` must
    // outlive the seed a re-claim writes (`SEED_FRESH_MODE_SQL`). Every build that reads the key
    // reads `open` as open.
    db.prepare(
        "INSERT INTO server_config (key, value, created_at) VALUES (?, ?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(&[
        d1_text(MODE_KEY),
        d1_text(mode.as_str()),
        d1_int(crate::utils::now_secs() as i64),
    ])?
    .run()
    .await?;
    answer(&db).await
}

pub async fn add_row(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match owner(&req, &ctx.env).await {
        Ok(id) => id,
        Err(resp) => return Ok(resp),
    };
    let body: serde_json::Value = req.json().await.unwrap_or_default();
    let row = match rule::check_new_row(&body) {
        Ok(r) => r,
        Err(code) => return json_err(400, code),
    };
    let db = ctx.env.d1("DB")?;
    #[derive(serde::Deserialize)]
    struct Count {
        n: i64,
    }
    let n = db.prepare(COUNT_SQL).first::<Count>(None).await?.map(|c| c.n).unwrap_or(0);
    if n >= rule::MAX_ROWS as i64 {
        return json_err(400, rule::LIST_FULL);
    }
    let (key, app, hash) = match &row.rule {
        AllowRule::Publisher { key_id, app_id } => (Some(key_id.as_str()), app_id.as_deref(), None),
        AllowRule::Hash { code_hash } => (None, None, Some(code_hash.as_str())),
    };
    let caps = serde_json::to_string(&row.max_caps).unwrap_or_else(|_| "[]".into());
    db.prepare(UPSERT_SQL)
        .bind(&[
            d1_opt_text(key),
            d1_opt_text(app),
            d1_opt_text(hash),
            d1_text(&caps),
            d1_text(&row.label),
            d1_text(&user_id),
            d1_int(crate::utils::now_ms() as i64),
        ])?
        .run()
        .await?;
    answer(&db).await
}

pub async fn remove_row(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let Some(id) = ctx.param("id").and_then(|p| p.parse::<i64>().ok()) else {
        return json_err(400, "bad_request");
    };
    let db = ctx.env.d1("DB")?;
    db.prepare(DELETE_SQL).bind(&[d1_int(id)])?.run().await?;
    answer(&db).await
}
