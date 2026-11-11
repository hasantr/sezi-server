//! `GET/POST/PATCH /admin/server-update` (owner) — the owner's side of a self-hosted relay's
//! one-tap update (`crate::server_update`, `docs/SERVER_UPDATE_PLAN.md` §4.2–4.3).
//!
//! - **GET** answers `{updater: {configured, seen_at, alive}, auto, request, request_ttl_ms}`:
//!   whether the box's update timer exists and called in lately, the nightly switch, and the latest
//!   request with how it ended (`request.ok`/`code`, `automatic` for a nightly run).
//! - **POST** `{to_build}` asks the box for that build — the newest, or a kept older one ("go
//!   back"). The relay checks only that it is a build stamp: the box installs nothing the signed
//!   channel does not name. An open request the box has not taken yet is replaced. Refused
//!   `409 server-update/no-updater` (no token configured) or `server-update/updater-offline` (the
//!   box has not called in within 15 min), `400 server-update/bad-build`.
//! - **PATCH** `{auto: "off"|"all"|"security"}` sets the nightly switch (D6: off by default);
//!   `400 server-update/bad-auto`.
//!
//! Every answer but a refusal is the GET's body.

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::server_update::{self as su, Auto};
use worker::*;

async fn owner(req: &Request, env: &Env) -> std::result::Result<String, Response> {
    let user_id = require_active_auth(req, env).await?.user_id;
    require_owner(&user_id, env).await?;
    Ok(user_id)
}

async fn status(env: &Env, db: &D1Database) -> Result<Response> {
    let now = crate::utils::now_ms() as i64;
    su::expire_stale(db, now).await?;
    let configured = su::configured(su::token_of(env).as_deref()).is_some();
    let seen = su::read_seen(db).await;
    let latest = su::row(db, su::LATEST_SQL).await?;
    Response::from_json(&su::status_body(configured, seen, su::read_auto(db).await, latest.as_ref(), now))
}

pub async fn get_server_update(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    status(&ctx.env, &ctx.env.d1("DB")?).await
}

pub async fn request_server_update(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match owner(&req, &ctx.env).await {
        Ok(u) => u,
        Err(resp) => return Ok(resp),
    };
    let to_build = req
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|b| b.get("to_build").and_then(|v| v.as_i64()))
        .filter(|b| su::valid_build(*b));
    let Some(to_build) = to_build else {
        return json_err(400, "server-update/bad-build");
    };
    if su::configured(su::token_of(&ctx.env).as_deref()).is_none() {
        return json_err(409, "server-update/no-updater");
    }
    let db = ctx.env.d1("DB")?;
    let now = crate::utils::now_ms() as i64;
    if !su::alive(su::read_seen(&db).await, now) {
        return json_err(409, "server-update/updater-offline");
    }
    db.batch(vec![
        db.prepare(su::SUPERSEDE_SQL).bind(&[d1_int(now)])?,
        db.prepare(su::INSERT_REQUEST_SQL).bind(&[d1_int(to_build), d1_text(&user_id), d1_int(now)])?,
    ])
    .await?;
    status(&ctx.env, &db).await
}

pub async fn set_server_update_auto(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let auto = req
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|b| b.get("auto").and_then(|v| v.as_str()).and_then(Auto::parse));
    let Some(auto) = auto else {
        return json_err(400, "server-update/bad-auto");
    };
    let db = ctx.env.d1("DB")?;
    su::set_config(&db, su::AUTO_KEY, auto.as_str()).await?;
    status(&ctx.env, &db).await
}
