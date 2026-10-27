//! The owner's built-in bot routes (docs/BOTS_HELPER_PLAN.md, "Relay — owner routes").
//!
//! | Route | What |
//! |---|---|
//! | `PUT /admin/bots/:id/builtin` | set `sheet` / `ai` / `hearings`, or `kind: null` for program mode → `{ok, sheet_secret?, has_api_key?}` |
//! | `GET /admin/bots/:id/builtin` | the configuration WITHOUT `api_key`, with `has_api_key` |
//!
//! The configuration is checked here (`builtin_rules::validate`) and kept in the bot's inbox,
//! with its secrets; D1 holds only what a listing needs — `bots.builtin`, `bots.ai_provider` and
//! `bots.ai_geo` — and loses the webhook, which a built-in runner replaces. The measured test is
//! `admin::test`, which hands a built-in bot to its inbox's `/bot/builtin-test`.

use super::builtin_rules::{self, PutBody};
use crate::d1util::{d1_opt_text, d1_text};
use crate::respond::json_err;
use worker::*;

/// Bind: room id.
pub(crate) const ROOM_EXISTS_SQL: &str = "SELECT id FROM groups WHERE id = ?1 LIMIT 1";

/// Bind: bot_id, builtin, ai_provider, ai_geo.
pub(crate) const SET_BUILTIN_SQL: &str =
    "UPDATE bots SET builtin = ?2, ai_provider = ?3, ai_geo = ?4, webhook_url = NULL WHERE bot_id = ?1";

/// The bot's id from the path once the owner and the bot are both checked, or the refusal.
async fn owned_bot(req: &Request, ctx: &RouteContext<()>) -> Result<std::result::Result<String, Response>> {
    if let Err(resp) = super::admin::owner(req, &ctx.env).await {
        return Ok(Err(resp));
    }
    let Some(bot_id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request").map(Err);
    };
    if !super::admin::live_bot(&ctx.env.d1("DB")?, &bot_id).await? {
        return json_err(404, "not_found").map(Err);
    }
    Ok(Ok(bot_id))
}

pub async fn put(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let bot_id = match owned_bot(&req, &ctx).await? {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };
    let Ok(body) = req.json::<PutBody>().await else {
        return json_err(400, "bad_request");
    };
    let checked = match builtin_rules::validate(body, builtin_rules::allow_lan(&ctx.env)) {
        Ok(c) => c,
        Err(code) => return json_err(400, code),
    };
    let kind = checked.config.as_ref().map(|c| c.kind.as_str());
    let provider = checked.config.as_ref().and_then(|c| c.model_provider()).map(|p| p.as_str());
    let geo = checked.config.as_ref().and_then(|c| c.model_geo()).map(|g| g.as_str());
    let db = ctx.env.d1("DB")?;
    // The hearings bot's room must exist (decision 2): a typo would lock every member out.
    if let Some(room) = checked.config.as_ref().and_then(|c| c.hearings.as_ref()).map(|h| h.allowed_room.as_str()) {
        let found = db.prepare(ROOM_EXISTS_SQL).bind(&[d1_text(room)])?.first::<serde_json::Value>(None).await?;
        if found.is_none() {
            return json_err(400, "builtin/hearings-room");
        }
    }
    let call = serde_json::json!({ "config": checked.config, "api_key": checked.api_key });
    let mut resp = super::bot_inbox(&ctx.env, &bot_id, Method::Post, "/bot/builtin", Some(call.to_string())).await?;
    if resp.status_code() != 200 {
        return crate::respond::passthrough(resp).await;
    }
    let answer: serde_json::Value = resp.json().await?;
    db.prepare(SET_BUILTIN_SQL)
        .bind(&[d1_text(&bot_id), d1_opt_text(kind), d1_opt_text(provider), d1_opt_text(geo)])?
        .run()
        .await?;
    // The members' disclosure chip comes from `GET /bots` (`ai_provider`), re-read on a
    // `contact_update`: without this an AI bot's chat showed the plain bot chip until each
    // member's app restarted (lab, 2026-10-26).
    super::provision::nudge_humans(&ctx.env, &db).await;
    Response::from_json(&answer)
}

pub async fn get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let bot_id = match owned_bot(&req, &ctx).await? {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };
    let resp = super::bot_inbox(&ctx.env, &bot_id, Method::Get, "/bot/builtin", None).await?;
    crate::respond::passthrough(resp).await
}
