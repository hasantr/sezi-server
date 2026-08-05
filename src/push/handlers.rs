use crate::auth::middleware::{device_revoked, require_auth, require_auth_device};
use crate::d1util::{d1_int, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RegisterBody {
    fcm_token: String,
    device_id: String,
    platform: String, // "android" | "ios"
}

pub async fn register(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, claim_dev) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    let body: RegisterBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.fcm_token.len() < 20
        || body.fcm_token.len() > 4096
        || body.device_id.is_empty()
        || body.device_id.len() > 128
        || (body.platform != "android" && body.platform != "ios")
    {
        return json_err(400, "bad_request");
    }
    // HARDENING (2026-06-25, Codex HIGH + audit #10): the `device_id` claim in the token
    // MUST match body.device_id, so a user cannot register a push token on behalf of ANOTHER
    // device using their own identity (device impersonation plus waking the wrong device).
    // This used to be skipped for a token carrying no claim; there is no such token.
    if claim_dev != body.device_id {
        return json_err(403, "device_mismatch");
    }
    // A revoked device may not register a push token. FAIL-CLOSED (W7, flagged by Codex
    // 2026-07-02): this used to be `.unwrap_or(false)`, i.e. a D1 error was read as "not
    // revoked" and the register was ALLOWED (fail-OPEN). That contradicted the fail-closed
    // stance of the send path (`messages::handlers::notify_recipient`'s `?`) and the WS upgrade
    // (`lib.rs`'s `sync_ws` route,
    // Err→503): during a D1 error window a revoked device could register a push token and
    // keep receiving wakes. Now it is at fail-closed parity with both.
    //
    // 401, not 403. This answered 403 while every other site raising `device_revoked` answers
    // 401 — `auth/refresh.rs`, `auth/relogin.rs`, `devices/handlers.rs`, `keys/handlers.rs`
    // (replenish and rotate), `messages/handlers.rs`, `plugin_log.rs`, `plugin_blob.rs` and
    // `groups.rs`. One condition must not have two statuses: a client keys its "this device is
    // finished, stop retrying and re-auth" branch on the status, and the odd one out reads as
    // "you are authenticated but not allowed to do THIS", which is the wrong instruction.
    match device_revoked(&ctx.env, &user_id, &body.device_id).await {
        Ok(true) => return json_err(401, "device_revoked"),
        Ok(false) => {}
        Err(_) => return json_err(503, "revoke_check_unavailable"),
    }
    let now = now_secs();
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, device_id) DO UPDATE SET
            fcm_token = excluded.fcm_token,
            platform = excluded.platform,
            last_seen_at = excluded.last_seen_at",
    )
    .bind(&[
        d1_text(&user_id),
        d1_text(&body.device_id),
        d1_text(&body.fcm_token),
        d1_text(&body.platform),
        d1_int(now as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;
    no_content()
}

#[derive(Deserialize)]
struct UnregisterBody {
    device_id: String,
}

pub async fn unregister(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let body: UnregisterBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.device_id.is_empty() || body.device_id.len() > 128 {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM push_tokens WHERE user_id = ? AND device_id = ?")
        .bind(&[d1_text(&user_id), d1_text(&body.device_id)])?
        .run()
        .await?;
    no_content()
}
