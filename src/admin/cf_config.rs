//! `PATCH /admin/cf-config` — Cloudflare Analytics credentials, owner
//! self-service ("every owner administers their own server from the app";
//! CLI-free setup: instead of `wrangler secret put`, the owner types the token
//! into the Sezi app).
//!
//! SECURITY CONTRACT (the reason this file exists):
//! - **OWNER-ONLY**: `require_owner` — admin is NOT enough. A CF API token is a
//!   strong credential, so only the server's owner may set or change it.
//! - **WRITE-ONLY**: the token is only ever written here; no endpoint — this one
//!   included — returns its value. The response and `/admin/stats` carry only
//!   `cf_configured: bool` (present or not), so the leak surface is zero.
//! - Storage: D1 `server_settings` (encrypted at rest by CF). The worker reads it
//!   in plaintext to build the Bearer header — it is operational config and
//!   cannot be encrypted with a key we do not hold. It is NOT E2E content, so the
//!   server-blind principle still holds (the owner's own token, on their server).
//! - Read chain lives in cf_analytics.rs: per key, **env secret FIRST, D1 second**
//!   (an env-set value wins); neither present → self-report (FAIL-OPEN, which is
//!   today's behaviour).

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_opt_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct CfConfigBody {
    /// Convention (same as update_settings): field ABSENT → keep current value;
    /// `""` (empty after trim) → NULL (clear, falling back to self-report);
    /// non-empty → set.
    cf_api_token: Option<String>,
    cf_account_id: Option<String>,
}

/// Field validation: sane length, no control characters. A CF token is ~40 chars
/// and an account id 32 hex chars, so 200 is generous headroom — this guards
/// against header injection and oversized-input DoS.
fn field_ok(s: &str) -> bool {
    s.len() <= 200 && !s.chars().any(|c| c.is_control())
}

/// Effective value: absent field keeps the current one; empty string → NULL
/// (clear); otherwise the trimmed new value.
fn effective(new: Option<String>, cur: Option<String>) -> Option<String> {
    match new {
        None => cur,
        Some(v) => {
            let t = v.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
    }
}

pub async fn set_cf_config(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // OWNER-ONLY, NOT require_admin: a CF token is a strong credential, so only
    // the server owner manages it (same authority class as set_role /
    // transfer_ownership).
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: CfConfigBody = req.json().await.unwrap_or_default();
    if body.cf_api_token.is_none() && body.cf_account_id.is_none() {
        return json_err(400, "bad_request");
    }
    if body.cf_api_token.as_deref().is_some_and(|v| !field_ok(v))
        || body.cf_account_id.as_deref().is_some_and(|v| !field_ok(v))
    {
        return json_err(400, "bad_request");
    }

    let db = ctx.env.d1("DB")?;
    // Read current values so an absent field is preserved (update_settings
    // pattern). NOTE: this SELECT exists only to preserve; the values are never
    // written into any response.
    #[derive(Deserialize)]
    struct CurRow {
        cf_api_token: Option<String>,
        cf_account_id: Option<String>,
    }
    let cur: Option<CurRow> = db
        .prepare("SELECT cf_api_token, cf_account_id FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await?;
    let (cur_token, cur_account) = cur
        .map(|c| (c.cf_api_token, c.cf_account_id))
        .unwrap_or((None, None));
    let new_token = effective(body.cf_api_token, cur_token);
    let new_account = effective(body.cf_account_id, cur_account);

    // Upsert, update_settings pattern. The INSERT arm (no row at all — in
    // practice unreachable thanks to the 0003 seed) leaves the other columns at
    // their schema DEFAULTs; the ON CONFLICT arm touches only the cf columns and
    // never name/retention.
    let now = now_secs();
    db.prepare(
        "INSERT INTO server_settings (id, cf_api_token, cf_account_id, updated_at)
         VALUES (1, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            cf_api_token = excluded.cf_api_token,
            cf_account_id = excluded.cf_account_id,
            updated_at = excluded.updated_at",
    )
    .bind(&[
        d1_opt_text(new_token.as_deref()),
        d1_opt_text(new_account.as_deref()),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    // WRITE-ONLY response: the token VALUE is never returned, only "is it
    // configured now" (env secret OR D1). Consistent with the env-first chain:
    // still true after clearing D1 if an env token exists.
    let cf_configured = crate::cf_analytics::is_configured(&ctx.env).await;
    Response::from_json(&serde_json::json!({ "cf_configured": cf_configured }))
}
