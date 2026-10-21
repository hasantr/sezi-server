//! `PATCH /admin/sfu-config` — group calls through Cloudflare Realtime SFU, owner self-service
//! (the `turn_config.rs` twin; board R6-Group-SFU frames 5, 6 and 12).
//!
//! SECURITY CONTRACT (as turn_config.rs):
//! - **OWNER-ONLY**: the token opens sessions on the owner's Cloudflare account and spends its
//!   budget, and the cap decides how much — admin is not enough.
//! - **WRITE-ONLY** for the token: the answer carries `sfu_configured` and never a value.
//! - A NEW app pair is tried before it is saved: one session is opened with it (Cloudflare bills
//!   nothing for a session with no tracks); a refusal answers `sfu_test_failed` and stores nothing,
//!   so a mistyped token shows here and not in the first lesson.
//!
//! Body: `{app_id?, app_token?, route?, cap_gb?}` — absent keeps, `""` clears (app id/token), a
//! value sets. `route` ∈ `server` | `crowded` | `direct`; `cap_gb` ≥ 0 (`0` = no cap).

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::sfu::config::{self, KEY_APP_ID, KEY_APP_TOKEN, KEY_CAP_GB, KEY_ROUTE};
use crate::sfu::policy::{credential_ok, OwnerRoute};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct Body {
    app_id: Option<String>,
    app_token: Option<String>,
    route: Option<String>,
    cap_gb: Option<i64>,
}

pub async fn set_sfu_config(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: Body = req.json().await.unwrap_or_default();
    if body.app_id.is_none() && body.app_token.is_none() && body.route.is_none() && body.cap_gb.is_none() {
        return json_err(400, "bad_request");
    }
    let trimmed = |v: &Option<String>| v.as_deref().map(str::trim).map(str::to_string);
    let (app_id, app_token) = (trimmed(&body.app_id), trimmed(&body.app_token));
    if app_id.as_deref().is_some_and(|v| !v.is_empty() && !credential_ok(v, 128))
        || app_token.as_deref().is_some_and(|v| !v.is_empty() && !credential_ok(v, 512))
    {
        return json_err(400, "bad_request");
    }
    if body.route.as_deref().is_some_and(|r| !OwnerRoute::valid(r.trim())) {
        return json_err(400, "bad_route");
    }
    if body.cap_gb.is_some_and(|c| !(0..=1_000_000).contains(&c)) {
        return json_err(400, "bad_cap");
    }

    let db = ctx.env.d1("DB")?;
    // Try the pair the server WILL have once this is saved — a new half beside the stored other.
    let setting_app = app_id.as_deref().is_some_and(|v| !v.is_empty())
        || app_token.as_deref().is_some_and(|v| !v.is_empty());
    if setting_app {
        let id = match app_id.as_deref().filter(|v| !v.is_empty()) {
            Some(v) => Some(v.to_string()),
            None => config::read(&db, KEY_APP_ID).await,
        };
        let token = match app_token.as_deref().filter(|v| !v.is_empty()) {
            Some(v) => Some(v.to_string()),
            None => config::read(&db, KEY_APP_TOKEN).await,
        };
        if let (Some(id), Some(token)) = (id, token) {
            if crate::sfu::cf::new_session(&id, &token).await.ok().flatten().is_none() {
                return json_err(400, "sfu_test_failed");
            }
        }
    }

    apply(&db, KEY_APP_ID, app_id).await?;
    apply(&db, KEY_APP_TOKEN, app_token).await?;
    apply(&db, KEY_ROUTE, body.route.map(|r| r.trim().to_string())).await?;
    apply(&db, KEY_CAP_GB, body.cap_gb.map(|c| c.to_string())).await?;

    Response::from_json(&serde_json::json!({
        "sfu_configured": config::is_configured(&ctx.env).await,
        "route": config::route(&ctx.env, &db).await.as_str(),
        "cap_gb": config::cap_gb(&ctx.env, &db).await,
    }))
}

/// One `server_config` key: absent → keep, `""` → delete, else upsert (as turn_config.rs).
async fn apply(db: &D1Database, key: &str, new: Option<String>) -> Result<()> {
    let Some(raw) = new else { return Ok(()) };
    let t = raw.trim();
    if t.is_empty() {
        db.prepare("DELETE FROM server_config WHERE key = ?").bind(&[d1_text(key)])?.run().await?;
        return Ok(());
    }
    db.prepare(
        "INSERT INTO server_config (key, value, created_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(&[d1_text(key), d1_text(t), d1_int(now_secs() as i64)])?
    .run()
    .await?;
    Ok(())
}
