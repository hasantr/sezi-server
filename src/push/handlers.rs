use crate::auth::middleware::{device_revoked, require_auth_device};
use crate::d1util::{d1_int, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use super::style::WakeStyle;

/// A device's token, registered or refreshed. A NEW token loses the relay mark of the old one
/// (K8, `wake.rs`): it may be another app's — the device moved between the published app and an
/// own build — and the next wake asks Google about it. The same token keeps its mark: Google's
/// answer about it does not change while the project does not.
///
/// Every register states how the device is woken (`style.rs`), so a device whose Autostart was
/// turned on goes back to `data` at its next register; a client that sends no `wake` registers
/// `data`, which is what every token was before.
pub(crate) const REGISTER_SQL: &str =
    "INSERT INTO push_tokens
        (user_id, device_id, fcm_token, platform, created_at, last_seen_at, wake, wake_lang)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, device_id) DO UPDATE SET
        relay_project = CASE WHEN push_tokens.fcm_token = excluded.fcm_token
                             THEN push_tokens.relay_project ELSE NULL END,
        fcm_token = excluded.fcm_token,
        platform = excluded.platform,
        last_seen_at = excluded.last_seen_at,
        wake = excluded.wake,
        wake_lang = excluded.wake_lang";

#[derive(Deserialize)]
struct RegisterBody {
    fcm_token: String,
    device_id: String,
    platform: String, // "android" | "ios"
    /// "data" (absent = data) | "visible": the device cannot be woken by a data push.
    #[serde(default)]
    wake: Option<String>,
    /// The visible notification's language, "tr" | "en".
    #[serde(default)]
    lang: Option<String>,
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
    let style = WakeStyle::parse(body.wake.as_deref(), body.lang.as_deref());
    let db = ctx.env.d1("DB")?;
    db.prepare(REGISTER_SQL)
    .bind(&[
        d1_text(&user_id),
        d1_text(&body.device_id),
        d1_text(&body.fcm_token),
        d1_text(&body.platform),
        d1_int(now as i64),
        d1_int(now as i64),
        d1_text(style.column()),
        style.lang_column().map(d1_text).unwrap_or(JsValue::NULL),
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
    let (user_id, claim_dev) = match require_auth_device(&req, &ctx.env) {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let body: UnregisterBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.device_id.is_empty() || body.device_id.len() > 128 {
        return json_err(400, "bad_request");
    }
    // A device unregisters ITS OWN token, as `register` registers its own. Bound to the user
    // alone, a linked device could delete the PRIMARY's token and silence both the relay's urgent
    // takeover nudge and the drain's alert for the whole six-hour hold
    // (docs/PRIMARY_DEVICE_LOSS_PLAN.md §7).
    if !may_unregister(&claim_dev, &body.device_id) {
        return json_err(403, "device_mismatch");
    }
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM push_tokens WHERE user_id = ? AND device_id = ?")
        .bind(&[d1_text(&user_id), d1_text(&body.device_id)])?
        .run()
        .await?;
    no_content()
}

/// May the device the token names unregister `body_device`'s push token? Only its own.
pub(crate) fn may_unregister(claim_dev: &str, body_device: &str) -> bool {
    !claim_dev.is_empty() && claim_dev == body_device
}

#[cfg(test)]
mod unregister_tests {
    use super::may_unregister;

    #[test]
    fn a_device_unregisters_its_own_token_and_no_other() {
        assert!(may_unregister("dev-l", "dev-l"), "its own");
        assert!(!may_unregister("dev-l", "dev-p"), "a linked device cannot silence the primary");
        assert!(!may_unregister("", ""), "no claim, nothing");
    }

    /// The handler takes the token's device claim and checks it before the DELETE.
    #[test]
    fn unregister_checks_the_device_claim_before_deleting() {
        let src = include_str!("handlers.rs");
        let start = src.find(concat!("pub async fn ", "unregister(")).unwrap();
        let body = &src[start..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains(concat!("require_auth_", "device(")));
        let check = body.find(concat!("may_", "unregister(&claim")).expect("the claim check");
        let delete = body.find(concat!("DELETE FROM ", "push_tokens")).expect("the delete");
        assert!(check < delete);
    }
}
