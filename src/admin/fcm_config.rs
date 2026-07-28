//! `PATCH /admin/fcm-config` — FCM push setup, owner self-service (twin of the
//! cf_config.rs pattern; "every owner administers their own server from the
//! app"). First-run setup is kept minimal — FCM was dropped from the template —
//! so the owner enables push LATER from the Sezi app: create a free Firebase
//! project, paste the service-account JSON, no `wrangler secret put` knowledge
//! required.
//!
//! SECURITY CONTRACT (identical to cf_config.rs):
//! - **OWNER-ONLY**: `require_owner` — admin is NOT enough. A service account
//!   carries a private key, so only the server's owner may set or change it.
//! - **WRITE-ONLY**: the values are only ever written here; no endpoint — this
//!   one included — returns them. The response and `/admin/stats` carry only
//!   `fcm_configured: bool`, so the leak surface is zero.
//! - Storage: D1 `server_config` (0025 key-value; encrypted at rest by CF). Same
//!   trade-off as cf_config: the worker must read it in plaintext to sign the
//!   Google OAuth assertion, and it cannot be encrypted with a key we do not
//!   hold. It is the owner's OWN Firebase project on their OWN server, and it is
//!   not E2E content (push is a contentless wake — leaking the key still does not
//!   reveal message content). For an owner who moves these into env secrets, env
//!   ALWAYS wins.
//! - Read chain lives in push/fcm.rs: per key, **env FIRST, D1 second** (an
//!   env-set value wins, keeping our prod path bit-identical); with neither, a
//!   direct FCM send is a silent no-op (FAIL-OPEN "not configured"), and delivery
//!   falls back to the shared push relay.

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct FcmConfigBody {
    /// Convention (cf_config / update_settings pattern): field ABSENT → keep
    /// current value; `""` (empty after trim) → DELETE the row (clear, so direct
    /// push goes back to a no-op); non-empty → set.
    fcm_project_id: Option<String>,
    fcm_service_account: Option<String>,
}

/// Project-id validation. Firebase project ids are short ([a-z0-9-], 6-30
/// chars), so 100 is generous headroom; control characters are rejected because
/// the value is interpolated into the FCM send URL
/// (`fcm.googleapis.com/v1/projects/{id}/messages:send`) — injection and
/// oversized-input DoS guard.
fn project_id_ok(s: &str) -> bool {
    s.len() <= 100 && !s.chars().any(|c| c.is_control())
}

/// Service-account validation: ≤16KB (a real SA JSON is ~2.4KB, so this is
/// generous headroom and a DoS guard), valid JSON, and both fields fcm.rs
/// ACTUALLY uses (`ServiceAccount { client_email, private_key }`) present as
/// non-empty strings. The wrong file (e.g. google-services.json, which has
/// neither field) is rejected EARLY so the owner sees it in the panel instead of
/// push dying silently in the field.
fn service_account_ok(s: &str) -> bool {
    if s.len() > 16 * 1024 {
        return false;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return false;
    };
    let has_str = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .is_some_and(|x| !x.trim().is_empty())
    };
    has_str("client_email") && has_str("private_key")
}

pub async fn set_fcm_config(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // OWNER-ONLY, NOT require_admin: a service account is a strong credential (a
    // Google private key), so only the server owner manages it (same authority
    // class as cf-config).
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: FcmConfigBody = req.json().await.unwrap_or_default();
    if body.fcm_project_id.is_none() && body.fcm_service_account.is_none() {
        return json_err(400, "bad_request");
    }
    // Validate only non-empty values — "" (clear) is always accepted.
    if let Some(v) = body.fcm_project_id.as_deref() {
        let t = v.trim();
        if !t.is_empty() && !project_id_ok(t) {
            return json_err(400, "bad_request");
        }
    }
    if let Some(v) = body.fcm_service_account.as_deref() {
        let t = v.trim();
        if !t.is_empty() && !service_account_ok(t) {
            return json_err(400, "bad_request");
        }
    }

    let db = ctx.env.d1("DB")?;
    apply(&db, "fcm_project_id", body.fcm_project_id).await?;
    apply(&db, "fcm_service_account", body.fcm_service_account).await?;

    // WRITE-ONLY response: the values are NEVER returned, only "can this server
    // push at all". Careful — `fcm::is_configured` is true when project-id AND
    // service-account are both present (env or D1, env-first so clearing D1 still
    // reports true if env is set) OR when a push relay URL resolves. The relay
    // falls back to a built-in default unless it is explicitly `off`, so this flag
    // does NOT mean "the owner's own FCM credentials are installed".
    // `fcm_configured` stays as it was — "will a push go out at all" — because that is what a health
    // indicator needs. `fcm_mode` answers the different question this screen is actually asking:
    // own credentials, the shared relay (the default, which the owner did NOT set up), or nothing.
    let mode = crate::push::fcm::mode(&ctx.env).await;
    Response::from_json(&serde_json::json!({
        "fcm_configured": mode.can_push(),
        "fcm_mode": mode.as_str(),
    }))
}

/// Apply a single key. Because `server_config` is key-value, cf_config's
/// "SELECT the current row to preserve it" dance is unnecessary: absent field →
/// leave the row alone; "" → DELETE (clear); non-empty → upsert (`ON CONFLICT`
/// updates only the value, so created_at stays the first-write stamp).
async fn apply(db: &D1Database, key: &str, new: Option<String>) -> Result<()> {
    let Some(raw) = new else {
        return Ok(()); // field absent → keep current value
    };
    let t = raw.trim();
    if t.is_empty() {
        db.prepare("DELETE FROM server_config WHERE key = ?")
            .bind(&[d1_text(key)])?
            .run()
            .await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_id_validation() {
        assert!(project_id_ok("sezi-481e9"));
        assert!(project_id_ok("a"));
        // Control character → reject (URL-injection guard).
        assert!(!project_id_ok("abc\ndef"));
        assert!(!project_id_ok(&"x".repeat(101)));
        assert!(project_id_ok(&"x".repeat(100)));
    }

    #[test]
    fn service_account_validation() {
        // Valid: both fields fcm.rs uses are populated.
        assert!(service_account_ok(
            r#"{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"}"#
        ));
        // Not JSON → reject (the owner finds out early, in the panel).
        assert!(!service_account_ok("bu json degil"));
        // Wrong file (google-services.json has no client_email/private_key) → reject.
        assert!(!service_account_ok(r#"{"project_info":{"project_id":"x"}}"#));
        // Fields present but empty → reject.
        assert!(!service_account_ok(
            r#"{"client_email":"","private_key":""}"#
        ));
        // private_key missing → reject.
        assert!(!service_account_ok(r#"{"client_email":"a@b.c"}"#));
        // Over 16KB → reject (DoS guard).
        let big = format!(
            r#"{{"client_email":"a@b.c","private_key":"{}"}}"#,
            "k".repeat(17 * 1024)
        );
        assert!(!service_account_ok(&big));
    }
}
