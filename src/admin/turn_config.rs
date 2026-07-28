//! `PATCH /admin/turn-config` — TURN setup, owner self-service (the `fcm_config.rs` twin).
//!
//! Calls between peers on DIFFERENT networks need a TURN relay, and the worker cannot be one — it
//! has no raw UDP — so it issues short-lived credentials against CF Realtime TURN. Until now the key
//! pair could only arrive as an env secret, which put a beta-blocking feature behind `wrangler
//! secret put` and shell access to whatever box the relay runs on. That is not a bar an ordinary
//! self-hoster clears, and it is the same bar FCM already removed.
//!
//! SECURITY CONTRACT (identical to fcm_config.rs):
//! - **OWNER-ONLY**: `require_owner` — admin is NOT enough. The API token can mint TURN
//!   credentials and therefore spend the owner's Cloudflare budget, so only the owner sets it.
//! - **WRITE-ONLY**: the values are only ever written here. No endpoint — this one included —
//!   returns them; the response and `/admin/stats` carry `turn_configured: bool` and nothing else.
//! - Storage: D1 `server_config` (the 0025 key-value table, encrypted at rest by CF). The worker
//!   must read it in plaintext to call the CF TURN API, so it cannot be encrypted with a key we do
//!   not hold — the same trade-off, and the same reasoning, as the FCM service account. Note what
//!   this credential is NOT: it mints relay credentials, and relayed media stays end-to-end
//!   encrypted, so leaking it costs money and reveals no message content.
//! - Read chain lives in `turn.rs`: per key, **env FIRST, D1 second**, so an owner who prefers env
//!   secrets keeps today's path and the app cannot override it.

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct TurnConfigBody {
    /// Convention (the fcm_config / update_settings pattern): field ABSENT → keep the current
    /// value; `""` (empty after trim) → DELETE the row, so TURN goes back to `disabled` and calls
    /// fall back to direct/STUN; non-empty → set.
    turn_key_id: Option<String>,
    turn_api_token: Option<String>,
}

/// Key-id validation. A CF TURN key id is a 32-character hex string; the bound is deliberately
/// looser than that so a format change on Cloudflare's side does not lock the owner out, while
/// still rejecting control characters — the value is interpolated into the CF API URL
/// (`/v1/turn/keys/{id}/credentials/generate-ice-servers`), so this is an injection guard as much
/// as a sanity check.
fn key_id_ok(s: &str) -> bool {
    s.len() <= 128 && !s.chars().any(|c| c.is_control())
}

/// Token validation: bounded length and no control characters. It travels in an `Authorization`
/// header, and a newline there would let a pasted value forge additional headers.
fn api_token_ok(s: &str) -> bool {
    s.len() <= 512 && !s.chars().any(|c| c.is_control())
}

pub async fn set_turn_config(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // OWNER-ONLY, not require_admin: this token spends the owner's Cloudflare budget.
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: TurnConfigBody = req.json().await.unwrap_or_default();
    if body.turn_key_id.is_none() && body.turn_api_token.is_none() {
        return json_err(400, "bad_request");
    }
    // Validate only non-empty values — "" (clear) is always accepted.
    if let Some(v) = body.turn_key_id.as_deref() {
        let t = v.trim();
        if !t.is_empty() && !key_id_ok(t) {
            return json_err(400, "bad_request");
        }
    }
    if let Some(v) = body.turn_api_token.as_deref() {
        let t = v.trim();
        if !t.is_empty() && !api_token_ok(t) {
            return json_err(400, "bad_request");
        }
    }

    let db = ctx.env.d1("DB")?;
    apply(&db, "turn_key_id", body.turn_key_id).await?;
    apply(&db, "turn_api_token", body.turn_api_token).await?;

    // WRITE-ONLY response: never the values, only whether a credential can now be issued. Note it
    // reports on the resolved chain, so an owner who has the pair in env secrets sees `true` even
    // after clearing the D1 rows — which is correct, because env wins.
    Response::from_json(&serde_json::json!({
        "turn_configured": crate::turn::is_configured(&ctx.env).await,
    }))
}

/// Apply a single key. `server_config` is key-value, so: absent field → leave the row alone; `""` →
/// DELETE (clear); non-empty → upsert, updating only the value so `created_at` stays the first-write
/// stamp.
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

    /// The validators exist to stop a pasted value from becoming a header or URL injection, so the
    /// negative cases are the load-bearing ones.
    #[test]
    fn a_newline_is_rejected_in_both_fields() {
        assert!(!key_id_ok("d9c05597\nHost: evil"));
        assert!(!api_token_ok("tok\r\nAuthorization: Bearer other"));
    }

    #[test]
    fn a_real_looking_pair_is_accepted() {
        assert!(key_id_ok("d9c0559738b42b7c8548f4b41c41594d"));
        assert!(api_token_ok(
            "abcdef0123456789_-ABCDEF0123456789abcdef0123456789"
        ));
    }

    #[test]
    fn oversized_input_is_rejected() {
        assert!(!key_id_ok(&"a".repeat(129)));
        assert!(!api_token_ok(&"a".repeat(513)));
    }
}
