use crate::auth::hashing::sha256_hex;
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::{b64u_encode, now_secs, random_bytes};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
    /// This device's device_id, as the caller believes it to be.
    ///
    /// Deliberately still optional, and deliberately NOT the binding — see
    /// `check_device_claim`. The session's device comes from the stored row, so a caller that
    /// cannot name its own device can still refresh; the field only ever REFUSES. Core's
    /// `run_token_refresh` sends `None` when it fails to re-derive the device from a corrupt
    /// identity blob, and that request must keep working: refusing it would strand the client
    /// with no way to renew a token it holds legitimately.
    #[serde(default)]
    device_id: Option<String>,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;

/// May a refresh naming `claim` renew a token ISSUED to `row`?
///
/// **The row is the authority; the claim can only refuse.** This used to be
/// `body.device_id.or(row.device_id)`, i.e. the caller could NAME the device the session
/// belonged to. Device ids are public — `GET /devices/list/:user_id` serves them — so a refresh
/// token bound to a device that had just been revoked could name a live sibling instead: the
/// revocation check then interrogated the sibling and passed, and `sign_access_token` minted an
/// access token CLAIMING the sibling. That is a forged device identity on every path that trusts
/// the token's device claim (message send's `sender_device_id` binding, the OTK pool scope,
/// `plugin_blob::gate`).
///
/// `Err(())` = the claim CONTRADICTS the row (→ 403). No claim at all is fine; the row still
/// decides, and the row is still what gets the revocation check.
fn check_device_claim(row: &str, claim: Option<&str>) -> std::result::Result<(), ()> {
    // `''` was the sentinel of the device-less population, never a device. Normalising it here
    // is what stops `device_id: ""` from reading as agreement with a real binding.
    match claim.filter(|d| !d.is_empty()) {
        Some(c) if c != row => Err(()),
        _ => Ok(()),
    }
}

pub async fn refresh(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: RefreshBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.refresh_token.len() < 20 || body.refresh_token.len() > 200 {
        return json_err(400, "bad_request");
    }

    let now = now_secs();
    let old_hash = sha256_hex(&body.refresh_token);
    let db = ctx.env.d1("DB")?;

    #[derive(Deserialize)]
    struct Row {
        user_id: String,
        expires_at: i64,
        /// The device this refresh token was issued to. Read as `Option` only because the D1
        /// column is nullable; every mint site writes one, so a NULL row is refused below
        /// rather than granted a device-less session.
        device_id: Option<String>,
    }
    let row: Option<Row> = db
        .prepare(
            "SELECT user_id, expires_at, device_id FROM refresh_tokens
             WHERE token_hash = ? AND revoked = 0 LIMIT 1",
        )
        .bind(&[d1_text(&old_hash)])?
        .first(None)
        .await?;
    let row = match row {
        Some(r) if (r.expires_at as u64) > now => r,
        _ => return json_err(401, "invalid_refresh"),
    };

    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")
        .bind(&[d1_text(&old_hash)])?
        .run()
        .await?;

    let user_id = row.user_id;
    // A row that names no device cannot exist: `auth::verify`, this handler, `auth::relogin` and
    // `devices::link` all bind one. Refusing is the honest answer — the alternative is minting a
    // device-less access token, which is the very thing every route downstream stopped
    // accommodating.
    let device_id = match row.device_id.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => d,
        None => return json_err(401, "invalid_refresh"),
    };
    // The stored row decides which device this session belongs to; the body may only reject.
    // See `check_device_claim` for what a caller-chosen device_id used to buy an attacker.
    if check_device_claim(device_id, body.device_id.as_deref()).is_err() {
        return json_err(403, "device_mismatch");
    }
    // M2-S3.5: a REMOVED device must not RESURRECT its session through /auth/refresh
    // (parity with relogin.rs). The device is revoked → 401, so it gets no new access token and
    // the session dies within the access TTL (15 min). Defence on top of the older token
    // deletion, and it now covers every refresh rather than only those that named a device.
    {
        #[derive(Deserialize)]
        struct RevRow {
            revoked_at: Option<i64>,
        }
        let rev: Option<RevRow> = db
            .prepare("SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
            .bind(&[d1_text(&user_id), d1_text(device_id)])?
            .first(None)
            .await?;
        if rev.and_then(|r| r.revoked_at).is_some() {
            return json_err(401, "device_revoked");
        }
    }
    let access_token = sign_access_token(&ctx.env, &user_id, device_id)?;
    let new_refresh = b64u_encode(&random_bytes(32));
    let new_hash = sha256_hex(&new_refresh);
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&new_hash),
        d1_text(&user_id),
        d1_int((now + REFRESH_TTL_SEC) as i64),
        d1_int(now as i64),
        d1_text(device_id),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SEC,
    }))
}

#[cfg(test)]
mod tests {
    use super::check_device_claim;

    /// The whole point: whatever the caller asks for, the session's device is the stored one.
    #[test]
    fn the_body_can_never_substitute_the_issued_binding() {
        // The attack: a token issued to a revoked device, naming a live sibling.
        assert_eq!(check_device_claim("revoked", Some("live")), Err(()));
        // Agreement is fine, and changes nothing.
        assert_eq!(check_device_claim("dev-a", Some("dev-a")), Ok(()));
        // No claim at all: the row still decides, and still gets the revocation check. Core
        // sends exactly this when it cannot re-derive its own device_id from the identity blob,
        // which is why the field stayed optional here and nowhere else.
        assert_eq!(check_device_claim("dev-a", None), Ok(()));
    }

    /// `''` was the sentinel of the device-less population, never a device. It must not read as
    /// agreement with a real binding now that the population is gone.
    #[test]
    fn the_empty_sentinel_is_not_a_device() {
        assert_eq!(
            check_device_claim("dev-a", Some("")),
            Ok(()),
            "an empty claim is no claim; it must not read as agreement with dev-a either"
        );
    }
}
