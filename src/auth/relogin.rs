//! `POST /auth/relogin` — identity-signed session recovery (K5c).
//!
//! When the `refresh_token` dies (rotated, expired or revoked) the session used to be
//! lost for good, because verify mints a NEW user_id and that breaks pairing. This
//! endpoint makes the client prove possession of its **existing** Ed25519 identity key
//! and then issues fresh tokens for the SAME `user_id`, preserving pairing and
//! identity.
//!
//! The server does not store the user's Ed25519 signing key separately
//! (`users.identity_pubkey` is the Curve25519/DH key). What it does have is the
//! `signed_prekeys` table, holding the user's SPK public key plus its Ed25519
//! signature (produced by `account.sign(spk_pub_bytes)` at registration/rotation).
//! Verification therefore has two stages:
//!   1) **Binding:** does the Ed25519 public key the client sent verify the stored SPK
//!      signature? If so, that key is the user's identity signing key.
//!   2) **Liveness:** does the same key verify a fresh
//!      `sezgi-relogin:{user_id}:{ts}` challenge signature, and is `ts` inside the
//!      freshness window (the replay bound)?
//!
//! If both hold → fresh access + refresh tokens.

use crate::auth::hashing::sha256_hex;
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_blob, d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::{b64_decode, b64u_encode, now_secs, random_bytes};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct ReloginBody {
    user_id: String,
    ed25519_pub_b64: String,
    ts: u64,
    signature_b64: String,
    /// The device recovering the session. MANDATORY: it selects which SPK the identity proof is
    /// checked against, it is the subject of the revocation check, and it becomes the claim on
    /// the minted token. Without it this endpoint used to read the `''` slot and skip the
    /// revocation check entirely.
    ///
    /// `identity_ed_pub_b64` used to live here too and was written straight into
    /// users.identity_ed_pub. It is deliberately gone: the field was never checked against
    /// anything, so a caller could seat an arbitrary key as the server-side identity anchor
    /// that `contact_qr` and `invite_attribution` later trust. The backfill now uses the key
    /// the challenge signature actually proves. Clients keep sending the field — it is simply
    /// ignored, which is what serde does with an unknown field here anyway.
    device_id: String,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;
/// Challenge freshness window: clock-skew tolerance and replay bound in one.
const CHALLENGE_WINDOW_SEC: u64 = 300;

pub async fn relogin(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: ReloginBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    // `''` was the sentinel that steered the SPK selection at the legacy slot while ALSO
    // skipping the revoked check. Both of those are gone, and so is the sentinel.
    if body.device_id.is_empty() || body.device_id.len() > 128 {
        return json_err(400, "device_required");
    }
    let dev = body.device_id.as_str();

    let now = now_secs();
    let skew = now.abs_diff(body.ts);
    if skew > CHALLENGE_WINDOW_SEC {
        return json_err(401, "stale_challenge");
    }

    // Parse the supplied Ed25519 public key.
    let ed_bytes = match b64_decode(&body.ed25519_pub_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return json_err(400, "bad_ed25519"),
    };
    let ed_arr: [u8; 32] = ed_bytes.as_slice().try_into().unwrap();
    let verifying = match VerifyingKey::from_bytes(&ed_arr) {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_ed25519"),
    };

    let db = ctx.env.d1("DB")?;

    // The user's stored SPK public key + signature (most recent), signed with Ed25519.
    #[derive(Deserialize)]
    struct SpkRow {
        prekey_pub: Vec<u8>,
        signature: Vec<u8>,
    }
    // M2-S3.2 (review HIGH): scope the SPK selection PER DEVICE. With multiple devices,
    // each device publishes the SPK of its OWN Account (append-only), so a device-blind
    // "newest wins" selection would, right after a linked device onboards, check the
    // primary's relogin proof against the LINKED device's SPK → identity_mismatch →
    // the primary can no longer recover its session.
    //
    // EXACTLY this device's slot. The selection used to widen to `device_id IS NULL OR
    // device_id = ''` and prefer the match only by ORDER BY, so the legacy slot was a fallback
    // any device could land on — and that slot is the one an identity claim could be planted in,
    // because it was also the one `keys::rotate_signed_prekey` would accept a device-less write
    // into. Both halves are gone: there is no device-less write, so there is nothing to fall
    // back to, and a device with no SPK of its own now gets `no_identity` instead of somebody
    // else's key.
    let spk: Option<SpkRow> = db
        .prepare(
            "SELECT prekey_pub, signature FROM signed_prekeys
             WHERE user_id = ? AND device_id = ?
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&[d1_text(&body.user_id), d1_text(dev)])?
        .first(None)
        .await?;
    let spk = match spk {
        Some(s) => s,
        None => return json_err(404, "no_identity"),
    };
    if spk.signature.len() != 64 {
        return json_err(500, "bad_spk_sig");
    }

    // 1) Binding: is the supplied Ed25519 public key the identity key that signed the
    //    user's SPK? The SPK signature covers the raw SPK public bytes (on the client:
    //    `account.sign(pub_key.as_bytes())` → the raw 32 bytes).
    let spk_sig_arr: [u8; 64] = spk.signature.as_slice().try_into().unwrap();
    let spk_sig = ed25519_dalek::Signature::from_bytes(&spk_sig_arr);
    if verifying.verify(&spk.prekey_pub, &spk_sig).is_err() {
        return json_err(401, "identity_mismatch");
    }

    // 2) Liveness: the fresh challenge signature is verified with the same key.
    let challenge = format!("sezgi-relogin:{}:{}", body.user_id, body.ts);
    let chal_bytes = match b64_decode(&body.signature_b64) {
        Ok(b) if b.len() == 64 => b,
        _ => return json_err(400, "bad_sig"),
    };
    let chal_arr: [u8; 64] = chal_bytes.as_slice().try_into().unwrap();
    let chal_sig = ed25519_dalek::Signature::from_bytes(&chal_arr);
    if verifying.verify(challenge.as_bytes(), &chal_sig).is_err() {
        return json_err(401, "bad_challenge");
    }

    // M2-S3.5 B4: a REMOVED device must not come back through relogin. The device has been
    // revoked (the primary dropped it from the list, so put_list set revoked_at=now) → 401 and
    // no token, even though the SPK verification above passed.
    //
    // This used to be skipped whenever the body named no device — an exemption kept so a
    // device-less primary could not be locked out of session recovery. With a device always
    // named there is nobody left to exempt, and the check now covers every relogin.
    {
        #[derive(Deserialize)]
        struct RevRow {
            revoked_at: Option<i64>,
        }
        let rev: Option<RevRow> = db
            .prepare("SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
            .bind(&[d1_text(&body.user_id), d1_text(dev)])?
            .first(None)
            .await?;
        if rev.and_then(|r| r.revoked_at).is_some() {
            return json_err(401, "device_revoked");
        }
    }

    // M2-S1: Ed25519 signing-key backfill, from `ed_bytes` — the key the challenge signature
    // was verified against a few lines up, and the only key in this request that anything has
    // proven. It used to take `body.identity_ed_pub_b64`, a separate field nothing compared to
    // `verifying` and nothing length-checked, while the comment here claimed it had been proven
    // cryptographically. `users.identity_ed_pub` is the server-side trust root that
    // `contact_qr::principal_is_authoritative` reads as `root_ed` and that
    // `invite_attribution` snapshots for the card-to-invite binding, so an unproven value
    // landing there is an anchor nobody signed for.
    //
    // Only fill it when empty — never overwrite an existing value (idempotent).
    db.prepare(
        "UPDATE users SET identity_ed_pub = ?
         WHERE id = ? AND identity_ed_pub IS NULL",
    )
    .bind(&[d1_blob(&ed_bytes), d1_text(&body.user_id)])?
    .run()
    .await?;

    // Proof accepted → fresh tokens for the EXISTING user_id. No new identity is
    // minted, so pairing survives.
    let access_token = sign_access_token(&ctx.env, &body.user_id, dev)?;
    let new_refresh = b64u_encode(&random_bytes(32));
    let new_hash = sha256_hex(&new_refresh);
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&new_hash),
        d1_text(&body.user_id),
        d1_int((now + REFRESH_TTL_SEC) as i64),
        d1_int(now as i64),
        d1_text(dev),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "user_id": body.user_id,
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SEC,
    }))
}

/// The trust-root backfill must use the key the challenge signature proved, never a field the
/// caller supplied alongside it.
///
/// This is a source-level guard rather than a behavioural test because the handler needs D1, a
/// Durable Object and a live worker environment — the same reason `admin/mod.rs` guards its auth
/// middleware this way. It is worth a guard at all because the regression is invisible at
/// runtime: writing an unproven key succeeds, returns 200, and only surfaces later as a contact
/// QR or an invite attribution that verifies against an anchor nobody signed for.
#[cfg(test)]
mod trust_root_backfill_guard {
    /// `include_str!` binds at compile time, so renaming this file breaks the build instead of
    /// silently emptying the guard.
    const SRC: &str = include_str!("relogin.rs");

    #[test]
    fn identity_ed_pub_is_backfilled_from_the_verified_key() {
        let update = SRC
            .find("UPDATE users SET identity_ed_pub")
            .expect("the identity_ed_pub backfill disappeared — if it moved, move this guard too");
        // The bind list follows the UPDATE within a few lines.
        let window = &SRC[update..SRC.len().min(update + 400)];
        assert!(
            window.contains("d1_blob(&ed_bytes)"),
            "the backfill must bind `ed_bytes`, the key `verifying` was built from and the \
             signature was checked against"
        );
        assert!(
            !window.contains("identity_ed_pub_b64"),
            "the backfill must not take a caller-supplied key: users.identity_ed_pub is the \
             trust root that contact_qr and invite_attribution read"
        );
    }
}
