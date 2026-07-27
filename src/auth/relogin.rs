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
use crate::d1util::{d1_blob, d1_int, d1_opt_text, d1_text};
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
    // M2-S1 (optional): this device's device_id plus the Ed25519 signing public key.
    // An older body without them works EXACTLY as before. identity_ed_pub_b64 is the
    // same key as ed25519_pub_b64 (already verified above), so it is used to backfill
    // users.identity_ed_pub.
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    identity_ed_pub_b64: Option<String>,
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
    // the primary can no longer recover its session. PREFER the SPK matching this
    // device's device_id, falling back to the legacy NULL/'' rows.
    let dev = body.device_id.as_deref();
    let spk: Option<SpkRow> = db
        .prepare(
            "SELECT prekey_pub, signature FROM signed_prekeys
             WHERE user_id = ? AND (device_id = ? OR device_id IS NULL OR device_id = '')
             ORDER BY CASE WHEN device_id = ? THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
        )
        .bind(&[d1_text(&body.user_id), d1_opt_text(dev), d1_opt_text(dev)])?
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

    // M2-S3.5 B4: a REMOVED device must not come back through relogin. If
    // body.device_id has been revoked (the primary dropped it from the list, so put_list
    // set revoked_at=now) we answer 401 and issue no token — even though the SPK
    // verification above passed. A missing or unknown device_id keeps the old behaviour:
    // an N=1 primary with a legacy device_id-less token is exempt from this check.
    if let Some(dev) = body.device_id.as_deref() {
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

    // M2-S1: optional Ed25519 signing-key backfill. `verifying` has already proven
    // CRYPTOGRAPHICALLY that this key is the user's identity, so it is safe to store.
    // Only fill it when empty — never overwrite an existing value (idempotent).
    if let Some(ed_b64) = body.identity_ed_pub_b64.as_deref() {
        if let Ok(ed_pub) = b64_decode(ed_b64) {
            db.prepare(
                "UPDATE users SET identity_ed_pub = ?
                 WHERE id = ? AND identity_ed_pub IS NULL",
            )
            .bind(&[d1_blob(&ed_pub), d1_text(&body.user_id)])?
            .run()
            .await?;
        }
    }

    // Proof accepted → fresh tokens for the EXISTING user_id. No new identity is
    // minted, so pairing survives.
    let device_id = body.device_id.as_deref();
    let access_token = sign_access_token(&ctx.env, &body.user_id, device_id)?;
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
        d1_opt_text(device_id),
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
