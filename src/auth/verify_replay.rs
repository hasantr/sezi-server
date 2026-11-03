//! Answering a registration again when its first answer was lost (audit 2026-11-03 finding #5).
//!
//! `POST /auth/verify` writes the whole account in one batch, which also deletes the single-use
//! code. If that batch committed and the answer never reached the app, the retry found no code and
//! the account was out of reach — for a server's owner, the server too. The batch now also writes
//! a receipt (migration 0057). A retry is answered from it, with FRESH tokens for the same account,
//! only when all of this holds:
//!
//! - the receipt is younger than [`RECEIPT_TTL_SECS`], and has had fewer than the code's own
//!   attempt ceiling of guesses — each try is charged before the code is compared;
//! - the code matches the hash the spent code had;
//! - the identity key and the device are the ones the account was registered with;
//! - the account still exists and has published no device list yet — after its first publish,
//!   the app plainly had its answer, and nothing more is ever handed out here.
//!
//! Old apps need nothing: their retry is the same request. The answer has the shape of the first
//! one; `landing` is null (the landing was applied by the first answer's request, server-side).

use crate::auth::hashing::{sha256_hex, verify_code};
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::utils::{b64_decode, b64u_encode, random_bytes};
use serde::Deserialize;
use worker::*;

/// How long a lost answer can be asked for again.
pub(crate) const RECEIPT_TTL_SECS: i64 = 30 * 60;

/// The receipt, from the code row it replaces, inside the registration batch (before the code's
/// DELETE). Binds: email, user_id, device_id, identity_hash, inviter_user_id, inviter_ed_pub,
/// expires_at.
pub(crate) const WRITE_RECEIPT_SQL: &str = "INSERT OR REPLACE INTO registration_receipts
       (email, code_hash, user_id, device_id, identity_hash, inviter_user_id, inviter_ed_pub,
        attempts, expires_at)
     SELECT ?1, code_hash, ?2, ?3, ?4, ?5, ?6, 0, ?7 FROM verification_codes WHERE email = ?1";

/// One charged try against a live receipt. Binds: email, max attempts, now.
pub(crate) const CLAIM_RECEIPT_SQL: &str = "UPDATE registration_receipts
        SET attempts = attempts + 1
      WHERE email = ?1 AND attempts < ?2 AND expires_at > ?3
  RETURNING code_hash, user_id, device_id, identity_hash, inviter_user_id, inviter_ed_pub";

/// The account still exists and has published no device. Bind: user_id.
pub(crate) const UNPUBLISHED_ACCOUNT_SQL: &str = "SELECT COUNT(*) AS n FROM users u
      WHERE u.id = ?1 AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.id)";

/// Expired receipts, for the daily cleanup. Bind: now.
pub(crate) const RECEIPT_CLEANUP_SQL: &str =
    "DELETE FROM registration_receipts WHERE expires_at < ?1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn receipt_statement(
    db: &D1Database,
    email: &str,
    user_id: &str,
    device_id: &str,
    identity_pubkey: &[u8],
    inviter_user_id: Option<&str>,
    inviter_ed_pub: Option<&str>,
    now: i64,
) -> Result<D1PreparedStatement> {
    db.prepare(WRITE_RECEIPT_SQL).bind(&[
        d1_text(email),
        d1_text(user_id),
        d1_text(device_id),
        d1_text(&identity_hash(identity_pubkey)),
        d1_opt_text(inviter_user_id),
        d1_opt_text(inviter_ed_pub),
        d1_int(now + RECEIPT_TTL_SECS),
    ])
}

pub(crate) fn identity_hash(identity_pubkey: &[u8]) -> String {
    sha256_hex(&b64u_encode(identity_pubkey))
}

#[derive(Deserialize)]
pub(crate) struct Receipt {
    pub(crate) code_hash: String,
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) identity_hash: String,
    pub(crate) inviter_user_id: Option<String>,
    pub(crate) inviter_ed_pub: Option<String>,
}

/// Does this retry belong to the registration the receipt records? Pure, so it is tested.
pub(crate) fn same_registration(r: &Receipt, code: &str, identity_pubkey: &[u8], device_id: &str) -> bool {
    verify_code(code, &r.code_hash)
        && r.device_id == device_id
        && crate::auth::hashing::secret_eq(&r.identity_hash, &identity_hash(identity_pubkey))
}

/// The answer to a retry whose code is already spent, or `None` to give the ordinary refusal.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn replay(
    env: &Env,
    db: &D1Database,
    email: &str,
    code: &str,
    identity_pubkey_b64: &str,
    device_id: &str,
    max_attempts: i64,
    refresh_ttl_secs: i64,
    access_ttl_secs: i64,
    now: i64,
) -> Result<Option<Response>> {
    let receipt: Option<Receipt> = db
        .prepare(CLAIM_RECEIPT_SQL)
        .bind(&[d1_text(email), d1_int(max_attempts), d1_int(now)])?
        .first(None)
        .await?;
    let Some(receipt) = receipt else { return Ok(None) };
    let Ok(identity_pubkey) = b64_decode(identity_pubkey_b64) else { return Ok(None) };
    if !same_registration(&receipt, code, &identity_pubkey, device_id) {
        return Ok(None);
    }
    #[derive(Deserialize)]
    struct CountRow {
        n: i64,
    }
    let open: Option<CountRow> = db
        .prepare(UNPUBLISHED_ACCOUNT_SQL)
        .bind(&[d1_text(&receipt.user_id)])?
        .first(None)
        .await?;
    if open.map(|r| r.n) != Some(1) {
        return Ok(None);
    }
    let access_token = sign_access_token(env, &receipt.user_id, device_id)?;
    let refresh = b64u_encode(&random_bytes(32));
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&sha256_hex(&refresh)),
        d1_text(&receipt.user_id),
        d1_int(now + refresh_ttl_secs),
        d1_int(now),
        d1_text(device_id),
    ])?
    .run()
    .await?;
    console_log!("verify: a lost registration answer was given again (user={})", receipt.user_id);
    Response::from_json(&serde_json::json!({
        "user_id": receipt.user_id,
        "access_token": access_token,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": access_ttl_secs,
        "inviter_user_id": receipt.inviter_user_id,
        "inviter_ed_pub": receipt.inviter_ed_pub,
        "landing": serde_json::Value::Null,
    }))
    .map(Some)
}

#[cfg(test)]
#[path = "verify_replay_tests.rs"]
mod tests;
