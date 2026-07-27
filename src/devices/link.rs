//! M2-S3.2: the QR link flow — cryptographically binding a second device to the primary.
//!
//! Three endpoints, all POST (never a GET query, so tokens never land in URL logs):
//!   `link-start`   (PRE-AUTH)      new device's ed/x pubs + device_id + PoP signature →
//!                                  a `link_code` (see `LINK_TTL_SEC`).
//!   `link-approve` (PRIMARY-AUTH)  the primary signs the new list (rev+1) →
//!                                  cross-check + atomic store + a (user, device) token.
//!   `link-status`  (PoP-AUTH)      the new device ed-signs the link_code and polls →
//!                                  once approved it receives the token EXACTLY ONCE
//!                                  (atomic consume).
//!
//! ## Security (red-team B7/H5)
//! - **PoP (link-start):** the new device sends `ed_priv.sign(ed_pub||x_pub)` and the server
//!   verifies it with ed_pub. This proves possession of ed_priv and binds the two keys
//!   together, so a stolen ed_pub paired with someone else's x_pub is rejected.
//! - **Status proof:** the new device sends `ed_priv.sign(link_code)`, verified against the
//!   stored new_ed_pub, so EVEN IF the link_code leaks only the holder of ed_priv gets a token.
//! - **Cross-check (approve):** the linked entry in the signed doc must match the EXACT keys
//!   recorded in link_requests (ed/x/device_id), so neither the server nor a MITM can
//!   substitute keys.
//! - **Atomic consume:** `DELETE ... WHERE status='approved' RETURNING` delivers the token to
//!   ONE device ONCE, and the row disappears immediately, keeping the exposure window minimal.

use crate::auth::hashing::sha256_hex;
use crate::auth::jwt::sign_access_token;
use crate::auth::middleware::require_auth;
use crate::d1util::{d1_blob, d1_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{b64_decode, b64u_encode, now_secs, random_bytes};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::Deserialize;
use worker::*;

use super::handlers::validate_and_store_signed_list;

// Covers the whole start→approve→consume flow, which involves a human scanning, comparing a
// fingerprint and passing biometrics. Deliberately short, to bound replay (H5).
const LINK_TTL_SEC: i64 = 120;
const REFRESH_TTL_SEC: i64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;
const MAX_PENDING: i64 = 50; // global ceiling on pending links (DoS guard)

// ---------------------------------------------------------------- link-start

#[derive(Deserialize)]
struct LinkStartBody {
    ed_pub_b64: String,
    x_pub_b64: String,
    device_id: String,
    #[serde(default)]
    label: Option<String>,
    /// PoP: `ed_priv.sign(ed_pub_bytes || x_pub_bytes)` (64 bytes, base64).
    link_sig_b64: String,
}

/// `POST /devices/link-start` (PRE-AUTH) — a new device starts a link request.
pub async fn link_start(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let ip = req
        .headers()
        .get("cf-connecting-ip")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".into());
    // The KV binding is OPTIONAL (template diet): with none we continue unlimited — see
    // ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("link:start:{ip}"), 10, 60).await
    {
        return json_err(429, "rate_limited");
    }

    let body: LinkStartBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    let ed = match b64_decode(&body.ed_pub_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return json_err(400, "bad_pubkey"),
    };
    let xk = match b64_decode(&body.x_pub_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return json_err(400, "bad_pubkey"),
    };
    if body.device_id.is_empty() || body.device_id.len() > 64 {
        return json_err(400, "bad_device_id");
    }

    // PoP: ed_priv.sign(ed || x) proves possession of ed_priv and binds the two keys.
    let ed_arr: [u8; 32] = ed.as_slice().try_into().unwrap();
    let verifying = match VerifyingKey::from_bytes(&ed_arr) {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_pubkey"),
    };
    let pop_sig = match b64_decode(&body.link_sig_b64) {
        Ok(b) if b.len() == 64 => b,
        _ => return json_err(400, "bad_pop"),
    };
    let pop_arr: [u8; 64] = pop_sig.as_slice().try_into().unwrap();
    let pop = ed25519_dalek::Signature::from_bytes(&pop_arr);
    let mut pop_msg = ed.clone();
    pop_msg.extend_from_slice(&xk);
    if verifying.verify(&pop_msg, &pop).is_err() {
        return json_err(400, "bad_pop");
    }

    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;

    // Global ceiling on pending links (DoS).
    #[derive(Deserialize)]
    struct CountRow {
        c: i64,
    }
    let cnt: Option<CountRow> = db
        .prepare(
            "SELECT COUNT(*) AS c FROM link_requests WHERE status='pending' AND expires_at > ?",
        )
        .bind(&[d1_int(now)])?
        .first(None)
        .await?;
    if cnt.map(|r| r.c).unwrap_or(0) >= MAX_PENDING {
        return json_err(429, "too_many_pending");
    }

    let link_code = b64u_encode(&random_bytes(32));
    db.prepare(
        "INSERT INTO link_requests
           (link_code, user_id, new_ed_pub, new_x_pub, new_device_id, label, status, created_at, expires_at)
         VALUES (?, NULL, ?, ?, ?, ?, 'pending', ?, ?)",
    )
    .bind(&[
        d1_text(&link_code),
        d1_blob(&ed),
        d1_blob(&xk),
        d1_text(&body.device_id),
        d1_opt_text(body.label.as_deref()),
        d1_int(now),
        d1_int(now + LINK_TTL_SEC),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "link_code": link_code,
        "expires_in": LINK_TTL_SEC,
    }))
}

// -------------------------------------------------------------- link-approve

#[derive(Deserialize)]
struct LinkApproveBody {
    link_code: String,
    doc_json: String,
    sig_b64: String,
}

#[derive(Deserialize)]
struct LinkRow {
    new_ed_pub: Vec<u8>,
    new_x_pub: Vec<u8>,
    new_device_id: String,
    status: String,
    expires_at: i64,
}

/// `POST /devices/link-approve` (PRIMARY-AUTH) — the primary approves the new list.
pub async fn link_approve(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth_user = match require_auth(&req, &ctx.env) {
        Ok(u) => u,
        Err(resp) => return Ok(resp),
    };

    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("devices:list:{auth_user}"),
        20,
        60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }

    let body: LinkApproveBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;

    let link: Option<LinkRow> = db
        .prepare(
            "SELECT new_ed_pub, new_x_pub, new_device_id, status, expires_at
             FROM link_requests WHERE link_code = ? LIMIT 1",
        )
        .bind(&[d1_text(&body.link_code)])?
        .first(None)
        .await?;
    let link = match link {
        Some(l) => l,
        None => return json_err(404, "link_not_found"),
    };
    if link.status != "pending" {
        return json_err(409, "link_not_pending");
    }
    if link.expires_at <= now {
        return json_err(410, "link_expired");
    }

    // Cross-check (B7): the signed doc must contain an entry carrying the EXACT keys recorded
    // in link_requests (ed/x/device_id). That is what blocks key substitution.
    #[derive(Deserialize)]
    struct XDoc {
        devices: Vec<XEntry>,
    }
    #[derive(Deserialize)]
    struct XEntry {
        device_id: String,
        ed_pub_b64: String,
        x_pub_b64: String,
    }
    let xdoc: XDoc = match serde_json::from_str(&body.doc_json) {
        Ok(d) => d,
        Err(_) => return json_err(400, "bad_doc"),
    };
    let matched = xdoc.devices.iter().any(|e| {
        e.device_id == link.new_device_id
            && b64_decode(&e.ed_pub_b64)
                .map(|b| b == link.new_ed_pub)
                .unwrap_or(false)
            && b64_decode(&e.x_pub_b64)
                .map(|b| b == link.new_x_pub)
                .unwrap_or(false)
    });
    if !matched {
        return json_err(400, "link_key_mismatch");
    }

    // Validate and store the list atomically (B6): the primary signature, the identity
    // binding and the rev condition all live in there.
    let rev = match validate_and_store_signed_list(&db, &auth_user, &body.doc_json, &body.sig_b64)
        .await?
    {
        Ok(rev) => rev,
        Err(resp) => return Ok(resp),
    };

    // Mint the tokens in memory only: an access JWT, plus a refresh token delivered in
    // plaintext while only its hash is stored.
    let access = sign_access_token(&ctx.env, &auth_user, Some(&link.new_device_id))?;
    let refresh = b64u_encode(&random_bytes(32));
    let refresh_hash = sha256_hex(&refresh);

    // ATOMIC CLAIM (review HIGH): first move link_requests from pending→approved and stash the
    // tokens for delivery. An empty RETURNING means the claim was lost — someone else approved,
    // consumed or expired it in between — and in that case we must NEVER create an
    // account-valid refresh_token, so no orphaned credential can leak. The previous ordering
    // INSERTed the refresh_token unconditionally and orphaned it whenever delivery failed.
    // The token INSERT happens ONLY after the claim is won.
    #[derive(Deserialize)]
    struct ClaimRow {
        #[allow(dead_code)]
        link_code: String,
    }
    let claimed: Option<ClaimRow> = db
        .prepare(
            "UPDATE link_requests SET status='approved', user_id=?, access_token=?, refresh_token=?
             WHERE link_code=? AND status='pending'
             RETURNING link_code",
        )
        .bind(&[
            d1_text(&auth_user),
            d1_text(&access),
            d1_text(&refresh),
            d1_text(&body.link_code),
        ])?
        .first(None)
        .await?;
    if claimed.is_none() {
        return json_err(409, "link_not_pending");
    }

    // Claim WON → only NOW write the account-valid refresh_token (hashed).
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&refresh_hash),
        d1_text(&auth_user),
        d1_int(now + REFRESH_TTL_SEC),
        d1_int(now),
        d1_text(&link.new_device_id),
    ])?
    .run()
    .await?;

    crate::realtime::nudge_grant_counterparts_best_effort(&ctx.env, &auth_user).await;
    Response::from_json(&serde_json::json!({ "rev": rev }))
}

// --------------------------------------------------------------- link-status

#[derive(Deserialize)]
struct LinkStatusBody {
    link_code: String,
    /// PoP: `ed_priv.sign(link_code_bytes)` (64 bytes, base64), verified against the stored
    /// new_ed_pub.
    proof_b64: String,
}

#[derive(Deserialize)]
struct StatusRow {
    new_ed_pub: Vec<u8>,
    status: String,
    reason: Option<String>,
    expires_at: i64,
}

#[derive(Deserialize)]
struct ConsumedRow {
    access_token: Option<String>,
    refresh_token: Option<String>,
    user_id: Option<String>,
    new_device_id: String,
}

/// `POST /devices/link-status` (PoP-AUTH) — the new device polls for approval.
pub async fn link_status(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Rate-limit (review HIGH): this is a pre-auth poll endpoint, so anyone holding a
    // link_code must not be able to hammer the DB SELECT, the ed verification and the consume
    // race without limit. At ~1.5/s the cap stays above legitimate polling.
    let ip = req
        .headers()
        .get("cf-connecting-ip")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".into());
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("link:status:{ip}"), 90, 60).await
    {
        return json_err(429, "rate_limited");
    }

    let body: LinkStatusBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;

    let row: Option<StatusRow> = db
        .prepare(
            "SELECT new_ed_pub, status, reason, expires_at
             FROM link_requests WHERE link_code = ? LIMIT 1",
        )
        .bind(&[d1_text(&body.link_code)])?
        .first(None)
        .await?;
    let row = match row {
        Some(r) => r,
        None => return json_err(404, "link_not_found"),
    };

    // Proof (H5): only the holder of ed_priv may read the status, so a leaked link_code cannot
    // be turned into a stolen token. proof = ed_priv.sign(link_code), verified against the
    // stored new_ed_pub.
    let ed_arr: [u8; 32] = match row.new_ed_pub.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return json_err(500, "bad_stored_key"),
    };
    let verifying = match VerifyingKey::from_bytes(&ed_arr) {
        Ok(v) => v,
        Err(_) => return json_err(500, "bad_stored_key"),
    };
    let proof = match b64_decode(&body.proof_b64) {
        Ok(b) if b.len() == 64 => b,
        _ => return json_err(401, "bad_proof"),
    };
    let proof_arr: [u8; 64] = proof.as_slice().try_into().unwrap();
    let proof_sig = ed25519_dalek::Signature::from_bytes(&proof_arr);
    if verifying
        .verify(body.link_code.as_bytes(), &proof_sig)
        .is_err()
    {
        return json_err(401, "bad_proof");
    }

    if row.status == "pending" && row.expires_at <= now {
        // Lazy GC: delete an expired pending row the moment we notice it, instead of leaving
        // the plaintext-waiting surface around until the daily cron. (An approved row is
        // deleted on consume.)
        let _ = db
            .prepare("DELETE FROM link_requests WHERE link_code=? AND status='pending'")
            .bind(&[d1_text(&body.link_code)])?
            .run()
            .await;
        return Response::from_json(&serde_json::json!({ "status": "expired" }));
    }

    match row.status.as_str() {
        "pending" => Response::from_json(&serde_json::json!({ "status": "pending" })),
        "rejected" => {
            Response::from_json(&serde_json::json!({ "status": "rejected", "reason": row.reason }))
        }
        "approved" => {
            // Atomic consume: only the poll that performs the approved→deleted transition
            // receives the token. If two polls race, one deletes the row and the other sees
            // "consumed".
            let consumed: Option<ConsumedRow> = db
                .prepare(
                    "DELETE FROM link_requests WHERE link_code=? AND status='approved'
                     RETURNING access_token, refresh_token, user_id, new_device_id",
                )
                .bind(&[d1_text(&body.link_code)])?
                .first(None)
                .await?;
            let c = match consumed {
                Some(c) => c,
                None => return Response::from_json(&serde_json::json!({ "status": "consumed" })),
            };
            // Trust-root fingerprint (H1): pull the primary's ed_pub out of the doc. The new
            // device shows it to the user and cross-checks it against the signed list.
            let primary_ed = match c.user_id.as_deref() {
                Some(uid) => primary_ed_pub_b64(&db, uid).await?,
                None => None,
            };
            Response::from_json(&serde_json::json!({
                "status": "approved",
                "user_id": c.user_id,
                "primary_ed_pub_b64": primary_ed,
                "access_token": c.access_token,
                "refresh_token": c.refresh_token,
                "device_id": c.new_device_id,
                "token_type": "Bearer",
                "expires_in": ACCESS_TTL_SEC,
            }))
        }
        _ => Response::from_json(&serde_json::json!({ "status": "consumed" })),
    }
}

/// Fetch the ed_pub_b64 of the PRIMARY device from the user's stored signed list — the
/// trust-root fingerprint. Missing row or unparseable doc → `None`.
async fn primary_ed_pub_b64(db: &D1Database, user_id: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct DocRow {
        doc_json: String,
    }
    let row: Option<DocRow> = db
        .prepare("SELECT doc_json FROM device_lists WHERE user_id = ? LIMIT 1")
        .bind(&[d1_text(user_id)])?
        .first(None)
        .await?;
    let Some(row) = row else { return Ok(None) };
    #[derive(Deserialize)]
    struct PDoc {
        devices: Vec<PEntry>,
    }
    #[derive(Deserialize)]
    struct PEntry {
        role: String,
        ed_pub_b64: String,
    }
    let doc: PDoc = match serde_json::from_str(&row.doc_json) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    Ok(doc
        .devices
        .into_iter()
        .find(|d| d.role == "primary")
        .map(|d| d.ed_pub_b64))
}
