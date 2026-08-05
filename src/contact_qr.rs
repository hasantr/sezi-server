//! Contact QR V2 worker boundary.
//!
//! This module intentionally has no dependency on `messaging-core`. It ports the
//! canonical transcript, Ed25519, SHA-256 commitment/hash and HMAC verification
//! byte-for-byte so a worker can verify core-generated wire objects. Route/module
//! registration is deliberately left to `lib.rs` integration.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::*;

use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::{now_ms, now_secs};

type HmacSha256 = Hmac<Sha256>;

const CONTACT_PROTOCOL_V2: u32 = 2;
const MUTUAL_ONCE_MODE_V2: &str = "mutual_once";
const MUTUAL_CONTACT_GRANT_V2: &str = "contact.mutual";
const MUTUAL_ONCE_MAX_TTL_MS: i64 = 15 * 60 * 1000;

const OFFER_ID_BYTES: usize = 16;
const CAPABILITY_SECRET_BYTES: usize = 32;
const HASH_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const ED25519_PUBLIC_BYTES: usize = 32;
const X25519_PUBLIC_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

const OFFER_SIGNATURE_DOMAIN: &[u8] = b"sezgi/contact-v2/mutual-once/offer-signature\0";
const OFFER_HASH_DOMAIN: &[u8] = b"sezgi/contact-v2/mutual-once/offer-hash\0";
const CAPABILITY_COMMITMENT_DOMAIN: &[u8] = b"sezgi/contact-v2/mutual-once/capability-commitment\0";
const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"sezgi/contact-v2/mutual-once/claim-signature\0";
const CAPABILITY_PROOF_DOMAIN: &[u8] = b"sezgi/contact-v2/mutual-once/capability-proof\0";
const CLAIM_ID_DOMAIN: &[u8] = b"sezgi/contact-v2/mutual-once/claim-id\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactPrincipalV2 {
    user_id: String,
    root_ed_pub_b64: String,
    root_x_pub_b64: String,
    device_id: String,
    device_ed_pub_b64: String,
    device_x_pub_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutualOnceOfferV2 {
    v: u32,
    mode: String,
    server_instance: String,
    offer_id: String,
    issuer: ContactPrincipalV2,
    issued_at_ms: i64,
    expires_at_ms: i64,
    max_claims: u32,
    capability_commitment_hex: String,
    issuer_signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutualOnceClaimV2 {
    v: u32,
    mode: String,
    server_instance: String,
    offer_id: String,
    offer_hash_hex: String,
    claimant: ContactPrincipalV2,
    claimant_list_rev: u64,
    nonce_hex: String,
    claimed_at_ms: i64,
    grants: Vec<String>,
    capability_secret_b64: String,
    claimant_signature_b64: String,
    capability_proof_b64: String,
}

#[derive(Debug, Clone)]
struct VerifiedOffer {
    offer: MutualOnceOfferV2,
    offer_hash_hex: String,
}

#[derive(Debug, Clone)]
struct VerifiedClaim {
    offer: MutualOnceOfferV2,
    claim: MutualOnceClaimV2,
    offer_hash_hex: String,
    claim_id_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyErrorKind {
    Malformed,
    UnsupportedVersion,
    InvalidMode,
    InvalidField,
    InvalidIdentity,
    InvalidSignature,
    InvalidCapability,
    InvalidCapabilityProof,
    WrongServer,
    NotYetValid,
    Expired,
    OfferMismatch,
    ClaimsPolicy,
    GrantRejected,
    SelfClaim,
}

#[derive(Debug, Clone)]
struct VerifyError {
    kind: VerifyErrorKind,
    message: &'static str,
}

type VerifyResult<T> = std::result::Result<T, VerifyError>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferBody {
    offer_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBody {
    claim_json: String,
}

#[derive(Deserialize)]
struct AuthorityRow {
    root_ed: Option<Vec<u8>>,
    root_x: Vec<u8>,
    device_list_rev: i64,
    device_ed: Vec<u8>,
    device_x: Vec<u8>,
}

#[derive(Deserialize)]
struct StoredOfferRow {
    offer_id: String,
    offer_hash_hex: String,
    issuer_user_id: String,
    issuer_device_id: String,
    offer_json: String,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
    consumed_claim_id: Option<String>,
}

#[derive(Deserialize)]
struct StoredClaimRow {
    claim_id_hex: String,
    claimant_user_id: String,
    grant_applied: i64,
    grant_id: Option<String>,
}

#[derive(Deserialize)]
struct StatusRow {
    offer_id: String,
    offer_hash_hex: String,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
    consumed_claim_id: Option<String>,
    claimant_user_id: Option<String>,
    grant_id: Option<String>,
}

#[derive(Deserialize)]
struct ExistsRow {
    n: i64,
}

/// `POST /contacts/qr/offers` — body `{ "offer_json": "..." }`.
/// Returns `{offer_id, offer_hash_hex, status, expires_at_ms}`. Same offer hash
/// is idempotent; same `offer_id` with another signed transcript is `409`.
pub async fn create_offer(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let auth_device = auth.device_id.as_str();
    // The KV binding is OPTIONAL (template diet): without it we continue unlimited.
    // Each offer is a ≤32KB D1 row with a daily 500-row cleanup, so unlimited create
    // is an insider D1-bloat surface (audit 2026-07-16). The UI's natural pace is
    // ~12/hour (5 min TTL).
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("qr:offer:{}", auth.user_id),
        30,
        3600,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let body: OfferBody = match req.json().await {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.offer_json.is_empty() || body.offer_json.len() > 32 * 1024 {
        return json_err(400, "bad_offer");
    }
    let server_fingerprint = match crate::server::handlers::server_instance_fingerprint(&ctx.env) {
        Ok(v) => v,
        Err(_) => return json_err(503, "server_identity_unavailable"),
    };
    let now_ms_value = now_ms() as i64;
    let verified = match verify_offer_json(&body.offer_json, &server_fingerprint, now_ms_value) {
        Ok(v) => v,
        Err(e) => return protocol_error_response(e),
    };
    if verified.offer.issuer.user_id != auth.user_id
        || verified.offer.issuer.device_id != auth_device
    {
        return json_err(403, "issuer_binding_invalid");
    }
    let db = ctx.env.d1("DB")?;
    if !principal_is_authoritative(&db, &verified.offer.issuer, None).await? {
        return json_err(403, "issuer_binding_invalid");
    }

    db.prepare(
        "INSERT OR IGNORE INTO contact_qr_offers
           (offer_id,offer_hash_hex,server_fingerprint,issuer_user_id,issuer_device_id,
            offer_json,issued_at_ms,expires_at_ms,max_claims,capability_commitment_hex,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&[
        d1_text(&verified.offer.offer_id),
        d1_text(&verified.offer_hash_hex),
        d1_text(&verified.offer.server_instance),
        d1_text(&verified.offer.issuer.user_id),
        d1_text(&verified.offer.issuer.device_id),
        d1_text(&body.offer_json),
        d1_int(verified.offer.issued_at_ms),
        d1_int(verified.offer.expires_at_ms),
        d1_int(verified.offer.max_claims as i64),
        d1_text(&verified.offer.capability_commitment_hex),
        d1_int(now_secs() as i64),
    ])?
    .run()
    .await?;

    let stored = fetch_offer(&db, &verified.offer.offer_id).await?;
    let Some(stored) = stored else {
        // A UNIQUE offer_hash collision under another id is terminal; the hash
        // binds offer_id, so this can only be corruption/conflict.
        return json_err(409, "offer_conflict");
    };
    if stored.offer_hash_hex != verified.offer_hash_hex
        || stored.issuer_user_id != auth.user_id
        || stored.issuer_device_id != auth_device
    {
        return json_err(409, "offer_conflict");
    }
    offer_response(&stored, now_ms_value)
}

/// `POST /contacts/qr/claims` — body `{ "claim_json": "..." }`.
/// The response never echoes claim JSON or capability secret.
pub async fn claim_offer(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let auth_device = auth.device_id.as_str();
    // Each claim costs 2×Ed25519 plus an HMAC verification — bound the CPU surface too.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("qr:claim:{}", auth.user_id),
        60,
        3600,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let body: ClaimBody = match req.json().await {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.claim_json.is_empty() || body.claim_json.len() > 48 * 1024 {
        return json_err(400, "bad_claim");
    }
    let parsed_claim: MutualOnceClaimV2 = match parse_json(&body.claim_json) {
        Ok(v) => v,
        Err(e) => return protocol_error_response(e),
    };
    let db = ctx.env.d1("DB")?;
    let Some(stored_offer) = fetch_offer(&db, &parsed_claim.offer_id).await? else {
        return json_err(404, "offer_not_found");
    };
    let server_fingerprint = match crate::server::handlers::server_instance_fingerprint(&ctx.env) {
        Ok(v) => v,
        Err(_) => return json_err(503, "server_identity_unavailable"),
    };
    let now_ms_value = now_ms() as i64;
    let verified = match verify_claim_json(
        &stored_offer.offer_json,
        &body.claim_json,
        &server_fingerprint,
        now_ms_value,
    ) {
        Ok(v) => v,
        Err(e) => return protocol_error_response(e),
    };
    if verified.offer_hash_hex != stored_offer.offer_hash_hex
        || verified.offer.offer_id != stored_offer.offer_id
    {
        return json_err(409, "offer_conflict");
    }
    if verified.claim.claimant.user_id != auth.user_id
        || verified.claim.claimant.device_id != auth_device
    {
        return json_err(403, "claimant_binding_invalid");
    }
    let list_rev = match i64::try_from(verified.claim.claimant_list_rev) {
        Ok(v) if v > 0 => v,
        _ => return json_err(403, "claimant_binding_invalid"),
    };
    if !principal_is_authoritative(&db, &verified.claim.claimant, Some(list_rev)).await? {
        return json_err(403, "claimant_binding_invalid");
    }
    // Re-check issuer device/root at consumption time. A revoked issuer device
    // invalidates an outstanding offer instead of leaving a stale capability live.
    if !principal_is_authoritative(&db, &verified.offer.issuer, None).await? {
        return json_err(409, "offer_unavailable");
    }
    if pair_is_blocked(&db, &verified.offer.issuer.user_id, &auth.user_id).await? {
        // Do not disclose which direction contains the block.
        return json_err(409, "contact_unavailable");
    }

    let nonce = match decode_canonical_hex_fixed(&verified.claim.nonce_hex, NONCE_BYTES) {
        Ok(v) => v,
        Err(e) => return protocol_error_response(e),
    };
    let proof = match decode_canonical_b64_fixed(
        &verified.claim.capability_proof_b64,
        HASH_BYTES,
        VerifyErrorKind::InvalidCapabilityProof,
    ) {
        Ok(v) => v,
        Err(e) => return protocol_error_response(e),
    };
    let nonce_hash = hex::encode(Sha256::digest(nonce));
    let proof_hash = hex::encode(Sha256::digest(proof));
    let created_at = now_secs() as i64;
    let issuer_user = verified.offer.issuer.user_id.clone();
    let claimant_user = verified.claim.claimant.user_id.clone();
    let issuer_event = format!("qr:{}:issuer", verified.claim_id_hex);
    let claimant_event = format!("qr:{}:claimant", verified.claim_id_hex);

    let statements = vec![
        db.prepare(INSERT_CLAIM_SQL).bind(&[
            d1_text(&verified.claim_id_hex),
            d1_text(&verified.offer.offer_id),
            d1_text(&claimant_user),
            d1_text(&verified.claim.claimant.device_id),
            d1_int(list_rev),
            d1_text(&nonce_hash),
            d1_int(verified.claim.claimed_at_ms),
            d1_text(&proof_hash),
            d1_int(created_at),
            d1_int(now_ms_value),
        ])?,
        db.prepare(CONSUME_OFFER_SQL).bind(&[
            d1_text(&verified.claim_id_hex),
            d1_text(&verified.offer.offer_id),
            d1_int(now_ms_value),
        ])?,
        db.prepare(UPSERT_QR_GRANT_SQL)
            .bind(&[d1_text(&verified.claim_id_hex), d1_int(created_at)])?,
        db.prepare(MARK_CLAIM_GRANT_SQL)
            .bind(&[d1_text(&verified.claim_id_hex)])?,
        db.prepare(INSERT_ISSUER_REVISION_SQL).bind(&[
            d1_text(&issuer_event),
            d1_int(created_at),
            d1_text(&verified.claim_id_hex),
        ])?,
        db.prepare(INSERT_CLAIMANT_REVISION_SQL).bind(&[
            d1_text(&claimant_event),
            d1_int(created_at),
            d1_text(&verified.claim_id_hex),
        ])?,
    ];
    db.batch(statements).await?;

    let winner = fetch_claim_for_offer(&db, &verified.offer.offer_id).await?;
    let Some(winner) = winner else {
        if pair_is_blocked(&db, &issuer_user, &claimant_user).await? {
            return json_err(409, "contact_unavailable");
        }
        return json_err(409, "offer_unavailable");
    };
    if winner.claim_id_hex != verified.claim_id_hex || winner.claimant_user_id != claimant_user {
        return json_err(409, "offer_consumed");
    }
    if winner.grant_applied != 1 {
        return json_err(409, "contact_unavailable");
    }
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &issuer_user).await;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &claimant_user).await;
    Response::from_json(&serde_json::json!({
        "offer_id": verified.offer.offer_id,
        "claim_id_hex": verified.claim_id_hex,
        "status": "consumed",
        "grant_id": winner.grant_id,
        "idempotent": stored_offer.consumed_claim_id.as_deref() == Some(&winner.claim_id_hex),
    }))
}

/// `GET /contacts/qr/offers/:id/status` — issuer-only status. It reveals no
/// capability material and never allows another member to enumerate offers.
pub async fn offer_status(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let Some(offer_id) = ctx.param("id") else {
        return json_err(400, "bad_request");
    };
    // Mobile polls every 2 s (~30/min per offer); 90/min covers three concurrent
    // offers (the same ceiling as link:status).
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("qr:status:{}", auth.user_id),
        90,
        60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let db = ctx.env.d1("DB")?;
    let row: Option<StatusRow> = db
        .prepare(
            "SELECT o.offer_id,o.offer_hash_hex,o.expires_at_ms,o.consumed_at_ms,
                    o.consumed_claim_id,c.claimant_user_id,c.grant_id
               FROM contact_qr_offers o
               LEFT JOIN contact_qr_claims c ON c.offer_id=o.offer_id
              WHERE o.offer_id=? AND o.issuer_user_id=? LIMIT 1",
        )
        .bind(&[d1_text(offer_id), d1_text(&auth.user_id)])?
        .first(None)
        .await?;
    let Some(row) = row else {
        return json_err(404, "offer_not_found");
    };
    let status = if row.consumed_claim_id.is_some() {
        "consumed"
    } else if now_ms() as i64 >= row.expires_at_ms {
        "expired"
    } else {
        "pending"
    };
    Response::from_json(&serde_json::json!({
        "offer_id": row.offer_id,
        "offer_hash_hex": row.offer_hash_hex,
        "status": status,
        "expires_at_ms": row.expires_at_ms,
        "consumed_at_ms": row.consumed_at_ms,
        "claimant_user_id": row.claimant_user_id,
        "grant_id": row.grant_id,
    }))
}

async fn principal_is_authoritative(
    db: &D1Database,
    principal: &ContactPrincipalV2,
    expected_list_rev: Option<i64>,
) -> Result<bool> {
    let row: Option<AuthorityRow> = db
        .prepare(
            "SELECT u.identity_ed_pub AS root_ed,u.identity_pubkey AS root_x,
                    u.device_list_rev,d.ed_pub AS device_ed,d.x_pub AS device_x
               FROM users u JOIN devices d ON d.user_id=u.id
              WHERE u.id=? AND d.device_id=? AND d.revoked_at IS NULL LIMIT 1",
        )
        .bind(&[d1_text(&principal.user_id), d1_text(&principal.device_id)])?
        .first(None)
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if expected_list_rev.is_some_and(|rev| row.device_list_rev != rev) {
        return Ok(false);
    }
    let Some(root_ed) = row.root_ed else {
        return Ok(false);
    };
    let claimed_root_ed = match decode_canonical_b64_fixed(
        &principal.root_ed_pub_b64,
        ED25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    ) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let claimed_root_x = match decode_canonical_b64_fixed(
        &principal.root_x_pub_b64,
        X25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    ) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let claimed_device_ed = match decode_canonical_b64_fixed(
        &principal.device_ed_pub_b64,
        ED25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    ) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let claimed_device_x = match decode_canonical_b64_fixed(
        &principal.device_x_pub_b64,
        X25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    ) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    Ok(root_ed == claimed_root_ed
        && row.root_x == claimed_root_x
        && row.device_ed == claimed_device_ed
        && row.device_x == claimed_device_x)
}

async fn pair_is_blocked(db: &D1Database, a: &str, b: &str) -> Result<bool> {
    let row: Option<ExistsRow> = db
        .prepare(
            "SELECT 1 AS n FROM contact_blocks
              WHERE (blocker_user_id=? AND blocked_user_id=?)
                 OR (blocker_user_id=? AND blocked_user_id=?) LIMIT 1",
        )
        .bind(&[d1_text(a), d1_text(b), d1_text(b), d1_text(a)])?
        .first(None)
        .await?;
    Ok(row.is_some_and(|v| v.n == 1))
}

async fn fetch_offer(db: &D1Database, offer_id: &str) -> Result<Option<StoredOfferRow>> {
    db.prepare(
        "SELECT offer_id,offer_hash_hex,issuer_user_id,issuer_device_id,offer_json,
                expires_at_ms,consumed_at_ms,consumed_claim_id
           FROM contact_qr_offers WHERE offer_id=? LIMIT 1",
    )
    .bind(&[d1_text(offer_id)])?
    .first(None)
    .await
}

async fn fetch_claim_for_offer(db: &D1Database, offer_id: &str) -> Result<Option<StoredClaimRow>> {
    db.prepare(
        "SELECT claim_id_hex,claimant_user_id,grant_applied,grant_id
           FROM contact_qr_claims WHERE offer_id=? LIMIT 1",
    )
    .bind(&[d1_text(offer_id)])?
    .first(None)
    .await
}

fn offer_response(row: &StoredOfferRow, now_ms_value: i64) -> Result<Response> {
    let status = if row.consumed_claim_id.is_some() {
        "consumed"
    } else if now_ms_value >= row.expires_at_ms {
        "expired"
    } else {
        "pending"
    };
    Response::from_json(&serde_json::json!({
        "offer_id": row.offer_id,
        "offer_hash_hex": row.offer_hash_hex,
        "status": status,
        "expires_at_ms": row.expires_at_ms,
        "consumed_at_ms": row.consumed_at_ms,
    }))
}

fn protocol_error_response(error: VerifyError) -> Result<Response> {
    let (status, code) = match error.kind {
        VerifyErrorKind::WrongServer => (403, "wrong_server"),
        VerifyErrorKind::Expired => (410, "offer_expired"),
        VerifyErrorKind::NotYetValid => (400, "offer_not_yet_valid"),
        VerifyErrorKind::InvalidSignature => (403, "signature_invalid"),
        VerifyErrorKind::InvalidCapability | VerifyErrorKind::InvalidCapabilityProof => {
            (403, "capability_invalid")
        }
        VerifyErrorKind::OfferMismatch => (409, "offer_mismatch"),
        VerifyErrorKind::SelfClaim => (409, "self_claim"),
        _ => (400, "invalid_contact_qr"),
    };
    let _ = error.message; // class-only response; never echo untrusted material.
    json_err(status, code)
}

const INSERT_CLAIM_SQL: &str = "INSERT OR IGNORE INTO contact_qr_claims
       (claim_id_hex,offer_id,claimant_user_id,claimant_device_id,claimant_list_rev,
        nonce_hash_hex,claimed_at_ms,capability_proof_hash_hex,grant_applied,grant_id,created_at)
     SELECT ?1,?2,?3,?4,?5,?6,?7,?8,0,NULL,?9
       FROM contact_qr_offers o
      WHERE o.offer_id=?2 AND o.consumed_claim_id IS NULL AND o.expires_at_ms>?10
        AND NOT EXISTS (SELECT 1 FROM contact_blocks b WHERE
          (b.blocker_user_id=o.issuer_user_id AND b.blocked_user_id=?3) OR
          (b.blocker_user_id=?3 AND b.blocked_user_id=o.issuer_user_id))";

const CONSUME_OFFER_SQL: &str = "UPDATE contact_qr_offers
        SET consumed_at_ms=COALESCE(consumed_at_ms,?3),
            consumed_claim_id=COALESCE(consumed_claim_id,?1)
      WHERE offer_id=?2 AND (consumed_claim_id IS NULL OR consumed_claim_id=?1)
        AND EXISTS (SELECT 1 FROM contact_qr_claims c
                     WHERE c.offer_id=?2 AND c.claim_id_hex=?1)";

pub(crate) const UPSERT_QR_GRANT_SQL: &str = concat!(
    "INSERT INTO contact_grants
       (grant_id,user_low,user_high,source,trust,accepted_request_id,created_at,revoked_at,revoked_by)
     SELECT 'qr:'||o.offer_id,
            ",
    crate::contact_grant::contact_pair_order_sql!("o.issuer_user_id", "c.claimant_user_id"),
    ",
            'qr','qr_verified',NULL,?2,NULL,NULL
       FROM contact_qr_claims c JOIN contact_qr_offers o ON o.offer_id=c.offer_id
      WHERE c.claim_id_hex=?1 AND c.grant_applied=0 AND o.consumed_claim_id=c.claim_id_hex
        AND ",
    crate::contact_grant::contact_pair_block_guard_sql!("o.issuer_user_id", "c.claimant_user_id"),
    "
     ON CONFLICT(user_low,user_high) DO UPDATE SET
       source='qr',trust='qr_verified',accepted_request_id=NULL,created_at=excluded.created_at,
       revoked_at=NULL,revoked_by=NULL"
);

const MARK_CLAIM_GRANT_SQL: &str = "UPDATE contact_qr_claims AS c
        SET grant_applied=1,
            grant_id=(SELECT g.grant_id FROM contact_grants g JOIN contact_qr_offers o
                       ON o.offer_id=c.offer_id
                      WHERE g.user_low=CASE WHEN o.issuer_user_id<c.claimant_user_id
                                             THEN o.issuer_user_id ELSE c.claimant_user_id END
                        AND g.user_high=CASE WHEN o.issuer_user_id<c.claimant_user_id
                                              THEN c.claimant_user_id ELSE o.issuer_user_id END
                        AND g.revoked_at IS NULL LIMIT 1)
      WHERE c.claim_id_hex=?1 AND c.grant_applied=0
        AND EXISTS (SELECT 1 FROM contact_grants g JOIN contact_qr_offers o
                     ON o.offer_id=c.offer_id
                    WHERE g.user_low=CASE WHEN o.issuer_user_id<c.claimant_user_id
                                           THEN o.issuer_user_id ELSE c.claimant_user_id END
                      AND g.user_high=CASE WHEN o.issuer_user_id<c.claimant_user_id
                                            THEN c.claimant_user_id ELSE o.issuer_user_id END
                      AND g.revoked_at IS NULL)";

const INSERT_ISSUER_REVISION_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id,account_id,peer_id,entity,entity_id,action,created_at)
     SELECT ?1,o.issuer_user_id,c.claimant_user_id,'grant',c.grant_id,'upsert',?2
       FROM contact_qr_claims c JOIN contact_qr_offers o ON o.offer_id=c.offer_id
      WHERE c.claim_id_hex=?3 AND c.grant_applied=1";

const INSERT_CLAIMANT_REVISION_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id,account_id,peer_id,entity,entity_id,action,created_at)
     SELECT ?1,c.claimant_user_id,o.issuer_user_id,'grant',c.grant_id,'upsert',?2
       FROM contact_qr_claims c JOIN contact_qr_offers o ON o.offer_id=c.offer_id
      WHERE c.claim_id_hex=?3 AND c.grant_applied=1";

#[path = "contact_qr_verify.rs"]
mod contact_qr_verify;
use contact_qr_verify::*;

#[cfg(test)]
#[path = "contact_qr_tests.rs"]
mod tests;
