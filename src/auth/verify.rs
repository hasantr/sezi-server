use crate::auth::hashing::{sha256_hex, verify_code};
use crate::auth::invite_attribution::{
    APPLY_INVITE_GRANT_SQL, INSERT_INVITER_GRANT_REVISION_SQL, INSERT_JOINER_GRANT_REVISION_SQL,
    LOAD_INVITER_SQL, MARK_ATTRIBUTED_SQL, UPGRADE_LEGACY_CLAIM_SQL,
};
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_blob, d1_int, d1_null, d1_opt_text, d1_prekey_id, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::json_err;
use crate::utils::{b64_decode, b64u_encode, now_secs, random_b64u, random_bytes};
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

#[derive(Deserialize)]
struct PrekeyBundle {
    prekey_id: u64,
    prekey_pub_b64: String,
    signature_b64: String,
}

#[derive(Deserialize)]
struct Otk {
    prekey_id: u64,
    prekey_pub_b64: String,
}

#[derive(Deserialize)]
struct VerifyBody {
    email: String,
    code: String,
    identity_pubkey_b64: String,
    signed_prekey: PrekeyBundle,
    otks: Vec<Otk>,
    display_name: Option<String>,
    // M2-S1 (optional; an older body without these works EXACTLY as before):
    // device_id = this installation's device identity (16 hex chars);
    // identity_ed_pub_b64 = the user's Ed25519 signing public key (base64). When
    // absent, the pre-M2-S1 behaviour applies.
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    identity_ed_pub_b64: Option<String>,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;

pub async fn verify(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Slim template: if the ENV var is missing, assume "prod" (FAIL-SECURE). The KV
    // binding is OPTIONAL — without it we continue unlimited, see
    // ratelimit::check_rate_limit_env.
    let env_name = crate::utils::var_or(&ctx.env, "ENV", "prod");
    if env_name == "prod" {
        let ip = req
            .headers()
            .get("cf-connecting-ip")
            .ok()
            .flatten()
            .unwrap_or_else(|| "local".into());
        if !check_rate_limit_env(&ctx.env, &format!("auth:verify:{}", ip), 5, 5 * 60).await {
            return json_err(429, "rate_limited");
        }
    }

    // SAHA-FIX (2026-06-27): req.json() goes through workerd's JS JSON.parse, so a u64
    // prekey_id (OTK) above 2^53 is rounded to f64 → serde u64 FAILS → registration
    // 400. Reading text() and parsing with Rust's serde_json keeps full precision.
    let raw = match req.text().await {
        Ok(t) => t,
        Err(_) => return json_err(400, "bad_request"),
    };
    let body: VerifyBody = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    let display_name = match body.display_name.as_deref() {
        Some(value) => match crate::auth::profile::validate_display_name(value) {
            Some(name) => Some(name),
            None => return json_err(400, "invalid_display_name"),
        },
        None => None,
    };

    if body.code.len() != 6 || !body.code.chars().all(|c| c.is_ascii_digit()) {
        return json_err(400, "bad_request");
    }
    if body.otks.len() > 100 {
        return json_err(400, "bad_request");
    }

    let now = now_secs();
    let db = ctx.env.d1("DB")?;

    #[derive(Deserialize)]
    struct VcRow {
        code_hash: String,
        attempts: i32,
        expires_at: i64,
        invite_token: Option<String>,
        invite_token_hash: Option<String>,
    }
    let vc: Option<VcRow> = db
        .prepare(
            "SELECT code_hash, attempts, expires_at, invite_token, invite_token_hash
               FROM verification_codes WHERE email = ? LIMIT 1",
        )
        .bind(&[d1_text(&body.email)])?
        .first(None)
        .await?;

    let vc = match vc {
        Some(v) if (v.expires_at as u64) > now => v,
        _ => return json_err(403, "no_code"),
    };
    if vc.attempts >= 5 {
        return json_err(403, "too_many_attempts");
    }
    if !verify_code(&body.code, &vc.code_hash) {
        db.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ?")
            .bind(&[d1_text(&body.email)])?
            .run()
            .await?;
        return json_err(403, "wrong_code");
    }

    // For verification codes that were already redeemed when 0031 was deployed, the
    // new hash column is NULL while the raw legacy invite_token is populated. Once the
    // correct code has been proven, SHA-256 the token in Rust, build the ledger
    // snapshot from the used source invite, and upgrade the VC row onto the hash
    // bridge. The ledger NEVER receives the raw bearer secret.
    if vc.invite_token_hash.is_none() {
        if let Some(raw_invite_token) = vc.invite_token.as_deref() {
            let token_hash = sha256_hex(raw_invite_token);
            #[derive(Deserialize)]
            struct UpgradeRow {
                #[allow(dead_code)]
                invite_token_hash: String,
            }
            let upgraded: Option<UpgradeRow> = db
                .prepare(UPGRADE_LEGACY_CLAIM_SQL)
                .bind(&[
                    d1_text(&token_hash),
                    d1_int(now as i64),
                    d1_text(raw_invite_token),
                ])?
                .first(None)
                .await?;
            // If the used source invite really exists (either freshly inserted, or the
            // ledger already had the same hash), bind the two short-lived tables by
            // hash. If the source is gone, do NOT invent a lost attribution — the
            // auto-intro stays fail-closed at None.
            if upgraded.is_some() {
                db.batch(vec![
                    db.prepare(
                        "UPDATE invite_tokens SET token_hash = COALESCE(token_hash, ?)
                          WHERE token = ? AND (token_hash IS NULL OR token_hash = ?)",
                    )
                    .bind(&[
                        d1_text(&token_hash),
                        d1_text(raw_invite_token),
                        d1_text(&token_hash),
                    ])?,
                    db.prepare(
                        "UPDATE verification_codes SET invite_token_hash = ?
                          WHERE email = ? AND invite_token = ? AND invite_token_hash IS NULL",
                    )
                    .bind(&[
                        d1_text(&token_hash),
                        d1_text(&body.email),
                        d1_text(raw_invite_token),
                    ])?,
                ])
                .await?;
            }
        }
    }

    let user_id = Uuid::new_v4().to_string();
    let identity_pubkey =
        b64_decode(&body.identity_pubkey_b64).map_err(|_| Error::RustError("bad ident".into()))?;
    let spk_pub = b64_decode(&body.signed_prekey.prekey_pub_b64)
        .map_err(|_| Error::RustError("bad spk pub".into()))?;
    let spk_sig = b64_decode(&body.signed_prekey.signature_b64)
        .map_err(|_| Error::RustError("bad spk sig".into()))?;

    // M2-S1: optional Ed25519 signing public key (absent → NULL, i.e. the old
    // behaviour).
    let identity_ed_pub: Option<Vec<u8>> = match body.identity_ed_pub_b64.as_deref() {
        Some(s) => Some(b64_decode(s).map_err(|_| Error::RustError("bad ed pub".into()))?),
        None => None,
    };
    let device_id = body.device_id.as_deref();

    // SELF-HEAL ORDERING (2026-07-06 sezi-server2 incident): sign the token BEFORE any
    // DB write. The old flow signed AFTER the user INSERT (and after the invite/code
    // mutations), so when a broken JWT key made signing fail, the user row was already
    // written — burning the owner slot on a device-less, token-less "ghost" user
    // (/bootstrap then returns 410 and the server is permanently locked). Signing and
    // refresh-token generation are pure CPU + key work with no DB access, so a failure
    // here means a 500 with zero DB mutations and NO ghost can be created. The success
    // path is bit-identical: same token, same writes, same relative order.
    let access_token = sign_access_token(&ctx.env, &user_id, device_id)?;
    let refresh = generate_refresh_token();
    let refresh_hash = sha256_hex(&refresh);

    // The first account to register becomes the owner (the server's founder, and
    // protected as such). Everyone after that is a member, and the owner can promote
    // members to admin later via set_role.
    #[derive(Deserialize)]
    struct UserRow {
        #[allow(dead_code)] // existence check only; the value is never read
        id: String,
    }
    let any_user: Option<UserRow> = db
        .prepare("SELECT id FROM users LIMIT 1")
        .first(None)
        .await?;
    let role = if any_user.is_none() {
        "owner"
    } else {
        "member"
    };

    db.prepare(
        "INSERT INTO users (id, email, identity_pubkey, identity_ed_pub, display_name, fcm_token, role, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&user_id),
        d1_text(&body.email),
        d1_blob(&identity_pubkey),
        match &identity_ed_pub {
            Some(b) => d1_blob(b),
            None => d1_null(),
        },
        d1_opt_text(display_name.as_deref()),
        d1_text(role),
        d1_int(now as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    // Directory V2 nudge log. The full roster remains virtual and policy-
    // filtered; this row only advances authoritative revision pull. No email,
    // last-seen or key material is copied into the log.
    db.prepare(
        "INSERT INTO directory_revisions
           (event_id, user_id, change_type, profile_revision, created_at)
         VALUES (?, ?, 'upsert', 1, ?)",
    )
    .bind(&[
        d1_text(&random_b64u(18)),
        d1_text(&user_id),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    db.prepare(
        "INSERT INTO signed_prekeys (user_id, prekey_id, prekey_pub, signature, created_at, device_id)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&user_id),
        // SAHA-FIX (2026-06-28): the registration SPK prekey_id is 53-bit masked too,
        // for parity with replenish. Without the mask, reading it back through workerd
        // makes the bundle 500 — a first-contact wedge.
        d1_prekey_id(body.signed_prekey.prekey_id),
        d1_blob(&spk_pub),
        d1_blob(&spk_sig),
        d1_int(now as i64),
        d1_text(device_id.unwrap_or("")), // device_id is NOT NULL DEFAULT '' (mig 0015) -> sentinel
    ])?
    .run()
    .await?;

    // Batch-insert the OTKs in groups of 20 to stay under D1's placeholder limit.
    // M2-S1 added the device_id column; when the body omits it we bind the ''
    // sentinel (see the NOT NULL note below), which marks legacy/primary.
    if !body.otks.is_empty() {
        for chunk in body.otks.chunks(20) {
            let mut sql = String::from(
                "INSERT OR IGNORE INTO one_time_prekeys (user_id, prekey_id, prekey_pub, consumed, device_id) VALUES ",
            );
            let mut binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(chunk.len() * 4);
            // Decode first so the pub_bytes outlive the binds vector, then bind.
            let mut pubs: Vec<Vec<u8>> = Vec::with_capacity(chunk.len());
            for k in chunk {
                let p = b64_decode(&k.prekey_pub_b64)
                    .map_err(|_| Error::RustError("bad otk pub".into()))?;
                pubs.push(p);
            }
            for (i, (k, p)) in chunk.iter().zip(pubs.iter()).enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str("(?, ?, ?, 0, ?)");
                binds.push(d1_text(&user_id));
                // SAHA-FIX (2026-06-28): registration OTK prekey_id is 53-bit masked
                // (parity with replenish).
                binds.push(d1_prekey_id(k.prekey_id));
                binds.push(d1_blob(p));
                // mig 0016: one_time_prekeys.device_id is NOT NULL DEFAULT '', so
                // binding NULL would violate NOT NULL; legacy/primary uses the ''
                // sentinel (the primary key is device-scoped).
                binds.push(d1_text(device_id.unwrap_or("")));
            }
            db.prepare(&sql).bind(&binds)?.run().await?;
        }
    }

    // CRYPTOGRAPHIC card↔invite binding (Hamle A / Codex final-review BLOCKER #1):
    // load the inviter's user_id AND identity_ed_pub from the durable ledger snapshot
    // taken at redeem time, and return them as `inviter_user_id` + `inviter_ed_pub`.
    // The joining client cross-checks BOTH the user_id and the ed_pub of the contact
    // card in the envelope against these. Matching the UUID alone is NOT enough: the
    // card binds user_id to ed_pub with a signature, but an attacker can mint a card
    // claiming the same UUID under a DIFFERENT ed key — hence the ed_pub cross-check.
    // The server's recorded primary ed key is the trust root here, because the server
    // is the membership authority.
    // P0: this does NOT depend on the source invite_tokens row. Even if TTL-GC deletes
    // the token between redeem and verify, the invite_attributions snapshot survives.
    // A NULL owner_user_id (open mode / no token / an older invite) or a NULL
    // identity_ed_pub (an older owner from before 0012) yields None, and the client
    // then skips auto-intro fail-closed.
    #[derive(Deserialize)]
    struct InviterRow {
        owner_user_id: Option<String>,
        inviter_ed_pub: Option<String>,
    }
    // inviter_ed_pub is a BLOB in the ledger (raw 32 bytes), converted with `hex()`
    // into a DETERMINISTIC uppercase-hex string so there is no base64-variant
    // ambiguity. The client carries the card's ed_pub as base64; the core handler
    // decodes it and hex-uppercases it into the SAME shape before comparing, making
    // the match format-exact.
    let inviter: Option<InviterRow> = db
        // hex(NULL) is '' in SQLite, so the SQL constant uses CASE to yield a real NULL.
        .prepare(LOAD_INVITER_SQL)
        .bind(&[d1_text(&body.email)])?
        .first(None)
        .await?;
    let (inviter_user_id, inviter_ed_pub) = match inviter {
        // Both must be present: without ed_pub the binding cannot be made, so we
        // fail closed to None.
        Some(InviterRow {
            owner_user_id: Some(uid),
            inviter_ed_pub: Some(ed),
        }) => (Some(uid), Some(ed)),
        _ => (None, None),
    };

    // One D1 batch updates the invite→user attribution, the legacy/API token row when
    // present, the bidirectional account contact grant and both accounts' revisions,
    // and then deletes the single-use verification code. A batch is an implicit
    // transaction, so it is impossible for the attribution to complete while the
    // grant/revisions are left half-written, or for the code to be deleted while the
    // attribution is lost. The grant is INSERT OR IGNORE: block/self/null cases are
    // no-ops, and an existing or revoked relationship is NEVER reopened. In open mode
    // invite_token/hash are NULL, so the invite statements are no-ops while the code
    // DELETE still runs normally.
    db.batch(vec![
        db.prepare(MARK_ATTRIBUTED_SQL).bind(&[
            d1_text(&user_id),
            d1_int(now as i64),
            d1_text(&body.email),
        ])?,
        db.prepare(
            "UPDATE invite_tokens
                SET used_by = COALESCE(used_by, ?)
              WHERE token = (SELECT invite_token FROM verification_codes WHERE email = ?)",
        )
        .bind(&[d1_text(&user_id), d1_text(&body.email)])?,
        db.prepare(APPLY_INVITE_GRANT_SQL).bind(&[
            d1_text(&body.email),
            d1_text(&user_id),
            d1_int(now as i64),
        ])?,
        db.prepare(INSERT_INVITER_GRANT_REVISION_SQL).bind(&[
            d1_text(&body.email),
            d1_text(&user_id),
            d1_int(now as i64),
        ])?,
        db.prepare(INSERT_JOINER_GRANT_REVISION_SQL).bind(&[
            d1_text(&body.email),
            d1_text(&user_id),
            d1_int(now as i64),
        ])?,
        db.prepare("DELETE FROM verification_codes WHERE email = ?")
            .bind(&[d1_text(&body.email)])?,
    ])
    .await?;

    // The refresh token's DB row is written in the post-signing block. What matters is
    // that the USER row is not written before signing; the refresh row was already
    // last in the sequence.
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&refresh_hash),
        d1_text(&user_id),
        d1_int((now + REFRESH_TTL_SEC) as i64),
        d1_int(now as i64),
        d1_opt_text(device_id),
    ])?
    .run()
    .await?;

    // Once the registration and grant writes are committed, send both sides nothing but
    // a wake-up nudge: no contact data travels in the frame, each side does an
    // authoritative pull. The joiner publishes its device list only after verify, so the
    // inviter is nudged again when PUT /devices/list commits — that way an initial 404
    // does not become a permanent wedge.
    if let Some(inviter) = inviter_user_id.as_deref() {
        crate::realtime::nudge_contact_update_best_effort(&ctx.env, inviter).await;
        crate::realtime::nudge_contact_update_best_effort(&ctx.env, &user_id).await;
    }

    Response::from_json(&serde_json::json!({
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SEC,
        // Hamle A: the inviter's user_id + primary ed_pub, for the CRYPTOGRAPHIC
        // card↔invite cross-check — the client requires BOTH the user_id and the
        // ed_pub to match. null means open mode / no token / an older invite / no ed
        // key, and the client then skips auto-intro fail-closed. Older clients simply
        // ignore these fields (additive).
        "inviter_user_id": inviter_user_id,
        "inviter_ed_pub": inviter_ed_pub,
    }))
}

fn generate_refresh_token() -> String {
    b64u_encode(&random_bytes(32))
}
