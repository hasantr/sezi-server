use crate::auth::hashing::{sha256_hex, verify_code};
use crate::auth::invite_attribution::{
    APPLY_INVITE_GRANT_SQL, INSERT_INVITER_GRANT_REVISION_SQL, INSERT_JOINER_GRANT_REVISION_SQL,
    DOOR_INVITE_OF_CODE_SQL, LOAD_INVITER_SQL, LOAD_REDEMPTION_SQL, MARK_ATTRIBUTED_SQL,
    UPGRADE_LEGACY_CLAIM_SQL,
};
use crate::auth::jwt::sign_access_token;
use crate::auth::landing::RedemptionRow;
use crate::d1util::{d1_blob, d1_int, d1_null, d1_opt_text, d1_prekey_id, d1_text};
use crate::ratelimit::{
    admit_env, client_ip, per_invite_limit, Admission, DOOR_IP_CEILING, DOOR_WINDOW_SECS,
};
use crate::respond::{json_err, rate_limited};
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
    /// This installation's device identity (16 hex chars). MANDATORY: it becomes the
    /// `device_id` claim of every token this account will ever hold, and the scope of its
    /// signed prekey and OTK pool. An account registered without one had no device to address
    /// and fell back to a `''` sentinel slot that nothing scoped; that population is gone.
    device_id: String,
    /// The user's Ed25519 signing public key (base64). Still optional, and NOT part of the
    /// device work: when absent `users.identity_ed_pub` is NULL and `auth::relogin` backfills
    /// it from the key its challenge signature proves.
    #[serde(default)]
    identity_ed_pub_b64: Option<String>,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;

/// Guesses allowed against one e-mail's 6-digit verification code before it is spent.
const MAX_CODE_ATTEMPTS: i64 = 5;

/// Read the code, test the ceiling and charge the attempt in ONE statement.
///
/// Split into read-then-write it is a limit of 5 SEQUENTIAL guesses, not 5 guesses: requests fired
/// at once all read the same `attempts`, all pass the ceiling and all get a guess, which turns a
/// 6-digit code's 1-in-200 000 chance into whatever concurrency the client can open. `UPDATE ...
/// WHERE attempts < ? RETURNING` makes the test and the increment one atomic act — a row comes back
/// only for a request that WON a slot, and the losers get no `code_hash` to compare against.
///
/// `expires_at > ?` is in the WHERE so an expired code cannot burn an attempt; the answer is
/// `no_code` either way, and without it an attacker could exhaust the counter of a code the victim
/// is about to have re-sent.
///
/// A CORRECT guess is charged too, deliberately: checking the code before charging is the
/// read-then-write shape again. The row is deleted on success, so the charge is invisible.
const CLAIM_CODE_ATTEMPT_SQL: &str = "UPDATE verification_codes SET attempts = attempts + 1
   WHERE email = ? AND attempts < ? AND expires_at > ?
   RETURNING code_hash, invite_token, invite_token_hash";

/// Why no attempt slot was granted — the wire code for a `CLAIM_CODE_ATTEMPT_SQL` that returned
/// nothing. Pure, so the classification is testable without D1.
///
/// `row` is `(attempts, expires_at)` from a plain re-read, or `None` when there is no row at all.
/// Both answers are 403; they differ only in what the client is told to do next, and a request
/// that lost the race to a genuine sibling reads as `no_code` rather than inventing a third state.
fn attempt_denial_code(row: Option<(i64, i64)>, now: i64, max: i64) -> &'static str {
    match row {
        Some((attempts, expires_at)) if expires_at > now && attempts >= max => "too_many_attempts",
        _ => "no_code",
    }
}

/// The role a new account is created with: `owner` for the registration that redeemed the genesis
/// invite, `member` for every other one (an owner promotes members to admin later via set_role).
///
/// The input is the fact the redeem claim recorded (`CLAIM_INVITE_SQL`), never the state of the
/// `users` table. "Owner = whoever registers first on an empty server" made ownership a race any
/// non-genesis registration could enter — open mode on a fresh server, a removed admin's invite,
/// a future multi-use invite — and it held only because nothing else could reach an empty server.
pub(crate) fn role_for_registration(redeemed_genesis: bool) -> &'static str {
    if redeemed_genesis {
        "owner"
    } else {
        "member"
    }
}

pub async fn verify(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Slim template: if the ENV var is missing, assume "prod" (FAIL-SECURE). The KV
    // binding is OPTIONAL — without it we continue unlimited, see
    // ratelimit::check_rate_limit_env. A refusal carries `Retry-After`, as redeem's does.
    // The per-address window is only a CEILING; the limit a lecture hall meets is the invite's own,
    // applied below once the e-mail names the redemption (`ratelimit`, "The door").
    let limited = crate::utils::var_or(&ctx.env, "ENV", "prod") == "prod";
    if limited {
        let key = format!("auth:verify:ip:{}", client_ip(&req, &ctx.env));
        if let Admission::Refused { retry_after_s } =
            admit_env(&ctx.env, &key, DOOR_IP_CEILING, DOOR_WINDOW_SECS).await
        {
            return rate_limited(retry_after_s);
        }
    }

    // `req.json()` goes through workerd's JS JSON.parse, so a u64 prekey_id (OTK) above 2^53 is
    // rounded to f64 → serde u64 fails → registration 400. Reading text() and parsing with Rust's
    // serde_json keeps full precision.
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
    // `''` was the sentinel the device-less population wrote under, so an empty string here is
    // that population arriving by another name and must be refused with the same answer as a
    // missing field.
    if body.device_id.is_empty() || body.device_id.len() > 128 {
        return json_err(400, "device_required");
    }
    if body.otks.len() > 100 {
        return json_err(400, "bad_request");
    }

    let now = now_secs();
    let db = ctx.env.d1("DB")?;

    #[derive(Deserialize)]
    struct VcRow {
        code_hash: String,
        invite_token: Option<String>,
        invite_token_hash: Option<String>,
    }
    // The invite's own window, before an attempt is charged. A code with no redemption behind it
    // has no invite to key by and is refused by the claim below anyway.
    if limited {
        #[derive(Deserialize)]
        struct DoorRow {
            invite_hash: String,
            seats: i64,
        }
        let door: Option<DoorRow> = db
            .prepare(DOOR_INVITE_OF_CODE_SQL)
            .bind(&[d1_text(&body.email)])?
            .first(None)
            .await?;
        if let Some(door) = door {
            let prefix = &door.invite_hash[..32.min(door.invite_hash.len())];
            let key = format!("auth:verify:inv:{prefix}");
            if let Admission::Refused { retry_after_s } =
                admit_env(&ctx.env, &key, per_invite_limit(door.seats), DOOR_WINDOW_SECS).await
            {
                return rate_limited(retry_after_s);
            }
        }
    }
    // One atomic claim: the ceiling test and the increment cannot be separated by a concurrent
    // request. See `CLAIM_CODE_ATTEMPT_SQL`.
    let vc: Option<VcRow> = db
        .prepare(CLAIM_CODE_ATTEMPT_SQL)
        .bind(&[
            d1_text(&body.email),
            d1_int(MAX_CODE_ATTEMPTS),
            d1_int(now as i64),
        ])?
        .first(None)
        .await?;

    let vc = match vc {
        Some(v) => v,
        None => {
            // No slot. Re-read purely to say WHY — the guess itself is already refused, so this
            // costs one query on the failure path and none on the happy one.
            #[derive(Deserialize)]
            struct StateRow {
                attempts: i64,
                expires_at: i64,
            }
            let state: Option<StateRow> = db
                .prepare("SELECT attempts, expires_at FROM verification_codes WHERE email = ? LIMIT 1")
                .bind(&[d1_text(&body.email)])?
                .first(None)
                .await?;
            let code = attempt_denial_code(
                state.map(|s| (s.attempts, s.expires_at)),
                now as i64,
                MAX_CODE_ATTEMPTS,
            );
            return json_err(403, code);
        }
    };
    if !verify_code(&body.code, &vc.code_hash) {
        // The attempt was charged by the claim above, so there is nothing left to write here —
        // which is the point: the increment can no longer be skipped, delayed or lost.
        return json_err(403, "wrong_code");
    }

    // A legacy claim has the hash column NULL and the raw `invite_token` populated. Once the
    // correct code is proven, SHA-256 the token in Rust, build the ledger snapshot from the used
    // source invite and move the VC row onto the hash bridge. The ledger NEVER receives the raw
    // bearer secret.
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

    // Optional Ed25519 signing public key; absent → NULL.
    let identity_ed_pub: Option<Vec<u8>> = match body.identity_ed_pub_b64.as_deref() {
        Some(s) => Some(b64_decode(s).map_err(|_| Error::RustError("bad ed pub".into()))?),
        None => None,
    };
    let device_id = body.device_id.as_str();

    // ORDERING: sign the token BEFORE any DB write. Signing after the user INSERT means a broken
    // JWT key writes the user row and then fails — burning the owner slot on a device-less,
    // token-less "ghost" that makes /bootstrap answer 410 and locks the server (see
    // `bootstrap::is_ghost_owner`, which cleans up after exactly that). Signing and refresh-token
    // generation are pure CPU with no DB access, so a failure here is a 500 with zero mutations.
    let access_token = sign_access_token(&ctx.env, &user_id, device_id)?;
    let refresh = generate_refresh_token();
    let refresh_hash = sha256_hex(&refresh);

    // CRYPTOGRAPHIC card↔invite binding: load the inviter's user_id AND identity_ed_pub from the
    // durable ledger snapshot taken at redeem time. The joining client cross-checks BOTH against
    // the contact card in the envelope. Matching the UUID alone is NOT enough — the card binds
    // user_id to ed_pub with a signature, but an attacker can mint a card claiming the same UUID
    // under a DIFFERENT ed key. The server's recorded primary ed key is the trust root, because the
    // server is the membership authority.
    //
    // It does NOT depend on the source `invite_tokens` row: even if TTL-GC deletes the token
    // between redeem and verify, the `invite_attributions` snapshot survives. A NULL owner_user_id
    // (the genesis invite / no token) or a NULL identity_ed_pub yields None, and the client then
    // skips auto-intro fail-closed.
    //
    // The same read carries the genesis fact the claim recorded, which decides the role below, so
    // it runs before the user row is written.
    #[derive(Deserialize)]
    struct InviterRow {
        owner_user_id: Option<String>,
        inviter_ed_pub: Option<String>,
        genesis: i64,
    }
    // `inviter_ed_pub` is a BLOB in the ledger, converted with `hex()` into uppercase hex so there
    // is no base64-variant ambiguity: the core handler decodes the card's base64 ed_pub into that
    // SAME shape before comparing, making the match format-exact.
    let inviter: Option<InviterRow> = db
        // hex(NULL) is '' in SQLite, so the SQL constant uses CASE to yield a real NULL.
        .prepare(LOAD_INVITER_SQL)
        .bind(&[d1_text(&body.email)])?
        .first(None)
        .await?;
    let redeemed_genesis = inviter.as_ref().is_some_and(|row| row.genesis == 1);
    // The redemption's other half of the snapshot: whether the invite introduces at all. A class
    // invite does not, so verify reports no inviter — the client then skips its auto-intro exactly
    // as it does for the genesis invite — and the grant statements below are no-ops.
    let redemption: Option<RedemptionRow> = db
        .prepare(LOAD_REDEMPTION_SQL)
        .bind(&[d1_text(&body.email)])?
        .first(None)
        .await?;
    let introduces = redemption.as_ref().is_none_or(|r| r.introduce == 1);
    let inviter = inviter.filter(|_| introduces);
    let (inviter_user_id, inviter_ed_pub) = match inviter {
        // Both must be present: without ed_pub the binding cannot be made, so fail closed.
        Some(InviterRow {
            owner_user_id: Some(uid),
            inviter_ed_pub: Some(ed),
            ..
        }) => (Some(uid), Some(ed)),
        _ => (None, None),
    };

    let role = role_for_registration(redeemed_genesis);
    let inserted = db
        .prepare(
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
        .await;
    if let Err(error) = inserted {
        // `idx_one_owner` is the backstop: two genesis claims can be in flight at once (the first
        // one's redeem flips its invite to used, so `/bootstrap` mints a second before the first
        // verifies), and only one of them may become the owner. The loser is told the gate closed,
        // in the words `/bootstrap` uses for it, rather than handed a bare 500.
        if role == "owner" && crate::welcome::owner_exists(&ctx.env).await == Some(true) {
            return json_err(410, "bootstrap_complete");
        }
        return Err(error);
    }

    // Directory V2 nudge log: the roster stays virtual and policy-filtered, and this row only
    // advances the authoritative revision pull. No email, last-seen or key material is copied in.
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
        // The registration SPK prekey_id is 53-bit masked, for parity with replenish: without
        // the mask, reading it back through workerd makes the bundle 500 — a first-contact wedge.
        d1_prekey_id(body.signed_prekey.prekey_id),
        d1_blob(&spk_pub),
        d1_blob(&spk_sig),
        d1_int(now as i64),
        d1_text(device_id),
    ])?
    .run()
    .await?;

    // Batch-insert the OTKs in groups of 20 to stay under D1's placeholder limit.
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
                // 53-bit masked, as above.
                binds.push(d1_prekey_id(k.prekey_id));
                binds.push(d1_blob(p));
                // The pool is device-scoped: this is the pool `keys::bundle` serves peers from
                // for this device, and the one `keys::replenish` tops up.
                binds.push(d1_text(device_id));
            }
            db.prepare(&sql).bind(&binds)?.run().await?;
        }
    }

    // ONE batch — an implicit transaction — so the attribution cannot complete while the
    // grant/revisions are half-written, nor the single-use code be deleted while the attribution is
    // lost. The grant is INSERT OR IGNORE: block/self/null cases are no-ops, and an existing or
    // revoked relationship is NEVER reopened. Where invite_token/hash are NULL (a code bridged
    // before 0031 whose ledger row could not be rebuilt) the invite statements are no-ops while the
    // code DELETE still runs.
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

    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&refresh_hash),
        d1_text(&user_id),
        d1_int((now + REFRESH_TTL_SEC) as i64),
        d1_int(now as i64),
        d1_text(device_id),
    ])?
    .run()
    .await?;

    // The account exists now, so the invite's landing group can take it.
    let landing = match &redemption {
        Some(row) => {
            crate::auth::landing::land_after_verify(&ctx.env, &db, &user_id, row, now as i64).await
        }
        None => None,
    };

    // Once the writes are committed both sides get a wake-up nudge and nothing else: no contact
    // data travels in the frame, each side pulls authoritatively. The joiner publishes its device
    // list only after verify, so the inviter is nudged again when PUT /devices/list commits —
    // otherwise an initial 404 becomes a permanent wedge.
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
        // The inviter's user_id + primary ed_pub for the card↔invite cross-check above; the client
        // requires BOTH to match. null means no inviter (the genesis invite) / no ed key, and the
        // client then skips auto-intro fail-closed. Older clients ignore the fields (additive).
        "inviter_user_id": inviter_user_id,
        "inviter_ed_pub": inviter_ed_pub,
        // Where the invite put the new member (`auth::landing`), or null. `added`: a pending group
        // row the client accepts on its own; `requested`: a join request a group admin decides;
        // `unavailable`: the invite named a group the joiner could not be put into.
        "landing": landing,
    }))
}

fn generate_refresh_token() -> String {
    b64u_encode(&random_bytes(32))
}

#[cfg(test)]
mod tests {
    use super::{attempt_denial_code, CLAIM_CODE_ATTEMPT_SQL, MAX_CODE_ATTEMPTS};
    use rusqlite::{params, Connection, OptionalExtension};

    const NOW: i64 = 1_780_000_000;

    fn codes_table(attempts: i64, expires_at: i64) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE verification_codes (
                 email TEXT PRIMARY KEY,
                 code_hash TEXT NOT NULL,
                 attempts INTEGER NOT NULL DEFAULT 0,
                 expires_at INTEGER NOT NULL,
                 invite_token TEXT,
                 invite_token_hash TEXT
             );",
        )
        .unwrap();
        c.execute(
            "INSERT INTO verification_codes VALUES ('a@b', 'hash', ?, ?, NULL, NULL)",
            params![attempts, expires_at],
        )
        .unwrap();
        c
    }

    /// One claim: `Some(code_hash)` when a slot was granted, `None` when it was refused.
    fn claim(c: &Connection) -> Option<String> {
        c.query_row(
            CLAIM_CODE_ATTEMPT_SQL,
            params!["a@b", MAX_CODE_ATTEMPTS, NOW],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .unwrap()
    }

    fn attempts_of(c: &Connection) -> i64 {
        c.query_row(
            "SELECT attempts FROM verification_codes WHERE email = 'a@b'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// With the test and the increment inside ONE statement the sixth claim finds `attempts < 5`
    /// false and gets no `code_hash` to compare against, no matter how many callers ask at once.
    /// rusqlite runs these sequentially, which is the point: the ceiling lives in the statement, so
    /// it holds without any ordering help from the caller.
    #[test]
    fn the_ceiling_grants_exactly_five_slots_and_no_more() {
        let c = codes_table(0, NOW + 600);
        let granted = (0..8).filter(|_| claim(&c).is_some()).count();
        assert_eq!(granted as i64, MAX_CODE_ATTEMPTS, "exactly five guesses are served");
        assert_eq!(
            attempts_of(&c),
            MAX_CODE_ATTEMPTS,
            "a refused claim must not keep incrementing — the counter stops at the ceiling"
        );
    }

    /// An EXPIRED code burns no attempt. Without the `expires_at` guard in the WHERE, an attacker
    /// could drain the counter of a code the victim is about to re-request.
    #[test]
    fn an_expired_code_is_refused_without_charging_an_attempt() {
        let c = codes_table(0, NOW - 1);
        assert!(claim(&c).is_none());
        assert_eq!(attempts_of(&c), 0);
    }

    /// A correct guess is charged too, and that is fine: the row is deleted on success. What
    /// matters here is that the FIRST claim on a fresh code returns the hash to compare against.
    #[test]
    fn a_fresh_code_hands_back_its_hash_once_per_attempt() {
        let c = codes_table(0, NOW + 600);
        assert_eq!(claim(&c).as_deref(), Some("hash"));
        assert_eq!(attempts_of(&c), 1);
    }

    /// The refusal classification, which is all the client sees of the difference.
    #[test]
    fn denial_reasons_separate_a_spent_code_from_a_missing_one() {
        assert_eq!(attempt_denial_code(None, NOW, 5), "no_code");
        assert_eq!(
            attempt_denial_code(Some((5, NOW + 600)), NOW, 5),
            "too_many_attempts"
        );
        assert_eq!(
            attempt_denial_code(Some((9, NOW + 600)), NOW, 5),
            "too_many_attempts",
            "past the ceiling is still the ceiling"
        );
        assert_eq!(
            attempt_denial_code(Some((5, NOW - 1)), NOW, 5),
            "no_code",
            "an expired code reads as absent, whatever its counter says"
        );
        assert_eq!(
            attempt_denial_code(Some((0, NOW + 600)), NOW, 5),
            "no_code",
            "a live code with attempts left returned no row: a lost race, not a spent code"
        );
    }
}
