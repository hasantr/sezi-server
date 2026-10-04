use crate::auth::hashing::{hash_code, sha256_hex};
use crate::auth::invite_attribution::CLAIM_INVITE_SQL;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::email::mailer::send_verification_code;
use crate::ratelimit::{
    admit_env, client_ip, peek_env, per_invite_limit, Admission, DOOR_IP_CEILING, DOOR_MISS_LIMIT,
    DOOR_WINDOW_SECS,
};
use crate::respond::{json_err, rate_limited};
use crate::utils::{now_secs, random_bytes};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RedeemBody {
    token: Option<String>,
    email: String,
}

const CODE_TTL_SEC: u64 = 10 * 60;

pub async fn redeem(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Slim template: if the ENV var is missing, assume "prod" (FAIL-SECURE — never
    // fall back to dev behaviour, so the rate limit stays on and dev_code does not
    // leak). Deployments that do set ENV behave bit-identically.
    let limited = crate::utils::var_or(&ctx.env, "ENV", "prod") == "prod";
    // Keyed per address only as a CEILING and a MISS counter; the limit a lecture hall actually
    // meets is the per-invite one below (`ratelimit`, "The door"). The KV binding is OPTIONAL
    // (slim template): without it, everything here continues unlimited. Every refusal carries
    // `Retry-After`: the person at the door is told when, not "later".
    let ip = client_ip(&req, &ctx.env);
    let miss_key = format!("auth:redeem:miss:{ip}");
    if limited {
        let key = format!("auth:redeem:ip:{ip}");
        if let Admission::Refused { retry_after_s } =
            admit_env(&ctx.env, &key, DOOR_IP_CEILING, DOOR_WINDOW_SECS).await
        {
            return rate_limited(retry_after_s);
        }
        if let Admission::Refused { retry_after_s } =
            peek_env(&ctx.env, &miss_key, DOOR_MISS_LIMIT, DOOR_WINDOW_SECS).await
        {
            return rate_limited(retry_after_s);
        }
    }
    // A refused redeem is charged to the address's miss counter, then answered as it always was.
    let refuse = |code: &'static str| {
        let env = ctx.env.clone();
        let key = miss_key.clone();
        async move {
            if limited {
                let _ = admit_env(&env, &key, DOOR_MISS_LIMIT, DOOR_WINDOW_SECS).await;
            }
            json_err(403, code)
        }
    };

    let body: RedeemBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    if body.email.len() > 254 || !body.email.contains('@') {
        return json_err(400, "bad_request");
    }
    if let Some(t) = &body.token {
        if t.len() < 8 || t.len() > 128 {
            return json_err(400, "bad_request");
        }
    }

    let now = now_secs();
    let db = ctx.env.d1("DB")?;

    // Every server is invite-only (`server::join_mode`): no invite, no code. The stored
    // `join_mode` is deliberately not read — a server that once stored `open` must not
    // start admitting walk-ins again.
    let token = match &body.token {
        Some(t) => t.clone(),
        None => return json_err(403, "invite_required"),
    };
    // A typed code (`K7QM-4827`) stands for its invite's token; everything after this line sees
    // only tokens. Tried FIRST, because the grammars cannot overlap: a code is at most 16
    // characters before normalising and a bearer token is 24 (`auth::invite_code`).
    let token = match crate::auth::invite_code::normalize(&token) {
        Some(code) => match token_for_code(&db, &code).await? {
            Some(token) => token,
            None => return refuse("invalid_invite").await,
        },
        None => token,
    };
    let token_hash = sha256_hex(&token);

    // The invite's own window, sized by its seats. Only for a token that names an invite: garbage
    // is already paid for by the miss counter and must not mint KV keys of its own.
    let profile = crate::auth::class_invite::kind_of(&db, &token).await?;
    if let (true, Some((_, seats))) = (limited, &profile) {
        let key = format!("auth:redeem:inv:{}", &token_hash[..32]);
        if let Admission::Refused { retry_after_s } =
            admit_env(&ctx.env, &key, per_invite_limit(*seats), DOOR_WINDOW_SECS).await
        {
            return rate_limited(retry_after_s);
        }
    }

    // A class invite has a claim of its own (`auth::class_invite`): many seats, one ledger row per
    // redemption, no introduction. Routed by kind BEFORE anything is claimed, so a class token never
    // reaches the single-use claim below and the genesis decision inside it stays untouched.
    let redemption = if profile.as_ref().is_some_and(|(kind, _)| kind == "class") {
        match crate::auth::class_invite::claim(&db, &token, &token_hash, &body.email, now as i64)
            .await?
        {
            Some(key) => Redemption {
                ledger_key: key,
                raw_token: None,
            },
            None => return refuse("invalid_invite").await,
        }
    } else {
        match claim_personal(&req, &ctx, &db, &token, &token_hash, now).await? {
            true => Redemption {
                ledger_key: token_hash.clone(),
                raw_token: Some(token.clone()),
            },
            false => return refuse("invalid_invite").await,
        }
    };

    let code = generate_code();
    let code_hash = hash_code(&code);

    // The raw invite_token is only a short-lived legacy bridge for a personal invite; the durable
    // binding goes through invite_token_hash — the ledger key of THIS redemption, which for a class
    // invite is not the token's hash. A class redemption bridges no raw token at all: verify's
    // `invite_tokens.used_by` write would otherwise stamp one student onto a row a hundred share.
    // When verify completes it deletes the VC row, and with it both values.
    db.prepare(
        "INSERT INTO verification_codes
           (email, code_hash, attempts, invite_token, invite_token_hash, expires_at, created_at)
         VALUES (?, ?, 0, ?, ?, ?, ?)
         ON CONFLICT(email) DO UPDATE SET
            code_hash = excluded.code_hash,
            attempts = 0,
            invite_token = excluded.invite_token,
            invite_token_hash = excluded.invite_token_hash,
            expires_at = excluded.expires_at,
            created_at = excluded.created_at",
    )
    .bind(&[
        d1_text(&body.email),
        d1_text(&code_hash),
        d1_opt_text(redemption.raw_token.as_deref()),
        d1_text(&redemption.ledger_key),
        d1_int((now + CODE_TTL_SEC) as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    send_verification_code(&ctx.env, &body.email, &code).await?;

    // The invite IS the registration authority, and because the onboarding client uses
    // a synthetic `@sezgi.local` address, mailing the code to a real inbox is pointless
    // (the user would never see it). So once the invite is claimed we return dev_code
    // even in prod — safe, since registration without an invite is impossible. The
    // e-mail-only path this used to keep for open mode went with open mode.
    // `join_mode` stays in the body for clients that read it.
    Response::from_json(&serde_json::json!({
        "ok": true,
        "dev_code": code,
        "join_mode": crate::server::join_mode::JOIN_MODE,
    }))
}

/// The token behind a canonical code, if any invite has it. Expiry, revocation and seats are the
/// claims' business, not this lookup's: it only translates.
pub(crate) const TOKEN_FOR_CODE_SQL: &str =
    "SELECT token FROM invite_tokens WHERE code_hash = ? LIMIT 1";

async fn token_for_code(db: &D1Database, canonical: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct TokenRow {
        token: String,
    }
    let row: Option<TokenRow> = db
        .prepare(TOKEN_FOR_CODE_SQL)
        .bind(&[d1_text(&crate::auth::invite_code::code_hash(canonical))])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.token))
}

/// What a won claim hands the verification-code bridge.
struct Redemption {
    /// The `invite_attributions` key of this redemption.
    ledger_key: String,
    /// The raw token, bridged for a personal invite only (see the INSERT above).
    raw_token: Option<String>,
}

/// The single-use claim of a personal (or the genesis) invite — today's path, unchanged. Returns
/// whether the claim was won.
async fn claim_personal(
    req: &Request,
    ctx: &RouteContext<()>,
    db: &D1Database,
    token: &str,
    token_hash: &str,
    now: u64,
) -> Result<bool> {
    // Active tokens minted before 0031 have a NULL hash column. Before claiming,
    // write the deterministic hash onto the source TTL row; newer invites already
    // carry it. A hash mismatch means DB corruption, in which case the UPDATE and
    // the claim are both no-ops — fail-closed.
    db.prepare(
        "UPDATE invite_tokens SET token_hash = COALESCE(token_hash, ?)
          WHERE token = ? AND used = 0 AND expires_at > ?
            AND (token_hash IS NULL OR token_hash = ?)",
    )
    .bind(&[
        d1_text(token_hash),
        d1_text(token),
        d1_int(now as i64),
        d1_text(token_hash),
    ])?
    .run()
    .await?;
    #[derive(Deserialize)]
    struct ClaimRow {
        #[allow(dead_code)] // read only for its presence (the single-writer result)
        invite_token_hash: String,
    }
    // P0: the ledger INSERT is the claim's LINEARIZATION POINT. Thanks to the
    // token-hash primary key, only one of two parallel redeems gets a RETURNING
    // row — the second loses even before the source invite is flipped to
    // `used=1`. The same statement snapshots the inviter id, the Ed root, whether
    // this is the genesis invite, and the metadata, so verify keeps the binding even
    // if maintenance later deletes the token. The raw bearer token is never written
    // to the ledger.
    // With a claim secret configured, only the request that carries it may redeem the genesis
    // invite (see CLAIM_INVITE_SQL); a refused genesis claim reads as any invalid invite.
    let genesis_allowed = crate::auth::claim::claim_authorized(req, &ctx.env);
    let claim: Option<ClaimRow> = db
        .prepare(CLAIM_INVITE_SQL)
        .bind(&[
            d1_text(token_hash),
            d1_int(now as i64),
            d1_text(token),
            d1_int(now as i64),
            d1_text(token_hash),
            d1_int(genesis_allowed as i64),
        ])?
        .first(None)
        .await?;
    if claim.is_none() {
        return Ok(false);
    }
    // NOTE:`email_hint` is now a cosmetic LABEL/NAME (free text from
    // create_invite) and is NOT matched against the e-mail during redeem. The old
    // email binding was REMOVED: it was useless against synthetic
    // u...@sezgi.local addresses and turned name labels into 400/mismatch errors.
    // The invite code is the single secret; if it is valid (used=0 and not
    // expired) the redeem succeeds.
    // Legacy/API compatibility: also flip the source token to used. Since the
    // claim authority is now the ledger primary key, this UPDATE affecting 0 rows
    // (an admin revoke or TTL-GC racing right after the claim) cannot undo a
    // won redeem — the attribution is already snapshotted and verify proceeds
    // safely. `uses` follows `used`: a personal invite has one seat and this is it.
    db.prepare(
        "UPDATE invite_tokens SET used = 1, uses = 1
          WHERE token = ? AND token_hash = ? AND used = 0 AND kind = 'personal'",
    )
    .bind(&[d1_text(token), d1_text(token_hash)])?
    .run()
    .await?;
    // The landing group, if the invite named one, onto this redemption's ledger row — beside the
    // claim rather than inside it (`auth::landing`).
    db.prepare(crate::auth::landing::SNAPSHOT_PERSONAL_LANDING_SQL)
        .bind(&[d1_text(token_hash)])?
        .run()
        .await?;
    Ok(true)
}

fn generate_code() -> String {
    let buf = random_bytes(4);
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) % 1_000_000;
    format!("{:06}", n)
}
