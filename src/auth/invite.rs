use crate::auth::hashing::{hash_code, sha256_hex};
use crate::auth::invite_attribution::CLAIM_INVITE_SQL;
use crate::d1util::{d1_int, d1_text};
use crate::email::mailer::send_verification_code;
use crate::ratelimit::check_rate_limit_env;
use crate::respond::json_err;
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
    let env_name = crate::utils::var_or(&ctx.env, "ENV", "prod");
    if env_name == "prod" {
        let ip = req
            .headers()
            .get("cf-connecting-ip")
            .ok()
            .flatten()
            .unwrap_or_else(|| "local".into());
        // The KV binding is OPTIONAL (slim template): without it, continue unlimited.
        let key = format!("auth:redeem:{}", ip);
        if !check_rate_limit_env(&ctx.env, &key, 5, 5 * 60).await {
            return json_err(429, "rate_limited");
        }
    }

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
    let token_hash = sha256_hex(&token);
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
        d1_text(&token_hash),
        d1_text(&token),
        d1_int(now as i64),
        d1_text(&token_hash),
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
    let genesis_allowed = crate::auth::claim::claim_authorized(&req, &ctx.env);
    let claim: Option<ClaimRow> = db
        .prepare(CLAIM_INVITE_SQL)
        .bind(&[
            d1_text(&token_hash),
            d1_int(now as i64),
            d1_text(&token),
            d1_int(now as i64),
            d1_text(&token_hash),
            d1_int(genesis_allowed as i64),
        ])?
        .first(None)
        .await?;
    if claim.is_none() {
        return json_err(403, "invalid_invite");
    }
    // NOTE: `email_hint` is now a cosmetic LABEL/NAME (free text from
    // create_invite) and is NOT matched against the e-mail during redeem. The old
    // email binding was REMOVED: it was useless against synthetic
    // u...@sezgi.local addresses and turned name labels into 400/mismatch errors.
    // The invite code is the single secret; if it is valid (used=0 and not
    // expired) the redeem succeeds.
    // Legacy/API compatibility: also flip the source token to used. Since the
    // claim authority is now the ledger primary key, this UPDATE affecting 0 rows
    // (an admin revoke or TTL-GC racing right after the claim) cannot undo a
    // won redeem — the attribution is already snapshotted and verify proceeds
    // safely.
    db.prepare(
        "UPDATE invite_tokens SET used = 1
          WHERE token = ? AND token_hash = ? AND used = 0",
    )
    .bind(&[d1_text(&token), d1_text(&token_hash)])?
    .run()
    .await?;

    let code = generate_code();
    let code_hash = hash_code(&code);

    // The raw invite_token is only a short-lived legacy bridge; the durable binding
    // goes through invite_token_hash. When verify completes it deletes the VC row,
    // and with it both values.
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
        d1_text(&token),
        d1_text(&token_hash),
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

fn generate_code() -> String {
    let buf = random_bytes(4);
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) % 1_000_000;
    format!("{:06}", n)
}
