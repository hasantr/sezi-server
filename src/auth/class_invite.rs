//! The class-invite claim — one token, many seats (campus plan R5, Wave F; migration 0042).
//!
//! A personal invite is claimed by `CLAIM_INVITE_SQL`: the ledger INSERT keyed by the token hash
//! is the linearization point, so the second redeem of the same token loses. That shape cannot
//! admit a second person by construction, which is why a class invite has a claim of its own —
//! and why the personal claim, and the genesis decision inside it, are left exactly as they are.
//! Redeem routes by `invite_tokens.kind` (`kind_of`) before it claims anything.
//!
//! **The class claim is ONE D1 batch** — an implicit transaction on a single writer — of three
//! statements, in this order:
//!
//! 1. [`RELEASE_SEATS_SQL`]: only when the invite LOOKS full, recount its seats as the
//!    redemptions that verified or still hold a live code. A student who scanned, got a code and
//!    walked away must not keep a seat forever; everyone else's count is untouched.
//! 2. [`TAKE_SEAT_SQL`]: `uses = uses + 1` under `uses < max_uses`, not revoked, not expired —
//!    the linearization point. It stamps a fresh random `claim_nonce` on the row.
//! 3. [`RECORD_REDEMPTION_SQL`]: the ledger row for THIS redemption, inserted only where the
//!    invite carries the nonce statement 2 wrote — i.e. exactly when the seat was won. It is
//!    keyed by `SHA-256(token_hash ':' nonce)`, so a class invite has one ledger row per
//!    redemption, each with its own verify, `used_by` and snapshot, and the primary key still
//!    refuses a duplicate. `genesis` is a literal 0 and `introduce` a literal 0: joining through a
//!    class invite never pairs the joiner with the admin, whatever the source row says.
//!
//! A redemption that is retried by the same e-mail while its code is still live reuses its
//! ledger row ([`INFLIGHT_REDEMPTION_SQL`]) instead of taking a second seat: a lecture hall on bad
//! Wi-Fi retries, and every retry used to cost a seat.

use crate::auth::hashing::sha256_hex;
use crate::d1util::{d1_int, d1_text};
use crate::utils::random_b64u;
use serde::Deserialize;
use worker::*;

/// Seats on one class invite. A lecture hall is the use case; above this an operator mints a
/// second invite. It also bounds the join requests one invite can create in one group.
pub(crate) const MAX_CLASS_SEATS: i64 = 1000;

/// The kind of an invite by its raw token, or `None` for a token that names no row. Read before
/// any claim so a class token never reaches the single-use claim (which would spend the whole
/// invite on one person) and a personal token never reaches this one. `kind` never changes after
/// the row is written, so the read cannot race the claim.
pub(crate) const KIND_SQL: &str =
    "SELECT kind, max_uses FROM invite_tokens WHERE token = ? LIMIT 1";

/// Statement 1. Binds: `?1` token_hash, `?2` now.
pub(crate) const RELEASE_SEATS_SQL: &str = "UPDATE invite_tokens SET uses = (
       SELECT COUNT(*) FROM invite_attributions ia
        WHERE ia.source_hash = invite_tokens.token_hash
          AND (ia.verified_at IS NOT NULL OR EXISTS (
                SELECT 1 FROM verification_codes vc
                 WHERE vc.invite_token_hash = ia.invite_token_hash AND vc.expires_at > ?2)))
     WHERE token_hash = ?1 AND kind = 'class' AND uses >= max_uses";

/// Statement 2 — the seat. Binds: `?1` token, `?2` token_hash, `?3` nonce, `?4` now. A row with no
/// minter is never a class invite; the predicate keeps this claim out of the genesis door's way.
pub(crate) const TAKE_SEAT_SQL: &str = "UPDATE invite_tokens
        SET uses = uses + 1, claim_nonce = ?3
      WHERE token = ?1 AND token_hash = ?2 AND kind = 'class' AND revoked_at IS NULL
        AND expires_at > ?4 AND uses < max_uses AND owner_user_id IS NOT NULL";

/// Statement 3 — the redemption's ledger row. Binds: `?1` redemption key, `?2` redeemed_at,
/// `?3` token_hash, `?4` nonce.
pub(crate) const RECORD_REDEMPTION_SQL: &str = "INSERT INTO invite_attributions
       (invite_token_hash, email_hint, inviter_user_id, inviter_ed_pub, used_by,
        created_at, expires_at, redeemed_at, verified_at, genesis,
        kind, source_hash, introduce, landing_room_id, landing_needs_approval)
     SELECT ?1, it.email_hint, it.owner_user_id, u.identity_ed_pub, NULL,
            it.created_at, it.expires_at, ?2, NULL, 0,
            'class', it.token_hash, 0, it.landing_room_id, it.landing_needs_approval
       FROM invite_tokens it
       LEFT JOIN users u ON u.id = it.owner_user_id
      WHERE it.token_hash = ?3 AND it.claim_nonce = ?4 AND it.kind = 'class'
     ON CONFLICT(invite_token_hash) DO NOTHING
     RETURNING invite_token_hash";

/// The in-flight redemption this e-mail already holds on this invite, if its code is still live.
/// Binds: email, token_hash, now.
pub(crate) const INFLIGHT_REDEMPTION_SQL: &str = "SELECT ia.invite_token_hash AS invite_token_hash
       FROM verification_codes vc
       JOIN invite_attributions ia ON ia.invite_token_hash = vc.invite_token_hash
      WHERE vc.email = ? AND ia.source_hash = ? AND ia.verified_at IS NULL
        AND vc.expires_at > ?
      LIMIT 1";

/// The ledger key of one class redemption. Hex SHA-256, so it satisfies the ledger's
/// `length(invite_token_hash) = 64` check and carries no bearer secret.
pub(crate) fn redemption_key(token_hash: &str, nonce: &str) -> String {
    sha256_hex(&format!("{token_hash}:{nonce}"))
}

#[derive(Deserialize)]
struct KeyRow {
    invite_token_hash: String,
}

/// `invite_tokens.kind` and its seats for a raw token; `None` when no row has it. The seats size
/// the invite's rate limit (`ratelimit::per_invite_limit`).
pub(crate) async fn kind_of(db: &D1Database, token: &str) -> Result<Option<(String, i64)>> {
    #[derive(Deserialize)]
    struct KindRow {
        kind: String,
        max_uses: i64,
    }
    let row: Option<KindRow> = db
        .prepare(KIND_SQL)
        .bind(&[d1_text(token)])?
        .first(None)
        .await?;
    Ok(row.map(|r| (r.kind, r.max_uses)))
}

/// Claim one seat on a class invite for `email`. Returns the redemption's ledger key — what the
/// verification-code bridge carries — or `None` when the invite is full, revoked, expired or
/// unknown (redeem answers all four `invalid_invite`, as it does for a spent personal invite).
pub(crate) async fn claim(
    db: &D1Database,
    token: &str,
    token_hash: &str,
    email: &str,
    now: i64,
) -> Result<Option<String>> {
    let inflight: Option<KeyRow> = db
        .prepare(INFLIGHT_REDEMPTION_SQL)
        .bind(&[d1_text(email), d1_text(token_hash), d1_int(now)])?
        .first(None)
        .await?;
    if let Some(row) = inflight {
        return Ok(Some(row.invite_token_hash));
    }
    let nonce = random_b64u(16);
    let key = redemption_key(token_hash, &nonce);
    let results = db
        .batch(vec![
            db.prepare(RELEASE_SEATS_SQL)
                .bind(&[d1_text(token_hash), d1_int(now)])?,
            db.prepare(TAKE_SEAT_SQL).bind(&[
                d1_text(token),
                d1_text(token_hash),
                d1_text(&nonce),
                d1_int(now),
            ])?,
            db.prepare(RECORD_REDEMPTION_SQL).bind(&[
                d1_text(&key),
                d1_int(now),
                d1_text(token_hash),
                d1_text(&nonce),
            ])?,
        ])
        .await?;
    let won = results
        .get(2)
        .map(|r| !r.results::<KeyRow>().unwrap_or_default().is_empty())
        .unwrap_or(false);
    Ok(won.then_some(key))
}

#[cfg(test)]
#[path = "class_invite_tests.rs"]
mod tests;
