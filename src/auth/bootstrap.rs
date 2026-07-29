use crate::auth::hashing::sha256_hex;
use crate::d1util::{d1_int, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::json_err;
use crate::utils::{now_secs, random_b64u};
use serde::Deserialize;
use worker::*;

// The genesis invite is effectively non-expiring (it is the founding gate): ~100 years.
const GENESIS_TTL_SEC: u64 = 100 * 365 * 24 * 60 * 60;

/// `GET /bootstrap` — the server's founding gate (pre-auth, self-closing).
///
/// **Chicken-and-egg fix:** creating the owner of an invite_only server needs an
/// invite, but the owner who would mint it does not exist yet. While there is NO
/// owner this endpoint mints (and returns) an automatic "genesis" invite; the FIRST
/// person to redeem that code becomes owner via the first-user-is-owner rule in
/// verify. Once an owner exists the endpoint returns 410 and stays closed forever —
/// which retires the manual `OWNERTEST2026` hack and lets the server bootstrap
/// itself.
///
/// The genesis invite is marked by **`owner_user_id IS NULL`**: real invites (from
/// `create_invite`) always have a minter, genesis has none. `email_hint` is NOT
/// usable as that marker — it is a cosmetic free-text label since the invite→e-mail
/// binding was removed (see invite.rs). Idempotent: until an owner exists, repeated
/// calls return the same token.
///
/// **Security nuance:** while there is no owner the endpoint is public, which leaves
/// a small race window between deploy and claim. That is acceptable for
/// personal/small/self-hosted servers; a future deploy secret (`ADMIN_INVITE_KEY`)
/// will harden the gate.
pub async fn bootstrap(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // HARDENING (2026-07-13): while there is no owner, /bootstrap is public (the
    // self-closing genesis gate), so SLOW DOWN bot-driven genesis enumeration with a
    // per-IP sliding window (twin of the invite redeem pattern). The KV binding is
    // OPTIONAL (the slim Lite install has no RATE_LIMIT): without it
    // check_rate_limit_env FAILS OPEN, i.e. the rate limiter never blocks the request
    // and the gate keeps working. Legitimate onboarding calls /bootstrap 1-3 times,
    // so 10 per 5 min is generous.
    let ip = req
        .headers()
        .get("cf-connecting-ip")
        .ok()
        .flatten()
        .unwrap_or_else(|| "local".into());
    let key = format!("auth:bootstrap:{}", ip);
    if !check_rate_limit_env(&ctx.env, &key, 10, 5 * 60).await {
        return json_err(429, "rate_limited");
    }

    let db = ctx.env.d1("DB")?;

    // Does an owner already exist? → the gate is closed. EXCEPTION (self-heal, from
    // the 2026-07-06 sezi-server2 incident): if the owner is a "GHOST" — registration
    // died halfway, the user row was written but token signing blew up, so no device,
    // key or session was ever created — wipe the ghost and reopen genesis. Nobody
    // should ever have to run DELETE from the D1 console.
    #[derive(Deserialize)]
    struct OwnerRow {
        id: String,
        email: String,
        created_at: i64,
    }
    let owner: Option<OwnerRow> = db
        .prepare("SELECT id, email, created_at FROM users WHERE role = 'owner' LIMIT 1")
        .first(None)
        .await?;
    if let Some(o) = owner {
        // Ghost signature (evidence from the registration flow — auth/verify.rs +
        // devices/handlers.rs):
        //  · a `devices` row is created ONLY by the authenticated PUT /devices publish,
        //    which cannot be called before registration returned a token → a ghost has
        //    0 rows.
        //  · a `refresh_tokens` row is created by EVERY token-issuing path
        //    (verify / relogin / refresh rotation / device-link) → a ghost that never
        //    logged in has 0 rows. (For a live owner, rotation always leaves ≥1 live
        //    row and cron only deletes expired/revoked ones, so a live owner never
        //    passes this gate and still gets 410.)
        //  · at least 10 minutes old (grace): registration may still be in flight
        //    (verify returned, the device publish has not landed yet) → do NOT touch a
        //    fresh account.
        let device_count = count_rows(&db, "SELECT COUNT(*) AS n FROM devices WHERE user_id = ?", &o.id).await?;
        let refresh_count =
            count_rows(&db, "SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?", &o.id).await?;
        if !is_ghost_owner(device_count, refresh_count, o.created_at, now_secs()) {
            return json_err(410, "bootstrap_complete");
        }
        // SECURITY NOTE: a device-less, session-less owner can do NOTHING anyway — no
        // key (cannot decrypt or send messages) and no token (cannot reach any
        // endpoint). This recovery therefore STEALS nothing from a legitimate owner; it
        // only frees a dead owner slot. Residual edge: a real owner who never connected
        // for 30+ days AND never published a device list (pre-device-list legacy) would
        // theoretically match the criteria. Current clients publish a device at
        // registration, so in practice that set is empty — an accepted trade-off,
        // recorded here.
        console_warn!(
            "bootstrap: GHOST owner detected (id={}, devices=0, refresh=0, age>=grace) → clearing it and reopening genesis aciliyor (self-heal; 2026-07-06 sezi-server2 vakasi)",
            o.id
        );
        // The cleanup is ONE ATOMIC BATCH (a D1 batch is an implicit transaction), so a
        // half-finished wipe cannot create a new class of broken state. The FK ordering
        // mirrors admin remove_member (admin/handlers.rs): referencing rows first, users
        // last. groups.created_by is deliberately absent — a ghost cannot create a group
        // (that requires auth), and if such an impossible row did exist the FK would
        // roll the batch back, which is a safe failure (nothing deleted, 500). Note: the
        // ghost never had a group key, so no epoch-floor bump is needed either.
        db.batch(vec![
            db.prepare("UPDATE invite_attributions SET used_by = NULL WHERE used_by = ?")
                .bind(&[d1_text(&o.id)])?,
            db.prepare(
                "UPDATE invite_attributions SET inviter_user_id = NULL WHERE inviter_user_id = ?",
            )
            .bind(&[d1_text(&o.id)])?,
            db.prepare("UPDATE invite_tokens SET used_by = NULL WHERE used_by = ?")
                .bind(&[d1_text(&o.id)])?,
            db.prepare("UPDATE invite_tokens SET owner_user_id = NULL WHERE owner_user_id = ?")
                .bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM signed_prekeys WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM one_time_prekeys WHERE user_id = ?")
                .bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM pending_messages WHERE recipient_id = ? OR sender_id = ?")
                .bind(&[d1_text(&o.id), d1_text(&o.id)])?,
            db.prepare("DELETE FROM media_objects WHERE uploader_id = ?")
                .bind(&[d1_text(&o.id)])?,
            // By the ghost criteria refresh/devices already have 0 rows — defensive
            // only (the batch is cheap).
            db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM push_tokens WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM group_members WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM devices WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            db.prepare("DELETE FROM device_lists WHERE user_id = ?").bind(&[d1_text(&o.id)])?,
            // Leftover verification code bound to the ghost's e-mail (verify normally
            // deletes it; defensive). Since the e-mail column is UNIQUE, clearing it
            // also makes re-registering with that address possible again.
            db.prepare("DELETE FROM verification_codes WHERE email = ?")
                .bind(&[d1_text(&o.email)])?,
            db.prepare("DELETE FROM users WHERE id = ? AND role = 'owner'")
                .bind(&[d1_text(&o.id)])?,
        ])
        .await?;
        console_log!("bootstrap: ghost owner {} cleared; falling back to the genesis flow", o.id);
        // Fall through to the normal genesis-mint flow below. The old, already
        // redeemed genesis has used=1 so it is not selected, and a fresh token is
        // minted.
    }

    let token = ensure_genesis_token(&db).await?;

    Response::from_json(&serde_json::json!({
        "bootstrap_token": token,
        "note": "The FIRST person to use this code becomes the server owner; after that this door closes.",
    }))
}

/// Genesis token get-or-mint, shared by the bootstrap handler and the welcome page.
/// CONTRACT: only call this when there is NO owner — the caller checks the gate,
/// this function performs NO owner check itself. Behaviour is bit-identical to the
/// original `bootstrap()` body: SELECT the existing unused genesis, and if there is
/// none, INSERT OR IGNORE followed by a canonical re-SELECT (the M10 race pattern,
/// preserved as is).
pub(crate) async fn ensure_genesis_token(db: &D1Database) -> Result<String> {
    // P0 self-heal: the ledger claim is redeem's authority. If a claim succeeded but
    // the legacy `used` UPDATE never landed, make sure the 0018 partial UNIQUE index
    // does not block minting a new genesis.
    db.prepare(
        "UPDATE invite_tokens SET used = 1
          WHERE used = 0 AND token_hash IS NOT NULL AND EXISTS (
            SELECT 1 FROM invite_attributions ia
             WHERE ia.invite_token_hash = invite_tokens.token_hash
          )",
    )
    .run()
    .await?;
    // Is there already an unused genesis invite? (owner_user_id IS NULL = minted by
    // the system)
    #[derive(Deserialize)]
    struct TokenRow {
        token: String,
    }
    let existing: Option<TokenRow> = db
        .prepare(
            "SELECT token FROM invite_tokens
             WHERE used = 0 AND owner_user_id IS NULL
             ORDER BY created_at ASC LIMIT 1",
        )
        .first(None)
        .await?;

    let token = match existing {
        Some(r) => r.token,
        None => {
            // M10 (bootstrap race): two concurrent /bootstrap calls could both see the
            // SELECT above as empty and INSERT multiple genesis rows. The partial UNIQUE
            // index from migration 0018 (`owner_user_id IS NULL AND used = 0`)
            // guarantees at most one unused genesis at a time, so `INSERT OR IGNORE` is
            // a no-op for whichever call loses the race (the UNIQUE violation is
            // swallowed); re-SELECTing the canonical row then makes BOTH calls return
            // the SAME single token (idempotent).
            let now = now_secs();
            let token = random_b64u(18); // 24 char b64u
            let token_hash = sha256_hex(&token);
            db.prepare(
                "INSERT OR IGNORE INTO invite_tokens
                   (token, token_hash, email_hint, used, used_by, owner_user_id, expires_at, created_at)
                 VALUES (?, ?, NULL, 0, NULL, NULL, ?, ?)",
            )
            .bind(&[
                d1_text(&token),
                d1_text(&token_hash),
                d1_int((now + GENESIS_TTL_SEC) as i64),
                d1_int(now as i64),
            ])?
            .run()
            .await?;
            // Re-SELECT the canonical genesis token: if our INSERT OR IGNORE lost the
            // race ours was not written, so read the one that was; if we won, this is
            // our own token.
            let winner: Option<TokenRow> = db
                .prepare(
                    "SELECT token FROM invite_tokens
                     WHERE used = 0 AND owner_user_id IS NULL
                     ORDER BY created_at ASC LIMIT 1",
                )
                .first(None)
                .await?;
            match winner {
                Some(r) => r.token,
                None => token, // unexpected (the index guarantees a row) — fall back to ours
            }
        }
    };
    Ok(token)
}

/// Ghost-owner grace window: an account younger than this is NEVER treated as a
/// ghost, because registration may still be in flight (verify returned, the device
/// publish is on its way).
const GHOST_GRACE_SEC: i64 = 10 * 60;

/// Ghost-owner criteria — PURE, so it is unit-tested. A conservative AND chain: no
/// device row AND no refresh-token row AND the account is at least 10 minutes old.
/// Unless all three hold, the owner is left alone (410 as usual).
fn is_ghost_owner(device_count: i64, refresh_count: i64, created_at: i64, now: u64) -> bool {
    let age = (now as i64).saturating_sub(created_at); // clock skew → negative age counts as young
    device_count == 0 && refresh_count == 0 && age >= GHOST_GRACE_SEC
}

/// Helper for `SELECT COUNT(*) AS n ...` (single-column count).
async fn count_rows(db: &D1Database, sql: &str, user_id: &str) -> Result<i64> {
    #[derive(Deserialize)]
    struct CountRow {
        n: i64,
    }
    let row: Option<CountRow> = db.prepare(sql).bind(&[d1_text(user_id)])?.first(None).await?;
    Ok(row.map(|r| r.n).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_750_000_000; // account creation instant (s)

    /// The field-incident profile (2026-07-06 sezi-server2): an owner with no device,
    /// no session and past the grace window → ghost, so recovery opens.
    #[test]
    fn a_ghost_profile_is_recognised() {
        let now = (T0 + GHOST_GRACE_SEC) as u64; // exact boundary: age == grace → ghost
        assert!(is_ghost_owner(0, 0, T0, now));
        assert!(is_ghost_owner(0, 0, T0, now + 86_400)); // and days later
    }

    /// Conservatism: a SINGLE liveness signal is enough to leave the owner alone.
    #[test]
    fn an_owner_with_a_device_or_session_is_never_a_ghost() {
        let now = (T0 + 30 * 24 * 3600) as u64; // even 30 days later
        assert!(!is_ghost_owner(1, 0, T0, now)); // published a device
        assert!(!is_ghost_owner(0, 1, T0, now)); // has a refresh token
        assert!(!is_ghost_owner(2, 3, T0, now)); // has both
    }

    /// Grace: a fresh account (registration may still be running) is not a ghost.
    #[test]
    fn a_fresh_account_is_protected_inside_the_grace_window() {
        assert!(!is_ghost_owner(0, 0, T0, T0 as u64)); // same instant
        assert!(!is_ghost_owner(0, 0, T0, (T0 + GHOST_GRACE_SEC - 1) as u64)); // 1s under the bound
    }

    /// Clock-skew defence: a created_at in the future (negative age) counts as young.
    #[test]
    fn a_future_dated_account_is_not_a_ghost() {
        assert!(!is_ghost_owner(0, 0, T0 + 3600, T0 as u64));
    }
}
