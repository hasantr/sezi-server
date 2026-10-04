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
/// **Chicken-and-egg:** creating the owner of an invite_only server needs an invite, but the owner
/// who would mint it does not exist yet. While there is NO owner this endpoint mints and returns an
/// automatic "genesis" invite; the person who redeems that code becomes the owner, because the
/// redeem claim records it as the genesis claim and verify grants `owner` from that record alone
/// (`invite_attribution::CLAIM_INVITE_SQL`, `verify::role_for_registration`). Being the first to
/// register is not what makes an owner. Once an owner exists it answers 410 and stays closed.
/// Idempotent: until then, repeated calls return the same token.
///
/// The genesis invite is marked by **`owner_user_id IS NULL`** — real invites always have a minter.
/// `email_hint` is NOT usable as that marker: it is a cosmetic free-text label (see invite.rs).
///
/// **Security nuance:** while there is no owner the endpoint is public, leaving a small race
/// window between deploy and claim. Acceptable for small self-hosted servers — and closable: a
/// relay given `SEZI_CLAIM_SECRET` answers only a request carrying it in `x-sezi-claim`
/// (`auth::claim`). That gate comes before everything else here, the ghost recovery included, so
/// without the secret this endpoint does nothing at all but answer the closed-gate 410.
///
/// The GHOST-OWNER SELF-HEAL below is NOT public: it deletes an existing owner row and reopens
/// genesis, so it requires `ADMIN_INVITE_KEY`. See `ghost_recovery_authorized`.
pub async fn bootstrap(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // While there is no owner this endpoint is public, so a per-IP sliding window slows bot-driven
    // genesis enumeration. The KV binding is OPTIONAL (a slim install has no RATE_LIMIT) and
    // `check_rate_limit_env` FAILS OPEN without it, so the gate keeps working. Legitimate
    // onboarding calls /bootstrap 1-3 times, so 10 per 5 min is generous.
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

    // The claim secret, when the relay has one, before any read: a caller without it learns
    // nothing from this endpoint that an owned server would not also say. The refusal is the
    // closed gate's own answer on purpose (`auth::claim` says why).
    if !crate::auth::claim::claim_authorized(&req, &ctx.env) {
        return json_err(410, "bootstrap_complete");
    }

    let db = ctx.env.d1("DB")?;

    // Does an owner already exist? → the gate is closed. EXCEPTION (self-heal): if the owner is a
    // "GHOST" — registration died halfway, the user row written but token signing blew up, so no
    // device, key or session was ever created — wipe the ghost and reopen genesis. Nobody should
    // have to run DELETE from the D1 console.
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
        // Ghost signature, read off the registration flow (auth/verify.rs, devices/handlers.rs):
        //  · a `devices` row comes ONLY from the authenticated PUT /devices publish, which cannot
        //    run before registration returned a token → a ghost has 0.
        //  · a `refresh_tokens` row comes from EVERY token-issuing path (verify / relogin /
        //    rotation / device-link) → a ghost that never logged in has 0. A live owner always
        //    keeps ≥1 live row (cron only deletes expired/revoked ones), so it never qualifies.
        //  · at least 10 minutes old: registration may still be in flight.
        //
        // THE KEY COMES FIRST, before any measurement of the owner. Everything below deletes an
        // account and reopens the founding gate, and an UNAUTHENTICATED GET must not reach that on
        // the strength of the server's own judgement about what a "ghost" is — the residual edge
        // noted below (an owner who never connected and never published a device list) is exactly
        // the case where an anonymous caller could delete a real account and claim the server.
        //
        // `ADMIN_INVITE_KEY` is the gate; `self_provision` generates it on a fresh deploy and names
        // this as the consumer. Without it the answer is the ordinary closed-gate 410 — the same
        // reply a healthy server gives, so the endpoint never advertises that this server qualifies.
        if !ghost_recovery_authorized(&req, &ctx.env) {
            return json_err(410, "bootstrap_complete");
        }
        let device_count = count_rows(&db, "SELECT COUNT(*) AS n FROM devices WHERE user_id = ?", &o.id).await?;
        let refresh_count =
            count_rows(&db, "SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?", &o.id).await?;
        if !is_ghost_owner(device_count, refresh_count, o.created_at, now_secs()) {
            return json_err(410, "bootstrap_complete");
        }
        // A device-less, session-less owner can do NOTHING anyway — no key, no token — so this
        // steals nothing from a legitimate owner; it frees a dead owner slot. Residual edge: an
        // owner who never connected AND never published a device list would match the criteria.
        // Current clients publish a device at registration, so that set is empty in practice.
        console_warn!(
            "bootstrap: GHOST owner detected (id={}, devices=0, refresh=0, age>=grace) → clearing it and reopening genesis aciliyor (self-heal; 2026-07-06 sezi-server2 vakasi)",
            o.id
        );
        // ONE ATOMIC BATCH (a D1 batch is an implicit transaction), so a half-finished wipe cannot
        // create a new class of broken state. The FK ordering mirrors admin remove_member
        // (admin/handlers.rs): referencing rows first, users last. `groups.created_by` is
        // deliberately absent — a ghost cannot create a group, and if such an impossible row did
        // exist the FK would roll the batch back, which is a safe failure (nothing deleted, 500).
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
///
/// CONTRACT: only call this when there is NO owner — the caller checks the gate, this function
/// performs NO owner check itself. SELECT the existing unused genesis, and if there is none,
/// INSERT OR IGNORE followed by a canonical re-SELECT (the race pattern below).
pub(crate) async fn ensure_genesis_token(db: &D1Database) -> Result<String> {
    // Self-heal: the ledger claim is redeem's authority. If a claim succeeded but the legacy `used`
    // UPDATE never landed, the partial UNIQUE index would block minting a new genesis.
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
            // Two concurrent /bootstrap calls can both see the SELECT above as empty. The partial
            // UNIQUE index (`owner_user_id IS NULL AND used = 0`) allows at most one unused genesis
            // at a time, so `INSERT OR IGNORE` is a no-op for whichever call loses the race;
            // re-SELECTing the canonical row then makes BOTH return the SAME token.
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
            // If our INSERT OR IGNORE lost the race ours was never written, so read the row that
            // won; if we won, this is our own token.
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

/// Header carrying `ADMIN_INVITE_KEY` for the ghost-owner recovery. A header rather than a query
/// parameter so the key does not end up in access logs or a browser's history.
const ADMIN_KEY_HEADER: &str = "x-sezgi-admin-key";

/// May THIS request run the ghost-owner recovery — delete an owner row and reopen genesis?
///
/// Two ways to fail closed, and both matter:
///  * no key configured at all → refuse. `self_provision` generates one on every fresh deploy, so
///    "unset" means an installation old enough to predate it or one whose key was cleared; either
///    way, minting a destructive capability out of nothing is the wrong default.
///  * key present but not matching → refuse, compared with `secret_eq` so the wrong answer takes
///    the same time as any other. The key is stored in plaintext (it is a deploy secret, not a
///    password), which is exactly the case `secret_eq` exists for.
fn ghost_recovery_authorized(req: &Request, env: &Env) -> bool {
    let Some(expected) = crate::self_provision::resolve_admin_invite_key(env) else {
        return false;
    };
    let submitted = req
        .headers()
        .get(ADMIN_KEY_HEADER)
        .ok()
        .flatten()
        .unwrap_or_default();
    crate::auth::hashing::secret_eq(&submitted, &expected)
}

/// Ghost-owner grace window: an account younger than this is NEVER treated as a ghost, because
/// registration may still be in flight (verify returned, the device publish is on its way).
const GHOST_GRACE_SEC: i64 = 10 * 60;

/// Ghost-owner criteria — PURE, so it is unit-tested. A conservative AND chain: no device row AND
/// no refresh-token row AND at least 10 minutes old. Unless all three hold, the owner is left
/// alone (410 as usual).
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

    /// `include_str!` binds at compile time and resolves relative to THIS file. Needles are split
    /// with `concat!` because this module is INLINE, so `SRC` contains the test source too.
    const SRC: &str = include_str!("bootstrap.rs");

    /// `ghost_recovery_authorized` needs a live `Request` and `Env`, so the ORDER of the gate is
    /// the part a host test can check — and order is the whole property. A key check that runs
    /// after the wipe is not a gate.
    ///
    /// It also guards against the gate being deleted outright, which is the likelier regression:
    /// the branch is unreachable on a healthy server, so nothing else would notice.
    #[test]
    fn the_ghost_recovery_is_gated_before_it_measures_or_deletes_anything() {
        let gate = SRC
            .find(concat!("if !ghost_recovery_", "authorized(&req, &ctx.env)"))
            .expect("the ADMIN_INVITE_KEY gate on the ghost-owner recovery is gone");
        let measure = SRC
            .find(concat!("let device_", "count = count_rows"))
            .expect("the ghost criteria moved — re-point this guard");
        let wipe = SRC
            .find("db.batch(vec![")
            .expect("the ghost cleanup batch moved — re-point this guard");
        assert!(
            gate < measure,
            "an unauthenticated caller must not even make the server judge whether its owner is a ghost"
        );
        assert!(gate < wipe, "the key check must precede the account deletion");
    }

    /// The refusal must be indistinguishable from a healthy closed gate: telling an anonymous
    /// caller that this server has a recoverable owner is itself the disclosure.
    #[test]
    fn an_unauthorized_recovery_answers_the_ordinary_closed_gate() {
        let gate = SRC
            .find(concat!("if !ghost_recovery_", "authorized(&req, &ctx.env)"))
            .unwrap();
        let after = &SRC[gate..];
        let refusal = after
            .find(concat!("json_", "err(410, \"bootstrap_complete\")"))
            .expect("the refusal after the gate is not the closed-gate 410");
        assert!(
            refusal < after.find("db.batch(vec![").unwrap(),
            "the gate's own refusal must come before the wipe"
        );
    }

    /// The claim secret is checked before the handler reads anything, and refuses with the closed
    /// gate's 410. Order is the property again: a check after the owner read would let a caller
    /// without the secret tell an unowned server from an owned one, and one after the mint would
    /// be no gate at all. The decision itself is unit-tested in `auth::claim`.
    #[test]
    fn the_claim_secret_is_checked_first_and_refuses_like_a_closed_gate() {
        let claim = SRC
            .find(concat!("if !crate::auth::claim::claim_", "authorized(&req, &ctx.env)"))
            .expect("the claim-secret gate on /bootstrap is gone");
        let first_read = SRC
            .find(concat!("let db = ctx.env.", "d1(\"DB\")?;"))
            .expect("the handler's D1 binding moved — re-point this guard");
        let ghost = SRC
            .find(concat!("if !ghost_recovery_", "authorized(&req, &ctx.env)"))
            .unwrap();
        let mint = SRC
            .find(concat!("let token = ensure_genesis_", "token(&db)"))
            .expect("the genesis mint moved — re-point this guard");
        assert!(claim < first_read, "the claim gate must come before any read");
        assert!(claim < ghost && claim < mint);
        let refusal = SRC[claim..]
            .find(concat!("json_", "err(410, \"bootstrap_complete\")"))
            .expect("the claim gate's refusal is not the closed-gate 410");
        assert!(claim + refusal < first_read, "the refusal belongs to the claim gate");
    }

    /// The profile seen in the field: an owner with no device, no session and past the grace
    /// window → ghost, so recovery opens.
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
