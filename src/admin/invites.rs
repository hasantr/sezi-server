//! The admin side of invites: mint, list and revoke (admin or owner).

use crate::auth::hashing::sha256_hex;
use crate::auth::middleware::{require_active_auth, require_admin};
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{now_secs, random_b64u};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct CreateInviteBody {
    email_hint: Option<String>,
    ttl_hours: Option<u64>,
    /// Minute-grained short TTL for in-person invites (5/15/60 min) — `ttl_hours`
    /// bottoms out at an hour, far too long for handing a code to someone face to
    /// face. When present this WINS over `ttl_hours`; when absent the `ttl_hours`
    /// path still works, so older clients that send it keep working.
    ttl_minutes: Option<u64>,
    /// `"personal"` (the default — today's single-use invite) or `"class"`.
    kind: Option<String>,
    /// Class only: how many people may come through it, 1..=`MAX_CLASS_SEATS`. A personal invite
    /// has exactly one seat; anything else for it is a 400.
    max_uses: Option<i64>,
    /// The invite's name ("BIL203 · 2026 fall"). The same column as `email_hint`, which older
    /// clients send; `label` wins when both are present.
    label: Option<String>,
    /// A group the joiner is put into after verify. It must be one the caller administers.
    landing_room_id: Option<String>,
    /// Class only, default `true`: the joiner waits as a join request until a group admin
    /// approves (Hasan, round 4). `true` on a personal invite is a 400 — a personally invited
    /// member always joins directly.
    landing_needs_approval: Option<bool>,
}

/// What an invite will be once the body is validated. Pure, so the rules are testable without D1.
#[derive(Debug, PartialEq)]
struct InviteShape {
    class: bool,
    max_uses: i64,
    label: Option<String>,
    introduce: bool,
    landing_room_id: Option<String>,
    landing_needs_approval: bool,
}

/// Validate the shape half of `POST /admin/invites`. `Err` is the wire error code (all 400).
fn resolve_invite_shape(body: &CreateInviteBody) -> core::result::Result<InviteShape, &'static str> {
    let class = match body.kind.as_deref() {
        None | Some("personal") => false,
        Some("class") => true,
        Some(_) => return Err("bad_kind"),
    };
    let label = body.label.clone().or_else(|| body.email_hint.clone());
    // A free-text label; only a length bound, as a DoS guard (redeem never matches it).
    if label.as_deref().is_some_and(|l| l.len() > 254) {
        return Err("bad_request");
    }
    let max_uses = match (class, body.max_uses) {
        (false, None | Some(1)) => 1,
        (false, Some(_)) => return Err("bad_max_uses"),
        (true, None) => return Err("bad_max_uses"),
        (true, Some(n)) if (1..=crate::auth::class_invite::MAX_CLASS_SEATS).contains(&n) => n,
        (true, Some(_)) => return Err("bad_max_uses"),
    };
    let landing_room_id = body.landing_room_id.clone().filter(|r| !r.is_empty());
    if landing_room_id.as_deref().is_some_and(|r| r.len() > 128) {
        return Err("bad_request");
    }
    let landing_needs_approval = match (class, body.landing_needs_approval) {
        (true, approval) => approval.unwrap_or(true) && landing_room_id.is_some(),
        (false, Some(true)) => return Err("approval_needs_class_invite"),
        (false, _) => false,
    };
    Ok(InviteShape {
        class,
        max_uses,
        label,
        // Personal: on, as it always was. Class: never — the board says it in so many words
        // ("no contact pairing"), and one admin is not 120 students' contact.
        introduce: !class,
        landing_room_id,
        landing_needs_approval,
    })
}

/// Resolve and validate the invite TTL in seconds. Precedence: `ttl_minutes` >
/// `ttl_hours` (older clients) > a 24 hour default. Out of range → `Err(())`, which the
/// caller turns into 400 bad_request:
///   - ttl_minutes: 1..=43200 (30 days)
///   - ttl_hours:   1..=24*30 (30 days)
fn resolve_invite_ttl_secs(
    ttl_minutes: Option<u64>,
    ttl_hours: Option<u64>,
) -> core::result::Result<u64, ()> {
    if let Some(m) = ttl_minutes {
        if !(1..=43200).contains(&m) {
            return Err(());
        }
        return Ok(m * 60);
    }
    if let Some(h) = ttl_hours {
        if !(1..=24 * 30).contains(&h) {
            return Err(());
        }
        return Ok(h * 60 * 60);
    }
    Ok(24 * 60 * 60)
}

pub async fn create_invite(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: CreateInviteBody = req.json().await.unwrap_or_default();
    // `email_hint`/`label` is a free-text LABEL/NAME (optional; the admin notes who or what the
    // invite was minted for). Redeem does NOT match it against the e-mail — binding it was
    // useless against synthetic u...@sezgi.local addresses.
    let shape = match resolve_invite_shape(&body) {
        Ok(shape) => shape,
        Err(code) => return json_err(400, code),
    };
    // TTL resolution: ttl_minutes > ttl_hours > 24h default.
    let ttl = match resolve_invite_ttl_secs(body.ttl_minutes, body.ttl_hours) {
        Ok(secs) => secs,
        Err(()) => return json_err(400, "bad_request"),
    };

    let db = ctx.env.d1("DB")?;
    // A landing group must be one the CALLER administers (round-4 default). Being a server admin
    // grants nothing inside a group (AGENTS.md, "Who the server owner is"), so without this an
    // admin could mint a door into any course on the server. A group that does not exist answers
    // the same as one the caller does not run.
    if let Some(room) = shape.landing_room_id.as_deref() {
        match crate::groups::group_role(&db, room, &user_id).await? {
            Some(role) if crate::groups::is_group_admin(&role) => {}
            _ => return json_err(403, "not_group_admin"),
        }
    }

    let now = now_secs();
    // Every new invite, personal or class, gets a typeable code beside its token. The code space
    // is ~6.6·10^11, so a collision with a LIVE code (the unique index on `code_hash`) is a
    // once-in-a-lifetime event — answered by drawing again rather than by failing the admin.
    let mut minted: Option<(String, String)> = None;
    for attempt in 0..3 {
        let token = random_b64u(18); // 24 char b64u
        let code = crate::auth::invite_code::generate();
        let inserted = db
            .prepare(INSERT_INVITE_SQL)
            .bind(&[
                d1_text(&token),
                d1_text(&sha256_hex(&token)),
                d1_opt_text(shape.label.as_deref()),
                d1_text(&user_id),
                d1_int((now + ttl) as i64),
                d1_int(now as i64),
                d1_text(if shape.class { "class" } else { "personal" }),
                d1_int(shape.max_uses),
                d1_int(shape.introduce as i64),
                d1_opt_text(shape.landing_room_id.as_deref()),
                d1_int(shape.landing_needs_approval as i64),
                d1_text(&crate::auth::invite_code::display(&code)),
                d1_text(&crate::auth::invite_code::code_hash(&code)),
            ])?
            .run()
            .await;
        match inserted {
            Ok(_) => {
                minted = Some((token, crate::auth::invite_code::display(&code)));
                break;
            }
            Err(error) if attempt == 2 => return Err(error),
            Err(_) => continue,
        }
    }
    let Some((token, code)) = minted else {
        return json_err(500, "invite_mint_failed");
    };

    // A personal invite answers in today's shape plus the new fields, all additive.
    Response::from_json(&serde_json::json!({
        "token": token,
        "code": code,
        "email_hint": shape.label,
        "label": shape.label,
        "kind": if shape.class { "class" } else { "personal" },
        "max_uses": shape.max_uses,
        "uses": 0,
        "introduce": shape.introduce,
        "landing_room_id": shape.landing_room_id,
        "landing_needs_approval": shape.landing_needs_approval,
        "expires_at": now + ttl,
        "created_at": now,
    }))
}

/// Binds: token, token_hash, label, owner, expires_at, created_at, kind, max_uses, introduce,
/// landing_room_id, landing_needs_approval, code (display form), code_hash.
pub(crate) const INSERT_INVITE_SQL: &str = "INSERT INTO invite_tokens
       (token, token_hash, email_hint, used, used_by, owner_user_id, expires_at, created_at,
        kind, max_uses, uses, introduce, landing_room_id, landing_needs_approval,
        code, code_hash)
     VALUES (?, ?, ?, 0, NULL, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)";

#[derive(Deserialize, Default)]
struct RevokeInviteBody {
    token: String,
}

/// Revoke an unused invite (admin). A used invite is never deleted.
pub async fn revoke_invite(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: RevokeInviteBody = req.json().await.unwrap_or_default();
    if body.token.is_empty() || body.token.len() > 128 {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    // One batch, class half first: the personal DELETE is scoped to `kind = 'personal'`, but a
    // class row must be marked before anything could mistake it for a deletable one. The in-flight
    // codes of the class go in the same transaction, so "nobody gets in with this code any more"
    // holds from the moment the admin presses revoke — including someone who scanned a photo of the
    // projector a minute ago and is typing the six digits now.
    let now = now_secs() as i64;
    db.batch(vec![
        db.prepare(REVOKE_CLASS_SQL)
            .bind(&[d1_int(now), d1_text(&body.token)])?,
        db.prepare(DROP_INFLIGHT_CLASS_CODES_SQL)
            .bind(&[d1_text(&body.token)])?,
        db.prepare(REVOKE_PERSONAL_SQL)
            .bind(&[d1_text(&body.token)])?,
    ])
    .await?;
    Response::from_json(&serde_json::json!({ "ok": true }))
}

/// A class invite is revoked by MARKING it: its card, its live count and who came through it stay
/// listable ("Revoked · 37/120"), and every claim tests `revoked_at IS NULL`. Binds: now, token.
pub(crate) const REVOKE_CLASS_SQL: &str = "UPDATE invite_tokens SET revoked_at = ?1
      WHERE token = ?2 AND kind = 'class' AND revoked_at IS NULL";

/// The class's redemptions that hold a code but have not verified lose it, so verify answers
/// `no_code`. Verified members are untouched — revoking the door does not remove anyone who came
/// through it. Binds: token.
pub(crate) const DROP_INFLIGHT_CLASS_CODES_SQL: &str = "DELETE FROM verification_codes
      WHERE invite_token_hash IN (
        SELECT ia.invite_token_hash FROM invite_attributions ia
          JOIN invite_tokens it ON ia.source_hash = it.token_hash
         WHERE it.token = ?1 AND it.kind = 'class' AND ia.verified_at IS NULL)";

/// A personal invite is revoked by deleting it, as before. If a ledger claim exists the invite has
/// been used even when the legacy `used` flag is still 0, and revoke must not delete it: the claim
/// INSERT is redeem's linearization point. `kind = 'personal'` is what keeps this statement off a
/// class row, whose redemptions are keyed by their own hashes and would pass the NOT EXISTS.
/// Binds: token.
pub(crate) const REVOKE_PERSONAL_SQL: &str = "DELETE FROM invite_tokens
      WHERE token = ?1 AND used = 0 AND kind = 'personal'
        AND NOT EXISTS (
          SELECT 1 FROM invite_attributions ia
           WHERE ia.invite_token_hash = invite_tokens.token_hash
        )";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_ttl_resolution() {
        // ttl_minutes=5 → 300 s (expires_at ≈ now+300, the in-person invite).
        assert_eq!(resolve_invite_ttl_secs(Some(5), None), Ok(300));
        // With both fields present, ttl_minutes WINS.
        assert_eq!(resolve_invite_ttl_secs(Some(5), Some(2)), Ok(300));
        // ttl_minutes bounds: 0 → 400, 43201 (30 days + 1) → 400, 43200 → OK.
        assert_eq!(resolve_invite_ttl_secs(Some(0), None), Err(()));
        assert_eq!(resolve_invite_ttl_secs(Some(43201), None), Err(()));
        assert_eq!(resolve_invite_ttl_secs(Some(43200), None), Ok(43200 * 60));
        // Backwards compatibility: the ttl_hours-only path keeps the existing rule
        // (1..=24*30, hours → seconds).
        assert_eq!(resolve_invite_ttl_secs(None, Some(1)), Ok(3600));
        assert_eq!(
            resolve_invite_ttl_secs(None, Some(24 * 30)),
            Ok(24 * 30 * 3600)
        );
        assert_eq!(resolve_invite_ttl_secs(None, Some(0)), Err(()));
        assert_eq!(resolve_invite_ttl_secs(None, Some(24 * 30 + 1)), Err(()));
        // Neither field → the 24 hour default.
        assert_eq!(resolve_invite_ttl_secs(None, None), Ok(24 * 60 * 60));
    }

    fn body(json: &str) -> CreateInviteBody {
        serde_json::from_str(json).unwrap()
    }

    /// Today's body still mints today's invite: one seat, introduced, nowhere to land.
    #[test]
    fn a_body_without_the_new_fields_is_a_personal_invite() {
        assert_eq!(
            resolve_invite_shape(&body(r#"{"email_hint":"Ayse","ttl_hours":24}"#)),
            Ok(InviteShape {
                class: false,
                max_uses: 1,
                label: Some("Ayse".into()),
                introduce: true,
                landing_room_id: None,
                landing_needs_approval: false,
            })
        );
    }

    #[test]
    fn a_class_invite_never_introduces_and_waits_for_approval_by_default() {
        let shape = resolve_invite_shape(&body(
            r#"{"kind":"class","max_uses":120,"label":"BIL203","landing_room_id":"g1"}"#,
        ))
        .unwrap();
        assert!(shape.class && !shape.introduce && shape.landing_needs_approval);
        assert_eq!(shape.max_uses, 120);
        // Auto-approval is a choice, and approval without a landing group means nothing.
        let auto = resolve_invite_shape(&body(
            r#"{"kind":"class","max_uses":5,"landing_room_id":"g1","landing_needs_approval":false}"#,
        ))
        .unwrap();
        assert!(!auto.landing_needs_approval);
        let no_room = resolve_invite_shape(&body(r#"{"kind":"class","max_uses":5}"#)).unwrap();
        assert!(!no_room.landing_needs_approval);
    }

    #[test]
    fn seats_and_approval_are_refused_where_they_mean_nothing() {
        for (json, code) in [
            (r#"{"kind":"class"}"#, "bad_max_uses"),
            (r#"{"kind":"class","max_uses":0}"#, "bad_max_uses"),
            (r#"{"kind":"class","max_uses":1001}"#, "bad_max_uses"),
            (r#"{"max_uses":2}"#, "bad_max_uses"),
            (r#"{"kind":"team"}"#, "bad_kind"),
            (
                r#"{"landing_room_id":"g1","landing_needs_approval":true}"#,
                "approval_needs_class_invite",
            ),
        ] {
            assert_eq!(resolve_invite_shape(&body(json)), Err(code), "{json}");
        }
        // A personal invite may land its joiner — directly.
        let personal = resolve_invite_shape(&body(r#"{"landing_room_id":"g1"}"#)).unwrap();
        assert_eq!(personal.landing_room_id.as_deref(), Some("g1"));
        assert!(!personal.landing_needs_approval);
    }

    /// Mint with a code, then find the invite again from what a student typed off the wall — and a
    /// second invite can never be minted on a live code.
    #[test]
    fn a_minted_code_leads_back_to_its_token_and_is_unique() {
        use crate::auth::invite_code::{code_hash, display, normalize};
        use rusqlite::params;
        let db = crate::test_schema::full_schema();
        db.execute(
            "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('adm','a@x',x'00',1)",
            [],
        )
        .unwrap();
        let mint = |token: &str, code: &str| {
            db.execute(
                INSERT_INVITE_SQL,
                params![
                    token,
                    sha256_hex(token),
                    "BIL203",
                    "adm",
                    9_999,
                    1,
                    "class",
                    120,
                    0,
                    Option::<String>::None,
                    0,
                    display(code),
                    code_hash(code)
                ],
            )
        };
        mint("class-token-one", "K7QM4827").unwrap();
        assert!(mint("class-token-two", "K7QM4827").is_err(), "the code index is unique");
        let typed = normalize(" k7qm 4827").unwrap();
        let token: String = db
            .query_row(crate::auth::invite::TOKEN_FOR_CODE_SQL, [code_hash(&typed)], |r| r.get(0))
            .unwrap();
        assert_eq!(token, "class-token-one");
        let shown: String = db
            .query_row("SELECT code FROM invite_tokens", [], |r| r.get(0))
            .unwrap();
        assert_eq!(shown, "K7QM-4827");
    }

    /// Revoke, against the real schema: a class invite is marked and its unverified codes go; a
    /// verified member's row is untouched; the personal DELETE never takes a class row.
    #[test]
    fn revoking_a_class_invite_marks_it_and_kills_its_live_codes() {
        use rusqlite::params;
        let db = crate::test_schema::full_schema();
        db.execute_batch(
            "INSERT INTO users (id, email, identity_pubkey, created_at)
               VALUES ('adm', 'a@x', x'00', 1);
             INSERT INTO invite_tokens
               (token, token_hash, used, owner_user_id, expires_at, created_at, kind, max_uses, uses)
               VALUES ('class-tok', 'h-class', 0, 'adm', 9999, 1, 'class', 10, 2),
                      ('pers-tok', 'h-pers', 0, 'adm', 9999, 1, 'personal', 1, 0);",
        )
        .unwrap();
        for (key, verified) in [("a".repeat(64), Some(5)), ("b".repeat(64), None)] {
            db.execute(
                "INSERT INTO invite_attributions
                   (invite_token_hash, inviter_user_id, created_at, expires_at, redeemed_at,
                    verified_at, kind, source_hash, introduce)
                 VALUES (?1, 'adm', 1, 9999, 2, ?2, 'class', 'h-class', 0)",
                params![key, verified],
            )
            .unwrap();
            db.execute(
                "INSERT INTO verification_codes
                   (email, code_hash, attempts, invite_token_hash, expires_at, created_at)
                 VALUES (?1, 'h', 0, ?1, 9999, 1)",
                params![key],
            )
            .unwrap();
        }
        for sql in [DROP_INFLIGHT_CLASS_CODES_SQL, REVOKE_PERSONAL_SQL] {
            db.execute(sql, ["class-tok"]).unwrap();
        }
        db.execute(REVOKE_CLASS_SQL, params![77, "class-tok"]).unwrap();
        let revoked: Option<i64> = db
            .query_row("SELECT revoked_at FROM invite_tokens WHERE token='class-tok'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(revoked, Some(77), "the class row is marked, not deleted");
        let codes: Vec<String> = db
            .prepare("SELECT invite_token_hash FROM verification_codes")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(codes, vec!["a".repeat(64)], "only the unverified redemption lost its code");
        db.execute(REVOKE_PERSONAL_SQL, ["pers-tok"]).unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM invite_tokens", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1,
            "a personal invite is still revoked by deleting it"
        );
    }
}
