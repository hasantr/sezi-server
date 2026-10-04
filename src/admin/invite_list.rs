//! `GET /admin/invites` — every invite, class invites first, a page at a time (admin or owner).
//!
//! ```text
//! GET /admin/invites?limit=100&cursor=<next>
//! 200 {"invites": [Invite], "next": "<cursor>" | null}
//! Invite = {
//!   "token", "code" | null, "kind": "personal" | "class", "label", "email_hint" (= label),
//!   "used",            // personal: redeemed · class: every seat taken
//!   "used_by", "used_by_email", "owner_user_id", "owner_email",
//!   "expires_at", "created_at", "expired",
//!   "max_uses" | null, "uses",        // seats and seats taken (live count)
//!   "joined",                         // redemptions that completed verify
//!   "pending_requests",               // join requests this invite left waiting in its group
//!   "landing_room_id" | null, "landing_group_name" | null, "landing_needs_approval",
//!   "introduce", "revoked", "revoked_at" | null
//! }
//! ```
//!
//! **Order.** Live class invites first — they are the ones an admin is watching fill up during a
//! lecture — then everything else, newest first, ties broken by token so a cursor is total. The
//! 100-row cap this replaced hid everything past the hundredth invite of an intake.
//!
//! **Rows the source table no longer has.** A used personal invite swept at its TTL is still
//! listed from the `invite_attributions` ledger (token `used:<12 hex>`), as before. A class
//! invite swept at its TTL is listed ONCE, summed from its redemptions (token `class:<12 hex>`,
//! `max_uses` null) — never as a hundred one-row entries. Neither kind of history row can be
//! revoked or shown on a projector; `code` is null on both.
//!
//! When a live personal row also has a ledger entry the ledger wins for used/used_by, so the
//! narrow window between the claim and the `used` UPDATE never shows up as "unused".

use serde::{Deserialize, Serialize};
use worker::*;

use crate::auth::middleware::{require_active_auth, require_admin};
use crate::d1util::{d1_int, d1_null, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;

const PAGE_DEFAULT: i64 = 100;
const PAGE_MAX: i64 = 200;

/// One page. Binds: `?1` cursor rank (NULL on the first page), `?2` cursor created_at, `?3` cursor
/// token, `?4` limit. Every arm of the UNION lists its columns in the same order.
pub(crate) const LIST_INVITES_PAGE_SQL: &str = "WITH live AS (
       SELECT CASE WHEN it.kind = 'class' THEN 0 ELSE 1 END AS rank,
              it.token AS token, it.code AS code, it.kind AS kind,
              COALESCE(it.email_hint, ia.email_hint) AS email_hint,
              CASE WHEN it.kind = 'class' THEN (CASE WHEN it.uses >= it.max_uses THEN 1 ELSE 0 END)
                   WHEN ia.invite_token_hash IS NULL THEN it.used ELSE 1 END AS used,
              COALESCE(ia.used_by, it.used_by) AS used_by,
              COALESCE(ia.inviter_user_id, it.owner_user_id) AS owner_user_id,
              it.expires_at AS expires_at, it.created_at AS created_at,
              it.max_uses AS max_uses, it.uses AS uses,
              CASE WHEN it.kind = 'class'
                   THEN (SELECT COUNT(*) FROM invite_attributions c
                          WHERE c.source_hash = it.token_hash AND c.verified_at IS NOT NULL)
                   WHEN COALESCE(ia.used_by, it.used_by) IS NULL THEN 0 ELSE 1 END AS joined,
              (SELECT COUNT(*) FROM group_join_requests r
                WHERE r.invite_hash = it.token_hash AND r.state = 'pending') AS pending_requests,
              it.landing_room_id AS landing_room_id,
              it.landing_needs_approval AS landing_needs_approval,
              it.introduce AS introduce, it.revoked_at AS revoked_at
         FROM invite_tokens it
         LEFT JOIN invite_attributions ia ON ia.invite_token_hash = it.token_hash
     ), spent AS (
       SELECT 1, 'used:' || substr(ia.invite_token_hash, 1, 12), NULL, 'personal',
              ia.email_hint, 1, ia.used_by, ia.inviter_user_id, ia.expires_at, ia.created_at,
              1, 1, CASE WHEN ia.used_by IS NULL THEN 0 ELSE 1 END, 0,
              ia.landing_room_id, 0, ia.introduce, NULL
         FROM invite_attributions ia
        WHERE ia.source_hash IS NULL
          AND NOT EXISTS (SELECT 1 FROM invite_tokens it WHERE it.token_hash = ia.invite_token_hash)
     ), swept_class AS (
       SELECT 1, 'class:' || substr(ia.source_hash, 1, 12), NULL, 'class',
              MAX(ia.email_hint), 1, NULL, MAX(ia.inviter_user_id), MAX(ia.expires_at),
              MIN(ia.created_at), NULL, COUNT(*),
              SUM(CASE WHEN ia.verified_at IS NULL THEN 0 ELSE 1 END),
              (SELECT COUNT(*) FROM group_join_requests r
                WHERE r.invite_hash = ia.source_hash AND r.state = 'pending'),
              MAX(ia.landing_room_id), MAX(ia.landing_needs_approval), 0, NULL
         FROM invite_attributions ia
        WHERE ia.source_hash IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM invite_tokens it WHERE it.token_hash = ia.source_hash)
        GROUP BY ia.source_hash
     ), all_rows AS (
       SELECT * FROM live UNION ALL SELECT * FROM spent UNION ALL SELECT * FROM swept_class
     )
     SELECT a.rank AS rank, a.token AS token, a.code AS code, a.kind AS kind,
            a.email_hint AS email_hint, a.used AS used, a.used_by AS used_by,
            a.owner_user_id AS owner_user_id, a.expires_at AS expires_at,
            a.created_at AS created_at, a.max_uses AS max_uses, a.uses AS uses,
            a.joined AS joined, a.pending_requests AS pending_requests,
            a.landing_room_id AS landing_room_id,
            a.landing_needs_approval AS landing_needs_approval,
            a.introduce AS introduce, a.revoked_at AS revoked_at,
            ub.email AS used_by_email, ob.email AS owner_email, g.name AS landing_group_name
       FROM all_rows a
       LEFT JOIN users ub ON a.used_by = ub.id
       LEFT JOIN users ob ON a.owner_user_id = ob.id
       LEFT JOIN groups g ON g.id = a.landing_room_id
      WHERE ?1 IS NULL OR a.rank > ?1
         OR (a.rank = ?1 AND (a.created_at < ?2 OR (a.created_at = ?2 AND a.token > ?3)))
      ORDER BY a.rank ASC, a.created_at DESC, a.token ASC
      LIMIT ?4";

/// The keyset position after a page.
#[derive(Serialize, Deserialize)]
struct Cursor {
    r: i64,
    c: i64,
    t: String,
}

#[derive(Deserialize)]
struct InviteRow {
    rank: i64,
    token: String,
    code: Option<String>,
    kind: String,
    email_hint: Option<String>,
    used: i64,
    used_by: Option<String>,
    owner_user_id: Option<String>,
    expires_at: i64,
    created_at: i64,
    max_uses: Option<i64>,
    uses: i64,
    joined: i64,
    pending_requests: i64,
    landing_room_id: Option<String>,
    landing_needs_approval: i64,
    introduce: i64,
    revoked_at: Option<i64>,
    used_by_email: Option<String>,
    owner_email: Option<String>,
    landing_group_name: Option<String>,
}

pub async fn list_invites(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let cursor: Option<Cursor> = match crate::page_cursor::from_request(&req) {
        Ok(c) => c,
        Err(()) => return json_err(400, "bad_cursor"),
    };
    let limit = crate::page_cursor::limit(
        crate::page_cursor::query(&req, "limit").as_deref(),
        PAGE_DEFAULT,
        PAGE_MAX,
    );
    let (r, c, t) = match &cursor {
        Some(k) => (d1_int(k.r), d1_int(k.c), d1_text(&k.t)),
        None => (d1_null(), d1_int(0), d1_text("")),
    };
    let db = ctx.env.d1("DB")?;
    // One row past the page says whether another exists.
    let mut rows: Vec<InviteRow> = db
        .prepare(LIST_INVITES_PAGE_SQL)
        .bind(&[r, c, t, d1_int(limit + 1)])?
        .all()
        .await?
        .results()?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().map(|row| {
            crate::page_cursor::encode(&Cursor {
                r: row.rank,
                c: row.created_at,
                t: row.token.clone(),
            })
        })
    } else {
        None
    };
    let now = now_secs();
    let invites: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "token": r.token,
                "code": r.code,
                "kind": r.kind,
                "label": r.email_hint,
                "email_hint": r.email_hint,
                "used": r.used == 1,
                "used_by": r.used_by,
                "used_by_email": r.used_by_email,
                "owner_user_id": r.owner_user_id,
                "owner_email": r.owner_email,
                "expires_at": r.expires_at,
                "created_at": r.created_at,
                "expired": (r.expires_at as u64) <= now,
                "max_uses": r.max_uses,
                "uses": r.uses,
                "joined": r.joined,
                "pending_requests": r.pending_requests,
                "landing_room_id": r.landing_room_id,
                "landing_group_name": r.landing_group_name,
                "landing_needs_approval": r.landing_needs_approval == 1,
                "introduce": r.introduce == 1,
                "revoked": r.revoked_at.is_some(),
                "revoked_at": r.revoked_at,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "invites": invites, "next": next }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    /// Two class invites (one live, one swept at its TTL with two redemptions), three personal
    /// ones (unused, used and live, used and swept), a join request on the live class.
    fn db() -> Connection {
        let db = crate::test_schema::full_schema();
        db.execute_batch(
            "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES
               ('adm', 'adm@x', x'00', 1), ('s1', 's1@x', x'00', 2), ('s2', 's2@x', x'00', 2),
               ('p1', 'p1@x', x'00', 2);
             INSERT INTO groups (id, name, created_by, created_at, updated_at)
               VALUES ('g', 'Data Structures', 'adm', 1, 1);
             INSERT INTO invite_tokens
               (token, token_hash, email_hint, used, owner_user_id, expires_at, created_at,
                kind, max_uses, uses, introduce, landing_room_id, landing_needs_approval, code)
             VALUES
               ('class-live', 'h-class-live', 'BIL203', 0, 'adm', 9999, 50, 'class', 120, 37, 0,
                'g', 1, 'K7QM-4827'),
               ('pers-unused', 'h-pers-unused', 'Ayse', 0, 'adm', 9999, 60, 'personal', 1, 0, 1,
                NULL, 0, 'Q7XK-M2PA'),
               ('pers-used', 'h-pers-used', 'Mert', 1, 'adm', 9999, 40, 'personal', 1, 1, 1,
                NULL, 0, 'B4NR-7WQE');
             INSERT INTO group_join_requests (group_id, user_id, invite_hash, state, requested_at)
               VALUES ('g', 's1', 'h-class-live', 'pending', 70);",
        )
        .unwrap();
        let ledger = |key: String, source: Option<&str>, used_by: Option<&str>, created: i64| {
            db.execute(
                "INSERT INTO invite_attributions
                   (invite_token_hash, email_hint, inviter_user_id, used_by, created_at, expires_at,
                    redeemed_at, verified_at, kind, source_hash, introduce)
                 VALUES (?1, 'x', 'adm', ?2, ?3, 100, ?3, ?4, ?5, ?6, ?7)",
                params![
                    key,
                    used_by,
                    created,
                    used_by.map(|_| created),
                    if source.is_some() {
                        "class"
                    } else {
                        "personal"
                    },
                    source,
                    if source.is_some() { 0 } else { 1 }
                ],
            )
            .unwrap();
        };
        // The live personal one, used by p1: its ledger row is keyed by its own hash.
        db.execute(
            "UPDATE invite_tokens SET token_hash = ?1 WHERE token = 'pers-used'",
            [&"a".repeat(64)],
        )
        .unwrap();
        ledger("a".repeat(64), None, Some("p1"), 40);
        // A personal invite swept long ago.
        ledger("b".repeat(64), None, Some("s2"), 10);
        // A class invite swept long ago: two redemptions, one verified.
        ledger("c".repeat(64), Some("h-class-old"), Some("s2"), 20);
        ledger("d".repeat(64), Some("h-class-old"), None, 20);
        // A redemption of the live class invite never shows as a row of its own.
        ledger("e".repeat(64), Some("h-class-live"), Some("s1"), 55);
        db
    }

    /// rank, token, kind, uses, joined, pending_requests, created_at.
    type Row = (i64, String, String, i64, i64, i64, i64);

    fn page(db: &Connection, after: Option<(i64, i64, &str)>, limit: i64) -> Vec<Row> {
        let (r, c, t) = match after {
            Some((r, c, t)) => (Some(r), c, t.to_string()),
            None => (None, 0, String::new()),
        };
        db.prepare(LIST_INVITES_PAGE_SQL)
            .unwrap()
            .query_map(params![r, c, t, limit], |row| {
                Ok((
                    row.get("rank")?,
                    row.get("token")?,
                    row.get("kind")?,
                    row.get("uses")?,
                    row.get("joined")?,
                    row.get("pending_requests")?,
                    row.get("created_at")?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn class_invites_come_first_with_their_live_counts() {
        let db = db();
        let all = page(&db, None, 50);
        let tokens: Vec<&str> = all.iter().map(|r| r.1.as_str()).collect();
        assert_eq!(
            tokens,
            [
                "class-live",
                "pers-unused",
                "pers-used",
                &format!("class:{}", &"h-class-old"[..11]),
                &format!("used:{}", "b".repeat(12)),
            ]
        );
        assert_eq!(
            all[0],
            (0, "class-live".into(), "class".into(), 37, 1, 1, 50)
        );
        let swept = &all[3];
        assert_eq!(
            (swept.2.as_str(), swept.3, swept.4),
            ("class", 2, 1),
            "summed, not one row each"
        );
    }

    #[test]
    fn the_cursor_walks_the_same_order_without_gaps() {
        let db = db();
        let all = page(&db, None, 50);
        let mut walked: Vec<Row> = Vec::new();
        let mut after: Option<(i64, i64, String)> = None;
        loop {
            let p = page(&db, after.as_ref().map(|(r, c, t)| (*r, *c, t.as_str())), 2);
            if p.is_empty() {
                break;
            }
            let last = p.last().unwrap();
            after = Some((last.0, last.6, last.1.clone()));
            walked.extend(p);
        }
        assert_eq!(walked, all);
    }
}
