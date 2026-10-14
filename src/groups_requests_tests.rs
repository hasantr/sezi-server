//! Join requests against the real schema, plus the source guard every group handler file carries.

use super::*;
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_780_000_000;

/// Group `g` run by `adm`, five students who asked to join at t = 1..=5.
fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, display_name, created_at) VALUES
           ('adm', 'a@x', x'00', 'Teacher', 1);
         INSERT INTO groups (id, name, created_by, created_at, updated_at)
           VALUES ('g', 'Data Structures', 'adm', 1, 1);
         INSERT INTO group_members (group_id, user_id, role, joined_at, status)
           VALUES ('g', 'adm', 'owner', 1, 'active');",
    )
    .unwrap();
    for i in 1..=5 {
        db.execute(
            "INSERT INTO users (id, email, identity_pubkey, display_name, created_at)
             VALUES (?1, ?1 || '@x', x'00', 'Student ' || ?1, 1)",
            [format!("s{i}")],
        )
        .unwrap();
        db.execute(
            "INSERT INTO group_join_requests
               (group_id, user_id, invite_hash, invite_label, state, requested_at)
             VALUES ('g', ?1, 'h-class', 'BIL203', 'pending', ?2)",
            params![format!("s{i}"), i],
        )
        .unwrap();
    }
    db
}

fn page(db: &Connection, after: Option<(i64, &str)>, limit: i64) -> Vec<String> {
    let (t, u) = match after {
        Some((t, u)) => (Some(t), u.to_string()),
        None => (None, String::new()),
    };
    db.prepare(LIST_PENDING_SQL)
        .unwrap()
        .query_map(params!["g", t, u, limit], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn state_of(db: &Connection, user: &str) -> Option<String> {
    db.query_row(
        "SELECT state FROM group_join_requests WHERE group_id='g' AND user_id=?1",
        [user],
        |r| r.get(0),
    )
    .optional()
    .unwrap()
}

fn approve(db: &Connection, user: Option<&str>, ceiling: i64) -> Vec<String> {
    if let Some(u) = user {
        db.execute(ADMIT_ONE_SQL, params!["g", u, NOW, "adm", ceiling])
            .unwrap();
    } else {
        db.execute(ADMIT_OLDEST_SQL, params!["g", NOW, "adm", ceiling])
            .unwrap();
    }
    db.prepare(MARK_APPROVED_SQL)
        .unwrap()
        .query_map(params!["g", user, NOW, "adm"], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn the_list_is_newest_first_and_the_cursor_walks_it_without_gaps() {
    let db = db();
    assert_eq!(page(&db, None, 2), ["s5", "s4"]);
    assert_eq!(page(&db, Some((4, "s4")), 2), ["s3", "s2"]);
    assert_eq!(page(&db, Some((2, "s2")), 2), ["s1"]);
}

/// Approval writes the ordinary consent row, added by the approver, and settles the request.
#[test]
fn approving_one_request_invites_the_requester_on_the_approvers_authority() {
    let db = db();
    assert_eq!(approve(&db, Some("s2"), 256), ["s2"]);
    let row: (String, Option<String>) = db
        .query_row(
            "SELECT status, added_by FROM group_members WHERE group_id='g' AND user_id='s2'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, ("pending".into(), Some("adm".into())));
    assert_eq!(state_of(&db, "s2").as_deref(), Some("approved"));
    assert!(
        approve(&db, Some("s2"), 256).is_empty(),
        "a second approve finds nothing pending"
    );
}

/// A full group refuses the request and leaves it pending — the handler answers 409, not 404.
#[test]
fn a_full_group_keeps_the_request_waiting() {
    let db = db();
    assert!(approve(&db, Some("s1"), 1).is_empty());
    assert_eq!(state_of(&db, "s1").as_deref(), Some("pending"));
}

#[test]
fn approve_all_admits_the_oldest_up_to_the_limit() {
    let db = db();
    let mut approved = approve(&db, None, 3);
    approved.sort();
    assert_eq!(approved, ["s1", "s2", "s3"]);
    assert_eq!(state_of(&db, "s4").as_deref(), Some("pending"));
    assert_eq!(state_of(&db, "s5").as_deref(), Some("pending"));
}

#[test]
fn a_denied_request_is_settled_and_nobody_is_added() {
    let db = db();
    let denied: Option<String> = db
        .query_row(DENY_SQL, params!["g", "s3", NOW, "adm"], |r| r.get(0))
        .optional()
        .unwrap();
    assert_eq!(denied.as_deref(), Some("s3"));
    assert_eq!(state_of(&db, "s3").as_deref(), Some("denied"));
    assert!(db
        .query_row(DENY_SQL, params!["g", "s3", NOW, "adm"], |r| r
            .get::<_, String>(0))
        .optional()
        .unwrap()
        .is_none());
    assert!(
        approve(&db, Some("s3"), 256).is_empty(),
        "a denied request cannot be approved"
    );
}

/// The requester sees their own requests, with the group's name, and nobody else's.
#[test]
fn the_requester_sees_only_their_own() {
    let db = db();
    db.query_row(DENY_SQL, params!["g", "s4", NOW, "adm"], |r| {
        r.get::<_, String>(0)
    })
    .unwrap();
    let mine: Vec<(String, Option<String>, String)> = db
        .prepare(MINE_SQL)
        .unwrap()
        .query_map(params!["s4", 50], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        mine,
        [("g".into(), Some("Data Structures".into()), "denied".into())]
    );
}

/// The decided rows go after their month, pending ones never.
#[test]
fn the_sweep_keeps_pending_requests() {
    let db = db();
    db.query_row(DENY_SQL, params!["g", "s1", 10, "adm"], |r| {
        r.get::<_, String>(0)
    })
    .unwrap();
    db.execute(crate::maintenance::DECIDED_JOIN_REQUEST_CLEANUP_SQL, [NOW])
        .unwrap();
    assert_eq!(state_of(&db, "s1"), None);
    assert_eq!(state_of(&db, "s2").as_deref(), Some("pending"));
}

/// A class invite as `invite_tokens` holds it, landing in `g`.
fn class_invite(db: &Connection, token: &str, expires_at: i64, revoked: bool) {
    db.execute(
        "INSERT INTO invite_tokens (token, token_hash, owner_user_id, email_hint, created_at,
                                    expires_at, kind, max_uses, introduce, landing_room_id,
                                    landing_needs_approval, revoked_at)
         VALUES (?1, 'h-' || ?1, 'adm', 'BIL203', 1, ?2, 'class', 100, 0, 'g', 1, ?3)",
        params![token, expires_at, if revoked { Some(5) } else { None }],
    )
    .unwrap();
}

fn landing_of(db: &Connection, token: &str) -> Option<(String, String, Option<String>, String)> {
    db.query_row(CLASS_LANDING_OF_TOKEN_SQL, params![token, NOW], |r| {
        Ok((r.get("room_id")?, r.get("invite_hash")?, r.get("label")?, r.get("name")?))
    })
    .optional()
    .unwrap()
}

/// `true` when the call opened (or re-opened) a request.
fn request_again(db: &Connection, user: &str) -> bool {
    db.query_row(REQUEST_AGAIN_SQL, params!["g", user, "h-cls", "BIL203", NOW], |_| Ok(()))
        .optional()
        .unwrap()
        .is_some()
}

/// Lab, 2026-10-05: Cem joined through the class invite, was let in, then removed. Using the
/// invite again from his existing account said "you are already on this server" and asked
/// nobody: there was no way back but an admin who happened to know his id. Someone already on
/// the server who presents a live class invite now asks to join its landing group — through the
/// same approval list.
#[test]
fn an_existing_member_presenting_a_class_invite_is_told_its_landing_group() {
    let db = db();
    class_invite(&db, "tok-live", NOW + 100, false);
    class_invite(&db, "tok-old", NOW - 1, false);
    class_invite(&db, "tok-revoked", NOW + 100, true);
    assert_eq!(
        landing_of(&db, "tok-live"),
        Some(("g".into(), "h-tok-live".into(), Some("BIL203".into()), "Data Structures".into()))
    );
    assert_eq!(landing_of(&db, "tok-old"), None, "expired");
    assert_eq!(landing_of(&db, "tok-revoked"), None, "revoked");
    assert_eq!(landing_of(&db, "nothing"), None);
}

#[test]
fn a_removed_student_asks_again_and_waits_for_the_admins() {
    let db = db();
    // s1 was let in, then removed: the approval is spent and no membership row is left.
    approve(&db, Some("s1"), 256);
    assert_eq!(state_of(&db, "s1").as_deref(), Some("approved"));
    db.execute("DELETE FROM group_members WHERE group_id='g' AND user_id='s1'", []).unwrap();

    assert!(request_again(&db, "s1"), "the old approval no longer holds: asked again");
    assert_eq!(state_of(&db, "s1").as_deref(), Some("pending"));
    assert_eq!(page(&db, None, 10).first().map(String::as_str), Some("s1"), "newest on top");
    // An admin approves it the ordinary way.
    assert_eq!(approve(&db, Some("s1"), 256), ["s1"]);

    // Someone new to the group (not s1..s5) asks for the first time.
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, display_name, created_at)
         VALUES ('cem', 'c@x', x'00', 'Cem', 1)",
        [],
    )
    .unwrap();
    assert!(request_again(&db, "cem"));
    assert_eq!(state_of(&db, "cem").as_deref(), Some("pending"));
}

#[test]
fn a_waiting_or_refused_request_is_not_reopened() {
    let db = db();
    assert!(!request_again(&db, "s2"), "already waiting: nothing new");
    assert_eq!(state_of(&db, "s2").as_deref(), Some("pending"));
    db.query_row(DENY_SQL, params!["g", "s3", NOW, "adm"], |r| r.get::<_, String>(0))
        .unwrap();
    assert!(!request_again(&db, "s3"), "the admins said no; asking again does not undo it");
    assert_eq!(state_of(&db, "s3").as_deref(), Some("denied"));
}

/// The same guard `groups_tests.rs` keeps over `groups.rs`: every handler here goes through the
/// revocation-aware gate, either directly or through `admin_gate`, which calls it.
#[test]
fn every_join_request_handler_gates_on_a_live_device() {
    const SRC: &str = include_str!("groups_requests.rs");
    let handlers = SRC.matches("\npub async fn ").count();
    let gated = SRC.matches("admin_gate(&req, &ctx)").count()
        + SRC
            .matches("require_live_device_auth(&req, &ctx.env)")
            .count();
    assert_eq!(handlers, gated, "{handlers} handlers, {gated} gated");
    assert!(handlers >= 5);
    assert!(SRC.contains("let caller = require_live_device_auth(req, &ctx.env)"));
    assert!(!SRC.contains("require_auth(") && !SRC.contains("require_owner("));
}
