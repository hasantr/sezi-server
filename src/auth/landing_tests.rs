//! Landing against the real schema: who is added directly, who waits as a request, and the rule
//! that a personally invited member never waits.

use super::*;
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_780_000_000;

/// Group `g` run by `adm`; `stu` has just registered; `ex` used to be an admin and is now a member.
fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES
           ('adm', 'a@x', x'00', 1), ('stu', 's@x', x'00', 2), ('ex', 'e@x', x'00', 1);
         INSERT INTO groups (id, name, created_by, created_at, updated_at)
           VALUES ('g', 'Data Structures', 'adm', 1, 1);
         INSERT INTO group_members (group_id, user_id, role, joined_at, status) VALUES
           ('g', 'adm', 'owner', 1, 'active'), ('g', 'ex', 'member', 1, 'active');",
    )
    .unwrap();
    db
}

fn land_direct(db: &Connection, minter: Option<&str>, ceiling: i64) -> bool {
    db.query_row(
        LAND_DIRECT_SQL,
        params!["g", "stu", NOW, minter, ceiling],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .unwrap()
    .is_some()
}

fn land_request(db: &Connection, room: &str) -> bool {
    db.query_row(
        LAND_REQUEST_SQL,
        params![room, "stu", "h-class", "BIL203", NOW],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .unwrap()
    .is_some()
}

#[test]
fn approval_is_only_ever_asked_of_a_class_invite() {
    assert_eq!(first_step(true, true), FirstStep::Request);
    assert_eq!(first_step(true, false), FirstStep::Direct);
    assert_eq!(first_step(false, false), FirstStep::Direct);
    // Even a corrupt snapshot cannot put a personal invitee into the request state.
    assert_eq!(first_step(false, true), FirstStep::Direct);
}

/// A direct landing is the ordinary consent row, added by the minter — so the joiner's
/// acceptance reaches someone who can hand over the room key.
#[test]
fn a_direct_landing_is_a_pending_row_added_by_the_minter() {
    let db = db();
    assert!(land_direct(&db, Some("adm"), LANDING_GROUP_CEILING));
    let row: (String, String, Option<String>) = db
        .query_row(
            "SELECT role, status, added_by FROM group_members WHERE group_id='g' AND user_id='stu'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, ("member".into(), "pending".into(), Some("adm".into())));
    assert!(
        !land_direct(&db, Some("adm"), LANDING_GROUP_CEILING),
        "a retry is a no-op"
    );
}

/// Nobody is added on the authority of someone who no longer holds it, and a full group is full.
#[test]
fn a_direct_landing_needs_a_sitting_admin_and_room() {
    let db = db();
    assert!(
        !land_direct(&db, Some("ex"), LANDING_GROUP_CEILING),
        "a demoted minter"
    );
    assert!(
        !land_direct(&db, None, LANDING_GROUP_CEILING),
        "a removed minter"
    );
    assert!(
        !land_direct(&db, Some("adm"), 2),
        "two rows already fill a ceiling of two"
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM group_members WHERE user_id='stu'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn a_request_is_written_once_and_only_for_a_group_that_exists() {
    let db = db();
    assert!(land_request(&db, "g"));
    assert!(
        !land_request(&db, "g"),
        "a verify retry does not duplicate it"
    );
    assert!(!land_request(&db, "gone"));
    let row: (String, Option<String>, Option<String>) = db
        .query_row(
            "SELECT state, invite_hash, invite_label FROM group_join_requests",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "pending".into(),
            Some("h-class".into()),
            Some("BIL203".into())
        )
    );
}

/// The cascades the teardowns rely on: neither deleting the group nor deleting the account needs a
/// statement of its own for the requests.
#[test]
fn requests_go_with_their_group_and_with_their_requester() {
    let db = db();
    land_request(&db, "g");
    db.execute("DELETE FROM users WHERE id = 'stu'", [])
        .unwrap();
    let count = |db: &Connection| {
        db.query_row("SELECT COUNT(*) FROM group_join_requests", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };
    assert_eq!(count(&db), 0);
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('stu', 's@x', x'00', 2)",
        [],
    )
    .unwrap();
    land_request(&db, "g");
    db.execute("DELETE FROM group_members WHERE group_id = 'g'", [])
        .unwrap();
    db.execute("DELETE FROM groups WHERE id = 'g'", []).unwrap();
    assert_eq!(count(&db), 0);
}

/// A personal invite's landing reaches its ledger row through the follow-up snapshot, and a class
/// row is never touched by it.
#[test]
fn the_personal_snapshot_copies_the_room_onto_the_redemption() {
    let db = db();
    db.execute_batch(
        "INSERT INTO invite_tokens
           (token, token_hash, used, owner_user_id, expires_at, created_at, landing_room_id)
           VALUES ('t', 'h-pers', 1, 'adm', 9999, 1, 'g');",
    )
    .unwrap();
    db.execute(
        "INSERT INTO invite_attributions
           (invite_token_hash, inviter_user_id, created_at, expires_at, redeemed_at)
         VALUES ('h-pers' || ?1, 'adm', 1, 9999, 2)",
        [&"0".repeat(58)],
    )
    .unwrap();
    // The ledger is keyed by the token hash; rebuild the fixture so the two agree.
    let key = format!("h-pers{}", "0".repeat(58));
    db.execute("UPDATE invite_tokens SET token_hash = ?1", [&key])
        .unwrap();
    db.execute(SNAPSHOT_PERSONAL_LANDING_SQL, [&key]).unwrap();
    let room: Option<String> = db
        .query_row("SELECT landing_room_id FROM invite_attributions", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(room.as_deref(), Some("g"));
}
