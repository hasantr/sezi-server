//! Drive spaces (`drive.rs`): every statement the handler issues, run with rusqlite against the
//! REAL migration chain, plus the statements elsewhere that now tell a space from a group.

use super::*;
use crate::test_schema::full_schema;
use rusqlite::{params, Connection};

fn db() -> Connection {
    let db = full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES
           ('ayse', 'ayse@example.test', x'00', 1),
           ('mert', 'mert@example.test', x'00', 1);
         INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES
           ('room-a', 'Physics 101', 'ayse', 1, 1);
         INSERT INTO group_members (group_id, user_id, role, joined_at, status) VALUES
           ('room-a', 'ayse', 'owner', 1, 'active');",
    )
    .unwrap();
    db
}

/// One call of `put_personal`'s batch, with `fresh` as the id it would mint.
fn ensure(db: &Connection, user: &str, fresh: &str) -> String {
    db.execute(ENSURE_PERSONAL_SQL, params![fresh, user, 10, SPACE_NAME]).unwrap();
    db.execute(ENSURE_PERSONAL_MEMBER_SQL, params![user, 10]).unwrap();
    db.query_row(PERSONAL_SQL, params![user], |r| r.get(0)).unwrap()
}

fn count(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn the_migration_is_wired_into_self_provision() {
    let src = include_str!("self_provision_migrations.rs");
    assert!(src.contains("include_str!(\"../migrations/0062_drive_spaces.sql\")"));
}

/// Every group made before 0062 is a group, and so is one made by the old INSERT that names no
/// kind — the previous build's writes still mean what they meant.
#[test]
fn a_group_without_a_kind_is_a_group() {
    let db = db();
    let kind: String = db.query_row(KIND_SQL, params!["room-a"], |r| r.get(0)).unwrap();
    assert_eq!(kind, "group");
}

/// Repeated calls, and calls that each minted their own id (two racing devices), all land on ONE
/// space with ONE owner row; the first id wins.
#[test]
fn a_member_has_one_personal_space_however_often_it_is_asked_for() {
    let db = db();
    let first = ensure(&db, "ayse", "drive-1");
    assert_eq!(first, "drive-1");
    assert_eq!(ensure(&db, "ayse", "drive-1"), "drive-1");
    assert_eq!(ensure(&db, "ayse", "drive-2"), "drive-1", "a second id never makes a second space");
    // The unique index alone also holds when the existence filter is bypassed.
    let raw = db.execute(
        "INSERT OR IGNORE INTO groups (id, name, created_by, created_at, updated_at, kind)
         VALUES ('drive-3', 'drive', 'ayse', 1, 1, 'drive_personal')",
        [],
    );
    assert_eq!(raw.unwrap(), 0);
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM groups WHERE created_by = 'ayse' AND kind = 'drive_personal'"),
        1
    );
    let (role, status): (String, String) = db
        .query_row(
            "SELECT role, status FROM group_members WHERE group_id = 'drive-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((role.as_str(), status.as_str()), ("owner", "active"));
    assert_eq!(count(&db, "SELECT COUNT(*) FROM group_members WHERE group_id = 'drive-1'"), 1);
    let name: String = db
        .query_row("SELECT name FROM groups WHERE id = 'drive-1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(name, SPACE_NAME, "a space's name on the relay says nothing");
    // Another member gets their own.
    assert_eq!(ensure(&db, "mert", "drive-m"), "drive-m");
}

/// The listing: a space only with `kinds=all`, and the total counts what the page would hold.
#[test]
fn a_space_is_listed_only_to_an_app_that_asks_for_it() {
    let db = db();
    ensure(&db, "ayse", "drive-1");
    let ids = |all: i64| -> Vec<(String, String)> {
        let mut stmt = db.prepare(crate::groups::read::MY_GROUPS_SQL).unwrap();
        stmt.query_map(params!["ayse", all, 200], |r| Ok((r.get(0)?, r.get(11)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(ids(0), vec![("room-a".to_string(), "group".to_string())]);
    let mut all = ids(1);
    all.sort();
    assert_eq!(
        all,
        vec![
            ("drive-1".to_string(), "drive_personal".to_string()),
            ("room-a".to_string(), "group".to_string())
        ]
    );
    let total = |all: i64| -> i64 {
        db.query_row(crate::groups::read::MY_GROUPS_COUNT_SQL, params!["ayse", all], |r| r.get(0))
            .unwrap()
    };
    assert_eq!((total(0), total(1)), (1, 2));
}

/// A personal space is no way past `MAX_OWNED_GROUPS`.
#[test]
fn a_personal_space_is_not_an_owned_group() {
    let db = db();
    ensure(&db, "ayse", "drive-1");
    let owned: i64 = db
        .query_row(crate::groups::transfer::OWNED_GROUP_COUNT_SQL, params!["ayse"], |r| r.get(0))
        .unwrap();
    assert_eq!(owned, 1, "room-a only");
}

/// The server's library retention is frozen onto a group's parts and never onto a drive's.
#[test]
fn a_drive_keeps_its_files_while_a_group_keeps_the_retention() {
    let db = db();
    ensure(&db, "ayse", "drive-1");
    db.execute("UPDATE server_settings SET library_retention_days = 90 WHERE id = 1", [])
        .unwrap();
    let retention = |room: &str| -> Option<i64> {
        db.query_row(crate::room_library::PUT_POLICY_SQL, params![room], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(retention("room-a"), Some(90));
    assert_eq!(retention("drive-1"), None);
    assert_eq!(retention("no-such-room"), Some(90), "an unknown room is treated as a group");
}

/// A class invite never lands anyone in a drive, directly or as a request.
#[test]
fn an_invite_never_lands_in_a_drive() {
    use crate::auth::landing::{LAND_DIRECT_SQL, LAND_REQUEST_SQL};
    let db = db();
    ensure(&db, "ayse", "drive-1");
    let mut direct = db.prepare(LAND_DIRECT_SQL).unwrap();
    let landed = direct
        .query(params!["drive-1", "mert", 20, "ayse", 256])
        .unwrap()
        .next()
        .unwrap()
        .is_some();
    assert!(!landed);
    let mut request = db.prepare(LAND_REQUEST_SQL).unwrap();
    let asked = request
        .query(params!["drive-1", "mert", "hash", "label", 20])
        .unwrap()
        .next()
        .unwrap()
        .is_some();
    assert!(!asked);
    // …while the same statements still land in a group.
    let mut direct = db.prepare(LAND_DIRECT_SQL).unwrap();
    assert!(direct
        .query(params!["room-a", "mert", 20, "ayse", 256])
        .unwrap()
        .next()
        .unwrap()
        .is_some());
}

/// Deleting the space (the ordinary group teardown) frees the member to have a new one.
#[test]
fn a_deleted_drive_can_be_made_again() {
    let db = db();
    ensure(&db, "ayse", "drive-1");
    db.execute("DELETE FROM groups WHERE id = 'drive-1'", []).unwrap();
    assert_eq!(ensure(&db, "ayse", "drive-2"), "drive-2");
}

/// Every write that would give a personal space a second member, a bot, a new owner, new
/// settings or a join request runs the guard first — a source-level check, as the rest of the
/// group surface's guards are, because the handlers need a live worker.
#[test]
fn every_write_that_would_open_a_personal_space_is_guarded() {
    let groups = include_str!("groups.rs");
    for name in ["add_member", "set_role", "update_settings"] {
        let start = groups.find(&format!("\npub async fn {name}(")).unwrap();
        let rest = &groups[start + 1..];
        let body = &rest[..rest.find("\npub async fn ").unwrap_or(rest.len())];
        assert!(body.contains("crate::drive::refuse_personal"), "{name} is not guarded");
    }
    let requests = include_str!("groups_requests.rs");
    let gate = &requests[requests.find("async fn admin_gate(").unwrap()..];
    assert!(gate[..gate.find("\n}\n").unwrap()].contains("crate::drive::refuse_personal"));
    let bots = include_str!("groups_bots.rs");
    let gate = &bots[bots.find("async fn gate(").unwrap()..];
    assert!(gate[..gate.find("\n}\n").unwrap()].contains("crate::drive::refuse_personal"));
}
