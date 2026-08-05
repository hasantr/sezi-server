//! Tests for `membership.rs` (split out per the 800-line ceiling; included via `#[path]`).
//! `super` = the `membership` module, so `use super::X` reaches the SQL constants unchanged.
//! `include_str!` on the migrations resolves relative to THIS file, which sits next to
//! `membership.rs` in `src/`, so the relative paths carry over untouched.

use super::{
    ADMIN_MEMBERSHIP_GUARD_SQL, INSERT_COUNTERPART_REVISIONS_SQL, PROMOTE_GROUP_SUCCESSORS_SQL,
    SELF_MEMBERSHIP_GUARD_SQL, TRANSFER_CREATED_GROUPS_SQL, UPSERT_COUNTERPART_TOMBSTONES_SQL,
};
use rusqlite::{params, Connection};

#[test]
fn transaction_guard_rejects_owner_or_missing_target() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE users(id TEXT PRIMARY KEY,role TEXT NOT NULL);
         INSERT INTO users VALUES('owner','owner'),('member','member');",
    )
    .unwrap();
    db.execute_batch(include_str!(
        "../migrations/0034_membership_cleanup_outbox.sql"
    ))
    .unwrap();

    for target in ["owner", "missing"] {
        let error = db
            .execute(SELF_MEMBERSHIP_GUARD_SQL, params![target])
            .unwrap_err();
        assert!(error.to_string().contains("NOT NULL"));
    }
    db.execute(SELF_MEMBERSHIP_GUARD_SQL, params!["member"])
        .unwrap();
    assert_eq!(
        db.query_row(
            "SELECT target_id FROM membership_delete_guard WHERE slot=1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap(),
        "member"
    );
}

#[test]
fn admin_guard_rechecks_both_roles_inside_the_delete_transaction() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE users(id TEXT PRIMARY KEY,role TEXT NOT NULL);
         CREATE TABLE devices(user_id TEXT,device_id TEXT,revoked_at INTEGER);
         INSERT INTO users VALUES
           ('owner','owner'),('admin','admin'),('other-admin','admin'),
           ('member','member'),('demoted','member');
         INSERT INTO devices VALUES
           ('owner','owner-device',NULL),('admin','admin-device',NULL),
           ('demoted','demoted-device',NULL);",
    )
    .unwrap();
    db.execute_batch(include_str!(
        "../migrations/0034_membership_cleanup_outbox.sql"
    ))
    .unwrap();

    for (target, caller) in [
        ("owner", "admin"),
        ("other-admin", "admin"),
        ("member", "demoted"),
        ("admin", "admin"),
    ] {
        let error = db
            .execute(
                ADMIN_MEMBERSHIP_GUARD_SQL,
                params![target, caller, format!("{caller}-device")],
            )
            .unwrap_err();
        assert!(error.to_string().contains("NOT NULL"));
    }

    db.execute(
        ADMIN_MEMBERSHIP_GUARD_SQL,
        params!["member", "admin", "admin-device"],
    )
    .unwrap();
    db.execute("DELETE FROM membership_delete_guard", [])
        .unwrap();
    db.execute(
        ADMIN_MEMBERSHIP_GUARD_SQL,
        params!["other-admin", "owner", "owner-device"],
    )
    .unwrap();

    db.execute("DELETE FROM membership_delete_guard", [])
        .unwrap();
    db.execute("UPDATE devices SET revoked_at=1 WHERE user_id='admin'", [])
        .unwrap();
    let error = db
        .execute(
            ADMIN_MEMBERSHIP_GUARD_SQL,
            params!["member", "admin", "admin-device"],
        )
        .unwrap_err();
    assert!(error.to_string().contains("NOT NULL"));
}

#[test]
fn membership_contact_tombstones_are_set_based_and_replay_safe() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE users(id TEXT PRIMARY KEY);
         INSERT INTO users VALUES('gone'),('grant-peer'),('request-peer'),('block-peer');
         CREATE TABLE contact_grants(user_low TEXT,user_high TEXT);
         CREATE TABLE contact_requests(source_user_id TEXT,target_user_id TEXT);
         CREATE TABLE contact_blocks(blocker_user_id TEXT,blocked_user_id TEXT);
         CREATE TABLE contact_revisions(
           revision INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,
           account_id TEXT NOT NULL,peer_id TEXT,entity TEXT NOT NULL,
           entity_id TEXT NOT NULL,action TEXT NOT NULL,created_at INTEGER NOT NULL);
         CREATE TABLE contact_tombstones(
           account_id TEXT NOT NULL,entity TEXT NOT NULL,entity_id TEXT NOT NULL,
           peer_id TEXT,revision INTEGER NOT NULL,deleted_at INTEGER NOT NULL,
           PRIMARY KEY(account_id,entity,entity_id));
         INSERT INTO contact_grants VALUES('gone','grant-peer');
         INSERT INTO contact_requests VALUES('request-peer','gone');
         INSERT INTO contact_blocks VALUES('gone','block-peer');",
    )
    .unwrap();

    for _ in 0..2 {
        db.execute(INSERT_COUNTERPART_REVISIONS_SQL, params!["gone", 10])
            .unwrap();
        db.execute(UPSERT_COUNTERPART_TOMBSTONES_SQL, params!["gone", 10])
            .unwrap();
    }
    let revisions: i64 = db
        .query_row("SELECT COUNT(*) FROM contact_revisions", [], |r| r.get(0))
        .unwrap();
    let tombstones: i64 = db
        .query_row("SELECT COUNT(*) FROM contact_tombstones", [], |r| r.get(0))
        .unwrap();
    assert_eq!(revisions, 3, "a replay must not multiply the revision");
    assert_eq!(tombstones, 3);
    let wrong_peer: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM contact_tombstones WHERE peer_id!='gone'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(wrong_peer, 0);
}

#[test]
fn group_owner_moves_to_active_admin_and_pending_only_group_closes() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE groups(id TEXT PRIMARY KEY,created_by TEXT NOT NULL);
         CREATE TABLE group_members(
           group_id TEXT,user_id TEXT,role TEXT,status TEXT,joined_at INTEGER,
           PRIMARY KEY(group_id,user_id));
         INSERT INTO groups VALUES('survives','gone'),('closes','gone');
         INSERT INTO group_members VALUES
           ('survives','gone','owner','active',1),
           ('survives','member','member','active',2),
           ('survives','admin','admin','active',3),
           ('closes','gone','owner','active',1),
           ('closes','pending','member','pending',2);",
    )
    .unwrap();
    db.execute(PROMOTE_GROUP_SUCCESSORS_SQL, params!["gone"])
        .unwrap();
    db.execute(TRANSFER_CREATED_GROUPS_SQL, params!["gone"])
        .unwrap();
    db.execute("DELETE FROM groups WHERE created_by=?", params!["gone"])
        .unwrap();

    let owner: (String, String) = db
        .query_row(
            "SELECT g.created_by,gm.role FROM groups g JOIN group_members gm
               ON gm.group_id=g.id AND gm.user_id=g.created_by WHERE g.id='survives'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(owner, ("admin".into(), "owner".into()));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM groups WHERE id='closes'", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

/// The three statements the account-deletion batch runs over groups, in order, against a fresh
/// in-memory schema seeded by the caller. Returns the connection so each test can assert on it.
///
/// `seed` is raw SQL for the `groups` / `group_members` rows. The columns are the ones the three
/// statements actually read; `groups.created_by` is what the succession keys on, NOT the owner row.
fn run_succession(seed: &str) -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE groups(id TEXT PRIMARY KEY,created_by TEXT NOT NULL);
         CREATE TABLE group_members(
           group_id TEXT,user_id TEXT,role TEXT,status TEXT,joined_at INTEGER,
           PRIMARY KEY(group_id,user_id));
         CREATE INDEX idx_group_members_user ON group_members(user_id);",
    )
    .unwrap();
    db.execute_batch(seed).unwrap();
    db.execute(PROMOTE_GROUP_SUCCESSORS_SQL, params!["gone"])
        .unwrap();
    db.execute(TRANSFER_CREATED_GROUPS_SQL, params!["gone"])
        .unwrap();
    db.execute("DELETE FROM groups WHERE created_by=?", params!["gone"])
        .unwrap();
    // The departing user's own membership rows go in the same batch, a few statements later. They
    // have to be replayed here too, or every owner assertion below still sees the owner row the
    // deletion is in the middle of removing.
    db.execute("DELETE FROM group_members WHERE user_id=?", params!["gone"])
        .unwrap();
    db
}

/// Who ended up holding `group`: (`groups.created_by`, the user_ids carrying an owner ROW). The
/// second half is a list rather than a single value on purpose — the two-owner state this
/// statement can produce is invisible to a query that assumes there is one.
fn holders(db: &Connection, group: &str) -> (Option<String>, Vec<String>) {
    let created_by = db
        .query_row(
            "SELECT created_by FROM groups WHERE id=?",
            params![group],
            |r| r.get::<_, String>(0),
        )
        .ok();
    let mut stmt = db
        .prepare(
            "SELECT user_id FROM group_members
              WHERE group_id=? AND role='owner' ORDER BY user_id",
        )
        .unwrap();
    let owners = stmt
        .query_map(params![group], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    (created_by, owners)
}

#[test]
fn succession_hands_the_room_to_the_admin_who_owns_the_fewest_groups() {
    // `busy` joined first, so the joined_at tiebreaker alone would name them. They already own
    // three other groups; `light` owns none. Both are admins, so the role tier cannot separate
    // them and the owned-group count decides.
    let db = run_succession(
        "INSERT INTO groups VALUES
           ('target','gone'),('b1','busy'),('b2','busy'),('b3','busy');
         INSERT INTO group_members VALUES
           ('target','gone','owner','active',1),
           ('target','busy','admin','active',2),
           ('target','light','admin','active',3),
           ('b1','busy','owner','active',1),
           ('b2','busy','owner','active',1),
           ('b3','busy','owner','active',1);",
    );
    assert_eq!(
        holders(&db, "target"),
        (Some("light".into()), vec!["light".to_string()]),
        "the lighter of two equally ranked admins inherits"
    );
}

#[test]
fn succession_keeps_an_admin_ahead_of_an_unloaded_plain_member() {
    // The role tier dominates the load tier, and this is the case that proves it: `loaded` owns
    // five groups, `fresh` owns none and joined earlier. The room still goes to the admin.
    // Handing it to someone who has never administered anything is what `transfer_to` refuses
    // outright; the cap is a brake on bulk dumping, not a reason to demote that preference.
    let db = run_succession(
        "INSERT INTO groups VALUES
           ('target','gone'),('l1','loaded'),('l2','loaded'),('l3','loaded'),
           ('l4','loaded'),('l5','loaded');
         INSERT INTO group_members VALUES
           ('target','gone','owner','active',1),
           ('target','fresh','member','active',2),
           ('target','loaded','admin','active',3),
           ('l1','loaded','owner','active',1),
           ('l2','loaded','owner','active',1),
           ('l3','loaded','owner','active',1),
           ('l4','loaded','owner','active',1),
           ('l5','loaded','owner','active',1);",
    );
    assert_eq!(
        holders(&db, "target"),
        (Some("loaded".into()), vec!["loaded".to_string()]),
        "an over-cap admin still outranks an unloaded member"
    );
}

#[test]
fn succession_still_names_someone_when_every_candidate_is_loaded() {
    // The failure mode a hard cap would introduce. Both admins are far past any plausible
    // ceiling, so a filter would leave no candidate, the group would fall through to
    // `DELETE FROM groups WHERE created_by=?` and the room would be destroyed. Ordering cannot
    // do that: the candidate set is unchanged, so somebody always takes it.
    let mut seed = String::from("INSERT INTO groups VALUES ('target','gone')");
    let mut members = String::from(
        "INSERT INTO group_members VALUES
           ('target','gone','owner','active',1),
           ('target','heavy','admin','active',2),
           ('target','heavier','admin','active',3)",
    );
    for i in 0..70 {
        let who = if i < 65 { "heavier" } else { "heavy" };
        seed.push_str(&format!(",('g{i}','{who}')"));
        members.push_str(&format!(",('g{i}','{who}','owner','active',1)"));
    }
    let db = run_succession(&format!("{seed};{members};"));
    assert_eq!(
        holders(&db, "target"),
        (Some("heavy".into()), vec!["heavy".to_string()]),
        "no candidate is under any cap, so the least loaded one takes it and the group lives"
    );
}

#[test]
fn succession_does_not_mint_a_second_owner_beside_a_sitting_one() {
    // `created_by` still points at the departing user while somebody else holds the owner row —
    // the shape `groups_transfer.rs` warns about when its third statement fails to land. Ranking
    // the sitting owner first makes the promotion a no-op instead of promoting `adm` alongside
    // them, which nothing on the group surface could then resolve.
    let db = run_succession(
        "INSERT INTO groups VALUES ('target','gone');
         INSERT INTO group_members VALUES
           ('target','gone','admin','active',1),
           ('target','adm','admin','active',2),
           ('target','sitting','owner','active',3);",
    );
    assert_eq!(
        holders(&db, "target"),
        (Some("sitting".into()), vec!["sitting".to_string()]),
        "the sitting owner keeps the room and stays the only one"
    );
}
