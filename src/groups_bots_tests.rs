//! A room's bots against the real schema (`test_schema::full_schema`, foreign keys ON as D1
//! enforces them): the statements run here are the very consts `groups_bots.rs`,
//! `groups_read.rs`, `groups_delete.rs` and `bots/provision.rs` ship, bound in the same order.
//!
//! The handlers themselves need D1, a Durable Object and a live worker, so who may call them is
//! guarded at source level at the bottom, the way `groups_tests.rs` guards the rest of the group
//! surface.

use super::*;
use crate::bots::provision::LEAVE_ROOMS_SQL;
use rusqlite::{params, Connection};

const NOW: i64 = 1_761_200_000;
const ROOM: &str = "g-room";
const OTHER: &str = "g-other";
/// In ROOM.
const BOT: &str = "b-echo";
/// In OTHER only.
const ELSEWHERE: &str = "b-elsewhere";
/// In ROOM, turned off.
const OFF: &str = "b-off";
/// Had a ROOM row when it was soft-deleted (the row the delete batch would drop, left in place).
const GONE: &str = "b-gone";

fn user(db: &Connection, id: &str, kind: &str) {
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, display_name, created_at, kind)
         VALUES (?1, ?1 || '@example.test', X'01', ?1, ?2, ?3)",
        params![id, NOW, kind],
    )
    .unwrap();
}

fn bot(db: &Connection, id: &str, name: &str) {
    user(db, id, "bot");
    db.execute(
        "INSERT INTO bots (bot_id, name, created_by, created_at) VALUES (?1, ?2, 'owner', ?3)",
        params![id, name, NOW],
    )
    .unwrap();
}

fn room(db: &Connection, id: &str, name: &str, admin: &str) {
    db.execute(
        "INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)",
        params![id, name, admin, NOW],
    )
    .unwrap();
    db.execute(
        "INSERT INTO group_members (group_id, user_id, role, joined_at, status)
         VALUES (?1, ?2, 'owner', ?3, 'active')",
        params![id, admin, NOW],
    )
    .unwrap();
}

/// Added the way `add_room_bot` adds: `ADD_ROOM_BOT_SQL`. Returns whether a row is new.
fn add(db: &Connection, group: &str, bot_id: &str, at: i64) -> bool {
    let mut stmt = db.prepare(ADD_ROOM_BOT_SQL).unwrap();
    let rows: Vec<String> = stmt
        .query_map(params![group, bot_id, "alice", at], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    !rows.is_empty()
}

fn setup() -> Connection {
    let db = crate::test_schema::full_schema();
    user(&db, "owner", "human");
    user(&db, "alice", "human");
    room(&db, ROOM, "Hukuk", "alice");
    room(&db, OTHER, "Arşiv", "alice");
    bot(&db, BOT, "Echo");
    bot(&db, ELSEWHERE, "Kayıt");
    bot(&db, OFF, "Off");
    bot(&db, GONE, "Gone");
    assert!(add(&db, ROOM, BOT, NOW + 1));
    assert!(add(&db, OTHER, ELSEWHERE, NOW + 2));
    assert!(add(&db, ROOM, OFF, NOW + 3));
    assert!(add(&db, ROOM, GONE, NOW + 4));
    db.execute("UPDATE bots SET disabled_at = ?2 WHERE bot_id = ?1", params![OFF, NOW + 5]).unwrap();
    db.execute("UPDATE bots SET deleted_at = ?2 WHERE bot_id = ?1", params![GONE, NOW + 6]).unwrap();
    db
}

fn room_bot(db: &Connection, group: &str, who: &str) -> bool {
    db.prepare(ROOM_BOT_SQL).unwrap().exists(params![group, who]).unwrap()
}

fn count(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn the_room_bot_sql_admits_only_a_bot_of_that_room() {
    let db = setup();
    assert!(room_bot(&db, ROOM, BOT), "a bot of the room");
    assert!(!room_bot(&db, ROOM, ELSEWHERE), "a bot of another room");
    assert!(room_bot(&db, OTHER, ELSEWHERE));
    assert!(!room_bot(&db, OTHER, BOT));
    assert!(!room_bot(&db, ROOM, "alice"), "a human, even the room's owner");
    assert!(!room_bot(&db, ROOM, GONE), "a deleted bot, even with its row still there");
    assert!(room_bot(&db, ROOM, OFF), "turning a bot off keeps its rooms");
    assert!(!room_bot(&db, "no-such-room", BOT));
}

#[test]
fn bot_rooms_lists_every_room_of_the_bot_by_name() {
    let db = setup();
    assert!(add(&db, OTHER, BOT, NOW + 7));
    let mut stmt = db.prepare(BOT_ROOMS_SQL).unwrap();
    let rooms: Vec<(String, String)> = stmt
        .query_map(params![BOT], |r| Ok((r.get("group_id")?, r.get("name")?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        rooms,
        vec![(OTHER.to_string(), "Arşiv".to_string()), (ROOM.to_string(), "Hukuk".to_string())]
    );
}

#[test]
fn adding_needs_a_live_enabled_bot_and_is_idempotent() {
    let db = setup();
    assert!(!add(&db, ROOM, BOT, NOW + 10), "already in the room: no new row, so no nudge");
    assert!(!add(&db, OTHER, OFF, NOW + 10), "a disabled bot is not added");
    assert!(!add(&db, OTHER, GONE, NOW + 10), "a deleted bot is not added");
    assert!(!add(&db, OTHER, "alice", NOW + 10), "a human is not a bot");
    let (by, at): (String, i64) = db
        .query_row(
            "SELECT added_by, added_at FROM group_bots WHERE group_id = ?1 AND bot_id = ?2",
            params![ROOM, BOT],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((by.as_str(), at), ("alice", NOW + 1), "the re-add changed nothing");
    // What the handler reads before adding, to answer 404 / 409.
    let state = |id: &str| -> Option<Option<i64>> {
        db.query_row(BOT_STATE_SQL, params![id], |r| r.get(0)).ok()
    };
    assert_eq!(state(BOT), Some(None));
    assert_eq!(state(OFF), Some(Some(NOW + 5)), "409 bot_disabled");
    assert_eq!(state(GONE), None, "404 bot_not_found");
    assert_eq!(state("alice"), None, "404 bot_not_found");
}

#[test]
fn removing_is_idempotent_and_says_whether_a_row_went() {
    let db = setup();
    let remove = |group: &str, id: &str| -> usize {
        let mut stmt = db.prepare(REMOVE_ROOM_BOT_SQL).unwrap();
        stmt.query_map(params![group, id], |r| r.get::<_, String>(0)).unwrap().count()
    };
    assert_eq!(remove(ROOM, BOT), 1);
    assert_eq!(remove(ROOM, BOT), 0, "a second remove: nothing went, no nudge, no event");
    assert_eq!(remove(ROOM, ELSEWHERE), 0, "a bot of another room is not touched");
    assert!(room_bot(&db, OTHER, ELSEWHERE));
}

#[test]
fn the_picker_lists_every_live_bot_and_marks_the_rooms_own() {
    let db = setup();
    let mut stmt = db.prepare(ROOM_BOT_PICKER_SQL).unwrap();
    let rows: Vec<(String, bool, bool)> = stmt
        .query_map(params![ROOM], |r| {
            Ok((
                r.get("bot_id")?,
                r.get::<_, Option<i64>>("disabled_at")?.is_some(),
                r.get::<_, Option<i64>>("added_at")?.is_some(),
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    // Ordered by name: Echo, Kayıt, Off. The deleted bot is not offered.
    assert_eq!(
        rows,
        vec![
            (BOT.to_string(), false, true),
            (ELSEWHERE.to_string(), false, false),
            (OFF.to_string(), true, true),
        ]
    );
}

#[test]
fn the_member_list_carries_live_room_bots_beside_the_members() {
    let db = setup();
    let mut stmt = db.prepare(super::super::read::ROOM_BOTS_SQL).unwrap();
    let rows: Vec<(String, String, Option<String>, i64)> = stmt
        .query_map(params![ROOM], |r| {
            Ok((r.get("bot_id")?, r.get("name")?, r.get("added_by")?, r.get("added_at")?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        rows,
        vec![
            (BOT.to_string(), "Echo".to_string(), Some("alice".to_string()), NOW + 1),
            (OFF.to_string(), "Off".to_string(), Some("alice".to_string()), NOW + 3),
        ],
        "by added_at; the deleted bot is left out, the disabled one stays"
    );
    // A bot is never a member row: the member list's own table holds none of them.
    assert_eq!(count(&db, "SELECT COUNT(*) FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE u.kind = 'bot'"), 0);
}

#[test]
fn the_event_names_the_room_and_the_admin() {
    let db = setup();
    let (room_name, who, role): (String, Option<String>, String) = db
        .query_row(ROOM_EVENT_SQL, params![ROOM, "alice"], |r| {
            Ok((r.get("room_name")?, r.get("display_name")?, r.get("server_role")?))
        })
        .unwrap();
    assert_eq!((room_name.as_str(), who.as_deref(), role.as_str()), ("Hukuk", Some("alice"), "member"));
}

#[test]
fn deleting_the_group_drops_its_bot_rows() {
    let db = setup();
    // The FK cascade alone, as if the explicit statement were not in the batch.
    db.execute("DELETE FROM group_members WHERE group_id = ?1", params![ROOM]).unwrap();
    db.execute("DELETE FROM groups WHERE id = ?1", params![ROOM]).unwrap();
    assert_eq!(count(&db, "SELECT COUNT(*) FROM group_bots WHERE group_id = 'g-room'"), 0, "cascade");
    assert_eq!(count(&db, "SELECT COUNT(*) FROM group_bots WHERE group_id = 'g-other'"), 1, "the room next door keeps its bot");
    // And the explicit statement the teardown batch carries does the same on its own.
    db.execute(super::super::delete::DELETE_ROOM_BOTS_SQL, params![OTHER]).unwrap();
    assert_eq!(count(&db, "SELECT COUNT(*) FROM group_bots"), 0);
}

#[test]
fn a_bots_soft_delete_takes_it_out_of_every_room() {
    let db = setup();
    assert!(add(&db, OTHER, BOT, NOW + 7));
    db.execute(LEAVE_ROOMS_SQL, params![BOT]).unwrap();
    assert_eq!(count(&db, "SELECT COUNT(*) FROM group_bots WHERE bot_id = 'b-echo'"), 0);
    assert!(room_bot(&db, OTHER, ELSEWHERE), "another bot's rooms stay");
    assert!(room_bot(&db, ROOM, OFF));
    assert_eq!(count(&db, "SELECT COUNT(*) FROM bots WHERE bot_id = 'b-echo'"), 1, "the bots row stays");
}

// ── Who may call the handlers ───────────────────────────────────────────────────────────────

const SRC: &str = include_str!("groups_bots.rs");

/// One function's source, from its `async fn <name>(` line to the next `async fn`.
fn fn_body<'a>(name: &str) -> &'a str {
    let start = SRC
        .find(&format!("async fn {name}("))
        .unwrap_or_else(|| panic!("no fn {name} in groups_bots.rs — re-point this guard"));
    let rest = &SRC[start..];
    let end = ["\nasync fn ", "\npub async fn "]
        .iter()
        .filter_map(|needle| rest[1..].find(needle))
        .min();
    &rest[..end.map_or(rest.len(), |i| i + 1)]
}

/// Every handler goes through `gate`, and `gate` decides by the IN-ROOM role of a live device:
/// a room's admins manage its bots, the server owner does not (R9 decision 6).
#[test]
fn every_room_bot_handler_gates_on_the_room_role_never_the_server_role() {
    let handlers = SRC.matches("\npub async fn ").count();
    assert_eq!(handlers, 3, "list, add, remove — re-point this guard if that changed");
    for name in ["list_room_bots", "add_room_bot", "remove_room_bot"] {
        assert!(fn_body(name).contains("gate(&req, &ctx)"), "{name} skips the gate");
    }
    let gate = fn_body("gate");
    assert!(gate.contains("require_live_device_auth(req"), "a revoked device keeps its token ~15 min");
    assert!(gate.contains("group_role(") && gate.contains("is_group_admin("));
    assert!(!gate.contains("server_role") && !gate.contains("users"), "the server role is no authority here");
    assert!(
        !SRC.contains(concat!("require_", "owner")),
        "the server owner turns a bot off or deletes it; adding it to a room is the room's call"
    );
    for name in ["add_room_bot", "remove_room_bot"] {
        assert!(fn_body(name).contains("notify::nudge_room("), "{name} must nudge the room");
    }
    assert!(!fn_body("list_room_bots").contains("notify::"), "a read must not fan out");
}
