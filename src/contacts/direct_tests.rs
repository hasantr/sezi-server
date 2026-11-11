//! The 1:1 gate between a blocked pair (P1, Hasan 2026-11-10: "blocking stops 1:1 only; the app
//! sorts it out"): a pair that shares an active group still carries the room's secrets to each
//! other over 1:1 Olm — room keys, key requests, scheduled room keys — so their send passes, but
//! SILENTLY (`RoomOnly`: stored, never a wake); a pair with no common group stays denied.

use super::*;
use rusqlite::{params, Connection};

const A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const B: &str = "bbbbbbbb-0000-4000-8000-000000000002";

fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    for id in [A, B] {
        db.execute(
            "INSERT INTO users (id, email, identity_pubkey, display_name, created_at, last_seen_at)
             VALUES (?1, ?1 || '@example.test', X'01', 'x', 0, 0)",
            params![id],
        )
        .unwrap();
    }
    db
}

fn decision(db: &Connection, caller: &str, target: &str) -> DirectDecision {
    db.query_row(DIRECT_AUTHZ_SQL, params![target, caller], |r| {
        Ok(decide(&AuthzRow {
            target_exists: r.get("target_exists")?,
            dm_policy: r.get("dm_policy")?,
            blocked: r.get("blocked")?,
            granted: r.get("granted")?,
            common_group: r.get("common_group")?,
        }))
    })
    .unwrap()
}

fn block(db: &Connection, blocker: &str, blocked: &str) {
    db.execute(
        "INSERT INTO contact_blocks (blocker_user_id, blocked_user_id, created_at) VALUES (?1, ?2, 0)",
        params![blocker, blocked],
    )
    .unwrap();
}

fn both_in_group(db: &Connection, status_b: &str) {
    db.execute("INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES ('g', 'g', ?1, 0, 0)", params![A])
        .unwrap();
    db.execute(
        "INSERT INTO group_members (group_id, user_id, role, joined_at, status) VALUES ('g', ?1, 'member', 0, 'active')",
        params![A],
    )
    .unwrap();
    db.execute(
        "INSERT INTO group_members (group_id, user_id, role, joined_at, status) VALUES ('g', ?1, 'member', 0, ?2)",
        params![B, status_b],
    )
    .unwrap();
}

#[test]
fn a_blocked_pair_without_a_common_group_stays_denied_both_ways() {
    let db = db();
    assert_eq!(decision(&db, A, B), DirectDecision::Allowed, "the default policy lets members talk");
    block(&db, A, B);
    assert_eq!(decision(&db, A, B), DirectDecision::Denied);
    assert_eq!(decision(&db, B, A), DirectDecision::Denied, "a block is either direction");
}

#[test]
fn a_blocked_pair_in_a_common_group_passes_silently_both_ways() {
    let db = db();
    both_in_group(&db, "active");
    block(&db, A, B);
    assert_eq!(decision(&db, B, A), DirectDecision::RoomOnly);
    assert_eq!(decision(&db, A, B), DirectDecision::RoomOnly);
    // The relay's send paths turn it into a silent store: no push wake, no backstop wake.
    assert_eq!(DirectDecision::RoomOnly.wake(Ordinary, false), Silent);
    assert_eq!(DirectDecision::RoomOnly.wake(Urgent, false), Silent, "a 1:1 ring between them never wakes");
    assert_eq!(DirectDecision::Allowed.wake(Urgent, false), Urgent);
}

use crate::push::coalesce::WakeIntent::{Ordinary, Silent, Urgent};

/// A group call (or a course session's start) from a member I blocked rings the ROOM on my phone
/// (Hasan, 2026-11-11: everything of a shared group works as for anyone): the one wake a RoomOnly
/// send keeps is an urgent ring the sender declared a room's. Nothing else gets a wake by saying
/// `room_ring`, and between anyone else the flag changes nothing.
#[test]
fn a_room_ring_is_the_one_wake_a_blocked_pair_keeps() {
    assert_eq!(DirectDecision::RoomOnly.wake(Urgent, true), Urgent, "a room's ring rings");
    assert_eq!(DirectDecision::RoomOnly.wake(Ordinary, true), Silent, "the flag alone wakes nothing");
    assert_eq!(DirectDecision::RoomOnly.wake(Silent, true), Silent);
    for asked in [Silent, Ordinary, Urgent] {
        for room_ring in [false, true] {
            assert_eq!(DirectDecision::Allowed.wake(asked, room_ring), asked, "{asked:?} {room_ring}");
        }
    }
}

#[test]
fn a_group_one_of_them_left_is_no_common_group() {
    let db = db();
    both_in_group(&db, "left");
    block(&db, B, A);
    assert_eq!(decision(&db, B, A), DirectDecision::Denied);
}
