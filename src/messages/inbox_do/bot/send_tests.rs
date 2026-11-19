//! Which of the bot's sent messages a member's `delivery_failed` marks for a resend, on rusqlite.

use super::super::store::tests::Lite;
use super::super::store::TABLES;
use super::mark_failed;
use rusqlite::{params, Connection};

const ANA: &str = "ana";

fn db() -> Lite {
    let c = Connection::open_in_memory().unwrap();
    for t in TABLES {
        c.execute_batch(t).unwrap();
    }
    Lite(c)
}

/// One sent message to `user`'s `device`; `pending` is the member inbox's row id, NULL while
/// the outbox's `/notify` has not answered yet.
fn sent(db: &Lite, uid: &str, user: &str, device: &str, pending: Option<i64>) {
    db.0.execute(
        "INSERT INTO bot_sent (msg_uid, user_id, device_id, pending_id, payload_json, created_at, failed)
         VALUES (?1, ?2, ?3, ?4, '{}', 0, 0)",
        params![uid, user, device, pending],
    )
    .unwrap();
}

fn failed(db: &Lite) -> Vec<String> {
    let mut s = db.0.prepare("SELECT msg_uid FROM bot_sent WHERE failed = 1 ORDER BY msg_uid").unwrap();
    s.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
}

fn week(db: &Lite) {
    sent(db, "b-1", ANA, "phone", Some(10));
    sent(db, "b-2", ANA, "phone", Some(11));
    sent(db, "b-3", ANA, "laptop", Some(12));
    sent(db, "b-4", ANA, "phone", None); // its /notify is still in flight
    sent(db, "b-5", "can", "phone", Some(11)); // another member's inbox numbers its own rows
}

/// One frame a member could not read used to mark EVERY message the bot had sent them in seven
/// days, and the next pair-ack resent the lot (review 2026-10-27, #5). The member's inbox
/// forwards the ids of ITS pending rows — what the bot's outbox wrote into `pending_id`.
#[test]
fn a_delivery_failure_marks_only_the_frames_it_names() {
    let db = db();
    week(&db);
    mark_failed(&db, ANA, Some("phone"), &[11]);
    assert_eq!(failed(&db), ["b-2"]);
    mark_failed(&db, ANA, Some("laptop"), &[12, 10]);
    assert_eq!(failed(&db), ["b-1", "b-2", "b-3"]);
}

#[test]
fn a_failure_naming_nothing_marks_the_member_whole() {
    let db = db();
    week(&db);
    mark_failed(&db, ANA, None, &[]);
    assert_eq!(failed(&db), ["b-1", "b-2", "b-3", "b-4"], "every row of hers, nobody else's");
}

/// The member's device can answer before the `/notify` that stored the frame has answered the
/// bot, so the id is not written yet: what is still unrecorded for that device is what it names.
#[test]
fn a_failure_naming_an_unrecorded_frame_marks_that_devices_frames_in_flight() {
    let db = db();
    week(&db);
    mark_failed(&db, ANA, Some("phone"), &[99]);
    assert_eq!(failed(&db), ["b-4"]);
    let db2 = self::db();
    week(&db2);
    mark_failed(&db2, ANA, Some("laptop"), &[99]);
    assert!(failed(&db2).is_empty(), "nothing of the laptop's is in flight");
}

/// Review H7, the half it left: an idle bot's sent messages and members' room calls go when their
/// 7 days end, because the alarm comes back for the oldest of them — and does not come back again
/// for a row the expiry it fires just deleted.
#[test]
fn the_alarm_comes_back_for_the_oldest_kept_row_and_not_twice() {
    use super::super::{dm_scope, room, room_store};
    use super::{KEPT_NEXT, SENT_TTL_MS};
    let db = db();
    for t in room_store::TABLES.iter().chain(dm_scope::TABLES.iter()) {
        db.0.execute_batch(t).unwrap();
    }
    let keeps = [SENT_TTL_MS, SENT_TTL_MS, room::CALL_TTL_MS, dm_scope::REPLY_WINDOW_MS];
    let next = |db: &Lite| -> Option<i64> { db.0.query_row(KEPT_NEXT, keeps, |r| r.get(0)).unwrap() };
    assert_eq!(next(&db), None, "nothing kept: no alarm");
    sent(&db, "b-1", ANA, "d1", None); // created_at 0
    db.0.execute(room_store::CALL_PUT, params!["room-1", "m-1", ANA, "hello", 5]).unwrap();
    assert_eq!(next(&db), Some(SENT_TTL_MS + 1), "the sent row is the oldest");
    // The tick at that time runs the expiries with `now - keep` as their cutoffs.
    let now = SENT_TTL_MS + 1;
    db.0.execute("DELETE FROM bot_sent WHERE created_at < ?", [now - SENT_TTL_MS]).unwrap();
    db.0.execute(room_store::CALLS_EXPIRE, [now - room::CALL_TTL_MS]).unwrap();
    assert_eq!(next(&db), Some(5 + room::CALL_TTL_MS + 1), "the call next, not the same time again");
    let now = 5 + room::CALL_TTL_MS + 1;
    db.0.execute(room_store::CALLS_EXPIRE, [now - room::CALL_TTL_MS]).unwrap();
    assert_eq!(next(&db), None, "all gone: the alarm is not armed for them");
}

#[test]
fn bot_rearm_arms_for_the_kept_rows() {
    let code = include_str!("outbox.rs");
    let rearm = &code[code.find("pub(super) async fn bot_rearm(").unwrap()..];
    assert!(rearm[..rearm.find("\n    }\n").unwrap()].contains("self.bot_kept_next()"));
    let send = include_str!("send.rs");
    let keep = &send[send.find("pub(super) async fn bot_housekeeping(").unwrap()..];
    let keep = &keep[..keep.find("\n    }\n").unwrap()];
    for expiry in ["bot_sent WHERE created_at <", "SEEN_EXPIRE", "WRITER_EXPIRE", "bot_room_housekeeping("] {
        assert!(keep.contains(expiry), "the tick expires {expiry}");
    }
}
