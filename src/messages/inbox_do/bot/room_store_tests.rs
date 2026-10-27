//! The room tables' SQL on rusqlite, through the same `SqlBotStore` the DO uses.

use super::super::store::tests::Lite;
use super::super::store::{SqlBotStore, TABLES as BOT_TABLES};
use super::*;
use rusqlite::Connection;
use sezi_bot_engine::{room_encrypt, room_prepare, room_text_payload, BotStore};

fn store() -> SqlBotStore<Lite> {
    let c = Connection::open_in_memory().unwrap();
    for t in BOT_TABLES.iter().chain(TABLES.iter()) {
        c.execute_batch(t).unwrap();
    }
    SqlBotStore { db: Lite(c) }
}

fn share(user: &str, device: &str, key: &str) -> RoomShare {
    RoomShare { user_id: user.into(), device_id: device.into(), key_b64: key.into() }
}

#[test]
fn the_tables_can_be_created_twice() {
    let s = store();
    for t in TABLES {
        s.db.0.execute_batch(t).unwrap();
    }
}

#[test]
fn a_session_and_its_shares_round_trip_and_go_with_the_room() {
    let mut s = store();
    assert_eq!(s.room_session("r"), None);
    let session = RoomSession { session_id: "s1".into(), pickle: "p".into(), created_at_ms: 1_761_200_000_000, sent: 7 };
    s.put_room_session("r", session.clone());
    assert_eq!(s.room_session("r"), Some(session));
    s.put_room_share("r", "s1", share("u", "d2", "k2"));
    s.put_room_share("r", "s1", share("u", "d1", "k1"));
    s.put_room_share("r", "s1", share("u", "d1", "k1-again"));
    s.put_room_share("r", "old", share("u", "d1", "stale"));
    assert_eq!(s.room_shares("r", "s1"), vec![share("u", "d1", "k1-again"), share("u", "d2", "k2")]);
    s.set_room_request_at("r", "u", 5);
    s.set_room_request_at("r", "u", 9);
    assert_eq!(s.room_request_at("r", "u"), Some(9));
    s.put_room_session("other", RoomSession { session_id: "x".into(), pickle: "q".into(), created_at_ms: 0, sent: 0 });

    s.forget_room("r");
    assert_eq!(s.room_session("r"), None);
    assert!(s.room_shares("r", "s1").is_empty() && s.room_shares("r", "old").is_empty());
    assert_eq!(s.room_request_at("r", "u"), None);
    assert!(s.room_session("other").is_some(), "another room is untouched");
}

/// The engine on this store: a session made, a post encrypted, its count kept.
#[test]
fn the_engine_runs_on_the_do_store() {
    let mut s = store();
    let key = [5u8; 32];
    let reg = sezi_bot_engine::create_identity("b", &key, 1, 1).unwrap();
    s.put_account(reg.account_pickle);
    let prep = room_prepare(&mut s, &key, "r", &[], 10).unwrap();
    assert!(prep.unshared.is_empty());
    room_encrypt(&mut s, &key, "r", &room_text_payload("hi", "b-1", None)).unwrap();
    let after = s.room_session("r").unwrap();
    assert_eq!((after.session_id, after.sent), (prep.session_id, 1));
}

#[test]
fn a_post_waits_in_order_and_a_room_left_drops_its_posts() {
    let s = store();
    for (room, at) in [("r", 1), ("r", 2), ("q", 3)] {
        s.db.run(POST_PUSH, &[Arg::T(room), Arg::T("{}"), Arg::I(at)]);
    }
    let next = |s: &SqlBotStore<Lite>| -> Option<(i64, String)> {
        s.db.0.query_row(POST_NEXT, rusqlite::params![0, "[]"], |r| Ok((r.get(0)?, r.get(1)?))).ok()
    };
    let (first, room) = next(&s).unwrap();
    assert_eq!(room, "r");
    s.db.run(POST_SKIPPED, &[Arg::T(r#"["u/d"]"#), Arg::I(first)]);
    let skipped: String = s.db.0.query_row("SELECT skipped FROM bot_room_posts WHERE id = ?", [first], |r| r.get(0)).unwrap();
    assert_eq!(skipped, r#"["u/d"]"#);
    s.db.run(POSTS_DROP_ROOM, &[Arg::T("r")]);
    assert_eq!(next(&s).map(|n| n.1), Some("q".into()));
    s.db.run(POSTS_EXPIRE, &[Arg::I(4)]);
    assert_eq!(s.db.int(POSTS_WAITING, &[Arg::I(0)]), Some(0));
}

/// A key request waits once per (room, member), the newest replacing an older one, oldest first;
/// it counts as room work waiting (so the alarm comes back for it), and goes with its room.
#[test]
fn key_requests_wait_once_per_member_and_count_as_room_work() {
    let s = store();
    s.db.run(ASK_PUT, &[Arg::T("r"), Arg::T("u"), Arg::Null, Arg::I(5)]);
    s.db.run(ASK_PUT, &[Arg::T("q"), Arg::T("v"), Arg::T("s1"), Arg::I(6)]);
    s.db.run(ASK_PUT, &[Arg::T("r"), Arg::T("u"), Arg::T("s2"), Arg::I(7)]);
    let due = |s: &SqlBotStore<Lite>| -> Vec<(String, String, Option<String>)> {
        let mut st = s.db.0.prepare(ASKS_DUE).unwrap();
        st.query_map([10], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(due(&s), vec![("q".into(), "v".into(), Some("s1".into())), ("r".into(), "u".into(), Some("s2".into()))]);
    assert_eq!(s.db.int(POSTS_WAITING, &[Arg::I(0)]), Some(2));
    s.db.run(ASK_DONE, &[Arg::T("q"), Arg::T("v")]);
    s.db.run(ASKS_DROP_ROOM, &[Arg::T("r")]);
    assert!(due(&s).is_empty());
    assert_eq!(s.db.int(POSTS_WAITING, &[Arg::I(0)]), Some(0));
}

#[test]
fn a_call_is_remembered_once_for_its_reply() {
    let s = store();
    s.db.run(CALL_PUT, &[Arg::T("r"), Arg::T("loc-7"), Arg::T("u-ayse"), Arg::T("yarın?"), Arg::I(1)]);
    s.db.run(CALL_PUT, &[Arg::T("r"), Arg::T("loc-7"), Arg::T("u-other"), Arg::T("forged"), Arg::I(2)]);
    let got: (String, String) =
        s.db.0.query_row(CALL_GET, ["r", "loc-7"], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(got, ("u-ayse".into(), "yarın?".into()), "the first sight wins");
    s.db.run(CALLS_EXPIRE, &[Arg::I(2)]);
    assert!(s.db.0.query_row(CALL_GET, ["r", "loc-7"], |_| Ok(())).is_err());
}
