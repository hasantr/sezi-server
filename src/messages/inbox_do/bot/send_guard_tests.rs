//! The bot's send limits, on rusqlite through the same `Exec` the DO's SQLite runs behind.

use super::super::store::tests::Lite;
use super::*;
use rusqlite::Connection;

fn db() -> Lite {
    let c = Connection::open_in_memory().unwrap();
    for t in TABLES {
        c.execute_batch(t).unwrap();
    }
    Lite(c)
}

const T0: i64 = 1_761_200_000_000;

#[test]
fn a_bot_sends_sixty_a_minute_and_is_told_when_the_next_fits() {
    let db = db();
    // Thirty chats, two sends each, one a second.
    for i in 0..SENDS_PER_MINUTE {
        let chat = format!("u:{}", i % 30);
        assert!(take_slot(&db, &chat, T0 + i * 1_000).is_ok(), "send {i}");
    }
    let now = T0 + 59_500;
    assert_eq!(take_slot(&db, "u:fresh", now), Err(1), "the first send leaves the window at T0+60s");
    // Exactly at the edge, the oldest has left.
    assert!(take_slot(&db, "u:fresh", T0 + 60_000).is_ok());
    assert_eq!(take_slot(&db, "u:fresh", T0 + 60_000), Err(1), "full again: the second leaves at T0+61s");
}

#[test]
fn one_chat_takes_at_most_thirty_of_the_minute() {
    let db = db();
    for i in 0..SENDS_PER_CHAT_PER_MINUTE {
        assert!(take_slot(&db, "u:flood", T0 + i).is_ok());
    }
    assert_eq!(take_slot(&db, "u:flood", T0 + 100), Err(60), "until the chat's first send leaves");
    assert!(take_slot(&db, "u:other", T0 + 100).is_ok(), "everybody else is still answered");
    assert!(take_slot(&db, "r:g-1", T0 + 100).is_ok(), "a room is its own chat");
}

#[test]
fn a_send_that_did_not_happen_gives_its_slot_back() {
    let db = db();
    let mut slots = Vec::new();
    for i in 0..SENDS_PER_CHAT_PER_MINUTE {
        slots.push(take_slot(&db, "u:a", T0 + i).unwrap());
    }
    assert!(take_slot(&db, "u:a", T0 + 50).is_err());
    refund(&db, slots[3]);
    assert!(take_slot(&db, "u:a", T0 + 50).is_ok(), "the refunded slot is free");
}

#[test]
fn the_wait_is_the_longer_of_the_two_windows_and_at_least_a_second() {
    let w = |count, oldest_ms| Window { count, oldest_ms };
    assert_eq!(admit(w(0, 0), w(0, 0), T0), Ok(()));
    assert_eq!(admit(w(59, T0), w(29, T0), T0), Ok(()));
    assert_eq!(admit(w(60, T0 - 59_999), w(0, 0), T0), Err(1), "1 ms rounds up to a second");
    assert_eq!(admit(w(60, T0 - 30_000), w(30, T0 - 10_000), T0), Err(50));
    assert_eq!(admit(w(60, T0 - 60_000), w(0, 0), T0), Err(1), "never 0");
    assert_eq!(chat_key(Some("alice"), None), "u:alice");
    assert_eq!(chat_key(None, Some("g-1")), "r:g-1");
}

/// The limit is the inbox's: no KV put per send (the whole server's limiter, 1,000 puts a day on
/// the free plan), and the slot is taken before anything is encrypted or queued.
#[test]
fn the_limit_is_counted_in_the_inbox_before_a_send_and_never_in_kv() {
    let api = include_str!("../../../bots/api.rs");
    assert!(!api.contains("check_rate_limit"), "the Worker no longer spends KV on bot sends");
    let mod_rs = include_str!("mod.rs");
    let body = &mod_rs[mod_rs.find("async fn bot_api(").expect("bot_api")..];
    let body = &body[..body.find("\n    }\n").expect("end")];
    let slot = body.find("take_slot(").expect("bot_api takes a slot");
    for send in ["bot_send_text(", "bot_send_room_text("] {
        assert!(slot < body.find(send).unwrap_or_else(|| panic!("{send}")), "{send} before the slot");
    }
    assert!(body.contains("refund("), "a send that did not happen gives its slot back");
}
