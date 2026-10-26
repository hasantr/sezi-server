//! Idempotent sending, on rusqlite through the same `Exec` the DO's SQLite runs behind.

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

/// The case 2.1 asked about: a program times out waiting for `sendMessage`, sends it again, and
/// must not post twice.
#[test]
fn a_retry_under_the_same_client_id_answers_the_first_message_id() {
    let db = db();
    let fp = fingerprint("u:alice", "Duruşma yarın 10:00", None);
    assert_eq!(replay(lookup(&db, "h-42").as_ref(), &fp, T0), Replay::New);
    reserve(&db, "h-42", &fp, "b-first", T0);
    mark_sent(&db, "b-first"); // the envelopes are queued
    // The program's answer is lost; it retries a few seconds later.
    let again = replay(lookup(&db, "h-42").as_ref(), &fp, T0 + 5_000);
    assert_eq!(again, Replay::Sent("b-first".into()));
    // Hours later, still the same message.
    assert_eq!(replay(lookup(&db, "h-42").as_ref(), &fp, T0 + 23 * 3600 * 1000), Replay::Sent("b-first".into()));
}

#[test]
fn the_same_client_id_with_other_content_is_a_conflict() {
    let db = db();
    let fp = fingerprint("u:alice", "a", None);
    reserve(&db, "x", &fp, "b-1", T0);
    mark_sent(&db, "b-1");
    for other in [
        fingerprint("u:bob", "a", None),
        fingerprint("u:alice", "b", None),
        fingerprint("r:g-1", "a", None),
        fingerprint("r:g-1", "a", Some("m-1")),
    ] {
        assert_eq!(replay(lookup(&db, "x").as_ref(), &other, T0 + 1), Replay::Conflict);
    }
    assert_ne!(fingerprint("r:g-1", "a", Some("m-1")), fingerprint("r:g-1", "a", Some("m-2")));
}

#[test]
fn a_send_still_in_flight_is_waited_for_and_an_abandoned_one_is_retried() {
    let db = db();
    let fp = fingerprint("u:alice", "a", None);
    reserve(&db, "x", &fp, "b-1", T0);
    assert_eq!(replay(lookup(&db, "x").as_ref(), &fp, T0 + 2_000), Replay::InFlight);
    assert_eq!(replay(lookup(&db, "x").as_ref(), &fp, T0 + ABANDONED_AFTER_MS - 1), Replay::InFlight);
    // Its request died with an evicted inbox: the id is free again, and the retry replaces it.
    assert_eq!(replay(lookup(&db, "x").as_ref(), &fp, T0 + ABANDONED_AFTER_MS), Replay::New);
    reserve(&db, "x", &fp, "b-2", T0 + ABANDONED_AFTER_MS);
    mark_sent(&db, "b-2");
    assert_eq!(replay(lookup(&db, "x").as_ref(), &fp, T0 + ABANDONED_AFTER_MS + 1), Replay::Sent("b-2".into()));
}

#[test]
fn a_send_that_did_not_happen_frees_its_id_and_a_sent_one_is_never_freed() {
    let db = db();
    let fp = fingerprint("u:alice", "a", None);
    reserve(&db, "x", &fp, "b-1", T0);
    release(&db, "x"); // e.g. `bot/no-devices`
    assert_eq!(lookup(&db, "x"), None);
    reserve(&db, "y", &fp, "b-2", T0);
    mark_sent(&db, "b-2");
    release(&db, "y"); // the drain after the queue failed: the message is still on its way
    assert_eq!(replay(lookup(&db, "y").as_ref(), &fp, T0 + 1), Replay::Sent("b-2".into()));
}

#[test]
fn a_client_id_is_remembered_for_a_day() {
    let db = db();
    let fp = fingerprint("u:alice", "a", None);
    reserve(&db, "old", &fp, "b-1", T0);
    reserve(&db, "new", &fp, "b-2", T0 + CLIENT_ID_TTL_MS);
    db.run(CLIENT_EXPIRE, &[Arg::I(T0 + 1)]);
    assert_eq!(lookup(&db, "old"), None);
    assert!(lookup(&db, "new").is_some());
}

/// The source-level half: nothing can slip between the replay's last read and the reservation,
/// and "sent" is written the moment the envelopes are queued — before any network.
#[test]
fn the_reservation_follows_the_replay_with_no_await_and_sent_is_marked_before_the_network() {
    let mod_rs = include_str!("mod.rs");
    let api = &mod_rs[mod_rs.find("async fn bot_api(").expect("bot_api")..];
    let api = &api[..api.find("\n    }\n").expect("end")];
    let after_replay = &api[api.find("bot_client_replay(").expect("replay")..];
    let between = &after_replay[..after_replay.find("send_replay::reserve(").expect("reserve")];
    assert_eq!(between.matches(".await").count(), 1, "only the replay's own await: {between}");
    assert!(api.contains("send_replay::release("), "a send that did not happen frees its id");

    let send = include_str!("send.rs");
    let text = &send[send.find("async fn bot_send_text(").expect("bot_send_text")..];
    let mark = text.find("mark_sent(").expect("1:1 marks sent");
    assert!(mark < text.find("bot_drain_outbox(").unwrap(), "1:1: sent before the drain");
    let room = include_str!("room.rs");
    let post = &room[room.find("async fn bot_send_room_text(").expect("bot_send_room_text")..];
    let mark = post.find("mark_sent(").expect("a room post marks sent");
    assert!(post.find("bot_queue_room_text(").unwrap() < mark);
    assert!(mark < post.find("arm_alarm_within(").unwrap(), "room: sent before the await");
}
