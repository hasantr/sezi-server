//! The gate's SQL against SQLite (the inbox's storage is SQLite too), and the one-door rule.

use super::*;
use crate::push::coalesce::{gate, Gate};
use rusqlite::{params, Connection, OptionalExtension};

fn db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute(WAKE_GATE_TABLE_SQL, []).unwrap();
    db
}

fn read(db: &Connection, key: &str) -> WakeMark {
    db.query_row(READ_SQL, [key], |r| {
        Ok(WakeMark { woke_for_ms: r.get(0)?, seen_ms: r.get(1)? })
    })
    .optional()
    .unwrap()
    .unwrap_or_default()
}

/// What `note_device_seen` runs for a known device.
fn seen(db: &Connection, device: &str, at: i64) {
    db.execute(SEEN_SQL, params![device, at]).unwrap();
    db.execute(SEEN_SQL, params![BLIND_KEY, at]).unwrap();
}

#[test]
fn a_mark_and_a_connection_live_side_by_side() {
    let db = db();
    assert_eq!(read(&db, "d0"), WakeMark::default());
    db.execute(MARK_SQL, params!["d0", 1_000]).unwrap();
    seen(&db, "d0", 900);
    assert_eq!(read(&db, "d0"), WakeMark { woke_for_ms: Some(1_000), seen_ms: Some(900) });
    // A newer wake replaces the mark and keeps the connection.
    db.execute(MARK_SQL, params!["d0", 2_000]).unwrap();
    assert_eq!(read(&db, "d0"), WakeMark { woke_for_ms: Some(2_000), seen_ms: Some(900) });
    assert_eq!(read(&db, BLIND_KEY).seen_ms, Some(900), "a device's connection is the blind key's too");
}

/// Two wakes finishing out of order: the later moment stands, on a fresh row and an existing one.
#[test]
fn a_mark_never_moves_back() {
    let db = db();
    db.execute(MARK_SQL, params!["d0", 2_000]).unwrap();
    db.execute(MARK_SQL, params!["d0", 1_000]).unwrap();
    assert_eq!(read(&db, "d0").woke_for_ms, Some(2_000));
    db.execute(MARK_SQL, params!["d0", 3_000]).unwrap();
    assert_eq!(read(&db, "d0").woke_for_ms, Some(3_000));
    // A row a connection created first (no mark yet) takes the mark as given.
    seen(&db, "d1", 500);
    db.execute(MARK_SQL, params!["d1", 1_000]).unwrap();
    assert_eq!(read(&db, "d1"), WakeMark { woke_for_ms: Some(1_000), seen_ms: Some(500) });
}

/// A socket with no known device is a target for every row, so it is seen for every key.
#[test]
fn a_socket_of_unknown_device_is_seen_for_everyone() {
    let db = db();
    db.execute(MARK_SQL, params!["d0", 1_000]).unwrap();
    db.execute(MARK_SQL, params!["d1", 1_000]).unwrap();
    db.execute(SEEN_ALL_SQL, params![1_500]).unwrap();
    assert_eq!(read(&db, "d0").seen_ms, Some(1_500));
    assert_eq!(read(&db, "d1").seen_ms, Some(1_500));
}

/// The race the moment closes: an envelope stored (its `covers_ms` taken) just before the device
/// connects, its wake decided just after. The connection already flushed it, so the mark that
/// wake leaves coalesces nothing — the next envelope after the device leaves wakes it.
#[test]
fn a_wake_decided_after_a_connection_does_not_silence_the_next_envelope() {
    let db = db();
    let covers = 10_000;
    seen(&db, "d0", covers + 3); // the socket is accepted, the queue flushed
    db.execute(MARK_SQL, params!["d0", covers]).unwrap(); // the wake goes out anyway
    // The device drains and leaves; a new envelope five seconds later:
    assert_eq!(gate(read(&db, "d0"), covers + 5_000), Gate::Send);
}

/// Every wake leaves from the recipient's inbox: the gate is there, so a wake sent from anywhere
/// else would bypass it. The needle is split so it cannot match itself here.
#[test]
fn every_wake_is_sent_from_the_recipients_inbox() {
    let needle = concat!("push::wake::", "maybe_push_wake(");
    let needle_many = concat!("push::wake::", "push_wake_devices(");
    let outside = [
        ("messages/handlers.rs", include_str!("../handlers.rs")),
        ("messages/group_fanout.rs", include_str!("../group_fanout.rs")),
        ("messages/fanout_retry.rs", include_str!("../fanout_retry.rs")),
        ("messages/inbox_do/ws.rs (the SENDER's inbox)", include_str!("ws.rs")),
        ("messages/inbox_do/bot/outbox.rs (a bot's inbox)", include_str!("bot/outbox.rs")),
    ];
    for (file, src) in outside {
        assert!(!src.contains(needle) && !src.contains(needle_many), "{file} sends a wake itself");
    }
    for (file, src) in [
        ("mod.rs (/notify)", include_str!("wake_gate.rs")),
        ("member_notify.rs", include_str!("member_notify.rs")),
        ("alarm_ops.rs", include_str!("alarm_ops.rs")),
    ] {
        assert!(src.contains(needle) || src.contains(needle_many), "{file} lost its wake");
    }
}
