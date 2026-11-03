//! The dead-device statements on a SQLite shaped like the inbox's own tables, capped at the
//! platform's bound-parameter limit.

use super::*;
use rusqlite::{params_from_iter, types::Value, Connection};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 24 * 3600;

fn inbox() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    crate::test_schema::cap_binds_like_d1(&db);
    db.execute_batch(
        "CREATE TABLE pending (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id TEXT NOT NULL,
                               envelope_b64 TEXT NOT NULL, created_at INTEGER NOT NULL,
                               device_id TEXT);
         CREATE TABLE wake_gate (device_id TEXT PRIMARY KEY, woke_for_ms INTEGER, seen_ms INTEGER);",
    )
    .unwrap();
    db
}

fn queue(db: &Connection, device: Option<&str>, created_at: i64) {
    db.execute(
        "INSERT INTO pending (sender_id, envelope_b64, created_at, device_id) VALUES ('s', 'e', ?1, ?2)",
        rusqlite::params![created_at, device],
    )
    .unwrap();
}

fn seen(db: &Connection, device: &str, at_secs: i64) {
    db.execute(
        "INSERT INTO wake_gate (device_id, seen_ms) VALUES (?1, ?2)",
        rusqlite::params![device, at_secs * 1000],
    )
    .unwrap();
}

fn rows_of(db: &Connection, device: &str) -> i64 {
    db.query_row("SELECT COUNT(*) FROM pending WHERE device_id = ?1", [device], |r| r.get(0))
        .unwrap()
}

/// Every message of the last ten days went to both devices of the account; the phone that was
/// lost a week ago never took one, the laptop takes them as they come.
fn interleaved(db: &Connection) {
    seen(db, "lost", NOW - 7 * DAY);
    seen(db, "laptop", NOW - 60);
    for i in 0..10 {
        let at = NOW - (10 - i) * DAY;
        queue(db, Some("lost"), at);
        queue(db, Some("laptop"), at);
    }
}

fn evict(db: &Connection, n: i64, connected: &[&str]) {
    let mut args: Vec<Value> = vec![n.into(), crate::push::coalesce::BLIND_KEY.to_string().into()];
    let mut open: Vec<&str> = connected.to_vec();
    if !open.is_empty() {
        open.push(crate::push::coalesce::BLIND_KEY);
    }
    args.extend(open.iter().map(|d| Value::from(d.to_string())));
    db.execute(&evict_sql(open.len()), params_from_iter(args)).unwrap();
}

#[test]
fn the_cap_evicts_a_dead_devices_rows_before_a_live_ones() {
    let db = inbox();
    interleaved(&db);
    // What the global-oldest eviction it replaces did: half of what it took was the laptop's.
    let old = inbox();
    interleaved(&old);
    old.execute(
        "DELETE FROM pending WHERE id IN (SELECT id FROM pending ORDER BY id ASC LIMIT ?)",
        [10],
    )
    .unwrap();
    assert_eq!(rows_of(&old, "laptop"), 5, "global-oldest took the live device's rows");

    evict(&db, 10, &[]);
    assert_eq!((rows_of(&db, "lost"), rows_of(&db, "laptop")), (0, 10));
}

#[test]
fn a_device_with_an_open_socket_is_evicted_last() {
    let db = inbox();
    // The laptop's last NEW connection is older than the lost phone's, but its socket is open now.
    seen(&db, "laptop", NOW - 9 * DAY);
    seen(&db, "lost", NOW - 7 * DAY);
    for i in 0..10 {
        queue(&db, Some("lost"), NOW - (10 - i) * DAY);
        queue(&db, Some("laptop"), NOW - (10 - i) * DAY);
    }
    evict(&db, 12, &["laptop"]);
    assert_eq!((rows_of(&db, "lost"), rows_of(&db, "laptop")), (0, 8));
}

#[test]
fn a_stalled_devices_rows_are_not_work_a_client_waits_for() {
    let db = inbox();
    interleaved(&db);
    // A device-blind row (the account's one unpublished device) is always live work.
    queue(&db, None, NOW - 9 * DAY);
    let (secs, ms) = stalled_binds(NOW);
    let (live, stalled): (i64, i64) = db
        .query_row(&pending_split_sql(), [secs, ms], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!((live, stalled), (11, 10), "the laptop's ten and the blind row are live");

    // The laptop is away for a week too: nothing of its queue is drained, nothing connected.
    db.execute("UPDATE wake_gate SET seen_ms = ?1 WHERE device_id = 'laptop'", [(NOW - 5 * DAY) * 1000])
        .unwrap();
    let (live, stalled): (i64, i64) = db
        .query_row(&pending_split_sql(), [secs, ms], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!((live, stalled), (1, 20));

    // A device that connected within the window is never stalled, however old its backlog.
    db.execute("UPDATE wake_gate SET seen_ms = ?1 WHERE device_id = 'laptop'", [(NOW - 60) * 1000])
        .unwrap();
    let (live, _): (i64, i64) = db
        .query_row(&pending_split_sql(), [secs, ms], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!(live, 11);
}

#[test]
fn a_revoked_devices_queue_is_dropped_whole() {
    let db = inbox();
    interleaved(&db);
    db.execute(DROP_DEVICE_ROWS_SQL, ["lost"]).unwrap();
    assert_eq!((rows_of(&db, "lost"), rows_of(&db, "laptop")), (0, 10));
}

#[test]
fn the_revoked_read_runs_on_the_real_schema() {
    let db = crate::test_schema::full_schema();
    let mut stmt = db.prepare(REVOKED_DEVICES_SQL).unwrap();
    let n = stmt.query_map(rusqlite::params!["u", 200], |_| Ok(())).unwrap().count();
    assert_eq!(n, 0);
}
