//! Tests for `maintenance.rs` (split out per the 800-line ceiling; included via `#[path]`).
//! `super` = the `maintenance` module, so `use super::*` reaches the private helpers and the
//! threshold constants exactly as it did while this was a trailing inline module.

use super::*;

#[test]
fn parse_stamp_falls_back_to_zero_when_corrupt_or_missing() {
    assert_eq!(parse_stamp(None), 0);
    assert_eq!(parse_stamp(Some("")), 0);
    assert_eq!(parse_stamp(Some("abc")), 0);
    assert_eq!(parse_stamp(Some("12.5")), 0);
    assert_eq!(parse_stamp(Some("-99")), 0, "a negative stamp clamps to 0");
    assert_eq!(parse_stamp(Some("1780000000")), 1_780_000_000);
    assert_eq!(parse_stamp(Some(" 42 ")), 42, "parses with surrounding whitespace");
}

#[test]
fn is_due_threshold_boundaries() {
    // Stamp = 0 (no row / first boot) → always due.
    assert!(is_due(1_780_000_000, 0, DRAIN_LAZY_AFTER_SECS));
    // Exactly at the threshold → due (>=).
    assert!(is_due(
        1000 + DRAIN_LAZY_AFTER_SECS,
        1000,
        DRAIN_LAZY_AFTER_SECS
    ));
    // One second below the threshold → not due.
    assert!(!is_due(
        1000 + DRAIN_LAZY_AFTER_SECS - 1,
        1000,
        DRAIN_LAZY_AFTER_SECS
    ));
    // Stamp in the future (clock skew) → not due (saturating).
    assert!(!is_due(1000, 2000, DRAIN_LAZY_AFTER_SECS));
}

#[test]
fn is_due_daily_threshold() {
    let t0 = 1_780_000_000i64;
    assert!(
        !is_due(t0 + 86_400, t0, DAILY_LAZY_AFTER_SECS),
        "24h = inside the margin, stays asleep"
    );
    assert!(is_due(t0 + 90_000, t0, DAILY_LAZY_AFTER_SECS), "25h → due");
}

#[test]
fn throttle_first_look_and_window() {
    assert!(
        throttle_due(0, 5, CHECK_EVERY_SECS),
        "an isolate checks on its first request"
    );
    assert!(!throttle_due(
        100,
        100 + CHECK_EVERY_SECS - 1,
        CHECK_EVERY_SECS
    ));
    assert!(throttle_due(100, 100 + CHECK_EVERY_SECS, CHECK_EVERY_SECS));
    // Clock moved backwards → do not look (and do not underflow).
    assert!(!throttle_due(200, 150, CHECK_EVERY_SECS));
}
// The parse_code_key test moved to storage/maint.rs along with the function itself.

// ── the consumed one-time prekey sweep ──────────────────────────────────────

use rusqlite::{params, Connection};

/// `one_time_prekeys` as `0016_otk_device_unique.sql` rebuilt it, minus the `REFERENCES users(id)`
/// that would drag a whole `users` table in. AUTOINCREMENT is NOT decoration here: it is the
/// property the id watermark rests on, so it has to be in the fixture.
fn otk_db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE one_time_prekeys (
           id          INTEGER PRIMARY KEY AUTOINCREMENT,
           user_id     TEXT NOT NULL,
           device_id   TEXT NOT NULL DEFAULT '',
           prekey_id   INTEGER NOT NULL,
           prekey_pub  BLOB NOT NULL,
           consumed    INTEGER NOT NULL DEFAULT 0,
           UNIQUE (user_id, device_id, prekey_id));
         CREATE INDEX idx_otk_lookup ON one_time_prekeys(user_id, consumed);",
    )
    .unwrap();
    db
}

/// The real `replenish` insert: `INSERT OR IGNORE`, which is the dedup under test.
fn publish(db: &Connection, prekey: i64) -> usize {
    db.execute(
        "INSERT OR IGNORE INTO one_time_prekeys (user_id, device_id, prekey_id, prekey_pub, consumed)
         VALUES ('u', 'dev', ?, x'00', 0)",
        params![prekey],
    )
    .unwrap()
}

fn sweep(db: &Connection, retain: i64, limit: i64) -> usize {
    db.execute(OTK_CONSUMED_CLEANUP_SQL, params![retain, limit])
        .unwrap()
}

fn ids(db: &Connection) -> Vec<i64> {
    let mut stmt = db
        .prepare("SELECT id FROM one_time_prekeys ORDER BY id")
        .unwrap();
    let out = stmt
        .query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    out
}

#[test]
fn otk_sweep_takes_consumed_rows_behind_the_window_and_nothing_else() {
    let db = otk_db();
    for prekey in 1..=100 {
        publish(&db, prekey);
    }
    // Odd ids consumed, even ids still live stock.
    db.execute(
        "UPDATE one_time_prekeys SET consumed = 1 WHERE id % 2 = 1",
        [],
    )
    .unwrap();
    // MAX(id) = 100, so a window of 50 puts the cutoff at id 50.
    assert_eq!(sweep(&db, 50, 1000), 25, "the 25 odd ids at or below 50");
    let left = ids(&db);
    assert!(
        left.iter().all(|id| *id % 2 == 0 || *id > 50),
        "only consumed rows behind the cutoff went: {left:?}"
    );
    assert_eq!(
        left.iter().filter(|id| **id % 2 == 0).count(),
        50,
        "every unconsumed row survives, however old"
    );
    assert_eq!(
        *left.last().unwrap(),
        100,
        "the watermark row is untouchable"
    );
}

#[test]
fn otk_sweep_is_bounded_per_run_and_converges_across_runs() {
    let db = otk_db();
    for prekey in 1..=100 {
        publish(&db, prekey);
    }
    db.execute(
        "UPDATE one_time_prekeys SET consumed = 1 WHERE id < 100",
        [],
    )
    .unwrap();
    // Cutoff at 90, so 90 rows are eligible and each run may take 7.
    let mut runs = 0;
    loop {
        let gone = sweep(&db, 10, 7);
        if gone == 0 {
            break;
        }
        assert!(gone <= 7, "a run must never exceed its limit, took {gone}");
        runs += 1;
        assert!(runs < 50, "the sweep is not converging");
    }
    assert_eq!(runs, 13, "90 rows at 7 a run");
    assert_eq!(
        ids(&db),
        (91..=100).collect::<Vec<_>>(),
        "the window and the watermark are what is left"
    );
}

#[test]
fn the_window_is_what_stops_a_republished_key_being_resurrected() {
    // The dedup this must not break: `replenish` appends under INSERT OR IGNORE against
    // UNIQUE (user_id, device_id, prekey_id), so re-publishing a key the server already holds is
    // a no-op — including when the held row is a spent one. That no-op is the record that keeps a
    // one-time key one-time.
    let db = otk_db();
    publish(&db, 777);
    for prekey in 1..=20 {
        publish(&db, prekey);
    }
    db.execute(
        "UPDATE one_time_prekeys SET consumed = 1 WHERE prekey_id = 777",
        [],
    )
    .unwrap();

    // With the SHIPPED window, a table this size is nowhere near the cutoff, so the tombstone
    // stays and the republish stays a no-op.
    assert_eq!(sweep(&db, OTK_CONSUMED_RETAIN_IDS, OTK_SWEEP_LIMIT), 0);
    assert_eq!(
        publish(&db, 777),
        0,
        "IGNORED against the surviving tombstone"
    );
    assert_eq!(
        db.query_row(
            "SELECT consumed FROM one_time_prekeys WHERE prekey_id = 777",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1,
        "the key stays spent"
    );

    // And the falsifying half, so the window's job is not a claim but a demonstration: sweep the
    // tombstone away and the SAME republish resurrects the key as servable stock.
    sweep(&db, 0, OTK_SWEEP_LIMIT);
    assert_eq!(publish(&db, 777), 1, "no tombstone left to collide with");
    assert_eq!(
        db.query_row(
            "SELECT consumed FROM one_time_prekeys WHERE prekey_id = 777",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0,
        "a spent one-time key is back in the pool — what the window exists to prevent"
    );
}

#[test]
fn otk_sweep_is_inert_with_no_watermark_and_no_consumed_rows() {
    let db = otk_db();
    // MAX(id) is NULL on an empty table; `id <= NULL` is NULL for every row, so the statement
    // deletes nothing rather than everything.
    assert_eq!(sweep(&db, OTK_CONSUMED_RETAIN_IDS, OTK_SWEEP_LIMIT), 0);
    assert_eq!(sweep(&db, 0, OTK_SWEEP_LIMIT), 0);
    for prekey in 1..=10 {
        publish(&db, prekey);
    }
    assert_eq!(sweep(&db, 0, OTK_SWEEP_LIMIT), 0, "nothing is consumed yet");
    assert_eq!(ids(&db).len(), 10);
}

#[test]
fn a_swept_id_is_never_handed_out_again_so_the_watermark_only_climbs() {
    // AUTOINCREMENT, and the reason the fixture insists on it. Without it SQLite reuses the ids
    // of deleted rows, a fresh key could land BELOW the cutoff the previous run computed, and the
    // sweep would delete keys published after it.
    let db = otk_db();
    for prekey in 1..=5 {
        publish(&db, prekey);
    }
    db.execute("UPDATE one_time_prekeys SET consumed = 1", [])
        .unwrap();
    assert_eq!(sweep(&db, 0, OTK_SWEEP_LIMIT), 5, "the table is emptied");
    publish(&db, 6);
    assert_eq!(
        ids(&db),
        vec![6],
        "the next id continues past the high-water"
    );
}

#[test]
fn the_shipped_window_leaves_a_live_relay_sized_table_alone() {
    // The evidence the window was sized against: the whole table on the live relay measured 648
    // rows on 2026-07-29 (the 648 → 626 totals in `keys/handlers.rs::replenish`). Every one of
    // them consumed is still two orders of magnitude inside the window, so a server of that size
    // never reaches this sweep at all.
    let db = otk_db();
    for prekey in 1..=648 {
        publish(&db, prekey);
    }
    db.execute("UPDATE one_time_prekeys SET consumed = 1", [])
        .unwrap();
    assert_eq!(sweep(&db, OTK_CONSUMED_RETAIN_IDS, OTK_SWEEP_LIMIT), 0);
    assert_eq!(ids(&db).len(), 648);
}
