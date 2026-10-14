//! The miss counter's statements against the real schema: a budget that is a bound, a window that
//! resets, a refund that gives back exactly one miss in its own window, and a sweep.

use super::*;
use crate::ratelimit::DOOR_MISS_LIMIT;
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_780_000_000;
const B: &str = "auth:redeem:miss:203.0.113.7";
const WINDOW: i64 = DOOR_WINDOW_SECS as i64;

fn take(db: &Connection, bucket: &str, now: i64) -> Option<i64> {
    db.query_row(
        RESERVE_SQL,
        params![bucket, now, WINDOW, DOOR_MISS_LIMIT as i64],
        |r| r.get(0),
    )
    .optional()
    .unwrap()
}

fn misses(db: &Connection, bucket: &str) -> i64 {
    db.query_row(
        "SELECT misses FROM door_misses WHERE bucket = ?1",
        [bucket],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn the_budget_is_a_bound_and_the_refusal_says_until_when() {
    let db = crate::test_schema::full_schema();
    for i in 0..DOOR_MISS_LIMIT as i64 {
        assert_eq!(take(&db, B, NOW + i), Some(NOW), "miss {i} is taken");
    }
    assert_eq!(
        take(&db, B, NOW + 40),
        None,
        "one past the limit is refused"
    );
    assert_eq!(take(&db, B, NOW + 41), None);
    assert_eq!(
        misses(&db, B),
        DOOR_MISS_LIMIT as i64,
        "a refusal costs nothing more"
    );
    let start: i64 = db.query_row(WINDOW_START_SQL, [B], |r| r.get(0)).unwrap();
    assert_eq!(retry_after(start, NOW + 40), (WINDOW - 40) as u64);
    // Another address has its own budget.
    assert_eq!(
        take(&db, "auth:redeem:miss:198.51.100.1", NOW + 40),
        Some(NOW + 40)
    );
}

#[test]
fn a_new_window_starts_from_one() {
    let db = crate::test_schema::full_schema();
    for _ in 0..DOOR_MISS_LIMIT {
        take(&db, B, NOW);
    }
    assert_eq!(take(&db, B, NOW + WINDOW - 1), None);
    assert_eq!(take(&db, B, NOW + WINDOW), Some(NOW + WINDOW));
    assert_eq!(misses(&db, B), 1);
}

#[test]
fn a_refund_gives_back_one_miss_and_only_in_its_own_window() {
    let db = crate::test_schema::full_schema();
    for _ in 0..DOOR_MISS_LIMIT {
        take(&db, B, NOW);
    }
    db.execute(REFUND_SQL, params![B, NOW]).unwrap();
    assert_eq!(misses(&db, B), DOOR_MISS_LIMIT as i64 - 1);
    assert_eq!(
        take(&db, B, NOW + 1),
        Some(NOW),
        "the refunded miss can be taken again"
    );
    // A refund from a window that is over does not reach into the new one.
    assert_eq!(take(&db, B, NOW + WINDOW), Some(NOW + WINDOW));
    db.execute(REFUND_SQL, params![B, NOW]).unwrap();
    assert_eq!(misses(&db, B), 1);
    // Nor below zero.
    db.execute(REFUND_SQL, params![B, NOW + WINDOW]).unwrap();
    db.execute(REFUND_SQL, params![B, NOW + WINDOW]).unwrap();
    assert_eq!(misses(&db, B), 0);
}

#[test]
fn the_sweep_forgets_finished_windows_only() {
    let db = crate::test_schema::full_schema();
    take(&db, B, NOW);
    take(&db, "fresh", NOW + WINDOW);
    db.execute(SWEEP_SQL, params![NOW + WINDOW, WINDOW])
        .unwrap();
    let left: Vec<String> = db
        .prepare("SELECT bucket FROM door_misses")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(left, ["fresh"]);
}
