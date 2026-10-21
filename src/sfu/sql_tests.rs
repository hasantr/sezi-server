//! The SFU's SQL against the real D1 schema (`test_schema::full_schema`): every statement prepares,
//! the month and room counters add up, the warnings latch, a session is found and pruned.

use super::*;
use rusqlite::params;

fn db() -> rusqlite::Connection {
    crate::test_schema::full_schema()
}

#[test]
fn every_statement_prepares_on_the_real_schema() {
    let db = db();
    for sql in [
        SQL_GROUP_SETTINGS,
        SQL_USAGE,
        SQL_INSERT_SESSION,
        SQL_SESSION,
        SQL_CALL_SESSIONS,
        SQL_ADD_USAGE,
        SQL_ADD_ROOM_USAGE,
        SQL_SET_WARNED,
        SQL_TOUCH_REPORT,
        SQL_PRUNE_SESSIONS,
        SQL_TOP_ROOMS,
    ] {
        db.prepare(sql).unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
}

#[test]
fn usage_adds_up_per_month_and_per_room_and_the_warnings_latch() {
    let db = db();
    db.execute(SQL_ADD_USAGE, params!["2026-10", 100]).unwrap();
    db.execute(SQL_ADD_USAGE, params!["2026-10", 50]).unwrap();
    db.execute(SQL_ADD_ROOM_USAGE, params!["2026-10", "r1", 100]).unwrap();
    db.execute(SQL_ADD_ROOM_USAGE, params!["2026-10", "r1", 50]).unwrap();
    db.execute(SQL_ADD_ROOM_USAGE, params!["2026-10", "r2", 7]).unwrap();
    let (bytes, w80, w100): (i64, i64, i64) = db
        .query_row(SQL_USAGE, params!["2026-10"], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    assert_eq!((bytes, w80, w100), (150, 0, 0));
    let r1: i64 = db
        .query_row("SELECT egress_bytes FROM sfu_room_usage WHERE month='2026-10' AND room_id='r1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(r1, 150);

    db.execute(SQL_SET_WARNED, params![1, 0, "2026-10"]).unwrap();
    db.execute(SQL_SET_WARNED, params![0, 0, "2026-10"]).unwrap();
    let (w80, w100): (i64, i64) = db
        .query_row(SQL_USAGE, params!["2026-10"], |r| Ok((r.get(1)?, r.get(2)?)))
        .unwrap();
    assert_eq!((w80, w100), (1, 0), "a warning once given stays given");
}

#[test]
fn a_session_is_found_listed_with_its_call_and_pruned() {
    let db = db();
    db.execute(SQL_INSERT_SESSION, params!["s1", "r1", "c1", "u1", 1_000]).unwrap();
    db.execute(SQL_INSERT_SESSION, params!["s2", "r1", "c1", "u2", 1_000]).unwrap();
    db.execute(SQL_INSERT_SESSION, params!["s3", "r1", "c2", "u3", 90_000]).unwrap();
    let (room, user, last): (String, String, Option<i64>) = db
        .query_row(SQL_SESSION, params!["s1"], |r| Ok((r.get(0)?, r.get(2)?, r.get(4)?)))
        .unwrap();
    assert_eq!((room.as_str(), user.as_str(), last), ("r1", "u1", None));
    db.execute(SQL_TOUCH_REPORT, params![1_030, "s1"]).unwrap();
    let last: Option<i64> = db.query_row(SQL_SESSION, params!["s1"], |r| r.get(4)).unwrap();
    assert_eq!(last, Some(1_030));

    let mut stmt = db.prepare(SQL_CALL_SESSIONS).unwrap();
    let mut ids: Vec<String> = stmt
        .query_map(params!["r1", "c1"], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    ids.sort();
    assert_eq!(ids, ["s1", "s2"], "only the same call's sessions");

    db.execute(SQL_PRUNE_SESSIONS, params![50_000]).unwrap();
    let left: i64 = db.query_row("SELECT COUNT(*) FROM sfu_sessions", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 1);
}

#[test]
fn a_call_is_going_on_while_a_session_of_it_reported_lately() {
    let db = db();
    db.execute(SQL_INSERT_SESSION, params!["s1", "r1", "c1", "u1", 1_000]).unwrap();
    db.execute(SQL_INSERT_SESSION, params!["s2", "r1", "c1", "u2", 3_000]).unwrap();
    let live = |call: &str, since: i64| -> (i64, Option<i64>) {
        db.query_row(SQL_CALL_LIVE, params!["r1", call, since], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
    };
    assert_eq!(live("c1", 900), (0, Some(1_000)), "opening a session is not media");
    db.execute(SQL_TOUCH_REPORT, params![2_500, "s1"]).unwrap();
    assert_eq!(live("c1", 2_000), (1, Some(1_000)), "a report keeps it going; its age is the first session's");
    assert_eq!(live("c1", 2_600).0, 0, "nothing reported since");
    assert_eq!(live("c2", 0), (0, None), "another call's sessions do not count");
}
