//! The self-host update's relay half: the token gate, liveness, the wire bodies, and every SQL
//! statement run against the real schema (`test_schema::full_schema`).

use super::*;
use rusqlite::{params, Connection};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn the_token_gate() {
    assert_eq!(check_token(None, Some(TOKEN)), TokenCheck::NotConfigured);
    assert_eq!(check_token(Some(""), Some("")), TokenCheck::NotConfigured);
    // A token too short to be one install-updater.sh made is no token: no updater.
    assert_eq!(check_token(Some("short"), Some("short")), TokenCheck::NotConfigured);
    assert_eq!(check_token(Some(TOKEN), None), TokenCheck::Wrong);
    assert_eq!(check_token(Some(TOKEN), Some("")), TokenCheck::Wrong);
    assert_eq!(check_token(Some(TOKEN), Some(&TOKEN[1..])), TokenCheck::Wrong);
    assert_eq!(check_token(Some(TOKEN), Some(TOKEN)), TokenCheck::Ok);
    // A trailing newline from a file read is not a different token.
    assert_eq!(check_token(Some(&format!("{TOKEN}\n")), Some(&format!(" {TOKEN}"))), TokenCheck::Ok);
}

#[test]
fn the_box_is_alive_for_fifteen_minutes() {
    let now = 10_000_000_000;
    assert!(!alive(None, now));
    assert!(alive(Some(now), now));
    assert!(alive(Some(now - ALIVE_MS), now));
    assert!(!alive(Some(now - ALIVE_MS - 1), now));
    // A stamp from the future (a clock that jumped) is not believed for long.
    assert!(!alive(Some(now + 10 * 60_000), now));
}

#[test]
fn builds_codes_and_switches() {
    assert!(valid_build(202_611_070_930));
    assert!(!valid_build(2026));
    assert!(!valid_build(0));
    assert!(!valid_build(2_026_110_709_300));
    assert_eq!(clean_code("unhealthy-rolled-back"), "unhealthy-rolled-back");
    assert_eq!(clean_code(" ok\n"), "ok");
    assert_eq!(clean_code("rm -rf /"), "unknown");
    assert_eq!(clean_code(""), "unknown");
    assert_eq!(clean_code(&"a".repeat(49)), "unknown");
    for a in [Auto::Off, Auto::All, Auto::Security] {
        assert_eq!(Auto::parse(a.as_str()), Some(a));
    }
    assert_eq!(Auto::parse("nightly"), None);
    // D6: off unless the owner said otherwise.
    assert_eq!(Auto::stored(None), Auto::Off);
    assert_eq!(Auto::stored(Some("garbage")), Auto::Off);
}

#[test]
fn a_result_body_is_small_and_typed() {
    let r = parse_result(br#"{"request_id":4,"to":202611070930,"from":202611010000,"ok":false,"code":"unhealthy-rolled-back","at":"x"}"#)
        .unwrap();
    assert_eq!(r.request_id, Some(4));
    assert_eq!((r.to, r.from, r.ok), (Some(202_611_070_930), Some(202_611_010_000), false));
    // update.sh writes `null` for a build it never chose.
    let r = parse_result(br#"{"to":null,"from":null,"ok":false,"code":"bad-signature"}"#).unwrap();
    assert_eq!((r.request_id, r.to), (None, None));
    assert!(parse_result(b"not json").is_none());
    assert!(parse_result(br#"{"code":"ok"}"#).is_none(), "ok is required");
    let mut big = br#"{"ok":true,"code":""#.to_vec();
    big.extend(std::iter::repeat_n(b'a', RESULT_MAX_BYTES));
    big.extend(br#""}"#);
    assert!(parse_result(&big).is_none());
}

fn db() -> Connection {
    crate::test_schema::full_schema()
}

fn latest(db: &Connection, sql: &str) -> Option<RequestRow> {
    db.query_row(sql, [], |r| {
        Ok(RequestRow {
            id: r.get(0)?,
            to_build: r.get(1)?,
            requested_by: r.get(2)?,
            requested_at: r.get(3)?,
            picked_at: r.get(4)?,
            done_at: r.get(5)?,
            ok: r.get(6)?,
            code: r.get(7)?,
            from_build: r.get(8)?,
            automatic: r.get(9)?,
        })
    })
    .ok()
}

fn request(db: &Connection, build: i64, at: i64) {
    db.execute(SUPERSEDE_SQL, params![at]).unwrap();
    db.execute(INSERT_REQUEST_SQL, params![build, "owner-1", at]).unwrap();
}

#[test]
fn a_request_is_picked_then_finished() {
    let db = db();
    request(&db, 202_611_070_930, 1_000);
    let open = latest(&db, OPEN_SQL).unwrap();
    assert_eq!((open.to_build, open.picked_at, open.done_at), (202_611_070_930, None, None));
    assert_eq!(
        poll_body(Some(&open), Auto::Off),
        json!({ "request": { "id": open.id, "to_build": 202_611_070_930i64 }, "auto": "off" })
    );
    db.execute(PICK_SQL, params![open.id, 2_000]).unwrap();
    // A second poll does not move when it was taken.
    db.execute(PICK_SQL, params![open.id, 3_000]).unwrap();
    assert_eq!(latest(&db, OPEN_SQL).unwrap().picked_at, Some(2_000));
    db.execute(FINISH_SQL, params![open.id, 9_000, 1, "ok", 202_611_010_000i64]).unwrap();
    assert!(latest(&db, OPEN_SQL).is_none(), "nothing open after the result");
    let done = latest(&db, LATEST_SQL).unwrap();
    assert_eq!((done.done_at, done.ok, done.code.as_deref()), (Some(9_000), Some(1), Some("ok")));
    assert_eq!(done.from_build, Some(202_611_010_000));
    let body = status_body(true, Some(9_000), Auto::Security, Some(&done), 10_000);
    assert_eq!(body["updater"], json!({ "configured": true, "seen_at": 9_000, "alive": true }));
    assert_eq!(body["auto"], "security");
    assert_eq!(body["request"]["ok"], true);
    assert_eq!(body["request"]["automatic"], false);
}

#[test]
fn a_new_request_replaces_one_not_yet_taken_but_not_one_running() {
    let db = db();
    request(&db, 202_611_070_930, 1_000);
    request(&db, 202_611_010_000, 2_000);
    let first = latest(&db, "SELECT id, to_build, requested_by, requested_at, picked_at, done_at, ok, code, from_build, automatic FROM server_update_requests ORDER BY id ASC LIMIT 1").unwrap();
    assert_eq!((first.ok, first.code.as_deref()), (Some(0), Some("superseded")));
    let open = latest(&db, OPEN_SQL).unwrap();
    assert_eq!(open.to_build, 202_611_010_000);
    // Once the box took it, a later tap does not close it: the run is under way.
    db.execute(PICK_SQL, params![open.id, 2_500]).unwrap();
    request(&db, 202_611_070_930, 3_000);
    let taken = latest(&db, &format!("SELECT id, to_build, requested_by, requested_at, picked_at, done_at, ok, code, from_build, automatic FROM server_update_requests WHERE id = {}", open.id)).unwrap();
    assert_eq!(taken.done_at, None);
}

#[test]
fn a_request_nobody_took_expires() {
    let db = db();
    request(&db, 202_611_070_930, 1_000);
    let now = 1_000 + REQUEST_TTL_MS + 1;
    db.execute(EXPIRE_SQL, params![now - REQUEST_TTL_MS, now]).unwrap();
    assert!(latest(&db, OPEN_SQL).is_none());
    assert_eq!(latest(&db, LATEST_SQL).unwrap().code.as_deref(), Some("expired"));
    // One taken is left to its result, however long it runs.
    request(&db, 202_611_070_930, 5_000);
    let id = latest(&db, OPEN_SQL).unwrap().id;
    db.execute(PICK_SQL, params![id, 5_001]).unwrap();
    let later = 5_000 + 10 * REQUEST_TTL_MS;
    db.execute(EXPIRE_SQL, params![later - REQUEST_TTL_MS, later]).unwrap();
    assert!(latest(&db, OPEN_SQL).is_some());
}

#[test]
fn a_nightly_run_is_a_row_of_its_own() {
    let db = db();
    db.execute(INSERT_RESULT_SQL, params![202_611_070_930i64, 7_000, 1, "ok", 202_611_010_000i64]).unwrap();
    let r = latest(&db, LATEST_SQL).unwrap();
    assert_eq!((r.automatic, r.requested_by.as_str(), r.ok), (1, "updater", Some(1)));
    assert!(latest(&db, OPEN_SQL).is_none(), "a nightly run opens nothing");
    assert_eq!(request_json(&r)["automatic"], true);
}

#[test]
fn the_switch_and_the_stamp_are_server_config_keys() {
    let db = db();
    for (key, value) in [(AUTO_KEY, "all"), (SEEN_KEY, "123"), (AUTO_KEY, "security")] {
        db.execute(CONFIG_WRITE_SQL, params![key, value, 1]).unwrap();
    }
    let read = |k: &str| db.query_row(CONFIG_READ_SQL, params![k], |r| r.get::<_, String>(0)).unwrap();
    assert_eq!(read(AUTO_KEY), "security");
    assert_eq!(read(SEEN_KEY), "123");
}

/// No token: the status says so, and nothing is alive whatever the stamp says.
#[test]
fn without_a_token_there_is_no_updater() {
    let body = status_body(false, Some(10), Auto::Off, None, 10);
    assert_eq!(body["updater"]["alive"], false);
    assert_eq!(body["request"], Value::Null);
}
