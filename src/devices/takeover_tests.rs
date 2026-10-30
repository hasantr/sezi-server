//! The takeover routes against the real schema (every statement the handlers run, run here), the
//! decisions they make before writing, and the source guards that keep the gates where they are.

use super::*;
use crate::devices::takeover_admin::{
    verdict, Verdict, ADMIN_LIST_SQL, APPROVE_SQL, REQUEST_BY_ID_SQL,
    WRONG_CODE_SQL,
};
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_790_000_000_000;

/// One admin-list row as the test reads it: id, device label, linked at, primary last seen, role.
type ListRow = (String, Option<String>, Option<i64>, Option<i64>, String);

/// Alice (member) with a primary `dp` and a linked phone `dl`; Adam (admin); Olga (owner).
fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, display_name, created_at, role) VALUES
           ('alice', 'a@x', x'00', 'Alice', 1, 'member'),
           ('adam', 'b@x', x'00', 'Adam', 1, 'admin'),
           ('olga', 'c@x', x'00', 'Olga', 1, 'owner');
         INSERT INTO devices (user_id, device_id, role, ed_pub, x_pub, label, added_at, last_seen_at) VALUES
           ('alice', 'dp', 'primary', x'01', x'02', 'primary', 10, 500),
           ('alice', 'dl', 'linked', x'03', x'04', 'Phone', 20, 900),
           ('adam', 'ap', 'primary', x'05', x'06', 'primary', 10, 0),
           ('adam', 'al', 'linked', x'07', x'08', 'Tablet', 30, 0);",
    )
    .unwrap();
    db
}

fn role(db: &Connection, user: &str, dev: &str) -> Option<String> {
    db.query_row(DEVICE_ROLE_SQL, params![user, dev], |r| r.get(0)).optional().unwrap()
}

fn escrow(db: &Connection, user: &str, dev: &str, id: &str) {
    db.execute(UPSERT_ESCROW_SQL, params![user, dev, id, "UgUgUgUgUgUgUgUgUgUgUgUgUgUgUgUgUgUgUgUgUgU=", NOW]).unwrap();
}

fn file(db: &Connection, id: &str, user: &str, dev: &str, at: i64) {
    db.execute(CLOSE_OPEN_OF_DEVICE_SQL, params![at, user, dev]).unwrap();
    db.execute(INSERT_REQUEST_SQL, params![id, user, dev, "otk", at, at + TAKEOVER_TTL_MS]).unwrap();
}

/// An approval at `now`, its release held until `release` (None: released at once).
fn approve(db: &Connection, admin: &str, id: &str, now: i64, release: Option<i64>) {
    let release = release.unwrap_or(now);
    db.execute(APPROVE_SQL, params![admin, now, release, release + TAKEOVER_TTL_MS, id, now, admin]).unwrap();
}

fn state(db: &Connection, id: &str) -> String {
    db.query_row("SELECT state FROM takeover_requests WHERE id = ?", [id], |r| r.get(0)).unwrap()
}

#[test]
fn a_device_role_is_read_only_for_an_active_device() {
    let db = db();
    assert_eq!(role(&db, "alice", "dp").as_deref(), Some("primary"));
    assert_eq!(role(&db, "alice", "dl").as_deref(), Some("linked"));
    db.execute("UPDATE devices SET revoked_at = 5 WHERE device_id = 'dl'", []).unwrap();
    assert_eq!(role(&db, "alice", "dl"), None, "a revoked device has no role");
    assert_eq!(role(&db, "alice", "nope"), None);
}

#[test]
fn an_escrow_is_one_row_per_device_and_a_new_one_replaces_it() {
    let db = db();
    escrow(&db, "alice", "dl", "e1");
    escrow(&db, "alice", "dl", "e2");
    let (id, n): (String, i64) = db
        .query_row("SELECT escrow_id, (SELECT COUNT(*) FROM device_escrow) FROM device_escrow", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((id.as_str(), n), ("e2", 1));
    let row: Option<(String, String)> = db
        .query_row(ESCROW_OF_SQL, params!["alice", "dl"], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .unwrap();
    assert_eq!(row.unwrap().0, "e2");
}

#[test]
fn a_new_request_cancels_the_open_one_and_the_latest_is_read() {
    let db = db();
    file(&db, "t1", "alice", "dl", NOW);
    file(&db, "t2", "alice", "dl", NOW + 1);
    assert_eq!(state(&db, "t1"), "cancelled");
    assert_eq!(state(&db, "t2"), "pending");
    let latest: String = db.query_row(LATEST_OF_DEVICE_SQL, params!["alice", "dl"], |r| r.get(0)).unwrap();
    assert_eq!(latest, "t2");
}

#[test]
fn an_open_request_expires_after_its_day_and_a_decided_one_does_not() {
    assert_eq!(effective_state("pending", NOW, None, NOW - 1), "pending");
    assert_eq!(effective_state("pending", NOW, None, NOW), "expired");
    assert_eq!(effective_state("approved", NOW, None, NOW + 5), "expired");
    assert_eq!(effective_state("refused", NOW, None, NOW + 5), "refused");
    assert_eq!(effective_state("failed", NOW, None, NOW + 5), "failed");
}

#[test]
fn the_admin_list_shows_others_pending_requests_with_the_primary_last_seen() {
    let db = db();
    file(&db, "t-alice", "alice", "dl", NOW);
    file(&db, "t-adam", "adam", "al", NOW);
    let rows: Vec<ListRow> = {
        let mut st = db.prepare(ADMIN_LIST_SQL).unwrap();
        st.query_map(params![NOW + 1, "adam"], |r| {
            Ok((r.get("id")?, r.get("label")?, r.get("linked_at")?, r.get("primary_last_seen")?, r.get("user_role")?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    };
    assert_eq!(rows.len(), 1, "an admin never sees their own request: {rows:?}");
    assert_eq!(rows[0], ("t-alice".into(), Some("Phone".into()), Some(20), Some(500), "member".into()));
    // Olga sees both, Adam's marked by his role.
    let n: i64 = db
        .query_row(&format!("SELECT COUNT(*) FROM ({})", ADMIN_LIST_SQL.trim_end_matches(';')), params![NOW + 1, "olga"], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2);
    // Past its day, nobody sees it.
    let n: i64 = db
        .query_row(&format!("SELECT COUNT(*) FROM ({ADMIN_LIST_SQL})"), params![NOW + TAKEOVER_TTL_MS, "olga"], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

/// The admin is told when the primary has no push token: a closed app could not be warned
/// during the hold. The PHONE's token does not count.
#[test]
fn the_admin_list_says_whether_the_primary_can_be_woken() {
    let db = db();
    file(&db, "t1", "alice", "dl", NOW);
    let has_push = |db: &Connection| -> i64 {
        db.query_row(&format!("SELECT primary_has_push FROM ({ADMIN_LIST_SQL})"), params![NOW + 1, "adam"], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(has_push(&db), 0);
    db.execute_batch(
        "INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at)
           VALUES ('alice', 'dl', 'fl', 'android', 1, 1);",
    )
    .unwrap();
    assert_eq!(has_push(&db), 0, "the requester's own token is not the primary's");
    db.execute_batch(
        "INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at)
           VALUES ('alice', 'dp', 'fp', 'android', 1, 1);",
    )
    .unwrap();
    assert_eq!(has_push(&db), 1);
}

#[test]
fn three_wrong_codes_end_a_request() {
    let db = db();
    file(&db, "t1", "alice", "dl", NOW);
    for n in 1..=3 {
        db.execute(WRONG_CODE_SQL, params![MAX_WRONG_CODES, MAX_WRONG_CODES, NOW + n, "t1"]).unwrap();
        let (st, wrong): (String, i64) = db
            .query_row("SELECT state, wrong_codes FROM takeover_requests WHERE id = 't1'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(wrong, n);
        assert_eq!(st, if n < 3 { "pending" } else { "failed" }, "after {n} wrong codes");
    }
    // A failed request takes no approval.
    approve(&db, "adam", "t1", NOW + 9, None);
    assert_eq!(state(&db, "t1"), "failed");
}

#[test]
fn an_approval_needs_a_pending_request_in_its_day_from_someone_else() {
    let db = db();
    file(&db, "t-adam", "adam", "al", NOW);
    approve(&db, "adam", "t-adam", NOW + 1, None);
    assert_eq!(state(&db, "t-adam"), "pending", "the SQL itself refuses a self-approval");
    approve(&db, "olga", "t-adam", NOW + 1, None);
    assert_eq!(state(&db, "t-adam"), "approved", "another admin approves it");
    let (user, otk, st): (String, String, String) = db
        .query_row(REQUEST_BY_ID_SQL, ["t-adam"], |r| Ok((r.get("user_id")?, r.get("one_time_pub_b64")?, r.get("state")?)))
        .unwrap();
    assert_eq!((user.as_str(), otk.as_str(), st.as_str()), ("adam", "otk", "approved"));

    file(&db, "t-late", "alice", "dl", NOW);
    approve(&db, "adam", "t-late", NOW + TAKEOVER_TTL_MS, None);
    assert_eq!(state(&db, "t-late"), "pending", "past its day it is not approved");
}

#[test]
fn the_first_release_ends_the_old_primarys_relay_session_and_nothing_else() {
    let db = db();
    db.execute_batch(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at, device_id) VALUES
           ('h-dp', 'alice', 9, 1, 'dp'), ('h-dl', 'alice', 9, 1, 'dl'), ('h-ap', 'adam', 9, 1, 'ap');
         INSERT INTO one_time_prekeys (user_id, prekey_id, prekey_pub, consumed, device_id) VALUES
           ('alice', 1, x'01', 0, 'dp'), ('alice', 2, x'02', 1, 'dp'), ('alice', 3, x'03', 0, 'dl');
         INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at) VALUES
           ('alice', 'dp', 'fp', 'android', 1, 1), ('alice', 'dl', 'fl', 'android', 1, 1);",
    )
    .unwrap();
    file(&db, "t1", "alice", "dl", NOW);
    let release = |db: &Connection| {
        for sql in END_OLD_PRIMARY_SQL {
            db.execute(sql, params!["t1", "alice", "alice"]).unwrap();
        }
    };
    release(&db);
    let count = |sql: &str| -> i64 { db.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert_eq!(count("SELECT COUNT(*) FROM refresh_tokens"), 3, "nothing goes while it is pending");
    approve(&db, "adam", "t1", NOW + 1, None);
    release(&db);
    assert_eq!(count("SELECT COUNT(*) FROM refresh_tokens WHERE device_id = 'dp'"), 0);
    assert_eq!(count("SELECT COUNT(*) FROM refresh_tokens"), 2, "the phone's and Adam's stay");
    assert_eq!(count("SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = 'dp'"), 1, "a consumed key's record stays");
    assert_eq!(count("SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = 'dl'"), 1);
    assert_eq!(count("SELECT COUNT(*) FROM push_tokens"), 1);
    assert_eq!(count("SELECT COUNT(*) FROM takeover_requests WHERE released_at IS NOT NULL"), 1, "the release is stamped");
    // A second read releases nothing more: a refresh token the device itself made later stays.
    db.execute("INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at, device_id) VALUES ('h-new', 'alice', 9, 1, 'dp')", []).unwrap();
    release(&db);
    assert_eq!(count("SELECT COUNT(*) FROM refresh_tokens WHERE device_id = 'dp'"), 1);
}

#[test]
fn a_primary_seen_within_a_day_holds_the_release_for_six_hours() {
    let hour = 60 * 60 * 1000;
    assert_eq!(release_at(Some(NOW - hour), NOW), NOW + RELEASE_HOLD_MS, "seen an hour ago: held");
    assert_eq!(RELEASE_HOLD_MS, 6 * hour);
    assert_eq!(release_at(Some(NOW - 25 * hour), NOW), NOW, "unseen for a day: at once");
    assert_eq!(release_at(None, NOW), NOW, "never seen: at once");
    assert_eq!(release_at(Some(0), NOW), NOW);

    // Against the schema: the primary's last-seen read, the approval, and how it reads after.
    let db = db();
    let seen: i64 = db.query_row(PRIMARY_OF_SQL, ["alice"], |r| r.get("last_seen_at")).unwrap();
    assert_eq!(seen, 500, "the primary's row, not the phone's");
    file(&db, "t1", "alice", "dl", NOW);
    let held_until = release_at(Some(NOW - hour), NOW);
    approve(&db, "adam", "t1", NOW, Some(held_until));
    let (st, exp, rel): (String, i64, Option<i64>) = db
        .query_row(LATEST_OF_DEVICE_SQL, params!["alice", "dl"], |r| {
            Ok((r.get("state")?, r.get("expires_at")?, r.get("release_at")?))
        })
        .unwrap();
    assert_eq!(effective_state(&st, exp, rel, NOW + hour), "held", "nothing sealed during the hold");
    assert_eq!(effective_state(&st, exp, rel, held_until - 1), "held");
    assert_eq!(effective_state(&st, exp, rel, held_until), "approved", "released after six hours");
    assert!(exp >= held_until + TAKEOVER_TTL_MS, "the device has a day from the release to finish");
    // A refusal during the hold ends it.
    db.execute(REFUSE_SQL, params!["alice", NOW + hour, "t1", "alice", NOW + hour]).unwrap();
    assert_eq!(state(&db, "t1"), "refused");
}

#[test]
fn the_primary_refuses_open_requests_on_its_own_account_only() {
    let db = db();
    file(&db, "t1", "alice", "dl", NOW);
    let open: Vec<String> = {
        let mut st = db.prepare(OPEN_AGAINST_USER_SQL).unwrap();
        st.query_map(params!["alice", NOW + 1], |r| r.get("id")).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(open, vec!["t1".to_string()]);
    // Adam cannot refuse Alice's.
    db.execute(REFUSE_SQL, params!["adam", NOW + 1, "t1", "adam", NOW + 1]).unwrap();
    assert_eq!(state(&db, "t1"), "pending");
    let read: Option<String> =
        db.query_row(MY_STATE_OF_SQL, params!["t1", "adam"], |r| r.get(0)).optional().unwrap();
    assert_eq!(read, None, "another account's request reads as nothing");
    // An approved one is refused all the same.
    approve(&db, "adam", "t1", NOW + 1, None);
    db.execute(REFUSE_SQL, params!["alice", NOW + 2, "t1", "alice", NOW + 2]).unwrap();
    assert_eq!(state(&db, "t1"), "refused");
}

#[test]
fn the_account_takes_its_escrow_and_requests_with_it() {
    let db = db();
    escrow(&db, "alice", "dl", "e1");
    file(&db, "t1", "alice", "dl", NOW);
    db.execute("DELETE FROM devices WHERE user_id = 'alice'", []).unwrap();
    db.execute("DELETE FROM users WHERE id = 'alice'", []).unwrap();
    let n: i64 = db
        .query_row("SELECT (SELECT COUNT(*) FROM device_escrow) + (SELECT COUNT(*) FROM takeover_requests)", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn the_verdict_is_decided_before_anything_is_written() {
    let (_, otk) = sezi_protocol::takeover::new_one_time_key();
    let code = sezi_protocol::takeover::takeover_code("t1", &otk);
    let v = |state: &str, approver: &str, typed: &str, now: i64| {
        verdict("t1", "alice", &otk, state, NOW + TAKEOVER_TTL_MS, approver, typed, now)
    };
    assert_eq!(v("pending", "adam", &code, NOW), Verdict::Approve);
    assert_eq!(v("pending", "adam", "000000", NOW), Verdict::WrongCode);
    assert_eq!(v("pending", "alice", &code, NOW), Verdict::OwnRequest);
    assert_eq!(v("approved", "adam", &code, NOW), Verdict::NotOpen);
    assert_eq!(v("pending", "adam", &code, NOW + TAKEOVER_TTL_MS), Verdict::NotOpen, "expired");
}

#[test]
fn ids_and_keys_are_checked_before_they_reach_the_database() {
    assert!(is_32_bytes_b64(&crate::utils::b64_encode(&[7u8; 32])));
    assert!(!is_32_bytes_b64(&crate::utils::b64_encode(&[7u8; 31])));
    assert!(!is_32_bytes_b64("not base64!"));
    assert!(is_plain_id("esc-3f_A9"));
    assert!(!is_plain_id(""));
    assert!(!is_plain_id("a b"));
    assert!(!is_plain_id(&"x".repeat(65)));
}

// ── source guards ─────────────────────────────────────────────────────────────────────────────

const SRC: &str = include_str!("takeover.rs");
const ADMIN_SRC: &str = include_str!("takeover_admin.rs");
const LIST_SRC: &str = include_str!("handlers.rs");

fn body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src.find(&format!("\npub async fn {name}(")).unwrap_or_else(|| panic!("no handler {name}"));
    let rest = &src[start + 1..];
    &rest[..rest.find("\npub async fn ").unwrap_or(rest.len())]
}

/// Only the primary stores R, only a linked device files a request, only the primary refuses.
#[test]
fn every_device_route_checks_the_callers_role() {
    for (name, role) in [
        ("put_escrow", "primary"),
        ("request_takeover", "linked"),
        ("takeovers_against_me", "primary"),
        ("refuse_takeover", "primary"),
    ] {
        let b = body(SRC, name);
        assert!(b.contains("require_active_auth"), "{name} has no active-device gate");
        assert!(b.contains(&format!("Some(\"{role}\")")), "{name} does not require the {role}");
    }
}

/// R leaves the relay only sealed to the request's one-time key, and only when approved.
#[test]
fn the_share_is_released_only_sealed_and_only_when_approved() {
    let b = body(SRC, "takeover_status");
    let gate = b.find(concat!("state == ", "\"approved\"")).expect("the approval gate moved");
    assert!(b.contains(concat!("effective_state(&row.state, row.expires_at, ", "row.release_at")), "the hold is read");
    let seal = b.find(concat!("seal_to_one_", "time_key")).expect("the seal moved");
    assert!(gate < seal);
    assert!(!b.contains(concat!("\"r_b64\": ", "e.r_b64")), "R is never served in the clear");
}

/// The admin routes are admin-gated, and the code check runs in the approval before any write.
#[test]
fn the_admin_routes_are_admin_only_and_check_the_code() {
    for name in ["list_takeovers", "approve_takeover"] {
        assert!(body(ADMIN_SRC, name).contains("require_admin("), "{name} is not admin-gated");
    }
    let b = body(ADMIN_SRC, "approve_takeover");
    assert!(b.find("verdict(").unwrap() < b.find("APPROVE_SQL").unwrap());
}

/// A device's revocation (the list PUT) deletes its share and ends its requests in the same batch.
#[test]
fn a_revoked_device_loses_its_share_and_its_requests() {
    let b = LIST_SRC;
    assert!(b.contains(concat!("DELETE FROM ", "device_escrow")));
    assert!(b.contains(concat!("UPDATE takeover_requests SET state = ", "'cancelled'")));
}

/// The relay tells the primary itself, on filing and on approval — never only through the
/// requester's notice, which a hostile client can skip.
#[test]
fn the_primary_is_notified_when_a_request_is_filed_and_when_it_is_approved() {
    assert!(body(SRC, "request_takeover").contains("notify_primary(&ctx.env, &db, &auth.user_id)"));
    let approve = body(ADMIN_SRC, "approve_takeover");
    assert!(approve.contains("notify_primary(&ctx.env, &db, &row.user_id)"));
    assert!(approve.find("release_at(seen, now)").unwrap() < approve.find("APPROVE_SQL").unwrap());
    assert!(SRC.contains(concat!("nudge_takeover_", "best_effort(env, user_id, &p.device_id)")));
}
