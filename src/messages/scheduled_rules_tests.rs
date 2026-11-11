use super::*;

const SENDER: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const PEER: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const OTHER: &str = "cccccccc-0000-4000-8000-000000000003";
const NOW: i64 = 1_800_000_000_000;

fn body() -> PutBody {
    PutBody {
        schedule_id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(),
        release_at_ms: NOW + 3_600_000,
        recipient_id: Some(PEER.into()),
        group_id: None,
        sender_device_id: "dev-s".into(),
        envelope_b64: sezi_protocol::envelope::WireEnvelope::scheduled_b64("0f8fad5b-d9cb-469f-a165-70867728950e", &"x".repeat(60)),
        targets: vec![
            Target { user_id: PEER.into(), device_ids: vec!["dev-p".into()] },
            Target { user_id: SENDER.into(), device_ids: vec!["dev-s".into()] },
        ],
    }
}

/// T11: shape, time, size and target bounds.
#[test]
fn validation_refuses_what_it_must() {
    assert_eq!(check_put(&body(), SENDER, NOW), Ok(Conversation::Direct(PEER)));
    let bad = |f: fn(&mut PutBody)| {
        let mut b = body();
        f(&mut b);
        check_put(&b, SENDER, NOW).map(|_| ()).unwrap_err().code
    };
    assert_eq!(bad(|b| b.schedule_id = "../x".into()), "bad_request");
    assert_eq!(bad(|b| b.schedule_id = "0F8FAD5B-D9CB-469F-A165-70867728950E".into()), "bad_request");
    assert_eq!(bad(|b| b.release_at_ms = NOW + MAX_AHEAD_MS + 1), "scheduled/too-far");
    assert_eq!(bad(|b| b.release_at_ms = NOW - MAX_LATE_MS - 1), "scheduled/too-far", "past the skew: a send dated in the past");
    assert_eq!(bad(|b| b.envelope_b64 = "x".repeat(MAX_ENVELOPE + 1)), "bad_request");
    assert_eq!(bad(|b| b.group_id = Some("room".into())), "bad_request", "both a peer and a room");
    assert_eq!(bad(|b| b.recipient_id = Some(SENDER.into())), "bad_request", "to oneself");
    assert_eq!(bad(|b| b.targets.clear()), "scheduled/bad-target");
    assert_eq!(bad(|b| b.targets[0].user_id = OTHER.into()), "scheduled/bad-target", "a 1:1 goes to its two");
    assert_eq!(bad(|b| b.targets.push(Target { user_id: PEER.into(), device_ids: vec!["d".into()] })), "scheduled/bad-target");
    assert_eq!(bad(|b| b.targets[0].device_ids.push("dev-p".into())), "scheduled/bad-target");
    assert_eq!(
        bad(|b| b.targets[0].device_ids = (0..=MAX_TARGET_DEVICES).map(|i| format!("d{i}")).collect()),
        "scheduled/bad-target"
    );
    let mut room = body();
    room.recipient_id = None;
    room.group_id = Some("room-1".into());
    room.targets[0].user_id = OTHER.into();
    assert_eq!(check_put(&room, SENDER, NOW), Ok(Conversation::Room("room-1")), "members are checked against D1");
    // A device that was offline at the time hands it over late: still taken, released at once.
    let mut late = body();
    late.release_at_ms = NOW - 60_000;
    assert!(check_put(&late, SENDER, NOW).is_ok());
}

fn set(items: &[&str]) -> HashSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn devices(items: &[(&str, &str)]) -> HashSet<(String, String)> {
    items.iter().map(|(u, d)| (u.to_string(), d.to_string())).collect()
}

/// T7 and T13: at the time, a target user no longer allowed (a removed member, a blocked 1:1) and a
/// revoked device get nothing; a sender who left the room, or whose device was revoked, releases
/// nothing at all.
#[test]
fn release_targets_drop_removed_members_and_revoked_devices() {
    let targets = vec![
        Target { user_id: PEER.into(), device_ids: vec!["p1".into(), "p2".into()] },
        Target { user_id: OTHER.into(), device_ids: vec!["o1".into()] },
        Target { user_id: SENDER.into(), device_ids: vec!["s1".into(), "s2".into()] },
    ];
    let all = devices(&[(PEER, "p1"), (PEER, "p2"), (OTHER, "o1"), (SENDER, "s1"), (SENDER, "s2"), (PEER, "p3")]);
    let everyone = set(&[SENDER, PEER, OTHER]);
    let out = release_targets(&targets, SENDER, "s1", &everyone, &all);
    assert_eq!(out.len(), 5, "p3 was added after scheduling: it never got the key and is not named");
    // OTHER removed from the room before the time.
    let out = release_targets(&targets, SENDER, "s1", &set(&[SENDER, PEER]), &all);
    assert!(!out.iter().any(|(u, _)| u == OTHER));
    // p2 revoked.
    let fewer = devices(&[(PEER, "p1"), (OTHER, "o1"), (SENDER, "s1"), (SENDER, "s2")]);
    assert!(!release_targets(&targets, SENDER, "s1", &everyone, &fewer).iter().any(|(_, d)| d == "p2"));
    // The sender left, or its scheduling device was revoked: nothing.
    assert!(release_targets(&targets, SENDER, "s1", &set(&[PEER, OTHER]), &all).is_empty());
    assert!(release_targets(&targets, SENDER, "s9", &everyone, &all).is_empty());
}

#[test]
fn the_alarm_takes_the_sooner_of_the_two() {
    assert_eq!(with_release(Some(90_000), Some(5_000)), Some(5_000));
    assert_eq!(with_release(Some(90_000), Some(500_000)), Some(90_000));
    assert_eq!(with_release(None, Some(500_000)), Some(500_000), "an idle inbox still wakes for a release");
    assert_eq!(with_release(None, Some(-5)), Some(0), "an overdue release runs now");
    assert_eq!(with_release(Some(7), None), Some(7));
    assert_eq!(with_release(None, None), None);
}

/// Re-review N4: the relay holds only a release, and only one naming the id it is held under.
#[test]
fn a_hand_over_must_be_a_release_of_its_own_id() {
    let mut other = body();
    other.envelope_b64 = vodozemac::base64_encode(br#"{"kind":1,"ciphertext":"AAAAAAAAAAAAAAAAAAAA"}"#);
    assert_eq!(check_put(&other, SENDER, NOW).unwrap_err().code, "bad_request", "not a release");
    let mut wrong_id = body();
    wrong_id.envelope_b64 =
        sezi_protocol::envelope::WireEnvelope::scheduled_b64("1f8fad5b-d9cb-469f-a165-70867728950e", &"x".repeat(60));
    assert_eq!(check_put(&wrong_id, SENDER, NOW).unwrap_err().code, "bad_request", "another id");
}

/// Review finding 2: a kind-3 envelope cannot be sent as an ordinary message.
#[test]
fn a_scheduled_envelope_is_refused_on_the_send_path() {
    let release = sezi_protocol::envelope::WireEnvelope::scheduled_b64("0f8fad5b-d9cb-469f-a165-70867728950e", "c2VhbGVk");
    assert!(is_scheduled_envelope(&release));
    let olm = vodozemac::base64_encode(br#"{"kind":1,"ciphertext":"AAAA"}"#);
    assert!(!is_scheduled_envelope(&olm));
    assert!(!is_scheduled_envelope("not base64 at all"));
    let src = include_str!("handlers.rs");
    assert!(src.contains("is_scheduled_envelope("), "the HTTP send path does not refuse a release");
    let ws = include_str!("inbox_do/ws.rs");
    assert!(ws.contains("is_scheduled_envelope("), "the socket's send does not refuse a release");
}

/// Review finding 4: the next row is chosen by when it is next to be tried, so a row that keeps
/// failing waits its backoff and the rows behind it go; a row past saving is given up before it is
/// tried again.
#[test]
fn a_failing_row_does_not_stand_in_front_of_the_others() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(SCHEDULED_TABLE_SQL).unwrap();
    let insert = |id: &str, release: i64, next: i64| {
        db.execute(
            "INSERT INTO scheduled (schedule_id, sender_id, sender_device_id, release_at, envelope_b64, targets_json,
                                    created_at, attempts, next_attempt_at)
             VALUES (?1, 's', 'd', ?2, 'e', '[]', 0, 0, ?3)",
            rusqlite::params![id, release, next],
        )
        .unwrap();
    };
    // `stuck` is due first by its time but failed and waits; `fresh` is due now.
    insert("stuck", NOW - 1_000, next_attempt_at(NOW, 2, false));
    insert("fresh", NOW - 10, NOW - 10);
    insert("later", NOW + 60_000, NOW + 60_000);
    let picked: String = db.query_row(SELECT_DUE_SQL, [NOW], |r| r.get(0)).unwrap();
    assert_eq!(picked, "fresh");
    assert_eq!(next_attempt_at(NOW, 9, true), NOW + RELEASE_RETRY_MS, "out of budget: the next run");
    assert!(next_attempt_at(NOW, 1, false) > NOW + RELEASE_RETRY_MS);
    assert!(next_attempt_at(NOW, 9, false) <= NOW + 300_000);
    assert!(!gives_up(NOW - 1_000, NOW));
    assert!(gives_up(NOW - RELEASE_GIVE_UP_MS - 1, NOW));
    let src = include_str!("inbox_do/scheduled.rs");
    let give_up = src.find("gives_up(").unwrap();
    let release = src.find("self.release_one(").unwrap();
    assert!(give_up < release, "a row past saving is tried again before it is given up");
}

/// Review finding 5: one alarm run fits the free plan's 50 subrequests whatever the room, on the
/// group fan-out's own arithmetic — one call per MEMBER (its inbox stores and wakes its devices from
/// its own invocation), the reserve (with the sender's own devices' wake), a fifth held back for a
/// retry. A 30-member room, three devices each, goes in at most three runs a second apart; the
/// largest a schedule may name in a handful.
#[test]
fn a_release_run_fits_the_subrequest_budget() {
    use crate::messages::budget::FREE_PLAN_SUBREQUESTS;
    let per_run = members_per_release_run(FREE_PLAN_SUBREQUESTS);
    let retries = (FREE_PLAN_SUBREQUESTS - RELEASE_RESERVED) / 5;
    assert!(per_run >= 10, "{per_run} member calls a run is too few");
    assert!(RELEASE_RESERVED + per_run + retries <= FREE_PLAN_SUBREQUESTS, "{per_run} calls do not fit");
    assert!(30usize.div_ceil(per_run) <= 3, "a 30-member room takes more than three runs: {per_run} a run");
    for members in [1usize, 31, 100, 199] {
        let runs = members.div_ceil(per_run);
        assert!(runs * per_run >= members && runs <= 20, "{members} members in {runs} runs");
    }
    let src = include_str!("inbox_do/scheduled.rs");
    assert!(src.contains("\"https://do.sezgi/notify-release\""), "a member costs one call, not one per device");
}

/// T1 (relay side): the held row is routing and an envelope the relay cannot open — no column for a
/// key, a text or anything decrypted.
#[test]
fn a_held_row_is_ciphertext_and_routing_only() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(SCHEDULED_TABLE_SQL).unwrap();
    let mut q = db.prepare("SELECT name FROM pragma_table_info('scheduled') ORDER BY cid").unwrap();
    let columns: Vec<String> = q.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
    assert_eq!(
        columns,
        [
            "schedule_id",
            "sender_id",
            "sender_device_id",
            "recipient_id",
            "group_id",
            "release_at",
            "envelope_b64",
            "targets_json",
            "created_at",
            "attempts",
            "next_attempt_at",
            "released_any"
        ]
    );
}

/// Re-review 6a: a take-back of a row the relay has started releasing (its budget ran out, or a
/// member's call failed, and the rest waits) is too late. The row stays and keeps releasing the
/// rest, and the answer says so; one released to nobody yet goes, and one not held says not held.
#[test]
fn a_take_back_after_a_partial_release_is_too_late() {
    assert_eq!(cancel_answer(Some(false)), (true, serde_json::json!({ "held": true, "released_any": false })));
    assert_eq!(cancel_answer(Some(true)), (false, serde_json::json!({ "held": true, "released_any": true })));
    assert_eq!(cancel_answer(None), (false, serde_json::json!({ "held": false, "released_any": false })));
}

/// Re-review 6a, on the table: a partial release marks the row, and the mark is what the take-back
/// reads.
#[test]
fn a_partial_release_marks_its_row() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(SCHEDULED_TABLE_SQL).unwrap();
    db.execute(
        "INSERT INTO scheduled (schedule_id, sender_id, sender_device_id, release_at, envelope_b64, targets_json,
                                created_at, next_attempt_at) VALUES ('a', 's', 'd', 1, 'e', '[]', 0, 1)",
        [],
    )
    .unwrap();
    let read = |db: &rusqlite::Connection| -> i64 {
        db.query_row("SELECT released_any FROM scheduled WHERE schedule_id = 'a'", [], |r| r.get(0)).unwrap()
    };
    assert_eq!(read(&db), 0, "a new row has released nothing");
    db.execute(BEGIN_RELEASE_SQL, ["a"]).unwrap();
    assert_eq!(read(&db), 1);
    // A failed member call keeps the row for its retry; the mark stays.
    db.execute("UPDATE scheduled SET targets_json = '[]', attempts = 1 WHERE schedule_id = 'a'", []).unwrap();
    assert_eq!(read(&db), 1, "once its release began, always");
}
