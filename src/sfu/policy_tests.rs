//! Tests for `policy.rs` (included via `#[path]`; `super` = the module itself).

use super::*;
use serde_json::json;

#[test]
fn the_route_defaults_to_the_server() {
    assert_eq!(OwnerRoute::parse(None), OwnerRoute::Server);
    assert_eq!(OwnerRoute::parse(Some("nonsense")), OwnerRoute::Server);
    assert_eq!(OwnerRoute::parse(Some(" crowded ")), OwnerRoute::Crowded);
    assert_eq!(OwnerRoute::parse(Some("direct")), OwnerRoute::Direct);
    assert!(OwnerRoute::valid("server") && !OwnerRoute::valid("sfu"));
}

#[test]
fn the_group_choice_comes_first_then_the_owner_then_the_sfu_then_the_budget() {
    let cap = DEFAULT_CAP_GB;
    let ok = decide(true, OwnerRoute::Server, false, 0, cap);
    assert!(ok.available && ok.reason.is_none());
    assert_eq!(decide(true, OwnerRoute::Server, true, 0, cap).reason, Some("group_direct"));
    assert_eq!(decide(false, OwnerRoute::Direct, false, 0, cap).reason, Some("owner_direct"));
    assert_eq!(decide(false, OwnerRoute::Server, false, 0, cap).reason, Some("not_configured"));
    assert_eq!(decide(true, OwnerRoute::Crowded, false, cap * GB, cap).reason, Some("capped"));
    assert!(decide(true, OwnerRoute::Server, false, cap * GB - 1, cap).available);
    assert!(decide(true, OwnerRoute::Server, false, i64::MAX, 0).available, "0 = no cap");
}

#[test]
fn only_an_explicit_direct_keeps_a_group_off_the_sfu() {
    assert!(group_is_direct(Some(r#"{"call_route":"direct","rec":"all"}"#)));
    assert!(!group_is_direct(Some(r#"{"call_route":"server"}"#)));
    assert!(!group_is_direct(Some(r#"{"rec":"all"}"#)));
    assert!(!group_is_direct(Some("not json")));
    assert!(!group_is_direct(None));
}

#[test]
fn a_report_counts_no_more_than_the_time_could_carry() {
    let per_sec = MAX_RECEIVE_BITS_PER_SEC / 8;
    assert_eq!(clamp_report(1_000, 30), 1_000);
    assert_eq!(clamp_report(i64::MAX, 30), per_sec * 30);
    assert_eq!(clamp_report(-5, 30), 0);
    assert_eq!(clamp_report(i64::MAX, 3_600), per_sec * MAX_REPORT_GAP_SECS, "a long gap is capped");
    assert_eq!(clamp_report(i64::MAX, 0), 0, "no time, nothing: reports back to back add nothing");
    assert_eq!(clamp_report(i64::MAX, -3), 0, "a clock that went back adds nothing either");
}

#[test]
fn each_warning_fires_once() {
    let cap = 1000;
    assert_eq!(crossed(799 * GB, cap, false, false), (false, false));
    assert_eq!(crossed(800 * GB, cap, false, false), (true, false));
    assert_eq!(crossed(900 * GB, cap, true, false), (false, false));
    assert_eq!(crossed(1000 * GB, cap, true, false), (false, true));
    assert_eq!(crossed(1000 * GB, cap, false, false), (true, true), "both in one jump");
    assert_eq!(crossed(5000 * GB, 0, false, false), (false, false), "no cap, no warning");
}

#[test]
fn a_member_pulls_only_tracks_of_its_own_call() {
    let allowed = vec!["s-a".to_string(), "s-b".to_string()];
    let ok = json!({"tracks": [
        {"location": "remote", "sessionId": "s-a", "trackName": "x-v"},
        {"location": "remote", "sessionId": "s-b", "trackName": "y-a"},
    ]});
    assert!(remote_tracks_ok(&ok, &allowed));
    let foreign = json!({"tracks": [{"location": "remote", "sessionId": "s-other", "trackName": "z"}]});
    assert!(!remote_tracks_ok(&foreign, &allowed));
    let local = json!({"sessionDescription": {"type": "offer", "sdp": "v=0"},
                       "tracks": [{"location": "local", "mid": "0", "trackName": "me-v"}]});
    assert!(remote_tracks_ok(&local, &allowed));
    assert!(!remote_tracks_ok(&json!({"tracks": [{"trackName": "no-location"}]}), &allowed));
    assert!(!remote_tracks_ok(&json!({"tracks": "nope"}), &allowed));
    assert!(!remote_tracks_ok(&json!([1, 2]), &allowed));
}

#[test]
fn a_pasted_credential_cannot_forge_a_header() {
    assert!(credential_ok("510c9339bed61e8e60099f2e86a4d6aa", 128));
    assert!(!credential_ok("abc\r\nx-evil: 1", 512));
    assert!(!credential_ok("with space", 512));
    assert!(!credential_ok("", 512));
    assert!(!credential_ok(&"a".repeat(129), 128));
}

#[test]
fn past_the_limit_a_call_already_going_on_is_still_joined() {
    let capped = decide(true, OwnerRoute::Server, false, 1000 * GB, 1000);
    assert!(!admits_running_call(&capped, false), "a new call goes direct");
    assert!(admits_running_call(&capped, true), "a late joiner of a running one is let in");
    for off in [
        decide(true, OwnerRoute::Server, true, 0, 1000),
        decide(true, OwnerRoute::Direct, false, 0, 1000),
        decide(false, OwnerRoute::Server, false, 0, 1000),
    ] {
        assert!(!admits_running_call(&off, true), "{:?} is a way turned off, not a budget", off.reason);
    }
    let open = decide(true, OwnerRoute::Server, false, 0, 1000);
    assert!(admits_running_call(&open, false));
}

#[test]
fn a_call_is_going_on_while_media_is_reported_and_for_a_lesson_s_length_at_most() {
    let now = 100_000;
    assert!(call_is_running(1, Some(now - 3600), now));
    assert!(!call_is_running(0, Some(now - 60), now), "nothing reported");
    assert!(!call_is_running(1, None, now));
    assert!(!call_is_running(3, Some(now - RUNNING_CALL_MAX_AGE_SECS - 1), now), "not all month");
}
