//! Tests for `live_location.rs`, included via `#[path]`.

use super::*;

fn word(at_ms: i64, stopped: bool) -> LiveWord {
    LiveWord { at_ms, stopped }
}

fn fix(latitude: f64, longitude: f64, at_ms: i64) -> Fix {
    Fix { latitude, longitude, at_ms }
}

#[test]
fn durations_are_the_three_offered() {
    assert_eq!(LiveDuration::FifteenMinutes.ms(), 15 * 60 * 1000);
    assert_eq!(LiveDuration::OneHour.ms(), 60 * 60 * 1000);
    assert_eq!(LiveDuration::EightHours.ms(), MAX_LIVE_MS);
}

#[test]
fn a_share_never_runs_past_eight_hours_from_its_start() {
    assert_eq!(effective_until(1_000, 1_000 + 60_000), 61_000);
    let week = 1_000 + 7 * 24 * 60 * MINUTE_MS;
    assert_eq!(effective_until(1_000, week), 1_000 + MAX_LIVE_MS + GRACE_MS);
}

#[test]
fn positions_must_be_plausible() {
    assert!(valid_position(41.0, 29.0, Some(12.0)));
    assert!(valid_position(-90.0, 180.0, None));
    for (la, lo, acc) in [
        (91.0, 0.0, None),
        (0.0, -181.0, None),
        (f64::NAN, 0.0, None),
        (0.0, f64::INFINITY, None),
        (0.0, 0.0, Some(-1.0)),
        (0.0, 0.0, Some(f64::NAN)),
    ] {
        assert!(!valid_position(la, lo, acc), "{la} {lo} {acc:?}");
    }
}

#[test]
fn an_update_after_the_window_is_late() {
    assert!(within_window(100, 100));
    assert!(within_window(100 + GRACE_MS, 100));
    assert!(!within_window(101 + GRACE_MS, 100));
}

#[test]
fn last_writer_wins_and_a_stop_is_final() {
    assert_eq!(accept(None, word(5, false)), Accept::Take);
    assert_eq!(accept(Some(word(5, false)), word(6, false)), Accept::Take);
    assert_eq!(accept(Some(word(5, false)), word(5, false)), Accept::Ignore, "a copy changes nothing");
    assert_eq!(accept(Some(word(6, false)), word(5, false)), Accept::Ignore, "older loses");
    assert_eq!(accept(Some(word(5, false)), word(5, true)), Accept::Take, "a stop at the same time wins");
    assert_eq!(accept(Some(word(9, false)), word(5, true)), Accept::StopOnly, "an older stop still ends it");
    assert_eq!(accept(Some(word(5, true)), word(9, false)), Accept::Ignore, "nothing revives a stopped share");
    assert_eq!(accept(Some(word(5, true)), word(9, true)), Accept::Ignore);
}

#[test]
fn distance_is_about_right() {
    // One thousandth of a degree of latitude is ~111 m.
    let d = distance_m(fix(41.0, 29.0, 0), fix(41.001, 29.0, 0));
    assert!((d - 111.2).abs() < 1.0, "{d}");
    assert_eq!(distance_m(fix(41.0, 29.0, 0), fix(41.0, 29.0, 0)), 0.0);
}

#[test]
fn the_rate_limit_sends_on_movement_or_heartbeat_never_faster() {
    let start = fix(41.0, 29.0, 0);
    assert!(should_send(None, start), "the first fix always goes");
    // Moved 111 m but only 10 s later: held.
    assert!(!should_send(Some(start), fix(41.001, 29.0, 10_000)));
    // Moved 111 m, 15 s later: sent.
    assert!(should_send(Some(start), fix(41.001, 29.0, MIN_INTERVAL_MS)));
    // Still (2 m), a minute later: held.
    assert!(!should_send(Some(start), fix(41.000_02, 29.0, 60_000)));
    // Still, two minutes later: the heartbeat.
    assert!(should_send(Some(start), fix(41.000_02, 29.0, HEARTBEAT_MS)));
}
