//! The rule alone. The loop that applies it is driven in `wake_tests.rs`.

use super::*;

const T: i64 = 1_700_000_000_000;

fn mark(woke_for: Option<i64>, seen: Option<i64>) -> WakeMark {
    WakeMark { woke_for_ms: woke_for, seen_ms: seen }
}

#[test]
fn a_device_never_woken_is_woken() {
    assert_eq!(gate(WakeMark::default(), T), Gate::Send);
    assert_eq!(gate(mark(None, Some(T - 5)), T), Gate::Send);
}

#[test]
fn an_unseen_device_woken_inside_the_window_is_coalesced() {
    assert_eq!(gate(mark(Some(T - 6_000), None), T), Gate::Coalesced { age_ms: 6_000 });
    // Seen BEFORE that wake's moment: that connection did not fetch what the wake was for.
    assert_eq!(gate(mark(Some(T - 6_000), Some(T - 60_000)), T), Gate::Coalesced { age_ms: 6_000 });
    assert_eq!(gate(mark(Some(T), None), T), Gate::Coalesced { age_ms: 0 });
}

/// The old debounce's bug: a follow-up arriving after the drain must wake.
#[test]
fn a_device_seen_since_the_wake_is_woken_at_once() {
    assert_eq!(gate(mark(Some(T - 6_000), Some(T - 2_000)), T), Gate::Send);
    assert_eq!(gate(mark(Some(T - 6_000), Some(T - 6_000)), T), Gate::Send, "a tie is seen");
}

/// A lost push is retried: past the window the next wake goes out, seen or not.
#[test]
fn past_the_window_the_next_wake_goes_out() {
    assert_eq!(gate(mark(Some(T - WAKE_COALESCE_MS), None), T), Gate::Send);
    assert_eq!(
        gate(mark(Some(T - WAKE_COALESCE_MS + 1), None), T),
        Gate::Coalesced { age_ms: WAKE_COALESCE_MS - 1 }
    );
}

#[test]
fn a_mark_from_the_future_never_coalesces() {
    assert_eq!(gate(mark(Some(T + 1), None), T), Gate::Send);
    assert_eq!(gate(mark(Some(T + 3_600_000), None), T), Gate::Send);
}
