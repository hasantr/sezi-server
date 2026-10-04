//! When the periodic alarm should fire AGAIN — and, just as important, when it should stop.
//!
//! **The billing reason.** `alarm()` used to end with an unconditional re-arm, so every
//! `UserInbox` that had ever been touched woke every `FLUSH_INTERVAL_MS` (90 s) for the rest of
//! its life: ~960 wakes per day per DO, forever, including inboxes whose account had been PURGED
//! (`REMOVED_ACCOUNT_KEY`) and inboxes with nothing at all to flush. A wake is a billed request
//! plus a storage read, and nothing in the system ever cancelled it — `delete_alarm` was never
//! called, and `storage.delete_all()` deliberately does NOT clear the alarm.
//!
//! **Why stopping is safe.** The alarm exists to flush queued work to a client that is not
//! talking to us right now. When there is no queued work and no socket, there is nothing for it
//! to do, and the two events that CREATE work both re-arm it themselves: `/notify` (a message
//! arriving for an offline recipient) and `ws_upgrade` (a client reconnecting). Both call
//! `ensure_alarm`, which is why the chain can be allowed to end rather than idle forever.
//!
//! The one thing that is NOT event-driven is the daily retention purge, so an otherwise idle DO
//! that still holds retention-eligible rows keeps a SLOW alarm (`IDLE_INTERVAL_MS`) instead of the
//! 90 s one. That is ~4 wakes a day rather than ~960, and the purge still happens.

/// What is still outstanding at the end of an `alarm()` run. Measured, never assumed: a SQL error
/// while counting reads as "there is work" (see `count_or_busy` at the call site), so a storage
/// hiccup can never be mistaken for idleness and silently end the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AlarmWork {
    /// The account was purged (`REMOVED_ACCOUNT_KEY`). Nothing will ever be queued here again.
    pub(super) account_removed: bool,
    /// Undelivered rows in `pending`.
    pub(super) pending_rows: i64,
    /// Unacked receipt forwards in `forward_queue`.
    pub(super) forward_rows: i64,
    /// Open WebSockets (hibernated ones included).
    pub(super) sockets: usize,
    /// Rows only the daily cleanup will ever remove: `receipt_state`, `self_read_state`,
    /// `receipt_uid_state`. They carry no delivery obligation, so they earn the slow alarm and
    /// not the fast one.
    pub(super) retained_rows: i64,
}

impl AlarmWork {
    /// Work a client is WAITING for — the only reason to keep waking every 90 s.
    fn has_live_work(&self) -> bool {
        self.pending_rows > 0 || self.forward_rows > 0 || self.sockets > 0
    }
}

/// How long until the next alarm, or `None` to let the chain END.
///
/// `None` is not a loss of function: `/notify` and `ws_upgrade` both call `ensure_alarm`, so the
/// chain restarts the moment there is anything to flush again.
pub(super) fn next_alarm_delay_ms(work: AlarmWork, flush_ms: i64, idle_ms: i64) -> Option<i64> {
    if work.account_removed {
        // A purged inbox has no future work by construction. Waking it 960 times a day to
        // rediscover that is the single clearest instance of the bug this module exists for.
        return None;
    }
    if work.has_live_work() {
        return Some(flush_ms);
    }
    if work.retained_rows > 0 {
        // Nothing to deliver, but the daily retention purge still has rows to collect.
        return Some(idle_ms);
    }
    None
}

/// Should `ensure_alarm` write an alarm, given the one currently armed?
///
/// The test is "armed NO LATER than `deadline_ms`", not "armed at all". Without that, the slow
/// idle alarm above would swallow the fast re-arm: a `/notify` arriving into an idle DO would see
/// an alarm six hours out, call it good, and the stuck-pending FCM backstop would run six hours
/// late. Arming is idempotent, so a redundant write is only a wasted storage op.
pub(super) fn alarm_needs_arming(current_ms: Option<i64>, deadline_ms: i64) -> bool {
    match current_ms {
        None => true,
        Some(t) => t > deadline_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLUSH: i64 = 90_000;
    const IDLE: i64 = 6 * 3600 * 1000;

    fn idle_work() -> AlarmWork {
        AlarmWork {
            account_removed: false,
            pending_rows: 0,
            forward_rows: 0,
            sockets: 0,
            retained_rows: 0,
        }
    }

    /// The purged inbox: the case that was costing ~960 wakes a day for an account that no
    /// longer exists.
    #[test]
    fn a_purged_account_never_re_arms() {
        let w = AlarmWork {
            account_removed: true,
            // Even with work on the books — a purge deletes the tables, so these cannot really
            // both hold, and if they somehow did the account is still gone.
            pending_rows: 5,
            forward_rows: 5,
            sockets: 1,
            retained_rows: 5,
        };
        assert_eq!(next_alarm_delay_ms(w, FLUSH, IDLE), None);
    }

    /// An inbox with nothing queued and nobody connected lets the chain end. `/notify` and
    /// `ws_upgrade` are what bring it back.
    #[test]
    fn a_completely_idle_inbox_lets_the_chain_end() {
        assert_eq!(next_alarm_delay_ms(idle_work(), FLUSH, IDLE), None);
    }

    /// Any one of the three live signals is enough to keep the fast alarm.
    #[test]
    fn each_kind_of_live_work_keeps_the_fast_alarm() {
        for w in [
            AlarmWork { pending_rows: 1, ..idle_work() },
            AlarmWork { forward_rows: 1, ..idle_work() },
            AlarmWork { sockets: 1, ..idle_work() },
        ] {
            assert_eq!(
                next_alarm_delay_ms(w, FLUSH, IDLE),
                Some(FLUSH),
                "{w:?} is outstanding work and must keep the 90s alarm"
            );
        }
    }

    /// Retention-only rows earn the SLOW alarm: the daily purge still runs, at ~4 wakes a day
    /// instead of ~960.
    #[test]
    fn retention_only_rows_get_the_slow_alarm_not_the_fast_one() {
        let w = AlarmWork { retained_rows: 12, ..idle_work() };
        assert_eq!(next_alarm_delay_ms(w, FLUSH, IDLE), Some(IDLE));
    }

    /// Live work OUTRANKS the retention-only case — a client waiting on a message must not be
    /// made to wait for the idle interval.
    #[test]
    fn live_work_outranks_retention_rows() {
        let w = AlarmWork { pending_rows: 1, retained_rows: 900, ..idle_work() };
        assert_eq!(next_alarm_delay_ms(w, FLUSH, IDLE), Some(FLUSH));
    }

    /// The trap the "armed no later than" rule exists for: an alarm parked six hours out must
    /// NOT count as armed when a message has just arrived and wants the 90 s backstop.
    #[test]
    fn a_far_future_alarm_does_not_satisfy_a_near_deadline() {
        let now = 1_780_000_000_000i64;
        assert!(alarm_needs_arming(None, now + FLUSH), "no alarm at all → arm");
        assert!(
            alarm_needs_arming(Some(now + IDLE), now + FLUSH),
            "the idle alarm is too far out to serve as the flush backstop"
        );
        assert!(
            !alarm_needs_arming(Some(now + FLUSH), now + FLUSH),
            "exactly at the deadline is soon enough (>, not >=)"
        );
        assert!(
            !alarm_needs_arming(Some(now + 1_000), now + FLUSH),
            "an alarm sooner than the deadline already covers it"
        );
    }
}
