//! The per-request subrequest budget for message fan-out.
//!
//! **The ceiling is real and it is low.** A Workers request may make roughly 50 subrequests on
//! the free plan, and D1 queries, KV reads, Durable Object calls and the FCM/relay POST all
//! count. An unbounded (member × device) loop runs out part-way through and every remaining pair
//! then FAILS for want of budget rather than reachability — failures that land in `fanout_retry`,
//! whose drain hits the same wall on the next cron and reproduces them.
//!
//! So a pair that cannot be afforded is recognised BEFORE it is attempted and written straight
//! into `fanout_retry`: same durable path, same drain, no wasted attempts, no dependence on where
//! the runtime happened to cut the loop off. Deferring is not a failure mode.
//!
//! **Spend as you go, reserve for the worst.** The cost of a pair is not fixed: an ONLINE
//! recipient costs one `/notify` and nothing else, while an offline one adds a push. So the loop
//! charges what it actually spends and only requires the worst case to be AVAILABLE before it
//! starts a pair. A twenty-member room whose members are all connected still fans out in full.

use worker::Env;

/// The free-plan ceiling. Named rather than inlined because everything below is arithmetic on it,
/// and because it is the number to change when the plan changes.
const FREE_PLAN_SUBREQUESTS: usize = 50;

/// Owner override, for a paid plan (where the ceiling is 1000). Read as a `var`, so a self-hosted
/// relay can raise it in `wrangler.toml` without a code change. Clamped: a value below the floor
/// would deliver nothing, and a value above the paid ceiling is a typo, not a wish.
/// The floor is `GROUP_SEND_PRELUDE + 1 + COST_PAIR_WORST_CASE` rounded up: below it the group
/// loop could not afford a single pair, and a fan-out that defers everything makes no progress.
const MIN_BUDGET: usize = 20;
const MAX_BUDGET: usize = 900;

/// One DO `/notify`.
pub(crate) const COST_NOTIFY: usize = 1;

/// One `maybe_push_wake`. It is NOT one subrequest: it resolves the send mode (up to two
/// `server_config` reads), selects the device's push tokens, and then posts to FCM or to the
/// relay — the FCM path first fetching a Google OAuth token. Four is the conservative reading, and
/// conservative is the right direction: overestimating defers a pair to a retry that will deliver
/// it, while underestimating resurrects the mid-loop cut-off this module exists to prevent.
pub(crate) const COST_PUSH_WAKE: usize = 4;

/// What one (member, device) pair must have AVAILABLE before it is attempted.
pub(crate) const COST_PAIR_WORST_CASE: usize = COST_NOTIFY + COST_PUSH_WAKE;

/// Subrequests the group send path has already spent before the fan-out loop begins: token
/// validation, the rate-limit KV window, the sender's revocation check, the group-role lookup, the
/// member×device query and the fan-out weight check. Counted generously, and one more is held back
/// for the single `fanout_retry` batch that closes the handler.
pub(crate) const GROUP_SEND_PRELUDE: usize = 12;

/// Subrequests the retry drain spends outside its loop: the atomic claim, and the one batch that
/// deletes what succeeded and re-schedules what did not.
pub(crate) const DRAIN_OVERHEAD: usize = 2;

/// The ceiling for this invocation.
pub(crate) fn resolve_budget(env: &Env) -> usize {
    crate::utils::var_or(env, "SUBREQUEST_BUDGET", "")
        .trim()
        .parse::<usize>()
        .unwrap_or(FREE_PLAN_SUBREQUESTS)
        .clamp(MIN_BUDGET, MAX_BUDGET)
}

/// A running count of what is left to spend in this request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SubrequestBudget {
    remaining: usize,
}

impl SubrequestBudget {
    /// `total` is the invocation ceiling; `reserved` is what the caller has already spent or is
    /// holding back. Saturating, so an over-reserved budget is simply empty rather than a panic.
    pub(crate) fn new(total: usize, reserved: usize) -> Self {
        Self {
            remaining: total.saturating_sub(reserved),
        }
    }

    pub(crate) fn can_afford(&self, cost: usize) -> bool {
        self.remaining >= cost
    }

    pub(crate) fn spend(&mut self, cost: usize) {
        self.remaining = self.remaining.saturating_sub(cost);
    }

    #[cfg(test)]
    fn remaining(&self) -> usize {
        self.remaining
    }
}

/// How many `fanout_retry` rows one drain may CLAIM.
///
/// Claiming more than can be processed is not free: a claimed row's `next_at` is pushed a
/// ten-minute lease ahead, so an over-claim parks work the drain never touched. The drain releases
/// what it could not afford (see `drain_fanout_retry`), and this keeps the over-claim small in the
/// first place by sizing the claim to the budget's BEST case — one `/notify` per row, which is
/// what an online recipient costs.
pub(crate) fn drain_claim_size(budget: usize, overhead: usize, ceiling: usize) -> usize {
    budget
        .saturating_sub(overhead)
        .checked_div(COST_NOTIFY)
        .unwrap_or(0)
        .min(ceiling)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of the bug: a fan-out that keeps attempting after the runtime has stopped
    /// answering. The budget must run out BEFORE the ceiling, not at it.
    #[test]
    fn a_wide_fanout_stops_paying_before_the_ceiling() {
        let mut b = SubrequestBudget::new(FREE_PLAN_SUBREQUESTS, GROUP_SEND_PRELUDE + 1);
        let mut attempted = 0;
        for _ in 0..200 {
            if !b.can_afford(COST_PAIR_WORST_CASE) {
                break;
            }
            attempted += 1;
            b.spend(COST_PAIR_WORST_CASE); // every recipient offline: the expensive case
        }
        assert!(attempted > 0, "a budget that attempts nothing is a broken fan-out");
        let spent = GROUP_SEND_PRELUDE + 1 + attempted * COST_PAIR_WORST_CASE;
        assert!(
            spent <= FREE_PLAN_SUBREQUESTS,
            "the loop spent {spent}, over the {FREE_PLAN_SUBREQUESTS} ceiling"
        );
    }

    /// Spending what is ACTUALLY used, not the worst case, is what keeps an ordinary room whole:
    /// when everyone is connected there is no push to pay for, so far more pairs fit.
    #[test]
    fn an_all_online_room_gets_many_more_pairs_than_an_all_offline_one() {
        let fits = |cost: usize| {
            let mut b = SubrequestBudget::new(FREE_PLAN_SUBREQUESTS, GROUP_SEND_PRELUDE + 1);
            let mut n = 0;
            while b.can_afford(COST_PAIR_WORST_CASE) {
                n += 1;
                b.spend(cost);
            }
            n
        };
        let online = fits(COST_NOTIFY);
        let offline = fits(COST_PAIR_WORST_CASE);
        assert!(
            online > offline * 3,
            "online pairs cost a fifth as much and must go much further ({online} vs {offline})"
        );
    }

    #[test]
    fn an_over_reserved_budget_is_empty_rather_than_a_panic() {
        let b = SubrequestBudget::new(10, 99);
        assert_eq!(b.remaining(), 0);
        assert!(!b.can_afford(1));
    }

    #[test]
    fn spending_saturates_at_zero() {
        let mut b = SubrequestBudget::new(3, 0);
        b.spend(100);
        assert_eq!(b.remaining(), 0);
    }

    /// The drain claims what it can plausibly finish, and never zero — a drain that claims nothing
    /// makes no progress and the queue never empties.
    #[test]
    fn the_drain_claim_fits_the_budget_and_is_never_zero() {
        assert_eq!(drain_claim_size(50, DRAIN_OVERHEAD, 50), 48);
        assert_eq!(
            drain_claim_size(50, DRAIN_OVERHEAD, 20),
            20,
            "the caller's own ceiling still wins"
        );
        assert_eq!(
            drain_claim_size(1, DRAIN_OVERHEAD, 50),
            1,
            "an exhausted budget still claims one row so the queue drains eventually"
        );
    }
}
