//! The per-invocation subrequest budget: the group fan-out, the retry drain, and the upkeep that
//! shares an invocation with them.
//!
//! **The ceiling is real and it is low.** A Workers invocation on the free plan may make 50
//! external subrequests, and Cloudflare's pages do not say whether a Durable Object call counts
//! toward those 50 or toward the 1,000 "to Cloudflare services" (read 2026-10-13; see I4.8 in
//! `docs/FIELD_READINESS_PLAN.md`). Everything here assumes the WORSE reading: every D1 query, KV
//! operation, DO call and fetch comes out of one purse of 50. If DO calls turn out to be in the
//! 1,000, the plan is merely conservative; it never depends on the generous reading.
//!
//! **The shape (D8, 2026-10-13).** A member costs the sender ONE call whatever its devices: its
//! own inbox stores a row per device and pays for the wake (`inbox_do/member_notify.rs`). A room
//! larger than one invocation can safely call goes to `/fanout` hops, each a fresh invocation.
//!
//! **Everything an invocation spends is reserved, not only the fan-out (the D8 review).** The
//! first version counted the fan-out and missed three things that share its invocation, and in
//! each case the subrequest cut off was the CLOSING batch, the one that records what happened:
//! - a cold isolate's self-provisioning, now counted where it runs and charged while recent
//!   (`self_provision::recent_spend`);
//! - the lazy maintenance kick that rides every fetch (`LAZY_KICK`). The lazy WORK no longer
//!   shares the request's invocation at all: it runs in a maintenance DO (`maintenance.rs`);
//! - what `scheduled()` and the maintenance run do after the drain (`CRON_TAIL`, `UPKEEP_TAIL`).
//!
//! Every close is reserved with one retry, and the drain is sized from the purse its caller grants
//! it, never from the whole ceiling.

use worker::Env;

/// The free-plan ceiling. Named rather than inlined because everything below is arithmetic on it,
/// and because it is the number to change when the plan changes.
pub(crate) const FREE_PLAN_SUBREQUESTS: usize = 50;

/// Owner override, for a paid plan. Read as a `var`, so a self-hosted relay can raise it in
/// `wrangler.toml` without a code change. Clamped: a value below the floor would deliver nothing,
/// and a value above this is a typo, not a wish.
const MIN_BUDGET: usize = 20;
pub(crate) const MAX_BUDGET: usize = 900;

/// One member call: a `/notify-member` to a member's inbox, or a `/fanout` to a hop. Either is
/// ONE subrequest in the caller's invocation, whatever the member's devices or wakes cost — those
/// are paid by the callee's own invocation.
pub(crate) const COST_MEMBER_CALL: usize = 1;

/// What the group send spends before its fan-out, counted call by call: `require_active_auth`
/// (account and device, 2 D1), the send rate limit (KV get + put), `device_revoked` (1 D1),
/// `group_role` (1 D1), the member×device query (1 D1), and the weighted rate limit (KV get +
/// put). Nine.
pub(crate) const SEND_PRELUDE: usize = 9;

/// What `maintenance::maybe_run_lazy` may spend inside ANY fetch invocation, concurrently with the
/// handler: the stamp read and, when something is due, one call to the maintenance DO. At most
/// once a minute per isolate, but reserved always — it cannot be predicted per request.
pub(crate) const LAZY_KICK: usize = 2;

/// A closing D1 batch, reserved with one retry: the batch that writes the send's failed members to
/// `fanout_retry`, or the drain's deletes and backoffs. It is the record of what happened, so it
/// is never the call that is cut off.
pub(crate) const CLOSE: usize = 2;

/// A hop spends nothing but its member calls: it runs in a Durable Object and touches only DO
/// storage, which is not a subrequest. Its failures travel back to the sender, which writes them.
pub(crate) const HOP_OVERHEAD: usize = 0;

/// The drain's own spend outside its rows: the claim, and the close (with its retry).
pub(crate) const DRAIN_OVERHEAD: usize = 1 + CLOSE;

/// `scheduled()` before its drain: `stamp_drain`, moved in front so a starved drain cannot leave
/// the lazy path believing the cron is dead.
pub(crate) const CRON_HEAD: usize = 1;
/// `scheduled()` after its drain on the frequent cron: `drain_purge_outbox`'s SELECT,
/// `run_storage_move`'s SELECT and `stamp_move`. (A purge row or a draining backend costs more;
/// both are rare, pre-date D8, and are bounded by their own code.)
pub(crate) const CRON_TAIL: usize = 3;

/// The maintenance DO before its drain: the stamp read and the drain stamp's claim (INSERT OR
/// IGNORE + UPDATE … RETURNING).
pub(crate) const UPKEEP_HEAD: usize = 3;
/// The maintenance DO after its drain: the purge outbox's SELECT, the move stamp's claim (2) and
/// `run_storage_move`'s SELECT.
pub(crate) const UPKEEP_TAIL: usize = 4;

/// At most this many member calls in flight at once. A Workers invocation may have six
/// connections waiting for response headers; a seventh queues. Matching it keeps the fan-out as
/// fast as the platform allows without leaning on that queue.
pub(crate) const MAX_CONCURRENT_CALLS: usize = 6;

/// At most this many rows per drain, whatever the purse — bounded by D1's response size.
pub(crate) const DRAIN_BATCH_CEILING: usize = 50;

/// What one member's WAKE can cost inside its own inbox DO, worst case: the push config (1 D1
/// query, every key at once), the token query (1), the shared OAuth token (KV get), and when it
/// must be minted Google (1 fetch) and the KV put (the service account comes with the config),
/// and at most one verdict write about the owner's own project (K8) — then per device a push, its
/// resend through the shared relay when Google refuses the project for that token (K8), and a
/// stale-token delete. Run, not just summed: `spend_tests.rs`
/// (`a_members_wake_with_the_relay_fallback_fits_its_bound`).
pub(crate) const MEMBER_WAKE_FIXED: usize = 6;
pub(crate) const MEMBER_WAKE_PER_DEVICE: usize = 3;
// Checked at compile time: a member's wake fits its own invocation with room to spare, even with
// the most devices an account may have (the token query is bounded by the same number).
const _: () = assert!(
    MEMBER_WAKE_FIXED + crate::devices::handlers::MAX_DEVICES * MEMBER_WAKE_PER_DEVICE
        <= FREE_PLAN_SUBREQUESTS / 2
);

/// The ceiling for this invocation.
pub(crate) fn resolve_budget(env: &Env) -> usize {
    crate::utils::var_or(env, "SUBREQUEST_BUDGET", "")
        .trim()
        .parse::<usize>()
        .unwrap_or(FREE_PLAN_SUBREQUESTS)
        .clamp(MIN_BUDGET, MAX_BUDGET)
}

/// Everything the group send holds back from its fan-out: what provisioning spent in this
/// invocation (0 on a warm isolate), its prelude, the lazy kick, and its close.
pub(crate) fn send_reserved(provision: usize) -> usize {
    provision + SEND_PRELUDE + LAZY_KICK + CLOSE
}

/// How many member calls one invocation plans for: what is left after `reserved`, less a fifth
/// held back so every planned member that fails can be tried once more in the same request. At
/// the free-plan 50, warm, that is 30 for the sender (50 − 13 = 37, less 7) and 40 for a hop (50,
/// less 10) — so a hop's worst case, forty calls and ten retries, is exactly the ceiling.
pub(crate) fn members_per_invocation(budget: usize, reserved: usize) -> usize {
    let avail = budget.saturating_sub(reserved);
    (avail - avail / 5).max(1)
}

/// How the sender reaches a room of `members`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FanoutPlan {
    /// Call every member's inbox from the sender's request.
    Direct,
    /// Hand the members to hops of at most `chunk` each.
    Hops { chunk: usize },
}

/// Direct while the sender's own invocation can call every member with retry headroom; hops
/// beyond. At the free-plan 50 on a warm isolate: direct up to 30 members, then hops of 40 — so
/// 80 members are two hop calls and the 256-member cap seven.
pub(crate) fn plan_group_fanout(budget: usize, reserved: usize, members: usize) -> FanoutPlan {
    if members <= members_per_invocation(budget, reserved) {
        FanoutPlan::Direct
    } else {
        FanoutPlan::Hops {
            chunk: members_per_invocation(budget, HOP_OVERHEAD),
        }
    }
}

/// The purse the cron grants its drain: the ceiling less provisioning, the head and the tail.
pub(crate) fn cron_drain_purse(budget: usize, provision: usize) -> usize {
    budget.saturating_sub(provision + CRON_HEAD + CRON_TAIL)
}

/// The purse the maintenance DO grants its drain.
pub(crate) fn upkeep_drain_purse(budget: usize) -> usize {
    budget.saturating_sub(UPKEEP_HEAD + UPKEEP_TAIL)
}

/// How many rows a drain with `purse` may claim: one call each, after its claim and close. Zero
/// when the purse cannot even close — then the drain does not start.
pub(crate) fn drain_rows(purse: usize) -> usize {
    purse.saturating_sub(DRAIN_OVERHEAD).min(DRAIN_BATCH_CEILING)
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
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The thresholds the plan quotes, at the free-plan ceiling on a warm isolate.
    #[test]
    fn direct_up_to_thirty_then_hops_of_forty() {
        let b = FREE_PLAN_SUBREQUESTS;
        let r = send_reserved(0);
        assert_eq!(plan_group_fanout(b, r, 30), FanoutPlan::Direct);
        assert_eq!(plan_group_fanout(b, r, 31), FanoutPlan::Hops { chunk: 40 });
        assert_eq!(plan_group_fanout(b, r, 256), FanoutPlan::Hops { chunk: 40 });
    }

    /// A cold isolate's provisioning shrinks what the sender calls directly.
    #[test]
    fn provisioning_shrinks_the_direct_room() {
        let b = FREE_PLAN_SUBREQUESTS;
        assert_eq!(plan_group_fanout(b, send_reserved(7), 25), FanoutPlan::Hops { chunk: 40 });
        assert_eq!(plan_group_fanout(b, send_reserved(7), 24), FanoutPlan::Direct);
    }

    /// Every budget the clamp allows can make progress: at least one member per invocation.
    #[test]
    fn the_floor_still_plans_a_member() {
        assert!(members_per_invocation(MIN_BUDGET, send_reserved(0)) >= 1);
        assert!(members_per_invocation(MIN_BUDGET, HOP_OVERHEAD) >= 1);
    }

    /// A drain that cannot pay for its close claims nothing.
    #[test]
    fn a_drain_that_cannot_close_does_not_start() {
        assert_eq!(drain_rows(DRAIN_OVERHEAD), 0);
        assert_eq!(drain_rows(DRAIN_OVERHEAD + 1), 1);
        assert_eq!(drain_rows(500), DRAIN_BATCH_CEILING);
    }
}
