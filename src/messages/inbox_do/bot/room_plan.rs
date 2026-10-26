//! The room round's pure decisions (`room.rs`, `room_asks.rs`), kept apart so they are tested
//! as they are: how many key shares a round can pay for, and when the alarm comes back for the
//! room work still waiting.
//!
//! **Progress is the rule.** A share is planned device by device — never a whole member at once —
//! so the most one share can cost is one device's key claim ([`CLAIM_COST`]), and a round that has
//! its full budget always makes progress. A round that made none (its budget was spent before it
//! started, a D1 read failed) waits [`STALL_MS`] instead of re-arming the alarm at once; a bot
//! that is off waits [`HOLD_MS`] (or its `/bot/wake`).

/// One device's key claim at worst: six D1 calls (`keys/bundle_slot.rs`).
pub(super) const CLAIM_COST: u32 = 6;
/// What a post or a key request reads before any share: the `group_bots` gate and the devices.
pub(super) const READS: u32 = 2;
/// A round that made no progress comes back after this.
pub(super) const STALL_MS: i64 = 5_000;
/// While the bot is off, room work is looked at again this often (the built-in runner's hold).
pub(super) const HOLD_MS: i64 = super::builtin_policy::HOLD_MS;

// A round with its whole budget can always pay for its reads and one device's claim.
const _: () = assert!(READS + CLAIM_COST <= super::room::ROOM_ROUND_MAX);

/// How many of the devices still owed a share, in order, one round can share with when `left`
/// subrequests remain: `has_session[i]` = the bot already holds a session with device `i` (no
/// claim, no cost). A prefix, so the order is kept across rounds; `true` when that is all of them.
pub(super) fn plan_shares(has_session: &[bool], left: u32) -> (usize, bool) {
    let mut cost = 0u32;
    for (i, has) in has_session.iter().enumerate() {
        let next = if *has { 0 } else { CLAIM_COST };
        if cost + next > left {
            return (i, false);
        }
        cost += next;
    }
    (has_session.len(), true)
}

/// How long until the room work still waiting needs the alarm again, after a round: `None` when
/// nothing waits, `Some(0)` at once.
pub(super) fn wait_after_round(work_left: bool, progressed: bool, held: bool) -> Option<i64> {
    match (work_left, held, progressed) {
        (false, _, _) => None,
        (true, _, true) => Some(0),
        (true, true, false) => Some(HOLD_MS),
        (true, false, false) => Some(STALL_MS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_are_planned_device_by_device_and_a_full_round_always_progresses() {
        // A member with five devices and no session: 30 subrequests at once used to be more than
        // any round may spend, so the post never moved (review, 2026-10-26).
        let five = [false; 5];
        assert_eq!(plan_shares(&five, 24), (4, false));
        assert_eq!(plan_shares(&five, 30), (5, true));
        assert_eq!(plan_shares(&five, CLAIM_COST), (1, false), "one claim always fits a full round");
        assert_eq!(plan_shares(&five, CLAIM_COST - 1), (0, false));
        assert_eq!(plan_shares(&[true, true, false, true], 5), (2, false), "sessions cost nothing");
        assert_eq!(plan_shares(&[true, true], 0), (2, true));
        assert_eq!(plan_shares(&[], 0), (0, true));
    }

    #[test]
    fn no_progress_backs_off_and_off_holds() {
        assert_eq!(wait_after_round(false, false, false), None);
        assert_eq!(wait_after_round(true, true, false), Some(0));
        assert_eq!(wait_after_round(true, true, true), Some(0), "something moved: go on at once");
        assert_eq!(wait_after_round(true, false, false), Some(STALL_MS), "never a hot loop");
        assert_eq!(wait_after_round(true, false, true), Some(HOLD_MS));
    }
}
