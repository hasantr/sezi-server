//! The room posts' order — and the one post allowed out of it (the webhook's rule,
//! `deliver_order.rs`).
//!
//! Posts go into their rooms oldest first, and a post whose round fails holds the ones behind it:
//! the round stops there, and the room round's no-progress wait climbs its ladder
//! (`room_plan::wait_after_stall`). Until 2026-10-27 that was all, so one post that could never be
//! made (a payload this build cannot read, an encrypt that keeps failing) held every other room
//! post for its whole 24 h (review #20).
//!
//! **A poison post is set aside.** When the head has failed [`ASIDE_AFTER`] times, the round tries
//! the post behind it at once, as a probe:
//! - **the probe moves** (sent on, or shared with at least one device): the room path works and
//!   only the head fails. The head is SET ASIDE (`bot_room_post_fail.aside`): retried on its own
//!   on the outbox's ladder, hourly, until its 24 h end, and the posts behind it go on. It may
//!   reach its room after posts written later.
//! - **the probe fails too**: D1 or the engine, not one post. Nothing is set aside and the round
//!   stops, as before.
//!
//! A set-aside post that fails again fails alone: the round goes on to the next.
//!
//! Generic over storage and the attempt so the host tests run it whole (`room_order_tests.rs`);
//! the DO drives it from `room.rs`.

use super::outbox::retry_delay_ms;
use super::store::{Arg, Exec};
use std::future::Future;

/// Failures after which a post at the head is probed past (the webhook's number).
pub(super) const ASIDE_AFTER: i64 = super::deliver_order::ASIDE_AFTER;

/// Bind: post_id.
pub(super) const FAIL_ATTEMPTS: &str = "SELECT attempts FROM bot_room_post_fail WHERE post_id = ?";
/// Bind: post_id.
pub(super) const FAIL_ASIDE_GET: &str = "SELECT aside FROM bot_room_post_fail WHERE post_id = ?";
/// Bind: post_id, attempts, next_at.
pub(super) const FAIL_PUT: &str = "INSERT INTO bot_room_post_fail (post_id, attempts, next_at) VALUES (?, ?, ?)
      ON CONFLICT(post_id) DO UPDATE SET attempts = excluded.attempts, next_at = excluded.next_at";
/// Bind: post_id.
pub(super) const FAIL_SET_ASIDE: &str = "UPDATE bot_room_post_fail SET aside = 1 WHERE post_id = ?";
/// Bind: post_id.
pub(super) const FAIL_DROP: &str = "DELETE FROM bot_room_post_fail WHERE post_id = ?";
/// Failure rows whose post is gone (sent, expired, its room left).
pub(super) const FAIL_ORPHANS: &str =
    "DELETE FROM bot_room_post_fail WHERE post_id NOT IN (SELECT id FROM bot_room_posts)";

/// What one attempt at a post did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Attempt {
    /// Finished with: sent on, dropped, or abandoned because its room changed.
    Moved,
    /// Shared as far as the budget paid; `progressed` = at least one device was. The round ends.
    Partial { progressed: bool },
    /// The bot is off: the post waits, and the round ends.
    Held,
    /// It failed.
    Failed,
}

/// What a round did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Round {
    pub(super) progressed: bool,
    pub(super) held: bool,
    /// It stopped on a failure that held the queue (not a set-aside post's own).
    pub(super) failed: bool,
}

/// Record a failure of `post` at `now`: its new attempt count.
fn note_failure<E: Exec>(db: &E, post: i64, now: i64) -> i64 {
    let attempts = db.int(FAIL_ATTEMPTS, &[Arg::I(post)]).unwrap_or(0);
    db.run(FAIL_PUT, &[Arg::I(post), Arg::I(attempts + 1), Arg::I(now + retry_delay_ms(attempts))]);
    attempts + 1
}

/// One round over the posts. `next(tried)` is the next post the round may try and its id
/// (`POST_NEXT`, with `tried` the JSON array of the ids already tried in it), `None` when there is
/// none or the budget is spent; `attempt(post)` makes one attempt at it. A post is tried once a
/// round.
pub(super) async fn post_round<E, P, N, A, F>(db: &E, now: impl Fn() -> i64, mut next: N, mut attempt: A) -> Round
where
    E: Exec,
    N: FnMut(&str) -> Option<(i64, P)>,
    A: FnMut(P) -> F,
    F: Future<Output = Attempt>,
{
    let mut round = Round::default();
    let mut tried: Vec<i64> = Vec::new();
    // Heads that failed their ASIDE_AFTER-th time in this round, waiting on the probe behind them.
    let mut probing: Vec<i64> = Vec::new();
    loop {
        let list = serde_json::to_string(&tried).unwrap_or_else(|_| "[]".into());
        let Some((id, post)) = next(&list) else { break };
        let aside = db.int(FAIL_ASIDE_GET, &[Arg::I(id)]).unwrap_or(0) != 0;
        match attempt(post).await {
            Attempt::Moved => {
                round.progressed = true;
                tried.push(id);
                db.run(FAIL_DROP, &[Arg::I(id)]);
                for h in probing.drain(..) {
                    db.run(FAIL_SET_ASIDE, &[Arg::I(h)]);
                }
            }
            Attempt::Partial { progressed } => {
                round.progressed |= progressed;
                if progressed {
                    for h in probing.drain(..) {
                        db.run(FAIL_SET_ASIDE, &[Arg::I(h)]);
                    }
                }
                break;
            }
            Attempt::Held => {
                round.held = true;
                break;
            }
            Attempt::Failed => {
                let attempts = note_failure(db, id, now());
                tried.push(id);
                if aside {
                    continue; // it fails alone: the posts in order go on
                }
                if attempts >= ASIDE_AFTER {
                    probing.push(id);
                    continue; // try the one behind it
                }
                round.failed = true;
                break; // an ordinary failure — or the probe failed too: not one post's
            }
        }
    }
    round
}

#[cfg(test)]
#[path = "room_order_tests.rs"]
mod tests;
