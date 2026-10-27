//! The webhook queue's order — and the one update allowed out of it.
//!
//! Updates go to the webhook oldest first, and a failure holds the ones behind it: while the
//! program's endpoint takes what it is sent, it sees updates in `update_id` order. A failing
//! update climbs the outbox's ladder (5 s, 30 s, 2 min, 10 min, then hourly).
//!
//! **A poison update** (Stripe's, GitHub's and Shopify's webhooks retry each event on its own
//! once it fails; receivers order by id). When the head has failed [`ASIDE_AFTER`] times — about
//! 13 minutes of failing, its next try an hour away — the round tries the update behind it at
//! once, as a probe:
//! - **the probe is taken**: the endpoint works and refuses only the head. The head is SET ASIDE
//!   (`bot_update_aside`): retried on its own, hourly, until the 24 h drop, and the queue goes on
//!   without it. It may arrive after updates written later; a program orders by `update_id`.
//! - **the probe fails too**: the endpoint is down, not one update. Nothing is set aside, the
//!   round stops, and the queue backs off as a whole behind its head — the head's hourly try plus
//!   one probe, never a POST per waiting update. A probe that has itself failed [`ASIDE_AFTER`]
//!   times is passed over the same way, so two poison updates in a row are found once the second
//!   has failed its five.
//!
//! Only an update that fails while a later one is TAKEN is set aside; an endpoint that fails
//! everything sets nothing aside however long it stays down.
//!
//! The round is generic over its storage and its POST so the host tests run it whole
//! (`deliver_order_tests.rs`); the DO drives it from `deliver.rs`.

use super::deliver::{HOOK_DONE, HOOK_RETRY};
use super::outbox::retry_delay_ms;
use super::store::{Arg, Exec};
use serde::Deserialize;
use std::future::Future;

/// Failures after which an update's back-off is the hourly rung (`outbox::retry_delay_ms`): the
/// round then tries the update behind it.
pub(super) const ASIDE_AFTER: i64 = 5;
/// Webhook POSTs one round may make, the queue's and the set-aside ones' together.
pub(super) const WEBHOOK_BATCH: i64 = 10;
/// What a round spends besides its POSTs: the D1 read of whether the bot is on, and the
/// `program_seen_at` write when something was taken.
pub(super) const WEBHOOK_OVERHEAD: u32 = 2;

/// The POSTs a round may make when `budget` subrequests are its share of the tick: none when
/// that does not cover its overhead and one POST.
pub(super) fn webhook_posts(budget: u32) -> i64 {
    (budget.saturating_sub(WEBHOOK_OVERHEAD) as i64).min(WEBHOOK_BATCH)
}

pub(super) const TABLES: [&str; 1] = [
    // An update the program kept refusing while it took a later one: off the queue's order,
    // retried on its own ladder. Gone with its update.
    "CREATE TABLE IF NOT EXISTS bot_update_aside (update_id INTEGER PRIMARY KEY)",
];

/// Bind: update_id.
pub(super) const ASIDE_PUT: &str = "INSERT OR IGNORE INTO bot_update_aside (update_id) VALUES (?)";
/// Bind: update_id.
pub(super) const ASIDE_DROP: &str = "DELETE FROM bot_update_aside WHERE update_id = ?";
/// Set-aside updates due now, oldest first. Bind: now, limit.
pub(super) const ASIDE_DUE: &str = "SELECT u.update_id, u.json, u.attempts, u.next_at
      FROM bot_updates u JOIN bot_update_aside a ON a.update_id = u.update_id
     WHERE u.delivered_at IS NULL AND COALESCE(u.next_at, 0) <= ? ORDER BY u.update_id LIMIT ?";
/// Marks whose update was taken, polled, confirmed or expired.
pub(super) const ASIDE_ORPHANS: &str = "DELETE FROM bot_update_aside WHERE update_id NOT IN
      (SELECT update_id FROM bot_updates WHERE delivered_at IS NULL)";
pub(super) const ASIDE_COUNT: &str = "SELECT COUNT(*) FROM bot_update_aside";

/// One update the webhook owes (a `HOOK_DUE` / `ASIDE_DUE` row).
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Due {
    pub(super) update_id: i64,
    pub(super) json: String,
    pub(super) attempts: i64,
    #[serde(default)]
    pub(super) next_at: Option<i64>,
}

/// The update as the program reads it: its stored JSON with its `update_id`. `None` for a row
/// that is not JSON (it never is): it is dropped rather than retried.
fn with_id(row: &Due) -> Option<String> {
    let mut update: serde_json::Value = serde_json::from_str(&row.json).ok()?;
    update.as_object_mut()?.insert("update_id".into(), row.update_id.into());
    Some(update.to_string())
}

/// One round: the queue in order (`main`, oldest first), then the set-aside updates that are due
/// (`aside(limit)`). `post(update_id, update_json)` is one POST — true when the program took it.
/// At most `max_posts` POSTs (`webhook_posts`). Whether anything was taken, and the POSTs made.
pub(super) async fn hook_round<E, A, P, F>(
    db: &E,
    main: Vec<Due>,
    aside: A,
    max_posts: i64,
    now: impl Fn() -> i64,
    mut post: P,
) -> (bool, i64)
where
    E: Exec,
    A: FnOnce(i64) -> Vec<Due>,
    P: FnMut(i64, String) -> F,
    F: Future<Output = bool>,
{
    let mut took_any = false;
    let mut posts = 0;
    // Heads that failed their ASIDE_AFTER-th time in this round, waiting on the probe behind
    // them: set aside if it is taken, left where they are if the round ends first.
    let mut probing: Vec<i64> = Vec::new();
    for row in main {
        let t = now();
        if row.next_at.is_some_and(|n| n > t) || posts >= max_posts {
            break; // the head waits on its back-off (the queue behind it with it), or the purse is spent
        }
        let Some(json) = with_id(&row) else {
            db.run(HOOK_DONE, &[Arg::I(row.update_id)]);
            continue;
        };
        posts += 1;
        if post(row.update_id, json).await {
            db.run(HOOK_DONE, &[Arg::I(row.update_id)]);
            took_any = true;
            // A later update was taken: what failed before it is the update, not the endpoint.
            for id in probing.drain(..) {
                db.run(ASIDE_PUT, &[Arg::I(id)]);
            }
            continue;
        }
        db.run(HOOK_RETRY, &[Arg::I(t + retry_delay_ms(row.attempts)), Arg::I(row.update_id)]);
        if row.attempts + 1 >= ASIDE_AFTER {
            probing.push(row.update_id);
            continue; // try the one behind it
        }
        break; // an ordinary failure — or the probe failed too: the endpoint, not one update
    }
    // Each set-aside update on its own ladder, in what the queue left of the round's POSTs.
    let left = max_posts - posts;
    let set_aside = if left > 0 { aside(left) } else { Vec::new() };
    for row in set_aside {
        let t = now();
        let Some(json) = with_id(&row) else {
            db.run(HOOK_DONE, &[Arg::I(row.update_id)]);
            continue;
        };
        posts += 1;
        if post(row.update_id, json).await {
            db.run(HOOK_DONE, &[Arg::I(row.update_id)]);
            db.run(ASIDE_DROP, &[Arg::I(row.update_id)]);
            took_any = true;
        } else {
            db.run(HOOK_RETRY, &[Arg::I(t + retry_delay_ms(row.attempts)), Arg::I(row.update_id)]);
        }
    }
    (took_any, posts)
}

#[cfg(test)]
#[path = "deliver_order_tests.rs"]
mod tests;
