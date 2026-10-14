//! The order the invite page asks things in, behind a seam so `route_tests.rs` runs it against an
//! in-memory counter and a fake lookup: what is counted, in which bucket, and what is answered
//! before the database is ever asked.

use worker::Result;

use super::lookup::{describe, DescribeRow, InviteView, LookupKey};
use crate::door_bucket::{Reservation, Reserved};
use crate::ratelimit::{door_miss_key, Admission, DOOR_IP_CEILING, DOOR_WINDOW_SECS};

/// The things the page needs from the outside world.
pub(crate) trait DoorPort {
    /// Take one miss from `bucket`'s budget, atomically (`door_bucket::reserve`).
    async fn reserve_miss(&self, bucket: &str, now: i64) -> Reserved;
    /// Give a reserved miss back (`door_bucket::refund`).
    async fn refund_miss(&self, reservation: &Reservation);
    /// Count one hit in `key`'s window, if it fits — the soft KV limiter (`ratelimit::admit_env`).
    async fn admit(&self, key: &str, max_hits: usize, window_s: u64) -> Admission;
    /// The one statement (`lookup::lookup`).
    async fn lookup(&self, key: &LookupKey, now: i64) -> Result<DescribeRow>;
}

/// What the page answers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    Usable(InviteView),
    /// Unknown, spent, expired, withdrawn, full or the founding invite — one answer for all.
    Unavailable,
    /// This address asked too often; come back in `retry_after_s`.
    Refused {
        retry_after_s: u64,
    },
}

/// The per-address ceiling's bucket: plain asking, hits and misses alike.
pub(crate) fn ceiling_key(ip: &str) -> String {
    format!("invite:page:ip:{ip}")
}

/// Ask, in order:
///
/// 1. The page's own per-address ceiling (soft, KV) — bounds plain reloading.
/// 2. A miss RESERVED from the address's door budget — SHARED with redeem ([`door_miss_key`]) and
///    taken in one atomic statement, so however many requests are in flight at most the budget's
///    worth reach the lookup, and this door adds no guesses to redeem's.
/// 3. The lookup. A usable invite gives the miss back; anything else keeps it.
///
/// `limited` is false on a non-prod relay, which (as redeem) runs unlimited.
pub(crate) async fn answer_with<P: DoorPort>(
    port: &P,
    ip: &str,
    key: &LookupKey,
    limited: bool,
    now: i64,
) -> Result<Answer> {
    let mut reservation = None;
    if limited {
        if let Admission::Refused { retry_after_s } = port
            .admit(&ceiling_key(ip), DOOR_IP_CEILING, DOOR_WINDOW_SECS)
            .await
        {
            return Ok(Answer::Refused { retry_after_s });
        }
        match port.reserve_miss(&door_miss_key(ip), now).await {
            Reserved::Taken(r) => reservation = Some(r),
            Reserved::Refused { retry_after_s } => return Ok(Answer::Refused { retry_after_s }),
        }
    }
    let row = port.lookup(key, now).await?;
    match describe(&row, now) {
        Some(view) => {
            if let Some(r) = &reservation {
                port.refund_miss(r).await;
            }
            Ok(Answer::Usable(view))
        }
        None => Ok(Answer::Unavailable),
    }
}
