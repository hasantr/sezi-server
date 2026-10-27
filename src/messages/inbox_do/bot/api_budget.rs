//! The bot's API call budget, counted in its own inbox (docs/BOTS_BUILD.md §2.5).
//!
//! A program holding the key could call `/bot/v1/*` in a loop: every call costs the server a D1
//! read (the key) and, for most methods, more. The send limits (`send_guard.rs`) bound only
//! `sendMessage`. On Cloudflare an edge rate-limiting rule can bound the rest, but a self-hosted
//! relay (bare workerd) has no edge, so the bound lives here: a token bucket of
//! [`BURST`] calls, refilled at [`PER_SECOND`] a second — 300 a minute sustained — for EVERY
//! method together. `getUpdates` counts once per call however long it waits.
//!
//! Why these numbers: a long-polling program makes about 2 calls a minute; one that answers every
//! message makes at most 60 sends a minute (the send limit) plus its polls; 300 leaves a working
//! program five times that. The burst equals the minute's send limit, so a program that sends its
//! 60 at once is held by the send limit, which says which chat, not by this.
//!
//! The bucket is two numbers in `bot_kv`, read and written in one synchronous block with no
//! `await`, so the count is exact; it costs the call one request to this inbox and no D1 write.
//! A refusal is `bot/rate-limited` (429) with `retry_after`, as the send limits answer.

use super::*;

/// Calls a bot may make at once.
pub(super) const BURST: i64 = 60;
/// Calls the bucket gains a second (300 a minute).
pub(super) const PER_SECOND: i64 = 5;
/// `bot_kv`: the bucket, `"<milli-calls>:<at ms>"`.
pub(super) const KV_BUCKET: &str = "api_bucket";

/// The bucket: what is in it (thousandths of a call) as of `at_ms`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Bucket {
    pub(super) milli: i64,
    pub(super) at_ms: i64,
}

impl Bucket {
    /// The stored bucket; `None` (a full one) when there is none or it does not read.
    pub(super) fn parse(raw: Option<&str>) -> Option<Bucket> {
        let (milli, at) = raw?.split_once(':')?;
        let (milli, at_ms) = (milli.parse::<i64>().ok()?, at.parse::<i64>().ok()?);
        (milli >= 0).then_some(Bucket { milli, at_ms })
    }

    pub(super) fn to_kv(self) -> String {
        format!("{}:{}", self.milli, self.at_ms)
    }
}

/// Take one call from the bucket at `now_ms`: the bucket after, and `Err(retry_after_s)` when it
/// had less than one call in it (it is then left as it was, refilled).
pub(super) fn take(bucket: Option<Bucket>, now_ms: i64) -> (Bucket, std::result::Result<(), u64>) {
    const ONE: i64 = 1_000;
    let full = Bucket { milli: BURST * ONE, at_ms: now_ms };
    let b = bucket.unwrap_or(full);
    // `PER_SECOND` calls a second is `PER_SECOND` thousandths a millisecond. A clock that went
    // back refills nothing.
    let gained = (now_ms - b.at_ms).max(0).saturating_mul(PER_SECOND);
    let milli = b.milli.saturating_add(gained).min(BURST * ONE);
    let at_ms = now_ms.max(b.at_ms);
    if milli < ONE {
        let wait_ms = (ONE - milli + PER_SECOND - 1) / PER_SECOND;
        return (Bucket { milli, at_ms }, Err((wait_ms as u64).div_ceil(1000).max(1)));
    }
    (Bucket { milli: milli - ONE, at_ms }, Ok(()))
}

impl UserInbox {
    /// `/bot/budget`: one call of the program's, or `bot/rate-limited`.
    pub(super) fn bot_take_call(&self) -> Result<Response> {
        let store = self.bot_store();
        let now = crate::utils::now_ms() as i64;
        let (after, verdict) = take(Bucket::parse(store.kv_get(KV_BUCKET).as_deref()), now);
        store.kv_put(KV_BUCKET, &after.to_kv());
        match verdict {
            Ok(()) => Response::empty().map(|r| r.with_status(204)),
            Err(retry_after_s) => super::send_guard::rate_limited(retry_after_s),
        }
    }
}

#[cfg(test)]
#[path = "api_budget_tests.rs"]
mod tests;
