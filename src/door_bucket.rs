//! The door's miss counter — what bounds guessing an invite code, at redeem and on the invite
//! page alike (migration 0047).
//!
//! **Reserve before, refund on a hit.** A request that is about to look an invite up first takes a
//! miss from its address's budget in ONE statement ([`RESERVE_SQL`]): the row is created, reset if
//! its window has passed, or incremented only while under [`DOOR_MISS_LIMIT`] — and `RETURNING`
//! says whether it was. Only then does the lookup run. A lookup that finds a usable invite gives
//! the miss back ([`REFUND_SQL`]). So however many requests one address has in flight, at most
//! `DOOR_MISS_LIMIT` of them get past the reservation in a window, and every one that did not find
//! an invite stays counted.
//!
//! **Why D1 and not the KV limiter.** KV is a read-modify-write over an eventually consistent store:
//! concurrent writes overwrite each other, reads are edge-cached, and every failure is read as
//! "allow". D1 executes each statement on its single primary, so the conditional increment is
//! atomic — and it needs no binding a deployment might lack: the table arrives with the other
//! self-applied migrations. One write per guess, plus one more on a hit.
//!
//! **Fails CLOSED.** If the counter cannot be written the door is refused for a minute. The KV
//! limiter fails open on purpose (losing a limit beats losing messaging); here the limit IS the
//! security of a 39-bit code, and D1 being down closes the door anyway.
//!
//! A fixed window rather than a sliding one: at the boundary an address can spend two windows'
//! misses back to back, which is still a bound (60 per five minutes at most).

use serde::Deserialize;
use worker::*;

use crate::d1util::{d1_int, d1_text};
pub(crate) use crate::ratelimit::{DOOR_MISS_LIMIT, DOOR_WINDOW_SECS};

/// Take one miss. Binds: `?1` bucket, `?2` now, `?3` window length, `?4` limit. Returns the row's
/// `window_start` when the miss was taken, nothing when the budget is spent.
pub(crate) const RESERVE_SQL: &str = "INSERT INTO door_misses (bucket, window_start, misses)
     VALUES (?1, ?2, 1)
     ON CONFLICT(bucket) DO UPDATE SET
       window_start = CASE WHEN door_misses.window_start <= ?2 - ?3
                           THEN ?2 ELSE door_misses.window_start END,
       misses = CASE WHEN door_misses.window_start <= ?2 - ?3
                     THEN 1 ELSE door_misses.misses + 1 END
     WHERE door_misses.window_start <= ?2 - ?3 OR door_misses.misses < ?4
     RETURNING window_start";

/// When the spent window began, for `Retry-After`. Binds: `?1` bucket.
pub(crate) const WINDOW_START_SQL: &str = "SELECT window_start FROM door_misses WHERE bucket = ?1";

/// Give a miss back — only in the window it was taken in. Binds: `?1` bucket, `?2` window_start.
pub(crate) const REFUND_SQL: &str = "UPDATE door_misses SET misses = misses - 1
     WHERE bucket = ?1 AND window_start = ?2 AND misses > 0";

/// The daily sweep: rows whose window is over carry nothing. Binds: `?1` now, `?2` window length.
pub(crate) const SWEEP_SQL: &str = "DELETE FROM door_misses WHERE window_start <= ?1 - ?2";

/// How long a refusal tells the caller to wait when the counter itself could not be used.
const UNAVAILABLE_RETRY_S: u64 = 60;

/// A miss taken from an address's budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reservation {
    pub(crate) bucket: String,
    pub(crate) window_start: i64,
}

/// What [`reserve`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reserved {
    Taken(Reservation),
    Refused { retry_after_s: u64 },
}

/// Seconds until a window that began at `window_start` is over — at least one.
pub(crate) fn retry_after(window_start: i64, now: i64) -> u64 {
    (window_start + DOOR_WINDOW_SECS as i64 - now).max(1) as u64
}

/// Take one miss from `bucket`'s budget.
pub(crate) async fn reserve(db: &D1Database, bucket: &str, now: i64) -> Reserved {
    #[derive(Deserialize)]
    struct Row {
        window_start: i64,
    }
    let closed = Reserved::Refused {
        retry_after_s: UNAVAILABLE_RETRY_S,
    };
    let taken: Option<Row> = match db.prepare(RESERVE_SQL).bind(&[
        d1_text(bucket),
        d1_int(now),
        d1_int(DOOR_WINDOW_SECS as i64),
        d1_int(DOOR_MISS_LIMIT as i64),
    ]) {
        Ok(stmt) => match stmt.first(None).await {
            Ok(row) => row,
            Err(e) => {
                console_log!("door bucket: reserve failed, door closed: {e}");
                return closed;
            }
        },
        Err(_) => return closed,
    };
    if let Some(row) = taken {
        return Reserved::Taken(Reservation {
            bucket: bucket.to_string(),
            window_start: row.window_start,
        });
    }
    let spent: Option<Row> = match db.prepare(WINDOW_START_SQL).bind(&[d1_text(bucket)]) {
        Ok(stmt) => stmt.first(None).await.ok().flatten(),
        Err(_) => None,
    };
    Reserved::Refused {
        retry_after_s: spent.map_or(UNAVAILABLE_RETRY_S, |r| retry_after(r.window_start, now)),
    }
}

/// Give a reserved miss back: the lookup found a usable invite. Best effort — a refund that fails
/// leaves the address one miss poorer, never richer.
pub(crate) async fn refund(db: &D1Database, reservation: &Reservation) {
    if let Ok(stmt) = db.prepare(REFUND_SQL).bind(&[
        d1_text(&reservation.bucket),
        d1_int(reservation.window_start),
    ]) {
        let _ = stmt.run().await;
    }
}

/// Forget windows that are over (daily maintenance).
pub(crate) async fn sweep(db: &D1Database, now: i64) -> Result<()> {
    db.prepare(SWEEP_SQL)
        .bind(&[d1_int(now), d1_int(DOOR_WINDOW_SECS as i64)])?
        .run()
        .await?;
    Ok(())
}

#[cfg(test)]
#[path = "door_bucket_tests.rs"]
mod tests;
