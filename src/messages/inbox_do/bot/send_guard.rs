//! What a program's sends are held to, counted in the bot's own inbox (docs/BOTS_BUILD.md §2.5).
//!
//! **The rate.** At most [`SENDS_PER_MINUTE`] `sendMessage`s a minute per bot, and at most
//! [`SENDS_PER_CHAT_PER_MINUTE`] of them into one chat (a member 1:1, or a room), over a sliding
//! minute. A refusal is `bot/rate-limited` (429) with `retry_after`: the seconds until the oldest
//! send in the way leaves the window.
//!
//! Why here and not in KV, where it was until 2026-10-26 (`ratelimit::check_rate_limit_env`):
//! - KV is the WHOLE server's limiter, and it wrote one KV put per send. Cloudflare's free plan
//!   allows 1,000 puts a day for the namespace, so one busy bot spent the day's budget in under
//!   seventeen minutes, after which every limit on the server — sends, the door, the fan-out
//!   guard — fails open for the rest of the day (`ratelimit.rs`, the 2026-06-27 wedge).
//! - KV is eventually consistent: parallel sends read the same old count, so it never bounded a
//!   program that sends concurrently.
//!
//! The inbox is one single-threaded object with its own synchronous SQLite: the count and the
//! slot it takes are one block with no `await` between them, so the limit is exact, and costs
//! nothing outside this object.
//!
//! **The per-chat limit** is what keeps one member from spending the bot's whole minute: a member
//! who writes 300 messages a minute (the relay's own per-user ceiling) to a bot whose program
//! answers each one used to take all 60 of the bot's sends, and everybody else's answers waited.

use super::store::{Arg, Exec};
use super::*;

/// Sends one bot may make in a minute.
pub(super) const SENDS_PER_MINUTE: i64 = 60;
/// Sends one bot may make into one chat in a minute.
pub(super) const SENDS_PER_CHAT_PER_MINUTE: i64 = 30;
/// The sliding window.
pub(super) const WINDOW_MS: i64 = 60_000;

pub(super) const TABLES: [&str; 2] = [
    // One row per admitted send, for a minute. `chat` is `u:<user_id>` or `r:<room_id>`.
    "CREATE TABLE IF NOT EXISTS bot_send_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, chat TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_bot_send_log_chat ON bot_send_log(chat, at)",
];

/// Bind: cutoff (now − window). A send at the cutoff has left the window.
pub(super) const SEND_LOG_PRUNE: &str = "DELETE FROM bot_send_log WHERE at <= ?";
pub(super) const SEND_LOG_ALL: &str = "SELECT COUNT(*) FROM bot_send_log";
pub(super) const SEND_LOG_ALL_OLDEST: &str = "SELECT COALESCE(MIN(at), 0) FROM bot_send_log";
/// Bind: chat.
pub(super) const SEND_LOG_CHAT: &str = "SELECT COUNT(*) FROM bot_send_log WHERE chat = ?";
/// Bind: chat.
pub(super) const SEND_LOG_CHAT_OLDEST: &str =
    "SELECT COALESCE(MIN(at), 0) FROM bot_send_log WHERE chat = ?";
/// Bind: at, chat.
pub(super) const SEND_LOG_PUT: &str = "INSERT INTO bot_send_log (at, chat) VALUES (?, ?) RETURNING id";
/// A send that took a slot and then did not happen gives it back. Bind: id.
pub(super) const SEND_LOG_REFUND: &str = "DELETE FROM bot_send_log WHERE id = ?";

/// One window's state: sends in it, and when the oldest of them was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Window {
    pub(super) count: i64,
    pub(super) oldest_ms: i64,
}

/// Admit one more send, or the seconds until one fits: until the oldest send of the window that
/// is full leaves it, and at least one (`Retry-After: 0` reads as "now", which was just refused).
pub(super) fn admit(all: Window, chat: Window, now_ms: i64) -> std::result::Result<(), u64> {
    let wait = |w: Window, max: i64| {
        (w.count >= max).then(|| ((w.oldest_ms + WINDOW_MS - now_ms).max(0) as u64).div_ceil(1000).max(1))
    };
    match (wait(all, SENDS_PER_MINUTE), wait(chat, SENDS_PER_CHAT_PER_MINUTE)) {
        (None, None) => Ok(()),
        (a, c) => Err(a.unwrap_or(0).max(c.unwrap_or(0))),
    }
}

/// The key a chat is counted under.
pub(super) fn chat_key(to_user: Option<&str>, room: Option<&str>) -> String {
    match (to_user, room) {
        (_, Some(r)) => format!("r:{r}"),
        (Some(u), None) => format!("u:{u}"),
        (None, None) => "u:".into(),
    }
}

/// Count and take a slot, synchronously: `Ok(slot id)` to give back with [`refund`] if the send
/// does not happen, or `Err(retry_after_s)`.
pub(super) fn take_slot<E: Exec>(db: &E, chat: &str, now_ms: i64) -> std::result::Result<i64, u64> {
    db.run(SEND_LOG_PRUNE, &[Arg::I(now_ms - WINDOW_MS)]);
    let window = |count: &str, oldest: &str, args: &[Arg<'_>]| Window {
        count: db.int(count, args).unwrap_or(0),
        oldest_ms: db.int(oldest, args).unwrap_or(0),
    };
    let all = window(SEND_LOG_ALL, SEND_LOG_ALL_OLDEST, &[]);
    let one = window(SEND_LOG_CHAT, SEND_LOG_CHAT_OLDEST, &[Arg::T(chat)]);
    admit(all, one, now_ms)?;
    Ok(db.int(SEND_LOG_PUT, &[Arg::I(now_ms), Arg::T(chat)]).unwrap_or(0))
}

pub(super) fn refund<E: Exec>(db: &E, slot: i64) {
    db.run(SEND_LOG_REFUND, &[Arg::I(slot)]);
}

/// `bot/rate-limited`, with `retry_after` in the body and in `Retry-After` (`bots::api`'s one
/// builder, which the call budget and the wrong-key brake answer with too).
pub(crate) fn rate_limited(retry_after_s: u64) -> Result<Response> {
    crate::bots::api::rate_limited(retry_after_s)
}

#[cfg(test)]
#[path = "send_guard_tests.rs"]
mod tests;
