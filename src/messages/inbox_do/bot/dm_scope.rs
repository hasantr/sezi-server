//! Whom a program bot may write to 1:1 (review 2026-11 H12, decision D4).
//!
//! D4, as Hasan took it on 2026-11-06: "Reply-only by default (last N days); 'write to anyone'
//! is a scope the owner grants; a strict DM policy and a revoked grant are always honoured."
//!
//! - **Reply-only, the default.** A program's `sendMessage` to a member goes only when that
//!   member wrote to the bot 1:1 — a text or a file — within [`REPLY_WINDOW_MS`]; otherwise
//!   `bot/reply-only` (403). Until 2026-11-18 a bot could write to every human on the server, so
//!   a leaked key was a way to message everyone ("send me your six-digit code"), each a waking
//!   push. A room call (`@bot`) does not open the member's 1:1: its answer goes to the room.
//! - **"Write to anyone"**, the owner's grant ([`Scope::Anyone`], `PATCH /admin/bots/:id
//!   {dm_scope}`), lifts the window — for a program that sends reminders or announcements.
//! - The strict DM policy and a member who removed the bot are the Worker's (`bots/api.rs`,
//!   `send_target`): they hold whatever the scope.
//!
//! Who wrote when is kept in `bot_writers` (who and when, never what), one row per member,
//! forgotten after the window. A bot's inbox from before this module has no rows, so a member's
//! 1:1 text the program was handed in the last 7 days (`bot_seen`, whose room calls carry a `/`
//! in their key) counts too: a running program does not lose its conversations at the update.
//! Built-in bots answer inside the inbox, not through `sendMessage`, and are not held here.

use super::store::{Arg, Exec};

/// How long a member's last 1:1 message lets the program write back.
pub(super) const REPLY_WINDOW_MS: i64 = 30 * 24 * 3600 * 1000;

/// `bot_kv`: the owner's grant. Absent = reply-only.
pub(super) const KV_SCOPE: &str = "dm_scope";

pub(super) const TABLES: [&str; 1] =
    ["CREATE TABLE IF NOT EXISTS bot_writers (user_id TEXT PRIMARY KEY, at INTEGER NOT NULL)"];

/// Bind: user, at.
pub(super) const WRITER_PUT: &str = "INSERT INTO bot_writers (user_id, at) VALUES (?, ?)
      ON CONFLICT(user_id) DO UPDATE SET at = MAX(at, excluded.at)";
/// Bind: cutoff.
pub(super) const WRITER_EXPIRE: &str = "DELETE FROM bot_writers WHERE at < ?";
/// Did this member write 1:1 since the cutoff? Bind: user, cutoff, user, cutoff.
pub(super) const WROTE_SINCE: &str = "SELECT EXISTS(SELECT 1 FROM bot_writers WHERE user_id = ? AND at >= ?)
      OR EXISTS(SELECT 1 FROM bot_seen WHERE from_user = ? AND at >= ? AND instr(msg_uid, '/') = 0)";

/// The owner's grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    /// Only to a member who wrote within the window.
    Reply,
    /// To any member the Worker lets through.
    Anyone,
}

impl Scope {
    pub(super) fn parse(s: &str) -> Option<Scope> {
        match s {
            "reply" => Some(Scope::Reply),
            "anyone" => Some(Scope::Anyone),
            _ => None,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Scope::Reply => "reply",
            Scope::Anyone => "anyone",
        }
    }

    /// The stored grant; anything unknown reads as the narrow one.
    pub(super) fn stored(v: Option<&str>) -> Scope {
        v.and_then(Scope::parse).unwrap_or(Scope::Reply)
    }
}

/// A member wrote to the bot 1:1. Synchronous, in the frame's block.
pub(super) fn note_writer(db: &impl Exec, user: &str, now_ms: i64) {
    db.run(WRITER_PUT, &[Arg::T(user), Arg::I(now_ms)]);
}

/// May the program write to `user` now? A read that fails refuses (fails closed).
pub(super) fn may_write(db: &impl Exec, scope: Scope, user: &str, now_ms: i64) -> bool {
    if scope == Scope::Anyone {
        return true;
    }
    let cutoff = now_ms - REPLY_WINDOW_MS;
    db.int(WROTE_SINCE, &[Arg::T(user), Arg::I(cutoff), Arg::T(user), Arg::I(cutoff)]).unwrap_or(0) == 1
}

#[cfg(test)]
#[path = "dm_scope_tests.rs"]
mod tests;
