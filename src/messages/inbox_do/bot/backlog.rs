//! What one member may leave waiting in a program bot's queue (docs/BOTS_BUILD.md §2.5).
//!
//! A member can push about 300 messages a minute at a bot (the relay's per-user limit, which fails
//! open). Every one became an update, and the program is handed updates in order: one member's
//! flood delayed everybody else's message behind it, and grew the inbox's storage for the 24 h
//! the updates are kept. Now:
//!
//! - **[`PER_SENDER`] updates waiting per member.** "Waiting" is not yet handed to the program
//!   (`bot_update_src`, whose row goes when the program takes the update), counted exactly in this
//!   inbox's SQLite in the frame's own synchronous block. 100 is far past what a person types
//!   while a working program keeps up — a program polling every few seconds holds a handful — and
//!   a third of the relay's minute: a flood fills it in 20 seconds and then costs nothing.
//! - **[`PER_BOT`] updates stored per bot**, everybody's together, handed out or not: the storage
//!   backstop for a program that is gone. Twenty members at their cap; at the 64 KiB an envelope
//!   may carry that is ~128 MiB at the very worst, ~2 MiB for ordinary texts.
//!
//! Past either, the member's message is not queued and the program never sees it. The frame is
//! still acked as read by the bot's inbox — its `delivered` tick is true, the relay has it — but
//! no `forward-read` follows, so the member's client never shows "the program has it". Failing
//! the frame instead would read as an Olm failure and start a re-pair. The member is TOLD, by
//! the bot itself, once per [`NOTICE_EVERY_MS`] — not per message — in the room call's language
//! when it said one, else in both (a 1:1 text carries no language).
//!
//! A built-in bot keeps its own caps (`builtin_store::DAILY_CALLS`, `DAILY_ROWS`); this is for a
//! program bot, 1:1 and room calls alike.

use super::builtin_copy::{line, Line};
use super::store::{Arg, Exec};
use super::*;
use crate::bots::builtin_rules::Lang;

/// Updates one member may have waiting for the program.
pub(super) const PER_SENDER: i64 = 100;
/// Updates one bot may hold, everybody's together.
pub(super) const PER_BOT: i64 = 2_000;
/// A refused member is told at most this often.
pub(super) const NOTICE_EVERY_MS: i64 = 10 * 60_000;
/// Members told in one tick; one told later fits the tick's purse (`builtin_policy`).
pub(super) const NOTICES_PER_TICK: usize = 3;

pub(super) const TABLES: [&str; 2] = [
    "CREATE INDEX IF NOT EXISTS idx_bot_update_src_from ON bot_update_src(from_user)",
    // When each refused member was last told.
    "CREATE TABLE IF NOT EXISTS bot_backlog_notice (user_id TEXT PRIMARY KEY, at INTEGER NOT NULL)",
];

/// Bind: from.
pub(super) const WAITING_FROM: &str = "SELECT COUNT(*) FROM bot_update_src WHERE from_user = ?";
pub(super) const STORED: &str = "SELECT COUNT(*) FROM bot_updates";
/// Tell the member now, unless they were told within the window: a row back when they are to
/// be told. Bind: user, now, cutoff (now − window).
pub(super) const NOTICE_TAKE: &str = "INSERT INTO bot_backlog_notice (user_id, at) VALUES (?, ?)
      ON CONFLICT(user_id) DO UPDATE SET at = excluded.at WHERE bot_backlog_notice.at <= ?
      RETURNING user_id";
/// A notice that could not be sent this tick: the next refusal tells them. Bind: user.
pub(super) const NOTICE_FORGET: &str = "DELETE FROM bot_backlog_notice WHERE user_id = ?";
/// Bind: cutoff.
pub(super) const NOTICE_EXPIRE: &str = "DELETE FROM bot_backlog_notice WHERE at <= ?";

/// What becomes of one member's message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Queue,
    /// Not queued; `tell` when this is the refusal the member hears about.
    Refused { code: &'static str, tell: bool },
}

/// Judge `from`'s next update, and take the notice when it is refused and `may_tell`.
/// Synchronous: it runs inside the frame's block.
pub(super) fn admit<E: Exec>(db: &E, from: &str, now: i64, may_tell: bool) -> Verdict {
    let code = if db.int(STORED, &[]).unwrap_or(0) >= PER_BOT {
        "bot/queue-full"
    } else if db.int(WAITING_FROM, &[Arg::T(from)]).unwrap_or(0) >= PER_SENDER {
        "bot/sender-backlog"
    } else {
        return Verdict::Queue;
    };
    let tell = may_tell
        && !db
            .texts(NOTICE_TAKE, &[Arg::T(from), Arg::I(now), Arg::I(now - NOTICE_EVERY_MS)])
            .is_empty();
    Verdict::Refused { code, tell }
}

/// The member's language, from a room call's `lang` (`tr`, `en-GB`…); `None` when it said none
/// this relay speaks.
pub(super) fn lang_of(tag: Option<&str>) -> Option<Lang> {
    let primary = tag?.split(['-', '_']).next()?.to_ascii_lowercase();
    match primary.as_str() {
        "tr" => Some(Lang::Tr),
        "en" => Some(Lang::En),
        _ => None,
    }
}

/// What the bot says to a refused member: in their language, or in both when it is not known.
pub(super) fn notice(lang: Option<Lang>) -> String {
    match lang {
        Some(l) => line(l, Line::ProgramBusy).to_string(),
        None => format!("{}\n\n{}", line(Lang::Tr, Line::ProgramBusy), line(Lang::En, Line::ProgramBusy)),
    }
}

/// [`admit`] for a frame being opened: logs a refusal by its code and, when this refusal is the
/// one the member hears about, notes them in `busy` for the tick to tell after the block.
pub(super) fn admit_member_update<E: Exec>(
    db: &E,
    from: &str,
    lang: Option<&str>,
    now: i64,
    busy: &mut std::collections::BTreeMap<String, Option<Lang>>,
) -> bool {
    match admit(db, from, now, busy.len() < NOTICES_PER_TICK) {
        Verdict::Queue => true,
        Verdict::Refused { code, tell } => {
            console_log!("[bot] member update not queued: {code}");
            if tell {
                busy.insert(from.to_string(), lang_of(lang));
            }
            false
        }
    }
}

impl UserInbox {
    /// Tell the members refused this tick, while the tick's purse allows; what it spent.
    pub(super) async fn bot_say_busy(&self, ctx: &BotCtx, busy: &std::collections::BTreeMap<String, Option<Lang>>) -> u32 {
        let mut spent = 0u32;
        for (user, lang) in busy {
            if !super::builtin_policy::fits(spent, super::builtin_policy::SAY_BASE) {
                self.bot_store().db.run(NOTICE_FORGET, &[Arg::T(user)]);
                continue;
            }
            match self.bot_send_text_queued(ctx, user, &notice(*lang)).await {
                Ok(cost) => spent += cost,
                Err(_) => {
                    spent += 1;
                    console_log!("[bot] backlog notice could not be queued");
                }
            }
        }
        spent
    }
}

#[cfg(test)]
#[path = "backlog_tests.rs"]
mod tests;
