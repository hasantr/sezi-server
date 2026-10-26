//! The built-in runner's decisions, kept pure so they are tested as they are: what a round may
//! spend, what a member's next message does to a pending row, how a proposal is shown, and when
//! a change of configuration makes what was owed to the old sheet meaningless.

use super::builtin_ai::{Role, Turn};
use super::builtin_copy::{line, Line};
use super::builtin_sheet::{self, Row};
use super::builtin_store as bs;
use crate::bots::builtin_rules::{Config, Lang};

// ── Budget ──────────────────────────────────────────────────────────────────────────────────
//
// The tick's purse is the 50 subrequests `messages/budget.rs` assumes. The built-in round and the
// outbox drain after it share `TICK_PURSE` of them; the rest is the tick's fixed work (the
// senders' prefetch, the key pool's top-up). A round item may START only if its base worst case
// fits in `ROUND_BUDGET`. The one cost a base cannot know is the key claims of a reply to a
// member device the bot has no session with yet (at most `MAX_CLAIMS_COST`); it can overshoot
// the round's budget once, after which no item starts, and the drain is handed what is left.

/// What the round commits to before an item starts.
pub(super) const ROUND_BUDGET: u32 = 10;
/// The round and the outbox drain together.
pub(super) const TICK_PURSE: u32 = 45;
/// The outbox drain's own ceiling (`outbox::DRAIN_BUDGET`).
pub(super) const DRAIN_CEILING: u32 = 35;
/// Key claims one reply can take beyond its device read: six D1 calls for each of a member's up
/// to five devices (`keys/bundle_slot.rs`, `devices::handlers::MAX_DEVICES`).
pub(super) const MAX_CLAIMS_COST: u32 = 6 * crate::devices::handlers::MAX_DEVICES as u32;
// The worst a round can end on — its last item started with the base just fitting, then its
// one reply needed every claim there is — still leaves the drain a share. Checked when it builds.
const _: () = assert!(ROUND_BUDGET + MAX_CLAIMS_COST < TICK_PURSE);

/// A line the bot says: the member's device read (claims come on top).
pub(super) const SAY_BASE: u32 = 1;
/// A model call and the reply's device read.
pub(super) const AI_BASE: u32 = 1 + SAY_BASE;
/// A sheet write at its worst (every hop, every GET re-asked) and the line said about it.
pub(super) const JOB_BASE: u32 = builtin_sheet::MAX_SPEND + SAY_BASE;

/// May an item whose base worst case is `base` start at `spent`?
pub(super) fn fits(spent: u32, base: u32) -> bool {
    spent + base <= ROUND_BUDGET
}

/// What the outbox drain may spend after a round that spent `round_spent`.
pub(super) fn drain_budget(round_spent: u32) -> u32 {
    TICK_PURSE.saturating_sub(round_spent).min(DRAIN_CEILING)
}

// ── The gate ────────────────────────────────────────────────────────────────────────────────

/// While the bot is off, the runner looks again this often (or at once on `/bot/wake`).
pub(super) const HOLD_MS: i64 = 10 * 60 * 1000;
/// When D1 did not answer whether the bot is on, the runner asks again after this.
pub(super) const D1_RETRY_MS: i64 = 30_000;

/// Whether a round runs, from D1's `(name, enabled)` of the bot.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Gate {
    /// On: run, under this name.
    Run(String),
    /// Off, deleted, or D1 silent: take NOTHING — no update is answered or taken, so a message
    /// the bot holds never gets its `forward-read` (the app shows it delivered, not read).
    Hold(i64),
}

pub(super) fn round_gate(row: Result<Option<(String, bool)>, ()>) -> Gate {
    match row {
        Ok(Some((name, true))) => Gate::Run(name),
        Ok(_) => Gate::Hold(HOLD_MS),
        Err(()) => Gate::Hold(D1_RETRY_MS),
    }
}

// ── Proposals ───────────────────────────────────────────────────────────────────────────────

/// What a member's message does to the row waiting for their yes. The caller drops the stored
/// proposal whatever this answers: the next message settles it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProposalStep {
    /// No live proposal (none, expired, or the bot no longer writes rows): an ordinary message.
    Ordinary,
    /// A yes or no that came after the wait.
    Lapsed,
    Confirm,
    Discard,
}

/// `proposal_at` = when the waiting row was proposed, if one is stored.
pub(super) fn proposal_step(proposal_at: Option<i64>, writes_sheet: bool, text: &str, now: i64) -> ProposalStep {
    let Some(at) = proposal_at.filter(|&at| writes_sheet && now - at < bs::PROPOSAL_KEEP_MS) else {
        return ProposalStep::Ordinary;
    };
    match super::builtin_ai::yes_or_no(text) {
        None => ProposalStep::Ordinary,
        Some(_) if bs::lapsed(at, now) => ProposalStep::Lapsed,
        Some(true) => ProposalStep::Confirm,
        Some(false) => ProposalStep::Discard,
    }
}

/// The answer, then the WHOLE row it proposes, then how to answer — within `max` characters.
/// The model's prose is what gets shortened; a row that cannot be shown whole is not proposed
/// (`None`): a member never confirms cells they were not shown.
pub(super) fn confirm_text(lang: Lang, shown: &str, row: &Row, max: usize) -> Option<String> {
    let mut tail = String::from(line(lang, Line::ConfirmRow));
    for (k, v) in &row.0 {
        tail.push_str(&format!("\n• {k}: {v}"));
    }
    tail.push_str("\n\n");
    tail.push_str(line(lang, Line::ConfirmHint));
    let room = max.checked_sub(tail.chars().count())?;
    let prose = shown.trim();
    // "…" and the blank line between them cost three characters.
    let prose = match prose.chars().count() {
        0 => String::new(),
        n if n + 2 <= room => format!("{prose}\n\n"),
        _ if room > 3 => format!("{}…\n\n", prose.chars().take(room - 3).collect::<String>().trim_end()),
        _ => String::new(),
    };
    Some(prose + &tail)
}

/// What heads a row proposed for a call in a group, sent to the caller 1:1 (`builtin_room.rs`):
/// which group it is for, and — when it took the place of a proposal still waiting — that the
/// member's next yes or no answers this one. There is ONE waiting proposal per member, so a 1:1
/// "evet" always confirms the last row they were shown, and that row says where it came from.
pub(super) fn room_proposal_header(lang: Lang, room_name: &str, replaced: bool) -> String {
    let from = line(lang, Line::ProposalFromRoom).replace("{room}", room_name.trim());
    if replaced {
        format!("{}\n{from}", line(lang, Line::ProposalReplaced))
    } else {
        from
    }
}

/// What a settled row leaves in the member's context, and what the bot says now: `None` for an
/// ordinary message. A confirmed row is remembered as "Kaydedildi." — the line the member is
/// shown when it lands — so the model can tell a saved row from one that was not (the system
/// prompt says so); it says nothing now, the landing does.
pub(super) fn settled_exchange(lang: Lang, step: &ProposalStep) -> Option<(Option<Line>, &'static str)> {
    let (now, remembered) = match step {
        ProposalStep::Ordinary => return None,
        ProposalStep::Confirm => (None, Line::RowSaved),
        ProposalStep::Discard => (Some(Line::RowDiscarded), Line::RowDiscarded),
        ProposalStep::Lapsed => (Some(Line::ProposalLapsed), Line::ProposalLapsed),
    };
    Some((now, line(lang, remembered)))
}

/// Does the change from `old` to `new` leave rows and proposals owed to a sheet that is no longer
/// written to — rows turned off, or a different address?
pub(super) fn sheet_target_changed(old: Option<&Config>, new: Option<&Config>) -> bool {
    let target = |c: Option<&Config>| c.filter(|c| c.writes_sheet()).and_then(|c| c.sheet_url.clone());
    target(old) != target(new)
}

/// Does a set change what the bot does — kind, sheet address, provider, address, model,
/// instructions, rows on or off, or a new key? Then what was measured on the old settings
/// (`last_ok_at`, `last_error`) is reset. The bot's language alone is not such a change.
pub(super) fn changes_behaviour(old: Option<&Config>, new: Option<&Config>, new_key: bool) -> bool {
    let what = |c: Option<&Config>| c.map(|c| (c.kind, c.sheet_url.clone(), c.ai.clone()));
    new_key || what(old) != what(new)
}

/// A test's outcome from its steps, in order: the first failing step's code, `Ok` only if every
/// step that ran passed (`sheet` = `None` when there is no sheet step).
pub(super) fn test_outcome(
    model: Result<(), &'static str>,
    sheet: Option<Result<(), &'static str>>,
) -> Result<(), &'static str> {
    model.and(sheet.unwrap_or(Ok(())))
}

/// The context sent to the model starts on a member's message (Anthropic requires the user to
/// speak first): a window that begins with an answer drops it.
pub(super) fn whole_turns(mut history: Vec<Turn>) -> Vec<Turn> {
    while history.first().is_some_and(|t| t.role != Role::User) {
        history.remove(0);
    }
    history
}

#[cfg(test)]
#[path = "builtin_policy_tests.rs"]
mod tests;
