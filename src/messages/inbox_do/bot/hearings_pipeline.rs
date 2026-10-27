//! The hearings bot's round as pure steps (docs/HEARINGS_BOT_PLAN.md §1.1): [`read`] decides
//! whether a record is refused, answered by the rules alone, or sent (masked) to the model — and
//! builds that request; [`finish`] turns the model's reply (or its absence) into the 1:1 answer,
//! the sheet row and the audit record. The one `await` between them, the model call, is the
//! inbox's (`builtin_hearings.rs`); everything a test needs to see is here.
//!
//! ```text
//! file / pasted text ─ sezi_hearings::read_* ─ refused? → the matching line
//!                    └ RuleSummary ─ sezi_redact::redact (hints: esas no, court, file-name words)
//!   rule-only when: ai off · criminal and !criminal_ai · no key · over the member's or the
//!                   bot's calls today ·
//!                   masking refused · the request would carry a vault value
//!   else ONE model call with the masked text ─ hearings_validate ─ fails? → rule-only
//! → hearings_answer: 1:1 text (names restored) + the role-only row + the audit (counts only)
//! ```
//!
//! **Fail closed.** Whatever goes wrong, the fallback is the rule-only answer, built from the
//! parser — never the unmasked text to the model. The vault lives in a [`Reading`] for one round
//! and is dropped with it; nothing here writes, logs or keeps it.

use super::builtin_copy::Line;
use super::builtin_sheet::Upsert;
use super::hearings_answer::{one_to_one, sheet_row, View};
use super::hearings_audit::AuditRecord;
use super::builtin_ai::{http_failure, transient};
use super::hearings_prompt::{parse_response, request_body, user_message, ModelReply};
use super::hearings_validate::validate;
use crate::bots::builtin_hearings_rules::{Columns, HearingsConfig};
use crate::bots::builtin_rules::Lang;
use sezi_hearings::{read_file, read_text, Limits, Refusal, RuleSummary, Source};
use sezi_redact::{leak_check_with, redact, Category, Policy, Redacted};

/// What a member sent.
pub(super) enum Input<'a> {
    /// A file's decrypted bytes and its name (the name is a hint for masking, never sent).
    File { bytes: &'a [u8], name: &'a str },
    /// Pasted text.
    Text(&'a str),
}

/// What decides the path, besides the record itself.
#[derive(Clone, Copy, Debug)]
pub(super) struct Gates {
    pub(super) has_key: bool,
    /// The member has model calls left today.
    pub(super) under_cap: bool,
    /// The bot has model calls left today, every member together (the owner's `daily_calls`).
    pub(super) bot_under_cap: bool,
}

/// The gates from today's counts: `member_used` this member's calls, `bot_used` the bot's.
pub(super) fn gates_of(has_key: bool, member_used: i64, bot_used: i64, cfg: &HearingsConfig) -> Gates {
    Gates {
        has_key,
        under_cap: member_used < super::builtin_store::DAILY_CALLS,
        bot_under_cap: bot_used < i64::from(cfg.daily_calls),
    }
}

/// A record read and masked: what [`finish`] builds from. Holds the unmasked decisions and the
/// vault — in memory, for this round only (the full text is dropped once masked).
pub(super) struct Reading {
    pub(super) summary: RuleSummary,
    pub(super) redacted: Result<Redacted, &'static str>,
    pub(super) policy: Policy,
    pub(super) audit: AuditRecord,
}

/// What [`read`] decided.
pub(super) enum Step {
    /// Not read: the line to say, and the audit.
    Refused { line: Line, audit: AuditRecord },
    /// Answered by the rules alone, for this reason (a code).
    RuleOnly { reading: Box<Reading>, why: &'static str },
    /// One model call, with this body.
    Model { reading: Box<Reading>, body: serde_json::Value },
}

/// The line for a record the rules would not read.
pub(super) fn refusal_line(r: Refusal) -> Line {
    match r {
        Refusal::NoTextLayer => Line::HearingsNoTextLayer,
        Refusal::NotARecord => Line::HearingsNotARecord,
        Refusal::TooLarge | Refusal::TooManyPages | Refusal::PdfContentLimit | Refusal::TooMuchText => {
            Line::HearingsTooLarge
        }
        Refusal::PdfEncrypted => Line::HearingsPdfEncrypted,
        Refusal::PdfUnreadable => Line::HearingsPdfUnreadable,
        Refusal::UnsupportedType => Line::HearingsUnsupportedType,
    }
}

/// Words of a file's name that may be a person's ("Ahmet Yılmaz zabıt.pdf"): capitalised
/// letters-only words of three or more, minus the words a record's file name is made of. They
/// are handed to the redactor as known names; the name itself is never sent anywhere.
pub(super) fn name_words(name: &str) -> Vec<String> {
    const COMMON: [&str; 16] = [
        "zabıt", "zabit", "zabıtı", "duruşma", "durusma", "tutanak", "tutanağı", "tutanagi", "esas", "karar",
        "mahkeme", "mahkemesi", "uyap", "belge", "dosya", "ara",
    ];
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    stem.split(|c: char| !c.is_alphabetic())
        .filter(|w| w.chars().count() >= 3 && w.chars().next().is_some_and(char::is_uppercase))
        .filter(|w| !COMMON.contains(&w.to_lowercase().as_str()))
        .map(str::to_string)
        .collect()
}

/// Read, mask and decide (the module doc's diagram, up to the model call).
pub(super) fn read(input: Input<'_>, cfg: &HearingsConfig, gates: Gates) -> Step {
    let limits = Limits::default();
    let (result, kind, file_name) = match input {
        Input::File { bytes, name } => (read_file(bytes, &limits), "file", Some(name)),
        Input::Text(t) => (read_text(t, &limits), "text", None),
    };
    let hearing = match result {
        Ok(h) => h,
        Err(r) => {
            let audit = AuditRecord { input: kind, outcome: r.code(), ..Default::default() };
            return Step::Refused { line: refusal_line(r), audit };
        }
    };
    let summary = hearing.summary();
    let (input, pages) = match &hearing.source {
        Source::Pdf(f) => ("pdf", i64::from(f.pages)),
        Source::Text => ("text", 0),
    };
    let policy = Policy {
        esas_no: summary.case_no.clone(),
        court: summary.court.clone(),
        known_names: file_name.map(name_words).unwrap_or_default(),
    };
    let redacted = redact(&hearing.text, &policy).map_err(|e| e.code());
    let audit = AuditRecord {
        input,
        pages,
        chars: hearing.text.chars().count() as i64,
        masked: redacted.as_ref().map(|r| AuditRecord::counts_of(&r.counts)).unwrap_or_default(),
        outcome: "ok",
        ..Default::default()
    };
    let criminal = summary.criminal || redacted.as_ref().is_ok_and(|r| r.kept.criminal);
    let why = if !cfg.ai {
        Some("hearings/ai-off")
    } else if criminal && !cfg.criminal_ai {
        Some("hearings/criminal")
    } else if !gates.has_key {
        Some("ai/no-key")
    } else if !gates.under_cap {
        Some("hearings/daily-limit")
    } else if !gates.bot_under_cap {
        Some("hearings/bot-daily-limit")
    } else {
        redacted.as_ref().err().copied()
    };
    drop(hearing);
    let reading = Box::new(Reading { summary, redacted, policy, audit });
    if let Some(why) = why {
        return Step::RuleOnly { reading, why };
    }
    let Ok(r) = reading.redacted.as_ref() else {
        return Step::RuleOnly { reading, why: "hearings/mask-leak" };
    };
    // The last look before anything leaves, at the one part of the request that carries the
    // record (the rest is this file's constants and the owner's model id). Checked as the text it
    // is, not as serialised JSON: there every line runs into one, and a neighbouring number
    // ("max_tokens": 16000) reads as a clerk's sicil.
    if leak_check_with(&user_message(&r.masked), &r.vault).is_err() {
        return Step::RuleOnly { reading, why: "hearings/mask-leak" };
    }
    let body = request_body(cfg, &r.masked);
    Step::Model { reading, body }
}

/// What came of the round's model step.
pub(super) enum ModelStep {
    /// None was made, for this reason.
    Skipped(&'static str),
    /// The HTTP answer (status 0 = none), or the transport's code.
    Answered(Result<(u16, String), &'static str>),
}

/// A passing model failure is tried this many times in all, as the AI kind's (`builtin_run.rs`).
pub(super) const MODEL_ATTEMPTS: i64 = 3;

/// What the round does with a model call's transport answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfterCall {
    /// A passing failure (a rate limit, an overload, a gateway, no answer in time) with tries
    /// left: the update waits and is read again; nothing is said, kept or counted.
    Retry,
    /// Go on to [`finish`] with it. `counted`: the member's and the bot's daily count is spent —
    /// only when the provider answered with something no retry changes (an answer, a bad key, a
    /// bad request). A passing failure on the last try, or an address refused before any call,
    /// answers rule-only and spends nothing.
    Keep { counted: bool },
}

/// [`AfterCall`] for `answered` (the HTTP answer, status 0 = none; `Err` = no request made) on
/// the update's try `attempts` (0 = the first).
pub(super) fn after_call(answered: &Result<(u16, String), &'static str>, attempts: i64) -> AfterCall {
    let Ok((status, _)) = answered else {
        return AfterCall::Keep { counted: false };
    };
    let passing = http_failure(*status).is_some_and(transient);
    match (passing, attempts + 1 < MODEL_ATTEMPTS) {
        (true, true) => AfterCall::Retry,
        (true, false) => AfterCall::Keep { counted: false },
        (false, _) => AfterCall::Keep { counted: true },
    }
}

/// The round's result.
pub(super) struct Answer {
    /// To the lawyer, 1:1, names restored.
    pub(super) text: String,
    /// The row to propose, when there is a sheet to write and a key to find the row by.
    pub(super) upsert: Option<Upsert>,
    pub(super) audit: AuditRecord,
}

/// Where the answer goes and what it may carry.
pub(super) struct Context<'a> {
    pub(super) lang: Lang,
    pub(super) columns: &'a Columns,
    pub(super) model: &'a str,
    pub(super) provider: crate::bots::builtin_rules::Provider,
    /// The lawyer's display name, for the sheet's "Avukat" cell.
    pub(super) lawyer: &'a str,
    pub(super) now_ms: i64,
    /// The bot writes a connected sheet.
    pub(super) writes_sheet: bool,
}

/// The 1:1 answer, the row and the audit, from a reading and its model step.
pub(super) fn finish(reading: &Reading, step: ModelStep, cx: &Context<'_>) -> Answer {
    let mut audit = reading.audit.clone();
    let vault = reading.redacted.as_ref().ok().map(|r| &r.vault);
    let masked = reading.redacted.as_ref().ok().map(|r| r.masked.as_str());
    let (model, why) = match step {
        ModelStep::Skipped(why) => (None, Some(why)),
        ModelStep::Answered(answered) => {
            audit.model = Some(cx.model.to_string());
            let reply: Result<ModelReply, &'static str> =
                answered.and_then(|(status, body)| parse_response(cx.provider, status, &body));
            if let Ok(r) = &reply {
                audit.tokens_in = r.tokens_in;
                audit.tokens_out = r.tokens_out;
            }
            let checked = reply.and_then(|r| match (vault, masked) {
                (Some(v), Some(m)) => validate(&r.json, v, m, &reading.summary),
                _ => Err("hearings/mask-leak"),
            });
            match checked {
                Ok(m) => (Some(m), None),
                Err(code) => (None, Some(code)),
            }
        }
    };
    audit.outcome = why.unwrap_or("ok");
    let note = match why {
        None | Some("hearings/ai-off") => None,
        Some("hearings/criminal") => Some(Line::HearingsCriminal),
        Some("hearings/daily-limit") => Some(Line::HearingsDailyLimit),
        Some("hearings/bot-daily-limit") => Some(Line::HearingsBotDailyLimit),
        Some(_) => Some(Line::HearingsSummaryFailed),
    };
    let view = View { rules: &reading.summary, model: model.as_ref(), vault };
    let rule_decisions = if model.is_none() { masked_rule_decisions(reading) } else { Vec::new() };
    let upsert = sheet_row(cx.lang, cx.columns, &view, &rule_decisions, cx.lawyer, cx.now_ms);
    let no_row_key = reading.summary.court.is_none() || reading.summary.case_no.is_none();
    let upsert = upsert.filter(|_| cx.writes_sheet);
    let ask = upsert.as_ref().and(reading.summary.case_no.as_deref());
    let mut text = one_to_one(cx.lang, &view, note, ask);
    if cx.writes_sheet && no_row_key {
        text.push_str("\n\n");
        text.push_str(super::builtin_copy::line(cx.lang, Line::HearingsNoRowKey));
    }
    Answer { text, upsert, audit }
}

/// The rules' decisions, each masked on its own (for a row the model did not write): the names
/// the whole record's masking found are handed in as known names, so a surname that recurs alone
/// in a decision is masked there too. A decision that would not mask is `None` (left out).
fn masked_rule_decisions(reading: &Reading) -> Vec<Option<String>> {
    let Ok(r) = reading.redacted.as_ref() else {
        return reading.summary.decisions.iter().map(|_| None).collect();
    };
    let known: Vec<String> = r
        .vault
        .iter()
        .filter(|(p, _)| matches!(p.category, Category::Kisi | Category::Sirket | Category::Ad))
        .map(|(_, v)| v.to_string())
        .collect();
    let policy = Policy { known_names: [reading.policy.known_names.clone(), known].concat(), ..reading.policy.clone() };
    reading
        .summary
        .decisions
        .iter()
        .map(|d| redact(&d.text, &policy).ok().map(|m| m.masked))
        .collect()
}

#[cfg(test)]
#[path = "hearings_pipeline_tests.rs"]
mod tests;
