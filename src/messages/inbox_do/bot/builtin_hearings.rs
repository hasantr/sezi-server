//! The hearing-minutes bot's round in its inbox (docs/HEARINGS_BOT_PLAN.md §1.1, H4): the I/O
//! around the pure steps of `hearings_pipeline.rs`.
//!
//! One member update, 1:1:
//! 1. **Who may ask** (decision 2): an active member of `allowed_room`, read from D1 at every
//!    text or file, before anything in it is read. Anyone else hears "Bu botu kullanma yetkin
//!    yok." and loses the row that waited for their yes. D1 silent: tried again later.
//! 2. **A text that answers a waiting row** ("evet" / "hayır", within 10 minutes) settles it: a
//!    yes queues the upsert (`builtin_jobs.rs` writes it, H5), a no or a lapse is said. Every
//!    other text is taken as pasted minutes.
//! 3. **The bytes**: a file through `bot_file_bytes` (its uploader, scope, bot and size checked
//!    on the relay's own record), the first file of a message only; pasted text as it is.
//! 4. **`read`**: refused → its line; else rule-only or ONE model call with the masked text.
//! 5. **`finish`**: the answer to the lawyer (names restored), the role-only row proposed
//!    ("Tabloya yazayım mı?"), the audit row (counts and codes only).
//!
//! A room call (H7 is not built) is answered in the room with one line: send it 1:1.
//!
//! **What is kept** (§8.2): the update and its file manifest go when this returns `Done`, success
//! or failure; the vault, the bytes and the text were never written; the proposal holds only the
//! role-only row; the bot's sent answer is blanked once delivered and gone after 24 h
//! (`builtin_hearings_retention`). This kind writes no AI turns.
//!
//! **CPU** (§3.1): a Workers Free plan's 10 ms may not cover a long PDF, and an invocation over
//! its CPU budget is simply ended — nothing in-process can catch it. So the round marks the
//! update it starts on (`hearings_inflight` in `bot_kv`) and clears the mark when it is done; a
//! tick that finds the mark of an update already tried [`MAX_TRIES`] times answers the member
//! with `Line::HearingsTooHeavy`, notes `hearings/needs-paid-plan` for the owner and drops it,
//! instead of dying on it forever.
//!
//! Logs carry codes and counts only — no text, names, file names, prompts, answers, esas nos or
//! courts (`hearings_log_tests.rs` reads this file's log lines to hold that).

use super::builtin_copy::{line, Line};
use super::builtin_policy::{self as policy, ProposalStep};
use super::builtin_run::{Handled, Run, MAX_REPLY_CHARS};
use super::builtin_sheet::Upsert;
use super::builtin_store as bs;
use super::hearings_answer::messages;
use super::hearings_audit::{self as audit, AuditRecord, SheetOutcome};
use super::hearings_pipeline::{finish, gates_of, read, Context, Gates, Input, ModelStep, Step};
use super::hearings_prompt::{self as prompt, CALL_TIMEOUT_MS};
use super::store::{Arg, Exec};
use super::*;
use crate::bots::builtin_rules::{outbound_url, HearingsConfig};

/// A record that ended the invocation this many times is given up on.
const MAX_TRIES: u32 = 2;
const KV_INFLIGHT: &str = "hearings_inflight";
/// What the owner's page says after a record kept ending the invocation.
pub(super) const NEEDS_PAID_PLAN: &str = "hearings/needs-paid-plan";
/// The bot's sent answers are kept this long at most (they carry names): 24 h, not 7 days.
pub(super) const SENT_KEEP_MS: i64 = 24 * 3600 * 1000;

#[derive(Deserialize)]
struct Waiting {
    row_json: String,
    at: i64,
}

impl UserInbox {
    /// One update for a hearings bot.
    pub(super) async fn builtin_hearings(
        &self,
        ctx: &BotCtx,
        run: &Run,
        update_id: i64,
        update: &serde_json::Value,
        now: i64,
        spent: &mut u32,
    ) -> Handled {
        let Some(h) = run.cfg.hearings.as_ref() else {
            return Handled::Done;
        };
        let s = |p: &str| update.pointer(p).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let kind = s("/kind");
        if kind == "call" {
            let Some(room) = super::builtin_room::RoomRef::of_update(update) else {
                return Handled::Done;
            };
            if !policy::fits(*spent, policy::SAY_BASE) {
                return Handled::NoRoom;
            }
            let (who, call) = (s("/who/user_id"), s("/message/text"));
            self.builtin_reply(ctx, &who, Some(&room), &call, line(run.lang, Line::HearingsOneToOneOnly), spent).await;
            return Handled::Done;
        }
        let from = s("/chat/user_id");
        if from.is_empty() || !matches!(kind.as_str(), "message" | "file") {
            return Handled::Done;
        }
        if !policy::fits(*spent, policy::HEARINGS_GATE_BASE) {
            return Handled::NoRoom;
        }
        let input_kind = if kind == "file" { "file" } else { "text" };
        // Decision 2: an active member of the owner's room, asked at every text before anything
        // in it is read — an "evet" to a waiting row too, or a member removed from the room could
        // still confirm the row proposed to them while they were in it.
        let allowed = match self.env.d1("DB") {
            Ok(db) => crate::groups::group_role(&db, &h.allowed_room, &from).await.map(|r| r.is_some()),
            Err(e) => Err(e),
        };
        *spent += policy::ROOM_CHECK;
        match allowed {
            Err(_) => return Handled::Retry,
            Ok(false) => {
                // The row proposed while they were a member is no longer theirs to confirm.
                self.bot_store().db.run(bs::PROPOSAL_DROP, &[Arg::T(&from)]);
                self.hearings_audit(&from, now, &AuditRecord { input: input_kind, outcome: "hearings/not-allowed", ..Default::default() });
                self.builtin_say(ctx, &from, line(run.lang, Line::HearingsNotAllowed), spent).await;
                return Handled::Done;
            }
            Ok(true) => {}
        }
        if !self.builtin_current(run) {
            return Handled::Abandon;
        }
        if kind == "message" {
            let who = (from.as_str(), s("/who/display_name"));
            if let Some(done) = self.hearings_settle(ctx, run, who.0, &who.1, &s("/message/text"), now, spent).await {
                return done;
            }
        }
        if !policy::fits(*spent, policy::HEARINGS_BASE - policy::ROOM_CHECK) {
            return Handled::NoRoom;
        }
        // A record that keeps ending the invocation (CPU) is given up on, said, and noted.
        if !self.hearings_try(update_id) {
            console_log!("[bot] hearings refusal {NEEDS_PAID_PLAN}");
            self.builtin_note(Err(NEEDS_PAID_PLAN), now);
            self.hearings_audit(&from, now, &AuditRecord { input: input_kind, outcome: NEEDS_PAID_PLAN, ..Default::default() });
            self.builtin_say(ctx, &from, line(run.lang, Line::HearingsTooHeavy), spent).await;
            self.hearings_done();
            return Handled::Done;
        }
        let handled = self.hearings_record(ctx, run, h, update, &from, now, spent).await;
        if !matches!(handled, Handled::NoRoom) {
            self.hearings_done();
        }
        handled
    }

    /// Steps 3–5 of the module doc, for a member already let in.
    #[allow(clippy::too_many_arguments)]
    async fn hearings_record(
        &self,
        ctx: &BotCtx,
        run: &Run,
        h: &HearingsConfig,
        update: &serde_json::Value,
        from: &str,
        now: i64,
        spent: &mut u32,
    ) -> Handled {
        let store = self.bot_store();
        let file = update.pointer("/files/0");
        let file_id = file.and_then(|f| f.get("file_id")).and_then(|v| v.as_str());
        let name = file.and_then(|f| f.get("name")).and_then(|v| v.as_str()).unwrap_or("");
        let bytes = match file_id {
            Some(id) => {
                let got = self.bot_file_bytes(ctx, id).await;
                *spent += 3;
                if !self.builtin_current(run) {
                    return Handled::Abandon;
                }
                match got {
                    Ok(b) => Some(b),
                    Err(e) => {
                        let code = match e {
                            super::files::FileError::TooLarge => "hearings/too-large",
                            super::files::FileError::StoreDown => return Handled::Retry,
                            _ => "hearings/file-unavailable",
                        };
                        self.hearings_audit(from, now, &AuditRecord { input: "file", outcome: code, ..Default::default() });
                        let l = if code == "hearings/too-large" { Line::HearingsTooLarge } else { Line::HearingsFileUnavailable };
                        self.builtin_say(ctx, from, line(run.lang, l), spent).await;
                        return Handled::Done;
                    }
                }
            }
            None => None,
        };
        let text = update.pointer("/message/text").and_then(|v| v.as_str()).unwrap_or("");
        let input = match &bytes {
            Some(b) => Input::File { bytes: b, name },
            None => Input::Text(text),
        };
        let day = bs::day_of(now);
        let used = store.db.int(bs::USAGE_GET, &[Arg::T(from), Arg::I(day)]).unwrap_or(0);
        // A read that failed counts as the cap reached: the rules answer, the owner pays nothing.
        let bot_used = store.db.int(bs::USAGE_DAY_TOTAL, &[Arg::I(day)]).unwrap_or(i64::MAX);
        let gates = gates_of(self.builtin_api_key().is_some(), used, bot_used, h);
        let step = read(input, h, gates);
        drop(bytes);
        let (reading, model) = match step {
            Step::Refused { line: l, audit } => {
                console_log!("[bot] hearings refusal {}", audit.outcome);
                self.hearings_audit(from, now, &audit);
                self.builtin_say(ctx, from, line(run.lang, l), spent).await;
                return Handled::Done;
            }
            Step::RuleOnly { reading, why } => (reading, ModelStep::Skipped(why)),
            Step::Model { reading, body } => {
                store.db.run(bs::USAGE_BUMP, &[Arg::T(from), Arg::I(day)]);
                let key = self.builtin_api_key().unwrap_or_default();
                let answered = match outbound_url(&prompt::endpoint(h), run.allow_lan) {
                    None => Err("ai/unreachable"),
                    Some(url) => {
                        super::builtin_ai::post_json(url.as_str(), &prompt::headers(h, &key), &body.to_string(), CALL_TIMEOUT_MS)
                            .await
                    }
                };
                *spent += 1;
                if !self.builtin_current(run) {
                    return Handled::Abandon; // answered on settings that are gone: nothing is kept
                }
                (reading, ModelStep::Answered(answered))
            }
        };
        let lawyer = update.pointer("/who/display_name").and_then(|v| v.as_str()).unwrap_or("");
        let cx = Context {
            lang: run.lang,
            columns: &h.columns,
            model: &h.model,
            provider: h.provider,
            lawyer,
            now_ms: now,
            writes_sheet: run.cfg.writes_sheet(),
        };
        let answer = finish(&reading, model, &cx);
        drop(reading);
        let outcome = answer.audit.outcome;
        console_log!("[bot] hearings outcome {outcome}");
        if outcome.starts_with("ai/") || outcome.starts_with("hearings/model") {
            self.builtin_note(Err(outcome), now);
        } else if answer.audit.model.is_some() {
            self.builtin_note(Ok(()), now);
        }
        let audit_id = self.hearings_audit(from, now, &answer.audit);
        if let Some(u) = &answer.upsert {
            store.db.run(bs::PROPOSAL_PUT, &[Arg::T(from), Arg::T(&u.to_json(audit_id)), Arg::T(""), Arg::I(now), Arg::Null]);
        }
        for m in messages(&answer.text, MAX_REPLY_CHARS) {
            self.builtin_say(ctx, from, &m, spent).await;
        }
        Handled::Done
    }

    /// A member's text, when a row waits for their yes: what became of it (`Some`), or `None`
    /// when it is an ordinary message (pasted minutes).
    #[allow(clippy::too_many_arguments)]
    async fn hearings_settle(
        &self,
        ctx: &BotCtx,
        run: &Run,
        from: &str,
        name: &str,
        text: &str,
        now: i64,
        spent: &mut u32,
    ) -> Option<Handled> {
        let store = self.bot_store();
        store.db.run(bs::PROPOSAL_EXPIRE, &[Arg::I(now - bs::PROPOSAL_KEEP_MS)]);
        let waiting: Option<Waiting> = self
            .state
            .storage()
            .sql()
            .exec_raw(bs::PROPOSAL_GET, Some(vec![JsValue::from_str(from)]))
            .and_then(|c| c.to_array())
            .ok()
            .and_then(|v: Vec<Waiting>| v.into_iter().next());
        let step = policy::proposal_step(waiting.as_ref().map(|w| w.at), run.cfg.writes_sheet(), text, now);
        if step == ProposalStep::Ordinary {
            return None;
        }
        let w = waiting?;
        if !policy::fits(*spent, policy::SAY_BASE) {
            return Some(Handled::NoRoom);
        }
        store.db.run(bs::PROPOSAL_DROP, &[Arg::T(from)]);
        let parsed = Upsert::parse(&w.row_json);
        let audit_id = parsed.as_ref().and_then(|(_, a)| *a);
        let settle = |o: SheetOutcome| {
            if let Some(id) = audit_id {
                store.db.run(audit::AUDIT_SHEET, &[Arg::T(o.as_str()), Arg::I(id)]);
            }
        };
        match step {
            ProposalStep::Confirm => {
                // The job's `text` stays empty: the minutes are never what a row carries.
                if parsed.is_some() {
                    store.db.run(
                        bs::JOB_PUSH,
                        &[Arg::T(from), Arg::T(name), Arg::T(""), Arg::T(&w.row_json), Arg::I(now), Arg::I(1), Arg::I(now), Arg::I(now), Arg::Null],
                    );
                }
            }
            ProposalStep::Discard => {
                settle(SheetOutcome::Declined);
                self.builtin_say(ctx, from, line(run.lang, Line::RowDiscarded), spent).await;
            }
            ProposalStep::Lapsed => {
                settle(SheetOutcome::Lapsed);
                self.builtin_say(ctx, from, line(run.lang, Line::ProposalLapsed), spent).await;
            }
            ProposalStep::Ordinary => {}
        }
        Some(Handled::Done)
    }

    /// One audit row; its id.
    fn hearings_audit(&self, user: &str, now: i64, a: &AuditRecord) -> Option<i64> {
        let opt = |v: Option<i64>| v.map_or(Arg::Null, Arg::I);
        self.bot_store().db.int(
            audit::AUDIT_PUT,
            &[
                Arg::T(user),
                Arg::I(now),
                Arg::T(a.input),
                Arg::I(a.pages),
                Arg::I(a.chars),
                Arg::T(&a.masked_json()),
                a.model.as_deref().map_or(Arg::Null, Arg::T),
                opt(a.tokens_in),
                opt(a.tokens_out),
                Arg::T(a.outcome),
            ],
        )
    }

    /// Mark `update_id` as being worked on: `false` when it already ended the invocation
    /// [`MAX_TRIES`] times (module doc, CPU).
    fn hearings_try(&self, update_id: i64) -> bool {
        let store = self.bot_store();
        let prior = store.kv_get(KV_INFLIGHT).and_then(|v| {
            let (id, n) = v.split_once(':')?;
            (id.parse::<i64>().ok()? == update_id).then(|| n.parse::<u32>().ok()).flatten()
        });
        let n = prior.unwrap_or(0);
        if n >= MAX_TRIES {
            return false;
        }
        store.kv_put(KV_INFLIGHT, &format!("{update_id}:{}", n + 1));
        true
    }

    fn hearings_done(&self) {
        self.bot_store().db.run("DELETE FROM bot_kv WHERE k = ?", &[Arg::T(KV_INFLIGHT)]);
    }

    /// The owner's "Dene": the fake record through the whole pipeline (the model too, when on),
    /// answered with the 1:1 text the owner would get — fake names restored. No audit row, no
    /// proposal, no counted call.
    pub(super) async fn hearings_test(
        &self,
        lang: crate::bots::builtin_rules::Lang,
        h: &HearingsConfig,
        now: i64,
        who_name: &str,
    ) -> (std::result::Result<(), &'static str>, Option<String>) {
        let gates = Gates { has_key: self.builtin_api_key().is_some(), under_cap: true, bot_under_cap: true };
        let allow_lan = crate::bots::builtin_rules::allow_lan(&self.env);
        let (reading, model) = match read(Input::Text(super::hearings_sample::SAMPLE_RECORD), h, gates) {
            Step::Refused { audit, .. } => return (Err(audit.outcome), None),
            Step::RuleOnly { reading, why } => (reading, ModelStep::Skipped(why)),
            Step::Model { reading, body } => {
                let key = self.builtin_api_key().unwrap_or_default();
                let answered = match outbound_url(&prompt::endpoint(h), allow_lan) {
                    None => Err("ai/unreachable"),
                    Some(url) => {
                        super::builtin_ai::post_json(url.as_str(), &prompt::headers(h, &key), &body.to_string(), CALL_TIMEOUT_MS)
                            .await
                    }
                };
                (reading, ModelStep::Answered(answered))
            }
        };
        let cx = Context {
            lang,
            columns: &h.columns,
            model: &h.model,
            provider: h.provider,
            lawyer: who_name,
            now_ms: now,
            writes_sheet: false,
        };
        let answer = finish(&reading, model, &cx);
        // Only a model failure fails the test: rule-only by the owner's choice is the bot working.
        let outcome = match answer.audit.outcome {
            "ok" | "hearings/ai-off" => Ok(()),
            code => Err(code),
        };
        (outcome, Some(answer.text))
    }

    /// The hearings kind's retention, in the tick's housekeeping (§8.2).
    pub(super) fn builtin_hearings_retention(&self, h: &HearingsConfig, now: i64) {
        let db = self.bot_store().db;
        db.run(audit::AUDIT_EXPIRE, &[Arg::I(now - i64::from(h.audit_days) * 86_400_000)]);
        db.run(SENT_EXPIRE, &[Arg::I(now - SENT_KEEP_MS)]);
    }

    /// `/forward-delivered` in bot mode: a member device read what the bot sent it. For the
    /// hearings kind the payload kept for a resend (the answer, with names) is blanked for that
    /// device at once: a delivered message is never resent to it.
    pub(crate) fn bot_hearings_delivered(&self, from: &str, ids: &[i64]) {
        if !self.builtin_config().is_some_and(|c| c.kind == crate::bots::builtin_rules::Kind::Hearings) {
            return;
        }
        let db = self.bot_store().db;
        for id in ids {
            db.run(SENT_BLANK, &[Arg::T(from), Arg::I(*id)]);
        }
    }

    /// What `/bot/state` adds for a hearings bot: counts of the last 30 days, no content.
    pub(super) fn hearings_state(&self, now: i64) -> serde_json::Value {
        #[derive(Deserialize)]
        struct KN {
            k: String,
            n: i64,
        }
        let sql = self.state.storage().sql();
        let since = JsValue::from_f64((now - audit::OWNER_VIEW_DAYS * 86_400_000) as f64);
        let counts = |q: &str| -> serde_json::Map<String, serde_json::Value> {
            sql.exec_raw(q, Some(vec![since.clone()]))
                .and_then(|c| c.to_array::<KN>())
                .unwrap_or_default()
                .into_iter()
                .map(|r| (r.k, r.n.into()))
                .collect()
        };
        serde_json::json!({
            "days": audit::OWNER_VIEW_DAYS,
            "by_outcome": counts(audit::AUDIT_BY_OUTCOME),
            "sheet": counts(audit::AUDIT_BY_SHEET),
            "last_at": self.bot_store().db.int(audit::AUDIT_LAST_AT, &[]),
        })
    }
}

/// Bind: user, pending id (the member inbox's id of one device's copy).
pub(super) const SENT_BLANK: &str = "UPDATE bot_sent SET payload_json = '' WHERE user_id = ? AND pending_id = ?";
/// Bind: cutoff.
pub(super) const SENT_EXPIRE: &str = "DELETE FROM bot_sent WHERE created_at < ?";
