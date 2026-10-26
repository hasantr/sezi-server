use super::*;
use crate::bots::builtin_rules::{AiConfig, Kind, Provider};

const MIN: i64 = 60_000;

#[test]
fn no_round_and_drain_together_pass_the_tick_purse() {
    // The worst a round can end on: the last item started with its base just fitting, then its
    // one reply needed every key claim there is.
    let worst_round = ROUND_BUDGET + MAX_CLAIMS_COST;
    assert!(worst_round <= TICK_PURSE, "{worst_round} > {TICK_PURSE}");
    for spent in 0..=worst_round {
        assert!(spent + drain_budget(spent) <= TICK_PURSE, "spent {spent}");
    }
    assert_eq!(drain_budget(0), DRAIN_CEILING, "a program bot's tick drains as before");
    assert_eq!(DRAIN_CEILING, super::super::outbox::DRAIN_BUDGET);
    // With the tick's own fixed work, inside the 50 `messages/budget.rs` assumes.
    assert!(TICK_PURSE as usize + 5 <= crate::messages::budget::FREE_PLAN_SUBREQUESTS);
}

#[test]
fn an_item_starts_only_when_its_worst_case_fits() {
    assert!(fits(1, JOB_BASE), "a sheet write fits a fresh round");
    assert!(!fits(3, JOB_BASE), "not after something else spent");
    assert!(fits(8, AI_BASE) && !fits(9, AI_BASE), "a model call needs two");
    assert!(fits(9, SAY_BASE) && !fits(10, SAY_BASE));
    assert_eq!(JOB_BASE, 8, "4 hops, 3 GETs asked again, the line about it");
}

#[test]
fn a_disabled_bot_takes_nothing_so_no_held_message_reads_as_read() {
    assert_eq!(round_gate(Ok(Some(("Katip".into(), true)))), Gate::Run("Katip".into()));
    assert_eq!(round_gate(Ok(Some(("Katip".into(), false)))), Gate::Hold(HOLD_MS), "off");
    assert_eq!(round_gate(Ok(None)), Gate::Hold(HOLD_MS), "deleted");
    assert_eq!(round_gate(Err(())), Gate::Hold(D1_RETRY_MS), "D1 silent: soon, not never");
    // The only `forward-read` a built-in bot sends is `bot_updates_taken`, once, in the updates'
    // part, which runs only past the gate (measured in the lab too: tools/lab/runs/2026-10-26/
    // bots-builtin, b-14 — a message sent while off stayed "delivered" until the bot was back).
    let run = include_str!("builtin_run.rs");
    let code = run.split("#[cfg(test)]").next().unwrap();
    assert_eq!(code.matches("bot_updates_taken(").count(), 1);
    assert!(code.find("round_gate(").unwrap() < code.find("bot_updates_taken(").unwrap());
    for other in [include_str!("builtin_jobs.rs"), include_str!("builtin.rs")] {
        assert!(!other.contains("bot_updates_taken("), "a held round must have no other way to read");
    }
}

#[test]
fn a_members_next_message_settles_the_waiting_row() {
    let now = 100 * MIN;
    let at = Some(now - MIN);
    assert_eq!(proposal_step(at, true, "evet", now), ProposalStep::Confirm);
    assert_eq!(proposal_step(at, true, "Hayır.", now), ProposalStep::Discard);
    assert_eq!(proposal_step(at, true, "ne zaman?", now), ProposalStep::Ordinary);
    assert_eq!(proposal_step(Some(now - 11 * MIN), true, "yes", now), ProposalStep::Lapsed);
    assert_eq!(proposal_step(None, true, "evet", now), ProposalStep::Ordinary, "nothing to confirm");
    assert_eq!(
        proposal_step(at, false, "evet", now),
        ProposalStep::Ordinary,
        "rows turned off: an evet is an ordinary message, never a row nothing writes"
    );
    assert_eq!(
        proposal_step(Some(now - bs::PROPOSAL_KEEP_MS), true, "evet", now),
        ProposalStep::Ordinary,
        "expired on read, even before housekeeping ran"
    );
}

#[test]
fn a_proposal_always_shows_the_whole_row_and_the_hint() {
    let row = Row(vec![("Tarih".into(), "27.10.2026".into()), ("Mahkeme".into(), "Ankara 3. Asliye".into())]);
    assert_eq!(
        confirm_text(Lang::Tr, "Not aldım.", &row, 4000).unwrap(),
        "Not aldım.\n\nŞunu kaydedeyim mi?\n• Tarih: 27.10.2026\n• Mahkeme: Ankara 3. Asliye\n\nevet / hayır"
    );
    assert_eq!(
        confirm_text(Lang::En, "  ", &row, 4000).unwrap(),
        "Shall I save this?\n• Tarih: 27.10.2026\n• Mahkeme: Ankara 3. Asliye\n\nyes / no"
    );
    // Long prose is cut; the row and the hint are not.
    let long = "ş".repeat(5000);
    let text = confirm_text(Lang::Tr, &long, &row, 4000).unwrap();
    assert_eq!(text.chars().count(), 4000);
    assert!(text.ends_with("• Mahkeme: Ankara 3. Asliye\n\nevet / hayır"));
    assert!(text.contains("…\n\nŞunu kaydedeyim mi?"));
    // A row that cannot be shown whole is not proposed at all.
    let wide = Row((0..20).map(|i| (format!("Sütun{i}"), "x".repeat(500))).collect());
    assert_eq!(confirm_text(Lang::Tr, "", &wide, 4000), None);
}

fn cfg(kind: Kind, url: Option<&str>, tool: bool) -> Config {
    Config {
        kind,
        lang: Lang::Tr,
        sheet_url: url.map(str::to_string),
        ai: (kind == Kind::Ai).then(|| AiConfig {
            provider: Provider::Openai,
            base_url: None,
            model: "m".into(),
            instructions: "x".into(),
            sheet_tool: tool,
        }),
    }
}

#[test]
fn what_was_owed_to_a_sheet_goes_when_the_sheet_does() {
    let a = cfg(Kind::Ai, Some("https://script.google.com/a/exec"), true);
    let b = cfg(Kind::Ai, Some("https://script.google.com/b/exec"), true);
    let off = cfg(Kind::Ai, None, false);
    let sheet_a = cfg(Kind::Sheet, Some("https://script.google.com/a/exec"), false);
    assert!(!sheet_target_changed(Some(&a), Some(&a)), "same sheet");
    assert!(!sheet_target_changed(Some(&a), Some(&sheet_a)), "same sheet, other kind");
    assert!(sheet_target_changed(Some(&a), Some(&b)), "another address");
    assert!(sheet_target_changed(Some(&a), Some(&off)), "rows turned off");
    assert!(sheet_target_changed(Some(&a), None), "program mode");
    assert!(!sheet_target_changed(None, Some(&off)), "nothing was owed");
}

#[test]
fn the_context_starts_on_the_members_message() {
    let t = |role, text: &str| Turn { role, text: text.into() };
    let h = vec![t(Role::Assistant, "a0"), t(Role::User, "q1"), t(Role::Assistant, "a1")];
    assert_eq!(whole_turns(h), vec![t(Role::User, "q1"), t(Role::Assistant, "a1")]);
    assert!(whole_turns(vec![t(Role::Assistant, "a")]).is_empty());
    assert!(whole_turns(Vec::new()).is_empty());
}

#[test]
fn a_set_that_changes_the_bot_resets_what_was_measured() {
    let a = cfg(Kind::Ai, Some("https://script.google.com/a/exec"), true);
    assert!(!changes_behaviour(Some(&a), Some(&a), false), "the same settings sent again");
    let mut lang = a.clone();
    lang.lang = Lang::En;
    assert!(!changes_behaviour(Some(&a), Some(&lang), false), "the language alone");
    assert!(changes_behaviour(Some(&a), Some(&a), true), "a new key");
    for change in [
        |c: &mut Config| c.kind = Kind::Sheet,
        |c: &mut Config| c.sheet_url = Some("https://script.google.com/b/exec".into()),
        |c: &mut Config| c.ai.as_mut().unwrap().provider = Provider::Anthropic,
        |c: &mut Config| c.ai.as_mut().unwrap().base_url = Some("https://api.openai.com/v1".into()),
        |c: &mut Config| c.ai.as_mut().unwrap().model = "other".into(),
        |c: &mut Config| c.ai.as_mut().unwrap().instructions = "changed".into(),
        |c: &mut Config| c.ai.as_mut().unwrap().sheet_tool = false,
    ] {
        let mut b = a.clone();
        change(&mut b);
        assert!(changes_behaviour(Some(&a), Some(&b), false), "{b:?}");
    }
    assert!(changes_behaviour(Some(&a), None, false), "back to program mode");
    assert!(changes_behaviour(None, Some(&a), false), "first set");
}

#[test]
fn a_tests_outcome_is_its_first_failing_step() {
    assert_eq!(test_outcome(Ok(()), None), Ok(()), "no sheet step");
    assert_eq!(test_outcome(Ok(()), Some(Ok(()))), Ok(()), "both passed");
    assert_eq!(test_outcome(Ok(()), Some(Err("bot/sheet-no-sheet"))), Err("bot/sheet-no-sheet"));
    assert_eq!(test_outcome(Err("ai/bad-key"), Some(Err("bot/sheet-secret"))), Err("ai/bad-key"), "the model first");
    assert_eq!(test_outcome(Err("ai/bad-key"), None), Err("ai/bad-key"));
}

#[test]
fn a_settled_row_is_remembered_as_what_the_member_was_told() {
    assert_eq!(settled_exchange(Lang::Tr, &ProposalStep::Ordinary), None, "an ordinary message: nothing");
    assert_eq!(
        settled_exchange(Lang::Tr, &ProposalStep::Confirm),
        Some((None, "Kaydedildi.")),
        "said when it lands; remembered now, in the words the system prompt names"
    );
    assert_eq!(settled_exchange(Lang::En, &ProposalStep::Confirm), Some((None, "Saved.")));
    assert_eq!(
        settled_exchange(Lang::Tr, &ProposalStep::Discard),
        Some((Some(Line::RowDiscarded), "Tamam, kaydetmedim."))
    );
    let lapsed = settled_exchange(Lang::Tr, &ProposalStep::Lapsed).unwrap();
    assert_eq!(lapsed.0, Some(Line::ProposalLapsed));
}

/// A row proposed for a room call names its group, and says so when it replaced a waiting one:
/// the 1:1 "evet" confirms exactly the row the member last saw (review, 2026-10-26).
#[test]
fn a_room_proposal_names_its_group_and_a_replacement_says_so() {
    assert_eq!(room_proposal_header(Lang::Tr, " Hukuk ", false), "“Hukuk” grubundaki mesajın için:");
    let replaced = room_proposal_header(Lang::En, "Law", true);
    assert_eq!(replaced, "This replaces the earlier proposal; your answer is for this one.\nFor your message in the group \"Law\":");
    let row = Row(vec![("Tarih".into(), "2026-10-27".into())]);
    let text = confirm_text(Lang::Tr, &room_proposal_header(Lang::Tr, "Hukuk", true), &row, 4000).unwrap();
    assert!(text.starts_with("Önceki öneri geçersiz"), "{text}");
    assert!(text.contains("“Hukuk”") && text.contains("• Tarih: 2026-10-27") && text.ends_with("evet / hayır"));
}

/// One member could fill the owner's sheet: every message to a sheet bot became a row, a stored
/// job and up to seven subrequests, with nothing counting them (audit 2026-10-26, note 1.1). A
/// member now gets `DAILY_ROWS` rows a day; past that they hear it ONCE and nothing is queued.
#[test]
fn a_sheet_bot_takes_a_bounded_number_of_rows_from_one_member_a_day() {
    assert_eq!(row_admission(0), RowAdmission::Queue);
    assert_eq!(row_admission(bs::DAILY_ROWS - 1), RowAdmission::Queue, "the last row of the day");
    assert_eq!(row_admission(bs::DAILY_ROWS), RowAdmission::Refuse { say: true }, "told once");
    assert_eq!(row_admission(bs::DAILY_ROWS + 1), RowAdmission::Refuse { say: false }, "then silent");
    assert_eq!(row_admission(i64::MAX), RowAdmission::Refuse { say: false });
    assert!(ROW_REFUSED.starts_with("bot/"));
    let said = line(Lang::Tr, Line::SheetDailyLimit);
    assert!(said.contains(&bs::DAILY_ROWS.to_string()), "the line names the cap: {said}");
    // The sheet arm of the runner asks before it queues, and counts what it takes.
    let run = include_str!("builtin_run.rs");
    let code = run.split("#[cfg(test)]").next().unwrap();
    let start = code.find("fn builtin_sheet_row(").expect("the sheet arm has its own fn");
    let rest = &code[start..];
    let body = &rest[..rest[1..].find("\n    fn ").map_or(rest.len(), |i| i + 1)];
    let ask = body.find("row_admission(").expect("the sheet arm asks the cap");
    let queue = body.find("builtin_queue_row(").expect("and queues the row");
    assert!(ask < queue, "the cap is asked before the row is queued");
    assert!(body.contains("SHEET_USAGE_BUMP"), "every row is counted");
}
