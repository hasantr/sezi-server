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
        assert!(spent + drain_budget(TICK_PURSE, spent) <= TICK_PURSE, "spent {spent}");
    }
    assert_eq!(drain_budget(TICK_PURSE, 0), DRAIN_CEILING, "a program bot's tick drains as before");
    assert_eq!(DRAIN_CEILING, super::super::outbox::DRAIN_BUDGET);
    // With the tick's own fixed work, inside the 50 `messages/budget.rs` assumes.
    assert!(TICK_PURSE + TICK_FIXED <= crate::messages::budget::FREE_PLAN_SUBREQUESTS as u32);
}

/// The purse was a fixed 45 whatever the relay's ceiling, so an owner who raised
/// `SUBREQUEST_BUDGET` (a paid plan, a self-hosted relay) bought the bots nothing (review
/// 2026-10-27, #13). It follows the ceiling up; below the free plan's it stays the free plan's,
/// which every plan has and the arithmetic here needs.
#[test]
fn the_tick_purse_follows_the_relays_subrequest_ceiling() {
    use crate::messages::budget::{FREE_PLAN_SUBREQUESTS, MAX_BUDGET};
    assert_eq!(tick_purse(FREE_PLAN_SUBREQUESTS), TICK_PURSE);
    assert_eq!(tick_purse(100), 100 - TICK_FIXED);
    assert_eq!(tick_purse(20), TICK_PURSE, "the floor");
    assert_eq!(tick_purse(MAX_BUDGET), MAX_BUDGET as u32 - TICK_FIXED);
    let big = tick_purse(200);
    assert!(drain_budget(big, 0) > DRAIN_CEILING, "a bigger purse drains more");
    assert!(super::super::room::room_budget(big, 0) > super::super::room::ROOM_ROUND_MAX);
}

/// Webhook POSTs and re-pairs were spent before the purse was counted, so a busy tick on the
/// free plan's 50 could overrun it (review 2026-10-27, #13). Every step at its worst, in the
/// tick's order, fits the ceiling.
#[test]
fn every_step_of_a_tick_at_its_worst_fits_the_ceiling() {
    use super::super::deliver_order::{webhook_posts, WEBHOOK_OVERHEAD};
    use super::super::room::{room_budget, DRAIN_FLOOR};
    for budget in [crate::messages::budget::FREE_PLAN_SUBREQUESTS, 64, 100, 300, 900] {
        let purse = tick_purse(budget);
        let mut spent = 0;
        let mut repairs = 0;
        while may_repair(purse, spent) {
            spent += REPAIR_BASE;
            repairs += 1;
        }
        assert!(repairs >= 1, "budget {budget}: a re-pair always fits a fresh tick");
        let hooks = before_drain(purse, spent);
        let posts = webhook_posts(hooks);
        if posts > 0 {
            spent += WEBHOOK_OVERHEAD + posts as u32;
        }
        if may_start_round(purse, spent) {
            spent += ROUND_BUDGET + MAX_CLAIMS_COST;
        }
        spent += room_budget(purse, spent);
        let drain = drain_budget(purse, spent);
        assert!(drain >= DRAIN_FLOOR, "budget {budget}: the drain is left its floor");
        spent += drain;
        assert!(spent + TICK_FIXED <= budget as u32, "budget {budget}: {spent} + {TICK_FIXED}");
    }
    // A fresh tick with nothing before it: the webhook takes its whole batch, the round starts.
    assert_eq!(webhook_posts(before_drain(TICK_PURSE, 0)), super::super::deliver_order::WEBHOOK_BATCH);
    assert!(may_start_round(TICK_PURSE, 0));
    assert_eq!(webhook_posts(WEBHOOK_OVERHEAD), 0, "no room for a POST: none is made");
}

#[test]
fn the_tick_counts_what_its_webhooks_and_repairs_spend() {
    let tick = include_str!("ingest.rs");
    let tick = &tick[tick.find("async fn bot_tick_inner(").unwrap()..];
    let tick = &tick[..tick.find("\n    }\n").unwrap()];
    assert!(tick.contains("tick_purse(crate::messages::budget::resolve_budget(&self.env))"));
    for step in ["self.bot_owed_repairs(", "self.bot_say_busy(", "self.bot_deliver_webhooks("] {
        let at = tick.find(step).unwrap_or_else(|| panic!("{step}"));
        assert!(tick[..at].ends_with("spent += "), "{step} is not counted");
    }
    let src = include_str!("deliver.rs");
    assert!(src.contains("async fn bot_deliver_webhooks(&self, ctx: &BotCtx, budget: u32) -> u32"));
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
        hearings: None,
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
fn records_sent_to_a_hearings_bot_never_reach_another_kind() {
    // Minutes waiting for a hearings bot (held, out of budget, D1 down) were sent to be MASKED.
    // Under an AI bot they would go to its model raw; under a sheet bot into a row's text; in
    // program mode to the program, files and all.
    let mut hearings = cfg(Kind::Sheet, Some("https://script.google.com/a/exec"), false);
    hearings.kind = Kind::Hearings;
    let ai = cfg(Kind::Ai, None, false);
    let sheet = cfg(Kind::Sheet, Some("https://script.google.com/a/exec"), false);
    assert!(drops_hearings_queue(Some(&hearings), Some(&ai)));
    assert!(drops_hearings_queue(Some(&hearings), Some(&sheet)));
    assert!(drops_hearings_queue(Some(&hearings), None), "program mode");
    assert!(!drops_hearings_queue(Some(&hearings), Some(&hearings)), "a re-set of the same kind");
    assert!(!drops_hearings_queue(Some(&ai), Some(&hearings)));
    assert!(!drops_hearings_queue(None, Some(&ai)));
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

/// The sheet's rows ran only after the members' updates and only while a row's worst case still
/// fit, so a steady stream of messages to an AI or hearings bot held them indefinitely (review
/// 2026-10-27, #14). While both are due they take turns going first, with the round's whole
/// budget.
#[test]
fn updates_and_sheet_rows_take_turns_while_both_are_due() {
    let mut turn = false;
    let mut firsts = Vec::new();
    for _ in 0..4 {
        firsts.push(jobs_go_first(true, true, turn));
        turn = next_jobs_turn(true, true, turn);
    }
    assert_eq!(firsts, [false, true, false, true], "turn about");
    // The round's whole budget is enough for a row, so the row going first is written.
    assert!(fits(1, JOB_BASE), "after the gate's read");
    // Only one due: it goes first, and the turn stays where it was.
    assert!(jobs_go_first(false, true, false));
    assert!(!jobs_go_first(true, false, true));
    assert!(next_jobs_turn(false, true, true) && !next_jobs_turn(true, false, false));
}

/// `bot_builtin_next` answered 0 while anything was due, so a part that could not move its due
/// work (a sheet whose address or secret is gone, say) re-armed the alarm at once on every tick
/// for as long as the work was there (review 2026-10-27, #14). It now waits on the outbox's
/// ladder, and only that part waits.
#[test]
fn a_part_that_cannot_move_its_due_work_backs_off_and_progress_resets_it() {
    let mut stalls = 0;
    let mut waits = Vec::new();
    for _ in 0..6 {
        let (s, wait) = after_part(stalls, true, true, false);
        stalls = s;
        waits.push(wait.expect("a stall always waits"));
    }
    assert_eq!(waits, [5_000, 30_000, 120_000, 600_000, 3_600_000, 3_600_000]);
    assert_eq!(after_part(stalls, true, true, true), (0, None), "it moved: back to at once");
    assert_eq!(after_part(3, true, false, false), (3, None), "not given its turn: no stall");
    assert_eq!(after_part(3, false, true, false), (3, None), "nothing was due");
}

#[test]
fn the_round_holds_each_part_on_its_own() {
    let src = include_str!("builtin.rs");
    let body = |name: &str| {
        let f = &src[src.find(&format!("fn {name}(")).unwrap()..];
        &f[..f.find("\n    }\n").unwrap()]
    };
    assert!(body("bot_builtin_next").contains("self.builtin_parts_next()"));
    for k in ["KV_UPDATES_HOLD", "KV_JOBS_HOLD"] {
        assert!(body("builtin_parts_next").contains(k), "the alarm ignores {k}");
    }
    let round = include_str!("builtin_run.rs");
    let round = &round[round.find("async fn bot_builtin_round(").unwrap()..];
    let round = &round[..round.find("\n    }\n").unwrap()];
    for f in ["jobs_go_first(", "next_jobs_turn(", "after_part("] {
        assert!(round.contains(f), "the round does not ask {f}");
    }
    // `/bot/wake` and an owner's set (the owner's own actions) end both waits at once.
    assert!(body("bot_wake").contains("PART_WAITS"));
    let set = body("bot_builtin_set");
    assert!(set.find("bs::GEN_BUMP").unwrap() < set.find("PART_WAITS").unwrap());
    let waits = &src[src.find("const PART_WAITS").unwrap()..];
    let waits = &waits[..waits.find("];").unwrap()];
    for k in ["KV_UPDATES_HOLD", "KV_UPDATES_STALLS", "KV_JOBS_HOLD", "KV_JOBS_STALLS"] {
        assert!(waits.contains(k), "{k} outlives the owner's action");
    }
}

#[test]
fn a_hearings_member_is_let_in_before_any_text_of_theirs_settles_a_row() {
    // Adversarial review 2026-10-27: an "evet" was read before `allowed_room`, so a member removed
    // from the room could still confirm the row proposed to them in the 10-minute window.
    let src = include_str!("builtin_hearings.rs");
    let start = src.find("pub(super) async fn builtin_hearings(").expect("the round's entry");
    let rest = &src[start..];
    let body = &rest[..rest[1..].find("\n    /// ").map_or(rest.len(), |i| i + 1)];
    let check = body.find("group_role(").expect("the round asks the room");
    let settle = body.find("self.hearings_settle(").expect("and settles a waiting row");
    assert!(check < settle, "membership is asked before a yes or no is read");
    // A member turned away loses the row waiting for them, and hears the usual line.
    let refused = &body[body.find("Ok(false) => {").expect("the refusal arm")..];
    let refused = &refused[..refused.find("Ok(true)").unwrap()];
    assert!(refused.contains("PROPOSAL_DROP"), "a refused member's proposal is dropped");
    assert!(refused.contains("Line::HearingsNotAllowed"));
    // The check and that line fit before the round commits to either.
    assert_eq!(HEARINGS_GATE_BASE, ROOM_CHECK + SAY_BASE);
    assert!(HEARINGS_GATE_BASE <= HEARINGS_BASE && fits(0, HEARINGS_BASE));
}
