use super::*;

/// H8: an AI bot's model call is refused past the member's own 50 a day, and past the bot's
/// `daily_calls` for every member together — a day whose total could not be read counts as
/// spent (fails closed), never as free.
#[test]
fn a_model_call_waits_for_the_members_and_the_bots_day() {
    assert_eq!(ai_limit(0, 0, 500), None);
    assert_eq!(ai_limit(bs::DAILY_CALLS - 1, 499, 500), None);
    assert_eq!(ai_limit(bs::DAILY_CALLS, 0, 500), Some(Line::DailyLimit), "the member's own first");
    assert_eq!(ai_limit(0, 500, 500), Some(Line::BotDailyLimit), "every member together");
    assert_eq!(ai_limit(3, 2, 2), Some(Line::BotDailyLimit), "an owner's low cap holds");
    assert_eq!(ai_limit(0, i64::MAX, 500), Some(Line::BotDailyLimit), "an unread day is a spent one");
}

/// The round reads the day's total before it calls the model, and fails closed when it cannot.
#[test]
fn the_round_reads_the_bots_day_before_it_spends_a_call() {
    let code = include_str!("builtin_run.rs");
    let read = code.find("bs::USAGE_DAY_TOTAL").expect("the round reads the bot's day");
    let gate = code.find("ai_limit(").expect("the round asks the gate");
    let bump = code.find("bs::USAGE_BUMP").expect("the round counts its call");
    assert!(read < gate && gate < bump, "read, judge, then count and call");
    assert!(code.contains("USAGE_DAY_TOTAL, &[Arg::I(day)]).unwrap_or(i64::MAX)"), "fails closed");
}
