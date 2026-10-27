//! The per-member cap on a program bot's queue, on rusqlite through the DO's own `Exec`.

use super::super::deliver::{SRC_DROP, SRC_PUT};
use super::super::store::tests::Lite;
use super::super::store::TABLES as BOT_TABLES;
use super::super::updates::UPDATE_PUSH;
use super::*;
use rusqlite::Connection;

const T0: i64 = 1_761_200_000_000;

fn db() -> Lite {
    let c = Connection::open_in_memory().unwrap();
    for t in BOT_TABLES.iter().chain(TABLES.iter()) {
        c.execute_batch(t).unwrap();
    }
    Lite(c)
}

/// What `bot_open_frames` does with an admitted update: the row and its source.
fn queue(db: &Lite, from: &str, now: i64) -> i64 {
    let id = db.int(UPDATE_PUSH, &[Arg::T("{}"), Arg::I(now)]).unwrap();
    db.run(SRC_PUT, &[Arg::I(id), Arg::T(from), Arg::I(id), Arg::T("m")]);
    id
}

/// One member flooding a bot: before, every message was queued and everybody else waited behind
/// all of them.
#[test]
fn a_member_has_at_most_a_hundred_waiting_and_everybody_else_is_still_queued() {
    let db = db();
    for i in 0..PER_SENDER {
        assert_eq!(admit(&db, "flood", T0 + i, true), Verdict::Queue, "message {i}");
        queue(&db, "flood", T0 + i);
    }
    let refused = admit(&db, "flood", T0 + 200, true);
    assert_eq!(refused, Verdict::Refused { code: "bot/sender-backlog", tell: true });
    assert_eq!(admit(&db, "alice", T0 + 200, true), Verdict::Queue, "another member is not held by it");
    // Told once per window, not once per message.
    let again = admit(&db, "flood", T0 + 300, true);
    assert_eq!(again, Verdict::Refused { code: "bot/sender-backlog", tell: false });
    let later = admit(&db, "flood", T0 + 200 + NOTICE_EVERY_MS, true);
    assert_eq!(later, Verdict::Refused { code: "bot/sender-backlog", tell: true }, "a new window, told again");
}

#[test]
fn what_the_program_takes_frees_the_members_slots() {
    let db = db();
    let ids: Vec<i64> = (0..PER_SENDER).map(|i| queue(&db, "m", T0 + i)).collect();
    assert!(matches!(admit(&db, "m", T0 + 200, true), Verdict::Refused { .. }));
    // A poll or a webhook took the first ten: their sources go (`bot_updates_taken`).
    db.run(SRC_DROP, &[Arg::I(ids[0]), Arg::I(ids[9])]);
    assert_eq!(admit(&db, "m", T0 + 300, true), Verdict::Queue);
}

#[test]
fn the_bots_whole_store_is_capped_for_everybody() {
    let db = db();
    for i in 0..PER_BOT {
        queue(&db, &format!("u{}", i % 40), T0);
    }
    assert_eq!(admit(&db, "fresh", T0 + 1, true), Verdict::Refused { code: "bot/queue-full", tell: true });
    // Handed out but not yet confirmed still takes storage.
    db.run(SRC_DROP, &[Arg::I(1), Arg::I(PER_BOT)]);
    assert!(matches!(admit(&db, "fresh2", T0 + 1, true), Verdict::Refused { code: "bot/queue-full", .. }));
    db.run("DELETE FROM bot_updates WHERE update_id <= 10", &[]);
    assert_eq!(admit(&db, "fresh2", T0 + 2, true), Verdict::Queue);
}

/// A refusal past the tick's notices is not marked told, so the member's next refusal tells them.
#[test]
fn a_refusal_that_cannot_be_told_now_is_told_next_time() {
    let db = db();
    for i in 0..PER_SENDER {
        queue(&db, "m", T0 + i);
    }
    assert_eq!(admit(&db, "m", T0 + 200, false), Verdict::Refused { code: "bot/sender-backlog", tell: false });
    assert_eq!(admit(&db, "m", T0 + 300, true), Verdict::Refused { code: "bot/sender-backlog", tell: true });
    // The send that did not fit gives the notice back (`bot_say_busy`).
    db.run(NOTICE_FORGET, &[Arg::T("m")]);
    assert_eq!(admit(&db, "m", T0 + 400, true), Verdict::Refused { code: "bot/sender-backlog", tell: true });
    db.run(NOTICE_EXPIRE, &[Arg::I(T0 + 400)]);
    assert_eq!(db.int("SELECT COUNT(*) FROM bot_backlog_notice", &[]), Some(0));
}

#[test]
fn the_member_is_told_in_their_language_or_in_both() {
    assert_eq!(lang_of(Some("tr")), Some(Lang::Tr));
    assert_eq!(lang_of(Some("tr-TR")), Some(Lang::Tr));
    assert_eq!(lang_of(Some("EN-gb")), Some(Lang::En));
    assert_eq!(lang_of(Some("de")), None);
    assert_eq!(lang_of(None), None);
    let (tr, en) = (line(Lang::Tr, Line::ProgramBusy), line(Lang::En, Line::ProgramBusy));
    assert_eq!(notice(Some(Lang::Tr)), tr);
    assert_eq!(notice(Some(Lang::En)), en);
    let both = notice(None);
    assert!(both.contains(tr) && both.contains(en));
    // Honest: it says the program did not get it, never that it read it.
    assert!(en.contains("not passed on"));
}

/// The cap stands between a member's frame and its update, in both arms, and only for a program
/// bot; a refused update leaves no source, so no `forward-read` (blue tick) can follow.
#[test]
fn every_member_update_is_admitted_before_it_is_queued() {
    let src = include_str!("ingest.rs");
    let block = &src[src.find("fn bot_open_frames(").unwrap()..];
    let block = &block[..block.find("\n    }\n").unwrap()];
    assert!(block.contains("builtin_config().is_none()"), "the cap is a program bot's");
    for arm in ["Inbound::Text {", "Inbound::Call {"] {
        let a = &block[block.find(arm).expect(arm)..];
        let push = a.find("bot_push_update(").expect("push");
        let admit = a.find("admit_member_update(").unwrap_or(usize::MAX);
        assert!(admit < push, "{arm} queues before it asks the cap");
    }
    let tick = &src[src.find("async fn bot_tick_inner(").unwrap()..];
    assert!(tick.contains("bot_say_busy("), "a refused member is never told");
    assert!(include_str!("send.rs").contains("backlog::NOTICE_EXPIRE"));
}

/// A program that polls but never sends `offset` confirms nothing: what it was handed stays
/// stored for 24 h, the bot's 2,000 fill, and every member hears the program is busy while the
/// owner's page showed nothing wrong — the program was seen, nothing waited unhanded (review
/// 2026-10-27, #19). The full queue is said, with how much of it the program has but never
/// confirmed.
#[test]
fn a_full_queue_is_shown_to_the_owner_with_what_the_program_never_confirmed() {
    let db = db();
    for i in 0..PER_BOT - 1 {
        queue(&db, if i % 2 == 0 { "a" } else { "b" }, T0);
    }
    assert!(!backlog_full(&db), "one short of the cap");
    db.0.execute("UPDATE bot_updates SET delivered_at = ?1", [T0]).unwrap();
    assert_eq!(unconfirmed(&db), PER_BOT - 1, "handed out, never confirmed");
    queue(&db, "c", T0);
    assert!(backlog_full(&db));
    assert!(matches!(admit(&db, "d", T0, false), Verdict::Refused { code: "bot/queue-full", .. }), "the same line");
    // `/bot/state` says it, and the owner's listing carries it.
    let state = include_str!("mod.rs");
    let state = &state[state.find("fn bot_state(").unwrap()..];
    let state = &state[..state.find("\n    }\n").unwrap()];
    assert!(state.contains("\"backlog_full\": backlog::backlog_full(&s.db)"));
    assert!(state.contains("\"unconfirmed\": backlog::unconfirmed(&s.db)"));
    let admin = include_str!("../../../bots/admin.rs");
    assert!(admin.contains("v[\"backlog_full\"] = state.backlog_full.into();"));
    assert!(admin.contains("v[\"unconfirmed\"] = state.unconfirmed.into();"));
}
