use super::*;
use super::super::store::tests::Lite;

const DAY: i64 = 24 * 3600 * 1000;
const NOW: i64 = 1_800_000_000_000;

fn db() -> Lite {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    for t in super::super::store::TABLES.iter().chain(TABLES.iter()) {
        c.execute_batch(t).unwrap();
    }
    Lite(c)
}

/// D4: the program writes back only to a member who wrote to the bot 1:1 within the window.
#[test]
fn reply_only_lets_the_program_answer_only_who_wrote_lately() {
    let db = db();
    assert!(!may_write(&db, Scope::Reply, "alice", NOW), "never wrote: refused");
    note_writer(&db, "alice", NOW - 29 * DAY);
    assert!(may_write(&db, Scope::Reply, "alice", NOW), "within the window");
    assert!(!may_write(&db, Scope::Reply, "alice", NOW + 2 * DAY), "past it");
    assert!(!may_write(&db, Scope::Reply, "bob", NOW), "one member's message opens no one else");
    // A later message moves the mark forward, an earlier one never back.
    note_writer(&db, "alice", NOW);
    note_writer(&db, "alice", NOW - 40 * DAY);
    assert!(may_write(&db, Scope::Reply, "alice", NOW + 29 * DAY));
}

#[test]
fn the_owners_grant_lifts_the_window() {
    let db = db();
    assert!(may_write(&db, Scope::Anyone, "carol", NOW));
    assert_eq!(Scope::stored(None), Scope::Reply, "the default is the narrow one");
    assert_eq!(Scope::stored(Some("anyone")), Scope::Anyone);
    assert_eq!(Scope::stored(Some("everyone")), Scope::Reply, "an unknown value is not a grant");
    for s in [Scope::Reply, Scope::Anyone] {
        assert_eq!(Scope::parse(s.as_str()), Some(s));
    }
}

/// An inbox from before `bot_writers`: a 1:1 text the program was handed counts, a room call
/// (`<room>/<msg_uid>` in `bot_seen`) does not.
#[test]
fn a_member_seen_before_this_build_still_counts_but_a_room_call_does_not() {
    let db = db();
    db.run(super::super::store::SEEN_PUT, &[Arg::T("dave"), Arg::T("m-1"), Arg::I(NOW - DAY)]);
    db.run(super::super::store::SEEN_PUT, &[Arg::T("erin"), Arg::T("room-1/m-2"), Arg::I(NOW - DAY)]);
    assert!(may_write(&db, Scope::Reply, "dave", NOW));
    assert!(!may_write(&db, Scope::Reply, "erin", NOW), "a room call opens no 1:1");
}

/// The alarm for it is `send.rs` `KEPT_NEXT` (`send_tests.rs`): one past the window, when the
/// tick's expiry deletes it.
#[test]
fn a_writer_row_goes_after_its_window() {
    let db = db();
    note_writer(&db, "alice", NOW);
    let rows = |db: &Lite| db.int("SELECT COUNT(*) FROM bot_writers", &[]).unwrap();
    db.run(WRITER_EXPIRE, &[Arg::I(NOW)]);
    assert_eq!(rows(&db), 1, "kept through its window");
    db.run(WRITER_EXPIRE, &[Arg::I(NOW + 1)]);
    assert_eq!(rows(&db), 0, "gone one past it");
}
