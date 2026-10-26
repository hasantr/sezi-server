//! The built-in tables' SQL on rusqlite (the `deliver_tests` style).

use super::*;
use rusqlite::{params, Connection};

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    for t in super::super::store::TABLES.iter().chain(TABLES.iter()) {
        c.execute_batch(t).unwrap();
    }
    c
}

fn recent(c: &Connection, user: &str, since: i64) -> Vec<(String, String)> {
    let mut s = c.prepare(TURNS_RECENT).unwrap();
    s.query_map(params![user, since, CONTEXT_TURNS * 2], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn the_tables_can_be_created_twice() {
    let c = db();
    for t in TABLES {
        c.execute_batch(t).unwrap();
    }
}

#[test]
fn context_is_the_members_last_ten_turns_oldest_first_and_a_day_long() {
    let c = db();
    for i in 0..15 {
        c.execute(TURN_PUT, params!["alice", "user", format!("q{i}"), 1_000 + i]).unwrap();
        c.execute(TURN_PUT, params!["alice", "assistant", format!("a{i}"), 1_000 + i]).unwrap();
    }
    c.execute(TURN_PUT, params!["bob", "user", "bob's", 1_000]).unwrap();
    let r = recent(&c, "alice", 0);
    assert_eq!(r.len(), 20, "ten turns, two rows each");
    assert_eq!(r[0], ("user".into(), "q5".into()), "oldest first");
    assert_eq!(r[19], ("assistant".into(), "a14".into()));
    assert!(r.iter().all(|(_, t)| t != "bob's"), "one member's context only");
    assert_eq!(recent(&c, "alice", 1_013).len(), 4, "older than the window is not context");

    c.execute(TURNS_TRIM, params!["alice", "alice", CONTEXT_TURNS * 2]).unwrap();
    let n: i64 = c.query_row("SELECT COUNT(*) FROM bot_ai_turns WHERE user_id = 'alice'", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 20);
    c.execute(TURNS_EXPIRE, [1_010]).unwrap();
    assert_eq!(recent(&c, "alice", 0).len(), 10);
    assert!(recent(&c, "bob", 0).is_empty(), "bob's day is over too");
}

#[test]
fn usage_counts_per_member_per_day() {
    let c = db();
    let get = |u: &str, d: i64| -> Option<i64> { c.query_row(USAGE_GET, params![u, d], |r| r.get(0)).ok() };
    assert_eq!(get("alice", 7), None);
    for _ in 0..3 {
        c.execute(USAGE_BUMP, params!["alice", 7]).unwrap();
    }
    c.execute(USAGE_BUMP, params!["alice", 8]).unwrap();
    assert_eq!((get("alice", 7), get("alice", 8), get("bob", 7)), (Some(3), Some(1), None));
    c.execute(USAGE_EXPIRE, [8]).unwrap();
    assert_eq!(get("alice", 7), None);
    assert_eq!(day_of(0), 0);
    assert_eq!(day_of(86_400_000 - 1), 0);
    assert_eq!(day_of(1_761_200_000_000), 20_384);
}

/// An inbox made before rooms gains the columns; on a fresh one the upgrade is a harmless error.
#[test]
fn the_room_columns_reach_old_and_new_tables() {
    let old = Connection::open_in_memory().unwrap();
    old.execute_batch(
        "CREATE TABLE bot_ai_proposals (user_id TEXT PRIMARY KEY, row_json TEXT NOT NULL, text TEXT NOT NULL, at INTEGER NOT NULL);
         CREATE TABLE bot_sheet_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, name TEXT NOT NULL,
           text TEXT NOT NULL, row_json TEXT, at INTEGER NOT NULL, confirm INTEGER NOT NULL DEFAULT 0,
           attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
           told INTEGER NOT NULL DEFAULT 0);",
    )
    .unwrap();
    for u in UPGRADES {
        old.execute_batch(u).unwrap();
    }
    old.execute(JOB_PUSH, params!["a", "A", "t", Option::<String>::None, 1, 0, 1, 1, "{}"]).unwrap();
    let fresh = db();
    for u in UPGRADES {
        assert!(fresh.execute_batch(u).is_err(), "already there");
    }
}

#[test]
fn a_proposal_is_one_per_member_and_lapses_after_ten_minutes() {
    let c = db();
    c.execute(PROPOSAL_PUT, params!["alice", r#"{"a":"1"}"#, "first", 1_000, Option::<String>::None]).unwrap();
    c.execute(PROPOSAL_PUT, params!["alice", r#"{"a":"2"}"#, "second", 2_000, r#"{"id":"g","name":"G","call_uid":"loc-1"}"#]).unwrap();
    let (row, text, at): (String, String, i64) =
        c.query_row(PROPOSAL_GET, ["alice"], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!((row.as_str(), text.as_str(), at), (r#"{"a":"2"}"#, "second", 2_000), "the newest replaces");
    let room: Option<String> = c.query_row(PROPOSAL_GET, ["alice"], |r| r.get(3)).unwrap();
    assert_eq!(room.as_deref(), Some(r#"{"id":"g","name":"G","call_uid":"loc-1"}"#), "and keeps its room");
    assert!(!lapsed(at, at + PROPOSAL_WAIT_MS - 1));
    assert!(lapsed(at, at + PROPOSAL_WAIT_MS));
    c.execute(PROPOSAL_DROP, ["alice"]).unwrap();
    assert!(c.query_row(PROPOSAL_GET, ["alice"], |r| r.get::<_, String>(0)).is_err());
}

#[test]
fn sheet_jobs_go_in_order_and_the_head_holds_the_queue() {
    let c = db();
    let push = |text: &str, at: i64| {
        c.execute(
            JOB_PUSH,
            params!["alice", "Alice", text, Option::<String>::None, at, 0, at, at, Option::<String>::None],
        )
        .unwrap();
    };
    push("one", 1_000);
    push("two", 2_000);
    let due = || -> Vec<(i64, String)> {
        let mut s = c.prepare(JOB_DUE).unwrap();
        s.query_map([5], |r| Ok((r.get(0)?, r.get(3)?))).unwrap().map(Result::unwrap).collect()
    };
    let next = || -> Option<i64> { c.query_row(JOB_NEXT, [], |r| r.get(0)).ok() };
    let jobs = due();
    assert_eq!(jobs.iter().map(|j| j.1.as_str()).collect::<Vec<_>>(), ["one", "two"]);
    assert_eq!(next(), Some(1_000));
    c.execute(JOB_RETRY, params![60_000, jobs[0].0]).unwrap();
    assert_eq!(next(), Some(60_000), "the head's back-off holds the queue");
    c.execute(JOB_DONE, [jobs[0].0]).unwrap();
    assert_eq!(next(), Some(2_000));
    c.execute(JOBS_FORGET, []).unwrap();
    assert_eq!(next(), None);
}

#[test]
fn leaving_ai_mode_forgets_every_member() {
    let c = db();
    c.execute(TURN_PUT, params!["alice", "user", "x", 1]).unwrap();
    c.execute(PROPOSAL_PUT, params!["alice", "{}", "x", 1, Option::<String>::None]).unwrap();
    c.execute(USAGE_BUMP, params!["alice", 1]).unwrap();
    for q in AI_FORGET {
        c.execute(q, []).unwrap();
    }
    let n: i64 = c
        .query_row(
            "SELECT (SELECT COUNT(*) FROM bot_ai_turns) + (SELECT COUNT(*) FROM bot_ai_proposals)
                  + (SELECT COUNT(*) FROM bot_ai_usage)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn the_built_in_reads_the_update_queue_with_its_age() {
    let c = db();
    c.execute(super::super::updates::UPDATE_PUSH.trim_end_matches(" RETURNING update_id"), params!["{}", 5]).unwrap();
    let (id, created): (i64, i64) = c.query_row(UPDATES_DUE, [10], |r| Ok((r.get(0)?, r.get(4)?))).unwrap();
    assert_eq!((id, created), (1, 5));
}

#[test]
fn every_owner_set_moves_the_generation_a_round_checks() {
    let c = db();
    let gen = || -> Option<i64> { c.query_row(GEN_GET, [], |r| r.get(0)).ok() };
    assert_eq!(gen(), None, "never set: the round reads 0");
    c.execute(GEN_BUMP, []).unwrap();
    assert_eq!(gen(), Some(1));
    c.execute(GEN_BUMP, []).unwrap();
    c.execute(GEN_BUMP, []).unwrap();
    assert_eq!(gen(), Some(3));
}

#[test]
fn the_alarm_comes_back_when_the_oldest_memory_is_due_to_go() {
    let c = db();
    let next = || -> Option<i64> {
        c.query_row(EXPIRY_NEXT, params![TURN_TTL_MS, PROPOSAL_KEEP_MS], |r| r.get(0)).unwrap()
    };
    assert_eq!(next(), None, "nothing remembered: no alarm for it");
    c.execute(TURN_PUT, params!["alice", "user", "q", 5_000]).unwrap();
    c.execute(TURN_PUT, params!["bob", "user", "q", 9_000]).unwrap();
    assert_eq!(next(), Some(5_000 + TURN_TTL_MS));
    c.execute(PROPOSAL_PUT, params!["alice", "{}", "t", 1_000, Option::<String>::None]).unwrap();
    assert_eq!(next(), Some(1_000 + PROPOSAL_KEEP_MS), "the earliest of both");
    c.execute(PROPOSALS_FORGET, []).unwrap();
    c.execute(TURNS_EXPIRE, [5_000 + 1]).unwrap();
    assert_eq!(next(), Some(9_000 + TURN_TTL_MS));
}

#[test]
fn authors_behind_a_failing_head_are_told_once_each() {
    let c = db();
    let push = |user: &str| {
        c.execute(JOB_PUSH, params![user, user, "t", Option::<String>::None, 1, 0, 1, 1, Option::<String>::None]).unwrap();
    };
    for u in ["head", "bob", "carol", "bob", "head"] {
        push(u);
    }
    let behind = |head: i64| -> Vec<String> {
        let mut s = c.prepare(JOB_BEHIND_UNTOLD).unwrap();
        s.query_map(params![head, 5], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    // The head's author was told by the failure line itself.
    c.execute(JOB_MARK_TOLD, ["head"]).unwrap();
    assert_eq!(behind(1), vec!["bob".to_string(), "carol".to_string()], "oldest first, one line per author");
    c.execute(JOB_MARK_TOLD, ["bob"]).unwrap();
    assert_eq!(behind(1), vec!["carol".to_string()]);
    let told: i64 = c.query_row("SELECT SUM(told) FROM bot_sheet_jobs", [], |r| r.get(0)).unwrap();
    assert_eq!(told, 4, "every row of a told author: its landing is said late");
}
