//! The bot inbox's SQL, run on rusqlite in the `dedup_sql_tests` style (`message.rs`): the same
//! `TABLES` and the same statement sequences the DO runs, through the same `SqlBotStore`, with a
//! rusqlite `Exec` in place of the DO's `SqlStorage`.

use super::*;
use rusqlite::{types::Value, Connection};
use sezi_bot_engine::BotStore;

pub(in crate::messages::inbox_do::bot) struct Lite(pub(in crate::messages::inbox_do::bot) Connection);

#[path = "engine_tests.rs"]
mod engine;

fn values(args: &[Arg<'_>]) -> Vec<Value> {
    args.iter()
        .map(|a| match a {
            Arg::T(s) => Value::Text(s.to_string()),
            Arg::I(n) => Value::Integer(*n),
            Arg::Null => Value::Null,
        })
        .collect()
}

impl Exec for Lite {
    fn run(&self, query: &str, args: &[Arg<'_>]) {
        self.0
            .execute(query, rusqlite::params_from_iter(values(args)))
            .unwrap_or_else(|e| panic!("{query}: {e}"));
    }

    fn texts(&self, query: &str, args: &[Arg<'_>]) -> Vec<String> {
        let mut stmt = self.0.prepare(query).unwrap();
        stmt.query_map(rusqlite::params_from_iter(values(args)), |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn int(&self, query: &str, args: &[Arg<'_>]) -> Option<i64> {
        let mut stmt = self.0.prepare(query).unwrap();
        let mut rows = stmt.query(rusqlite::params_from_iter(values(args))).unwrap();
        rows.next().unwrap().map(|r| r.get::<_, i64>(0).unwrap())
    }
}

fn store() -> SqlBotStore<Lite> {
    let c = Connection::open_in_memory().unwrap();
    for t in TABLES {
        c.execute_batch(t).unwrap();
    }
    SqlBotStore { db: Lite(c) }
}

#[test]
fn the_tables_can_be_created_twice() {
    let s = store();
    for t in TABLES {
        s.db.0.execute_batch(t).unwrap();
    }
}

#[test]
fn a_new_session_pushes_the_old_ones_into_the_archive_and_the_archive_is_capped() {
    let mut s = store();
    for p in ["s1", "s2", "s3", "s4", "s5", "s6"] {
        s.put_current_session("alice", "devA", p.to_string());
    }
    assert_eq!(
        s.sessions("alice", "devA"),
        vec!["s6", "s5", "s4", "s3"],
        "the current first, then at most three older ones, newest first"
    );
    let slots: Vec<i64> = {
        let mut st = s.db.0.prepare("SELECT slot FROM bot_olm ORDER BY slot").unwrap();
        st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(slots, vec![0, 1, 2, 3], "slots stay contiguous");
}

#[test]
fn a_retired_session_is_archived_with_none_current_until_one_is_promoted() {
    let mut s = store();
    s.put_current_session("alice", "devA", "s1".into());
    s.put_current_session("alice", "devA", "s2".into());
    s.retire_current("alice", "devA");
    assert_eq!(s.current_session("alice", "devA"), None);
    assert_eq!(s.sessions("alice", "devA"), vec!["s2", "s1"], "the archive alone, newest first");
    s.retire_current("alice", "devA"); // nothing current: a no-op
    assert_eq!(s.sessions("alice", "devA"), vec!["s2", "s1"]);
    // With nothing current, index 0 is the archive's first.
    s.promote("alice", "devA", 1, "s1'".into());
    assert_eq!(s.current_session("alice", "devA").as_deref(), Some("s1'"));
    assert_eq!(s.sessions("alice", "devA"), vec!["s1'", "s2"]);
}

/// The DO store and the engine's own `MemStore` agree after the same operations — the engine's
/// tests run on `MemStore`, so this is what lets them speak for the relay.
#[test]
fn the_sql_store_behaves_like_the_engines_mem_store() {
    use sezi_bot_engine::mem::MemStore;
    enum Op {
        Put(&'static str),
        Retire,
        Promote(usize, &'static str),
        Wipe,
    }
    let ops = [
        Op::Put("a"), Op::Retire, Op::Put("b"), Op::Put("c"), Op::Retire, Op::Retire,
        Op::Promote(2, "a+"), Op::Put("d"), Op::Put("e"), Op::Put("f"), Op::Retire,
        Op::Promote(0, "f+"), Op::Promote(3, "c+"), Op::Promote(9, "z"), Op::Retire,
        Op::Put("g"), Op::Wipe, Op::Retire, Op::Put("h"), Op::Promote(0, "h+"),
    ];
    let (mut sql, mut mem) = (store(), MemStore::default());
    for (n, op) in ops.iter().enumerate() {
        for s in [&mut sql as &mut dyn BotStore, &mut mem as &mut dyn BotStore] {
            match op {
                Op::Put(p) => s.put_current_session("u", "d", p.to_string()),
                Op::Retire => s.retire_current("u", "d"),
                Op::Promote(i, p) => s.promote("u", "d", *i, p.to_string()),
                Op::Wipe => s.wipe_user("u"),
            }
        }
        assert_eq!(sql.sessions("u", "d"), mem.sessions("u", "d"), "after op {n}");
        assert_eq!(sql.current_session("u", "d"), mem.current_session("u", "d"), "after op {n}");
    }
}

#[test]
fn sessions_are_kept_per_device_and_per_user() {
    let mut s = store();
    s.put_current_session("alice", "devA", "a1".into());
    s.put_current_session("alice", "devB", "b1".into());
    s.put_current_session("bob", "devA", "x1".into());
    s.put_current_session("alice", "devA", "a2".into());
    assert_eq!(s.sessions("alice", "devA"), vec!["a2", "a1"]);
    assert_eq!(s.sessions("alice", "devB"), vec!["b1"]);
    assert_eq!(s.sessions("bob", "devA"), vec!["x1"]);
}

#[test]
fn promoting_an_archived_session_makes_it_current_and_keeps_the_rest_in_order() {
    let mut s = store();
    for p in ["s1", "s2", "s3", "s4"] {
        s.put_current_session("alice", "devA", p.to_string());
    }
    assert_eq!(s.sessions("alice", "devA"), vec!["s4", "s3", "s2", "s1"]);
    // s2 (index 2) decrypted and advanced to s2'.
    s.promote("alice", "devA", 2, "s2'".into());
    assert_eq!(s.sessions("alice", "devA"), vec!["s2'", "s4", "s3", "s1"]);
    // Promoting the current one replaces it in place.
    s.promote("alice", "devA", 0, "s2''".into());
    assert_eq!(s.sessions("alice", "devA"), vec!["s2''", "s4", "s3", "s1"]);
}

#[test]
fn promoting_an_index_that_is_gone_keeps_the_advanced_session() {
    let mut s = store();
    s.put_current_session("alice", "devA", "s1".into());
    s.promote("alice", "devA", 5, "s9".into());
    assert_eq!(s.sessions("alice", "devA"), vec!["s9", "s1"]);
}

#[test]
fn wiping_a_user_drops_every_device_of_that_user_only() {
    let mut s = store();
    s.put_current_session("alice", "devA", "a".into());
    s.put_current_session("alice", "devB", "b".into());
    s.put_current_session("bob", "devA", "x".into());
    s.wipe_user("alice");
    assert!(s.sessions("alice", "devA").is_empty());
    assert!(s.sessions("alice", "devB").is_empty());
    assert_eq!(s.sessions("bob", "devA"), vec!["x"]);
}

#[test]
fn the_account_and_the_repair_clock_round_trip_and_overwrite() {
    let mut s = store();
    assert_eq!(s.account(), None);
    s.put_account("p1".into());
    s.put_account("p2".into());
    assert_eq!(s.account().as_deref(), Some("p2"));
    assert_eq!(s.last_repair_at("alice"), None);
    s.set_last_repair_at("alice", 1_700_000_000_123);
    s.set_last_repair_at("alice", 1_700_000_020_456);
    assert_eq!(s.last_repair_at("alice"), Some(1_700_000_020_456));
    assert_eq!(s.last_repair_at("bob"), None);
}
