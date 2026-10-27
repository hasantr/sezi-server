//! The webhook round run whole on rusqlite, against a simulated endpoint and clock: a poison
//! update is set aside and the queue goes on; an endpoint that is down sets nothing aside and
//! costs a few POSTs an hour, not one per waiting update.

use super::super::deliver::{HOOK_DUE, HOOK_NEXT};
use super::super::store::tests::Lite;
use super::super::store::TABLES as BOT_TABLES;
use super::super::updates::UPDATE_PUSH;
use super::*;
use rusqlite::{params, Connection};
use std::cell::{Cell, RefCell};

const T0: i64 = 1_761_200_000_000;
const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn rows(c: &Connection, query: &str, args: &[i64]) -> Vec<Due> {
    let mut s = c.prepare(query).unwrap();
    s.query_map(rusqlite::params_from_iter(args), |r| {
        Ok(Due { update_id: r.get(0)?, json: r.get(1)?, attempts: r.get(2)?, next_at: r.get(3)? })
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// A bot inbox's webhook queue, an endpoint that refuses what `refuse` says, and a clock.
struct Sim {
    db: Lite,
    clock: Cell<i64>,
    refuse: Box<dyn Fn(i64) -> bool>,
    /// Every POST: (when, update_id, taken).
    posts: RefCell<Vec<(i64, i64, bool)>>,
}

impl Sim {
    fn new(refuse: impl Fn(i64) -> bool + 'static) -> Sim {
        let c = Connection::open_in_memory().unwrap();
        for t in BOT_TABLES.iter().chain(TABLES.iter()) {
            c.execute_batch(t).unwrap();
        }
        Sim { db: Lite(c), clock: Cell::new(T0), refuse: Box::new(refuse), posts: RefCell::default() }
    }

    fn push(&self) -> i64 {
        self.db.0.query_row(UPDATE_PUSH, params!["{\"kind\":\"message\"}", self.clock.get()], |r| r.get(0)).unwrap()
    }

    /// One tick's webhook round, as `bot_deliver_webhooks` drives it.
    fn round(&self) {
        let c = &self.db.0;
        let main = rows(c, HOOK_DUE, &[WEBHOOK_BATCH]);
        let now = self.clock.get();
        let aside = |limit: i64| rows(c, ASIDE_DUE, &[now, limit]);
        block_on(hook_round(&self.db, main, aside, || self.clock.get(), |id, json| {
            assert!(json.contains(&format!("\"update_id\":{id}")), "the POST names its update");
            let taken = !(self.refuse)(id);
            self.posts.borrow_mut().push((self.clock.get(), id, taken));
            std::future::ready(taken)
        }));
    }

    /// Run the alarm until `end`: each tick at the time the queue asks for.
    fn run_until(&self, end: i64) {
        for _ in 0..100_000 {
            let next: Option<i64> = self.db.0.query_row(HOOK_NEXT, [], |r| r.get(0)).unwrap_or(None);
            let Some(next) = next else { break };
            let at = next.max(self.clock.get());
            if at > end {
                break;
            }
            self.clock.set(at);
            let before = self.posts.borrow().len();
            self.round();
            // A tick that POSTed nothing and left the queue due at once would spin the alarm.
            let again: Option<i64> = self.db.0.query_row(HOOK_NEXT, [], |r| r.get(0)).unwrap_or(None);
            if self.posts.borrow().len() == before && again.is_some_and(|t| t <= at) {
                panic!("a hot alarm at {at}: nothing POSTed and the queue is still due");
            }
        }
        self.clock.set(end.max(self.clock.get()));
    }

    fn taken(&self) -> Vec<i64> {
        self.posts.borrow().iter().filter(|p| p.2).map(|p| p.1).collect()
    }

    fn posts_of(&self, id: i64) -> usize {
        self.posts.borrow().iter().filter(|p| p.1 == id).count()
    }

    fn posts_between(&self, from: i64, to: i64) -> usize {
        self.posts.borrow().iter().filter(|p| p.0 >= from && p.0 < to).count()
    }

    fn aside(&self) -> i64 {
        self.db.int(ASIDE_COUNT, &[]).unwrap()
    }
}

/// One update the program always refuses used to hold every later one for its whole 24 hours.
#[test]
fn a_poison_update_is_set_aside_and_the_queue_goes_on_in_order() {
    let sim = Sim::new(|id| id == 1);
    let ids: Vec<i64> = (0..4).map(|_| sim.push()).collect();
    assert_eq!(ids[0], 1);
    sim.run_until(T0 + 20 * MIN);
    assert_eq!(sim.taken(), ids[1..].to_vec(), "the ones behind it arrive, in order");
    assert_eq!(sim.posts_of(ids[0]), ASIDE_AFTER as usize, "set aside at its fifth failure");
    assert_eq!(sim.aside(), 1);
    // About 13 minutes of failing, not an hour: 5 s + 30 s + 2 min + 10 min.
    let freed = sim.posts.borrow().iter().find(|p| p.2).unwrap().0;
    assert_eq!(freed - T0, 5_000 + 30_000 + 120_000 + 600_000);

    // A later update is not held by it.
    sim.clock.set(T0 + 30 * MIN);
    let late = sim.push();
    sim.run_until(T0 + 30 * MIN + 1);
    assert_eq!(sim.taken().last(), Some(&late), "taken at once");

    // The poison keeps its own ladder — hourly — until the 24 h drop.
    sim.run_until(T0 + 24 * HOUR - 1);
    let tries = sim.posts_of(ids[0]);
    assert!((ASIDE_AFTER as usize + 22..=ASIDE_AFTER as usize + 24).contains(&tries), "{tries} tries");
    assert!(!sim.taken().contains(&ids[0]));
}

/// A set-aside update that the program takes in the end is delivered — late, after later ones.
#[test]
fn a_set_aside_update_taken_later_arrives_late_and_leaves_the_aside() {
    let healed = std::rc::Rc::new(Cell::new(false));
    let h = healed.clone();
    let sim = Sim::new(move |id| id == 1 && !h.get());
    let ids: Vec<i64> = (0..3).map(|_| sim.push()).collect();
    sim.run_until(T0 + 20 * MIN);
    assert_eq!(sim.aside(), 1);
    healed.set(true);
    sim.run_until(T0 + 2 * HOUR);
    assert_eq!(sim.taken(), vec![ids[1], ids[2], ids[0]], "update_id order is the program's to restore");
    sim.db.run(ASIDE_ORPHANS, &[]);
    assert_eq!(sim.aside(), 0, "the mark goes with the update");
}

/// An endpoint that is down fails everything: nothing is set aside, and the queue backs off as a
/// whole — a few POSTs an hour, however many updates wait. Setting each failing head aside on its
/// own would have retried every one of them hourly: a storm against an endpoint already down.
#[test]
fn an_endpoint_that_is_down_sets_nothing_aside_and_is_not_stormed() {
    let sim = Sim::new(|_| true);
    for _ in 0..200 {
        sim.push();
    }
    sim.run_until(T0 + 24 * HOUR - 1);
    assert_eq!(sim.aside(), 0, "nothing proved a single update bad");
    assert!(sim.taken().is_empty());
    let last_hour = sim.posts_between(T0 + 23 * HOUR, T0 + 24 * HOUR);
    assert!(last_hour <= 8, "{last_hour} POSTs in the 24th hour");
    let all = sim.posts.borrow().len();
    assert!(all <= 120, "{all} POSTs in a day against a dead endpoint");
}

/// Two poison updates in a row look like an outage until the second has failed its five; then
/// the probe behind them is taken and both are set aside.
#[test]
fn two_poison_updates_in_a_row_are_both_set_aside() {
    let sim = Sim::new(|id| id <= 2);
    let ids: Vec<i64> = (0..4).map(|_| sim.push()).collect();
    sim.run_until(T0 + 6 * HOUR);
    assert_eq!(sim.taken(), ids[2..].to_vec());
    assert_eq!(sim.aside(), 2);
}

#[test]
fn the_alarm_follows_the_queue_head_and_the_earliest_set_aside_update() {
    let sim = Sim::new(|_| false);
    let (a, b) = (sim.push(), sim.push());
    let c = &sim.db.0;
    let next = || -> Option<i64> { c.query_row(HOOK_NEXT, [], |r| r.get(0)).unwrap_or(None) };
    c.execute(HOOK_RETRY, params![50_000, a]).unwrap();
    c.execute(ASIDE_PUT, [a]).unwrap();
    assert_eq!(next(), Some(0), "b heads the queue now, due at once");
    assert_eq!(rows(c, HOOK_DUE, &[10]).iter().map(|d| d.update_id).collect::<Vec<_>>(), vec![b]);
    c.execute(HOOK_DONE, [b]).unwrap();
    assert_eq!(next(), Some(50_000), "only the set-aside one waits");
    assert_eq!(rows(c, ASIDE_DUE, &[49_999, 10]).len(), 0);
    assert_eq!(rows(c, ASIDE_DUE, &[50_000, 10]).len(), 1);
    c.execute(HOOK_DONE, [a]).unwrap();
    assert_eq!(next(), None);
}

/// The DO's round is this one, and a taken update is still "the program has it": the member's
/// `forward-read` (their blue tick) for the set-aside updates as for the rest.
#[test]
fn the_do_drives_this_round_and_marks_what_it_takes_read() {
    let src = include_str!("deliver.rs");
    let round = &src[src.find("async fn bot_deliver_webhooks(").unwrap()..];
    let round = &round[..round.find("\n    }\n").unwrap()];
    assert!(round.contains("hook_round("), "the DO runs its own loop");
    let taken = round.find("webhook::taken(").expect("taken");
    assert!(taken < round.find("bot_updates_taken(").expect("forward-read"));
    assert!(round.contains("ASIDE_DUE"), "set-aside updates are never retried");
    let housekeeping = include_str!("send.rs");
    assert!(housekeeping.contains("ASIDE_ORPHANS"), "marks outlive their updates");
}
