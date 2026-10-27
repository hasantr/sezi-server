//! The room posts' round run whole on rusqlite, against simulated attempts and a clock that moves
//! as the room round's own wait says: a poison post is set aside and the posts behind it go on; a
//! room path that is down sets nothing aside.

use super::super::room_plan::wait_after_stall;
use super::super::room_store::{POSTS_WAITING, POST_DONE, POST_NEXT, POST_PUSH, TABLES as ROOM_TABLES};
use super::super::store::tests::Lite;
use super::super::store::TABLES as BOT_TABLES;
use super::*;
use rusqlite::Connection;
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

/// A bot inbox's room posts, attempts that fail where `fails` says, and a clock.
struct Sim {
    db: Lite,
    clock: Cell<i64>,
    fails: Box<dyn Fn(i64) -> bool>,
    /// Every attempt: (when, post, failed).
    attempts: RefCell<Vec<(i64, i64, bool)>>,
    stalls: Cell<i64>,
}

impl Sim {
    fn new(fails: impl Fn(i64) -> bool + 'static) -> Sim {
        let c = Connection::open_in_memory().unwrap();
        for t in BOT_TABLES.iter().chain(ROOM_TABLES.iter()) {
            c.execute_batch(t).unwrap();
        }
        Sim { db: Lite(c), clock: Cell::new(T0), fails: Box::new(fails), attempts: RefCell::default(), stalls: Cell::new(0) }
    }

    fn post(&self) {
        self.db.run(POST_PUSH, &[Arg::T("r"), Arg::T("{}"), Arg::I(self.clock.get())]);
    }

    /// One room round, as `bot_room_round` drives it, with the budget for `per_round` attempts.
    fn round(&self, per_round: usize) -> Round {
        let left = Cell::new(per_round);
        let next = |tried: &str| -> Option<(i64, i64)> {
            if left.get() == 0 {
                return None;
            }
            left.set(left.get() - 1);
            let id: i64 = self.db.0.query_row(POST_NEXT, rusqlite::params![self.clock.get(), tried], |r| r.get(0)).ok()?;
            Some((id, id))
        };
        block_on(post_round(&self.db, || self.clock.get(), next, |id| {
            let failed = (self.fails)(id);
            self.attempts.borrow_mut().push((self.clock.get(), id, failed));
            if !failed {
                self.db.run(POST_DONE, &[Arg::I(id)]);
            }
            std::future::ready(if failed { Attempt::Failed } else { Attempt::Moved })
        }))
    }

    /// Run the alarm until `end`, each round at the time the last one's wait asked for.
    fn run_until(&self, end: i64) {
        while self.clock.get() < end {
            let r = self.round(10);
            let waiting = self.db.int(POSTS_WAITING, &[Arg::I(self.clock.get())]).unwrap() > 0;
            let (wait, stalls) = wait_after_stall(waiting, r.progressed && !r.failed, r.held, true, self.stalls.get());
            self.stalls.set(stalls);
            let next_aside: Option<i64> =
                self.db.0.query_row(super::super::room_store::ASIDE_NEXT, [], |r| r.get(0)).unwrap();
            let at = match (wait, next_aside) {
                (Some(ms), _) => self.clock.get() + ms.max(1),
                (None, Some(t)) => t.max(self.clock.get() + 1),
                (None, None) => break,
            };
            self.clock.set(at.min(end));
        }
    }

    fn moved(&self) -> Vec<i64> {
        self.attempts.borrow().iter().filter(|a| !a.2).map(|a| a.1).collect()
    }

    fn aside(&self) -> i64 {
        self.db.0.query_row("SELECT COUNT(*) FROM bot_room_post_fail WHERE aside = 1", [], |r| r.get(0)).unwrap()
    }
}

/// One room post that could never be made held every other room post for its whole 24 h
/// (review 2026-10-27, #20).
#[test]
fn a_poison_post_is_set_aside_and_the_posts_behind_it_go_on() {
    let sim = Sim::new(|id| id == 1);
    for _ in 0..4 {
        sim.post();
    }
    sim.run_until(T0 + 30 * MIN);
    assert_eq!(sim.moved(), [2, 3, 4], "in order, behind the one set aside");
    assert_eq!(sim.aside(), 1);
    let fifth = sim.attempts.borrow().iter().filter(|a| a.1 == 1).nth(ASIDE_AFTER as usize - 1).unwrap().0;
    assert!(fifth - T0 < 20 * MIN, "set aside at its fifth failure, minutes in");
    // On its own from then on: hourly, and a post written later is not held by it.
    sim.post();
    sim.run_until(T0 + 5 * HOUR);
    assert_eq!(sim.moved(), [2, 3, 4, 5]);
    let tries_after = sim.attempts.borrow().iter().filter(|a| a.1 == 1 && a.0 > T0 + HOUR).count();
    assert!((3..=5).contains(&tries_after), "about hourly: {tries_after}");
}

/// D1 or the engine failing fails every post: that is not one post, and nothing is set aside.
#[test]
fn a_room_path_that_is_down_sets_nothing_aside() {
    let down = std::rc::Rc::new(Cell::new(true));
    let d = down.clone();
    let sim = Sim::new(move |_| d.get());
    for _ in 0..3 {
        sim.post();
    }
    sim.run_until(T0 + 6 * HOUR);
    assert!(sim.moved().is_empty());
    assert_eq!(sim.aside(), 0, "the probe failed too, every time");
    let late = sim.attempts.borrow().iter().filter(|a| a.0 > T0 + 5 * HOUR).count();
    assert!(late <= 3, "the head and its probe about hourly, not a try per post: {late}");
    // Back up: everything goes, in order.
    down.set(false);
    sim.run_until(T0 + 8 * HOUR);
    assert_eq!(sim.moved(), [1, 2, 3]);
}

/// Two poison posts in a row: the second is found once it has failed its five as the probe.
#[test]
fn two_poison_posts_in_a_row_are_both_set_aside() {
    let sim = Sim::new(|id| id <= 2);
    for _ in 0..3 {
        sim.post();
    }
    // The second fails as the probe on the round's hourly ladder: five of those, then both go.
    sim.run_until(T0 + 3 * HOUR);
    assert!(sim.moved().is_empty(), "not yet: the probe has not failed its five");
    sim.run_until(T0 + 8 * HOUR);
    assert_eq!(sim.moved(), [3]);
    assert_eq!(sim.aside(), 2);
}

/// The DO's room round is this one, and its alarm knows when a set-aside post is due.
#[test]
fn the_do_drives_this_round() {
    let src = include_str!("room.rs");
    let round = &src[src.find("async fn bot_room_round(").unwrap()..];
    let round = &round[..round.find("\n    }\n").unwrap()];
    assert!(round.contains("room_order::post_round("), "the DO runs its own loop");
    assert!(round.contains("rs::POSTS_WAITING, &[Arg::I(now)]"));
    let next = &src[src.find("fn bot_room_next(").unwrap()..];
    assert!(next[..next.find("\n    }\n").unwrap()].contains("rs::ASIDE_NEXT"));
    let keep = &src[src.find("fn bot_room_housekeeping(").unwrap()..];
    assert!(keep[..keep.find("\n    }\n").unwrap()].contains("room_order::FAIL_ORPHANS"), "failure rows outlive their posts");
}
