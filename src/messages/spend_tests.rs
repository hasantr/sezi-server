//! The subrequest budget, tested by RUNNING the real orchestration under a hard ceiling.
//!
//! The D8 review's F7: the first budget tests replayed a copy of the logic and counted only the
//! fan-out's own spend, so three overruns that shared its invocation went unseen (a cold isolate's
//! provisioning, the lazy drain, the rest of `scheduled()`). Here the REAL functions run —
//! `group_fanout::fan_out_and_close` and `run_hop`, `fanout_retry::drain_with`,
//! `maintenance::upkeep_with` and `cron_with` — against fakes of their seams that charge every
//! subrequest to a `Meter`. The meter refuses the 51st call exactly as the platform would (under
//! the reading the budget assumes: D1, KV and DO calls all count), and a test fails if anything
//! was refused. Failures are injected per member, per hop and per close.
//!
//! What stays outside the run, honestly: the D1/KV calls BEFORE these functions — the send's
//! prelude (`budget::SEND_PRELUDE`), the lazy kick (`LAZY_KICK`) and provisioning — are charged to
//! the meter up front from their constants. Provisioning's own count is pinned by a source guard
//! below (every D1 call in `self_provision.rs` is counted where it is made).

use super::budget::{self, FREE_PLAN_SUBREQUESTS, LAZY_KICK, SEND_PRELUDE};
use super::group_fanout::{
    fan_out_and_close, run_hop, FanoutCalls, GroupMessage, Member, MemberOutcome, RetryStore,
    SendVerdict,
};
use super::handlers::{drain_with, RetryQueue, RetryRow, RowWrite};
use crate::maintenance::{cron_with, upkeep_with, UpkeepPort, DAILY_CRON, FREQUENT_CRON};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;
use worker::{Error, Result};

/// Run a future whose fakes never pend: a poll with a no-op waker is enough.
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// One invocation's subrequests. `tick` refuses past the ceiling, as the platform does.
#[derive(Default)]
struct Meter {
    spent: Cell<usize>,
    refused: Cell<usize>,
    ceiling: usize,
}

impl Meter {
    fn new(ceiling: usize, already: usize) -> Rc<Self> {
        Rc::new(Self { spent: Cell::new(already), refused: Cell::new(0), ceiling })
    }
    fn tick(&self) -> Result<()> {
        if self.spent.get() >= self.ceiling {
            self.refused.set(self.refused.get() + 1);
            return Err(Error::RustError("Too many subrequests".into()));
        }
        self.spent.set(self.spent.get() + 1);
        Ok(())
    }
    fn assert_within(&self, what: &str) {
        assert_eq!(self.refused.get(), 0, "{what}: {} call(s) refused past the ceiling", self.refused.get());
        assert!(self.spent.get() <= self.ceiling, "{what}: spent {}", self.spent.get());
    }
}

/// Every member call, and hops that run the REAL `run_hop` in a fresh invocation of their own.
struct FakeCalls {
    meter: Rc<Meter>,
    /// user → how many of its next calls fail.
    member_faults: RefCell<HashMap<String, usize>>,
    /// How many hop calls fail AFTER their members were reached (the review's F4 shape).
    hop_faults: Cell<usize>,
    /// user → how many times its inbox was reached.
    reached: RefCell<HashMap<String, usize>>,
    /// Every hop invocation's meter, for its own ceiling check.
    hop_meters: RefCell<Vec<Rc<Meter>>>,
}

impl FakeCalls {
    fn new(meter: Rc<Meter>) -> Self {
        Self {
            meter,
            member_faults: RefCell::new(HashMap::new()),
            hop_faults: Cell::new(0),
            reached: RefCell::new(HashMap::new()),
            hop_meters: RefCell::new(Vec::new()),
        }
    }
    fn failing(self, users: &[Member], times: usize) -> Self {
        for m in users {
            self.member_faults.borrow_mut().insert(m.user_id.clone(), times);
        }
        self
    }
    fn reached(&self, user: &str) -> usize {
        self.reached.borrow().get(user).copied().unwrap_or(0)
    }
    fn hops_within(&self) {
        for (i, m) in self.hop_meters.borrow().iter().enumerate() {
            m.assert_within(&format!("hop {i}"));
        }
    }
}

impl FanoutCalls for FakeCalls {
    async fn member(&self, _msg: &GroupMessage, m: &Member) -> Result<i64> {
        self.meter.tick()?;
        let mut faults = self.member_faults.borrow_mut();
        if let Some(n) = faults.get_mut(&m.user_id) {
            if *n > 0 {
                *n -= 1;
                return Err(Error::RustError("injected member failure".into()));
            }
        }
        *self.reached.borrow_mut().entry(m.user_id.clone()).or_default() += 1;
        Ok(1)
    }

    async fn hop(&self, msg: &GroupMessage, chunk: &[Member]) -> Result<Vec<MemberOutcome>> {
        self.meter.tick()?;
        // The hop's own invocation: a fresh purse, the same member faults, the real `run_hop`.
        let hop_meter = Meter::new(FREE_PLAN_SUBREQUESTS, 0);
        self.hop_meters.borrow_mut().push(hop_meter.clone());
        let inner = FakeCalls {
            meter: hop_meter,
            member_faults: RefCell::new(std::mem::take(&mut *self.member_faults.borrow_mut())),
            hop_faults: Cell::new(0),
            reached: RefCell::new(std::mem::take(&mut *self.reached.borrow_mut())),
            hop_meters: RefCell::new(Vec::new()),
        };
        let outcomes = run_hop(&inner, msg, chunk, FREE_PLAN_SUBREQUESTS).await;
        *self.member_faults.borrow_mut() = inner.member_faults.into_inner();
        *self.reached.borrow_mut() = inner.reached.into_inner();
        if self.hop_faults.get() > 0 {
            self.hop_faults.set(self.hop_faults.get() - 1);
            return Err(Error::RustError("injected hop failure after delivery".into()));
        }
        Ok(outcomes)
    }

    async fn pause(&self) {}
}

/// The send's close.
struct FakeStore {
    meter: Rc<Meter>,
    failures: Cell<usize>,
    queued: RefCell<Vec<String>>,
}

impl RetryStore for FakeStore {
    async fn enqueue(&self, _msg: &GroupMessage, members: &[&Member]) -> Result<()> {
        self.meter.tick()?;
        if self.failures.get() > 0 {
            self.failures.set(self.failures.get() - 1);
            return Err(Error::RustError("injected D1 failure".into()));
        }
        self.queued.borrow_mut().extend(members.iter().map(|m| m.user_id.clone()));
        Ok(())
    }
}

/// The retry queue.
struct FakeQueue {
    meter: Rc<Meter>,
    rows: RefCell<Vec<RetryRow>>,
    close_failures: Cell<usize>,
    closed: Cell<usize>,
}

impl RetryQueue for FakeQueue {
    async fn claim(&self, n: usize, _now: i64) -> Result<Vec<RetryRow>> {
        self.meter.tick()?;
        Ok(self.rows.borrow().iter().take(n).cloned().collect())
    }
    async fn close(&self, writes: &[RowWrite]) -> Result<()> {
        self.meter.tick()?;
        if self.close_failures.get() > 0 {
            self.close_failures.set(self.close_failures.get() - 1);
            return Err(Error::RustError("injected D1 failure".into()));
        }
        let gone: Vec<i64> = writes
            .iter()
            .filter_map(|w| if let RowWrite::Delete(id) = w { Some(*id) } else { None })
            .collect();
        self.rows.borrow_mut().retain(|r| !gone.contains(&r.id));
        self.closed.set(self.closed.get() + 1);
        Ok(())
    }
}

/// The upkeep seams; the drain inside runs the REAL `drain_with` on the same meter.
struct FakeUpkeep {
    meter: Rc<Meter>,
    queue: FakeQueue,
    calls: FakeCalls,
    /// Every step that ran, in order — a step is recorded only if its subrequest was granted.
    ran: RefCell<Vec<&'static str>>,
}

impl FakeUpkeep {
    fn new(meter: Rc<Meter>, backlog: usize) -> Self {
        Self {
            queue: FakeQueue {
                meter: meter.clone(),
                rows: RefCell::new(rows(backlog)),
                close_failures: Cell::new(0),
                closed: Cell::new(0),
            },
            calls: FakeCalls::new(meter.clone()),
            meter,
            ran: RefCell::new(Vec::new()),
        }
    }
    fn step(&self, name: &'static str, cost: usize) {
        if (0..cost).all(|_| self.meter.tick().is_ok()) {
            self.ran.borrow_mut().push(name);
        }
    }
    fn ran(&self, name: &str) -> bool {
        self.ran.borrow().contains(&name)
    }
}

impl UpkeepPort for FakeUpkeep {
    async fn read_stamps(&self) -> Option<(i64, i64, i64)> {
        self.step("read_stamps", 1);
        Some((0, i64::MAX / 2, 0)) // drain and move long overdue, daily fresh
    }
    async fn claim(&self, key: &'static str, _now: i64, _cutoff: i64) -> bool {
        self.step(key, 2);
        self.ran(key)
    }
    async fn stamp(&self, key: &'static str) {
        self.step(key, 1);
    }
    async fn drain(&self, purse: usize) {
        let r = drain_with(&self.queue, &self.calls, purse, 0).await;
        if r.closed {
            self.ran.borrow_mut().push("drain_closed");
        }
    }
    async fn purge_outbox(&self) {
        self.step("purge_outbox", 1);
    }
    async fn storage_move(&self) {
        self.step("storage_move", 1);
    }
    async fn daily(&self) {
        self.step("daily", 1);
    }
    fn log(&self, _line: String) {}
}

fn members(n: usize) -> Vec<Member> {
    (0..n)
        .map(|i| Member { user_id: format!("m{i}"), devices: Some(vec![format!("d{i}a"), format!("d{i}b")]) })
        .collect()
}

fn rows(n: usize) -> Vec<RetryRow> {
    (0..n)
        .map(|i| RetryRow {
            id: i as i64,
            recipient_id: format!("q{i}"),
            recipient_device: None,
            recipient_devices: Some(r#"["a","b"]"#.into()),
            sender_id: "s".into(),
            sender_device: Some("sd".into()),
            envelope_b64: "e".into(),
            group_id: "g".into(),
            attempts: 0,
            silent: 0,
        })
        .collect()
}

fn message() -> GroupMessage {
    GroupMessage {
        sender_id: "s".into(),
        sender_device_id: "sd".into(),
        envelope_b64: "e".into(),
        group_id: "g".into(),
        silent: false,
    }
}

/// One group send: the prelude, provisioning and the lazy kick charged up front, then the REAL
/// fan-out and close.
fn send(room: &[Member], provision: usize, calls: impl FnOnce(Rc<Meter>) -> FakeCalls, store_failures: usize)
    -> (SendVerdict, Rc<Meter>, FakeCalls, FakeStore) {
    let meter = Meter::new(FREE_PLAN_SUBREQUESTS, provision + SEND_PRELUDE + LAZY_KICK);
    let calls = calls(meter.clone());
    let store = FakeStore { meter: meter.clone(), failures: Cell::new(store_failures), queued: RefCell::new(vec![]) };
    let verdict = block_on(fan_out_and_close(
        &calls,
        &store,
        &message(),
        room,
        FREE_PLAN_SUBREQUESTS,
        budget::send_reserved(provision),
    ));
    (verdict, meter, calls, store)
}

// ---- The critic's three cases (7b3653e9), now on the real paths ----

/// A cold isolate sending to a 30-member room, 7 of whom fail every attempt: the failures are
/// queued, the close lands inside the ceiling, and the send says so. Both a deployment with
/// secrets (3 D1 to provision) and a secretless fork (≈7) are covered.
#[test]
fn critic_a_cold_isolate_group_send_still_reaches_its_closing_batch() {
    let room = members(30);
    for provision in [0, 3, 7, 11] {
        let (verdict, meter, calls, store) =
            send(&room, provision, |m| FakeCalls::new(m).failing(&room[..7], usize::MAX), 0);
        meter.assert_within(&format!("sender, provision {provision}"));
        calls.hops_within();
        assert_eq!(verdict, SendVerdict::Sent { first_id: Some(1), queued: 7 }, "provision {provision}");
        assert_eq!(store.queued.borrow().len(), 7, "provision {provision}: the 7 are in the queue");
    }
}

/// The lazy drain on a backlog larger than one run: it closes inside its own invocation, and the
/// purge outbox and the move tick after it still run.
#[test]
fn critic_the_lazy_drain_closes_inside_its_invocation() {
    let meter = Meter::new(FREE_PLAN_SUBREQUESTS, 0);
    let up = FakeUpkeep::new(meter.clone(), 120);
    block_on(upkeep_with(&up, FREE_PLAN_SUBREQUESTS, 1_000_000));
    meter.assert_within("upkeep DO");
    assert!(up.ran("drain_closed"), "the drain's close landed: {:?}", up.ran.borrow());
    assert!(up.ran("purge_outbox") && up.ran("storage_move"), "{:?}", up.ran.borrow());
    assert!(up.queue.rows.borrow().len() < 120, "the backlog shrank");
}

/// The cron drain on a full backlog leaves room for the rest of `scheduled()`, on a cold isolate.
#[test]
fn critic_the_cron_drain_leaves_room_for_the_rest_of_scheduled() {
    for provision in [0, 3, 7] {
        let meter = Meter::new(FREE_PLAN_SUBREQUESTS, provision);
        let up = FakeUpkeep::new(meter.clone(), 120);
        block_on(cron_with(&up, FREE_PLAN_SUBREQUESTS, provision, FREQUENT_CRON));
        meter.assert_within(&format!("cron, provision {provision}"));
        for step in ["maint_drain_at", "drain_closed", "purge_outbox", "storage_move", "maint_storage_move_at"] {
            assert!(up.ran(step), "provision {provision}: {step} did not run: {:?}", up.ran.borrow());
        }
    }
}

// ---- The rest of the shape, with failures injected ----

/// An asleep 80 × 2 class: all reached in the send, two hops, no invocation over the ceiling.
#[test]
fn an_80_member_class_is_reached_in_the_send() {
    let room = members(80);
    let (verdict, meter, calls, _) = send(&room, 0, FakeCalls::new, 0);
    meter.assert_within("sender");
    calls.hops_within();
    assert_eq!(verdict, SendVerdict::Sent { first_id: Some(1), queued: 0 });
    assert!(room.iter().all(|m| calls.reached(&m.user_id) == 1));
}

/// The 256-member cap on a cold, secretless isolate, every member failing its first attempt: no
/// invocation goes over, and every member is either reached or queued — none is lost. Retries are
/// capped at a fifth of a purse, so most of this pathological room goes to the drain, which is
/// the design: the in-request retry is for a hiccup, the queue for an outage.
#[test]
fn the_member_cap_cold_with_every_call_failing_once() {
    let room = members(256);
    let (verdict, meter, calls, store) = send(&room, 11, |m| FakeCalls::new(m).failing(&room, 1), 0);
    meter.assert_within("sender");
    calls.hops_within();
    let reached = room.iter().filter(|m| calls.reached(&m.user_id) == 1).count();
    let queued = store.queued.borrow().len();
    assert_eq!(verdict, SendVerdict::Sent { first_id: Some(1), queued });
    assert_eq!(reached + queued, 256, "reached {reached}, queued {queued}");
}

/// The same room, every member healthy: nothing deferred even when the isolate is cold.
#[test]
fn the_member_cap_cold_and_healthy_is_reached_in_the_send() {
    let room = members(256);
    let (verdict, meter, calls, _) = send(&room, 11, FakeCalls::new, 0);
    meter.assert_within("sender");
    calls.hops_within();
    assert_eq!(verdict, SendVerdict::Sent { first_id: Some(1), queued: 0 });
}

/// A hop that reaches its members and then fails (its answer lost): the sender retries the hop,
/// the members are reached a second time — which the inbox's dedup turns into no second row and
/// no second wake (`member_notify.rs`) — and nobody is lost.
#[test]
fn a_hop_that_fails_after_delivery_loses_nobody() {
    let room = members(80);
    let (verdict, meter, calls, _) = send(&room, 0, |m| {
        let c = FakeCalls::new(m);
        c.hop_faults.set(1);
        c
    }, 0);
    meter.assert_within("sender");
    calls.hops_within();
    assert_eq!(verdict, SendVerdict::Sent { first_id: Some(1), queued: 0 });
    let twice = room.iter().filter(|m| calls.reached(&m.user_id) == 2).count();
    assert_eq!(twice, 40, "the failed hop's chunk was re-sent once");
}

/// A close that fails once is retried and lands; one that fails twice is NOT acknowledged.
#[test]
fn a_failed_close_is_retried_and_never_swallowed() {
    let room = members(10);
    let (once, meter, _, store) = send(&room, 0, |m| FakeCalls::new(m).failing(&room[..3], usize::MAX), 1);
    meter.assert_within("close retried");
    assert_eq!(once, SendVerdict::Sent { first_id: Some(1), queued: 3 });
    assert_eq!(store.queued.borrow().len(), 3);
    let (twice, meter, _, _) = send(&room, 0, |m| FakeCalls::new(m).failing(&room[..3], usize::MAX), 2);
    meter.assert_within("close failed twice");
    assert_eq!(twice, SendVerdict::NotRecorded { queued: 3 }, "the sender must be told to resend");
}

/// Every member failing: a 502, nothing queued (the sender resends the whole message).
#[test]
fn a_total_failure_is_a_retryable_502() {
    let room = members(10);
    let (verdict, meter, _, store) = send(&room, 0, |m| FakeCalls::new(m).failing(&room, usize::MAX), 0);
    meter.assert_within("total failure");
    assert_eq!(verdict, SendVerdict::AllFailed);
    assert!(store.queued.borrow().is_empty());
}

/// The drain with failing rows backs them off, and a close that fails once still lands.
#[test]
fn the_drain_backs_off_failures_and_retries_its_close() {
    let meter = Meter::new(FREE_PLAN_SUBREQUESTS, 0);
    let queue = FakeQueue { meter: meter.clone(), rows: RefCell::new(rows(20)), close_failures: Cell::new(1), closed: Cell::new(0) };
    let failing: Vec<Member> = (0..5).map(|i| Member { user_id: format!("q{i}"), devices: None }).collect();
    let calls = FakeCalls::new(meter.clone()).failing(&failing, usize::MAX);
    let r = block_on(drain_with(&queue, &calls, FREE_PLAN_SUBREQUESTS, 0));
    meter.assert_within("drain");
    assert_eq!((r.claimed, r.delivered, r.failed, r.closed), (20, 15, 5, true));
    assert_eq!(queue.rows.borrow().len(), 5, "the failed rows stay, backed off");
}

/// The daily cron does not drain: the heavy daily set gets the invocation.
#[test]
fn the_daily_cron_leaves_the_drain_to_the_frequent_one() {
    let meter = Meter::new(FREE_PLAN_SUBREQUESTS, 3);
    let up = FakeUpkeep::new(meter.clone(), 120);
    block_on(cron_with(&up, FREE_PLAN_SUBREQUESTS, 3, DAILY_CRON));
    meter.assert_within("daily cron");
    assert!(!up.ran("maint_drain_at") && up.ran("daily") && up.ran("maint_daily_at"));
    assert_eq!(meter.spent.get(), 3 + 4, "provisioning, the move tick and its stamp, daily and its stamp");
}

/// Provisioning is charged by count, so every D1 call in `self_provision.rs` must be counted where
/// it is made: one `spent()` per call site.
#[test]
fn every_provisioning_d1_call_is_counted() {
    const SRC: &str = include_str!("../self_provision.rs");
    let code = SRC.split("#[cfg(test)]").next().unwrap();
    let calls = [".run()", ".first(None)", ".all()", "db.batch("]
        .iter()
        .map(|p| code.matches(p).count())
        .sum::<usize>();
    let counted = code.matches("    spent();").count();
    assert_eq!(calls, counted, "a D1 call in self_provision.rs is not charged to the budget");
}

// ---- A member's wake, inside its own inbox DO's invocation (K8 adds the relay fallback) ----

/// The REAL `push::wake::wake_with`, every subrequest charged (config, tokens, the OAuth mint on a
/// cold isolate, each send, each resend, each delete, each verdict write), with the most devices
/// an account may have, in every shape the K8 fallback can take. Each fits the budget's bound,
/// which the compile-time check in `budget.rs` holds under half the ceiling.
#[test]
fn a_members_wake_with_the_relay_fallback_fits_its_bound() {
    use crate::push::wake::tests::{first_own_build, mismatch, relay_ok, relay_stale, sent, FakeWake};
    let n = crate::devices::handlers::MAX_DEVICES;
    let bound = budget::MEMBER_WAKE_FIXED + n * budget::MEMBER_WAKE_PER_DEVICE;
    let relay_off = |f: FakeWake| {
        f.cfg.borrow_mut().relay_url = None;
        f
    };
    let cases: Vec<(&str, FakeWake)> = vec![
        ("every device sent", FakeWake::own(n, sent, relay_ok)),
        ("refused, relayed and marked", FakeWake::own(n, mismatch, relay_ok)),
        ("refused, relay says stale", FakeWake::own(n, mismatch, relay_stale)),
        ("one reached, the rest refused, relayed and marked", FakeWake::own(n, first_own_build, relay_ok)),
        ("one reached, the rest refused and stale", FakeWake::own(n, first_own_build, relay_stale)),
        ("one reached, the rest refused, relay off", relay_off(FakeWake::own(n, first_own_build, relay_ok))),
    ];
    for (what, f) in cases {
        // The first wake (direct, relay, mark) and the next (straight to the relay).
        for wake in ["first", "second"] {
            f.spent.set(0);
            f.wake();
            assert!(f.spent.get() <= bound, "{what}, {wake} wake: spent {} > {bound}", f.spent.get());
        }
    }
}
