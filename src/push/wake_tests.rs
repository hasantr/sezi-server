//! The wake: its token reads against the real schema, and the REAL `wake_with` loop against a
//! fake port — the K8 fallback above all (a project Google refuses for these phones).

use super::*;

/// A user with ten token rows: five live devices, two revoked ones whose tokens were never
/// deleted (the D8 review's F6), and three older tokens with no device row at all (from before
/// device addressing). What does a device-blind wake read?
fn tokens_read_for_a_blind_wake() -> Vec<String> {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('u', 'u@x', x'00', 1)",
        [],
    )
    .unwrap();
    for i in 0..7 {
        let revoked = if i >= 5 { "1" } else { "NULL" };
        db.execute_batch(&format!(
            "INSERT INTO devices (user_id, device_id, role, ed_pub, x_pub, added_at, revoked_at)
               VALUES ('u', 'd{i}', 'linked', x'00', x'00', 1, {revoked});
             INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at)
               VALUES ('u', 'd{i}', 't{i}', 'android', 1, {i});"
        ))
        .unwrap();
    }
    for i in 0..3 {
        db.execute_batch(&format!(
            "INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at)
               VALUES ('u', 'o{i}', 'old{i}', 'android', 1, -1);"
        ))
        .unwrap();
    }
    let mut stmt = db.prepare(USER_TOKENS_SQL).unwrap();
    stmt.query_map(["u"], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn a_revoked_devices_token_is_not_woken() {
    let tokens = tokens_read_for_a_blind_wake();
    assert!(!tokens.iter().any(|t| t == "t5" || t == "t6"), "{tokens:?}");
}

#[test]
fn a_blind_wake_is_bounded_by_the_device_cap() {
    assert!(tokens_read_for_a_blind_wake().len() <= crate::devices::handlers::MAX_DEVICES);
    assert!(
        USER_TOKENS_SQL.ends_with(&format!("LIMIT {}", crate::devices::handlers::MAX_DEVICES)),
        "the token query's LIMIT and MAX_DEVICES drifted apart"
    );
}

#[test]
fn a_blind_wake_reads_the_newest_live_tokens() {
    assert_eq!(tokens_read_for_a_blind_wake(), ["t4", "t3", "t2", "t1", "t0"]);
}

// ---- The loop, against a fake port ----

use std::cell::{Cell, RefCell};
use std::future::Future;

/// Run a future whose fakes never pend: a poll with a no-op waker is enough.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// A server's push state and its outside world. `record` writes into `cfg`, so a second wake
/// reads what the first one recorded — as D1 would hand it back. Every call is charged to
/// `spent` as the subrequest it is in production, the first direct send with the OAuth mint
/// (KV get, Google, KV put) on top: the worst case, a cold isolate.
pub(crate) struct FakeWake {
    pub(crate) cfg: RefCell<PushConfig>,
    pub(crate) tokens: Vec<TokenRow>,
    pub(crate) direct_answer: fn(&str) -> DirectSend,
    pub(crate) relay_answer: fn(&str) -> Result<bool>,
    pub(crate) calls: RefCell<Vec<String>>,
    pub(crate) spent: Cell<usize>,
    minted: Cell<bool>,
}

pub(crate) const MINT: usize = 3;

impl FakeWake {
    /// A server with its own project set, `n` devices `d0..` with tokens `t0..`, Google answering
    /// `direct` and the relay `relay`.
    pub(crate) fn own(n: usize, direct: fn(&str) -> DirectSend, relay: fn(&str) -> Result<bool>) -> Self {
        Self {
            cfg: RefCell::new(PushConfig {
                project_id: Some("owner-proj".into()),
                service_account: Some("{}".into()),
                relay_url: Some("https://relay".into()),
                rejected: None,
                reached: None,
            }),
            tokens: (0..n)
                .map(|i| TokenRow { device_id: format!("d{i}"), fcm_token: format!("t{i}") })
                .collect(),
            direct_answer: direct,
            relay_answer: relay,
            calls: RefCell::new(Vec::new()),
            spent: Cell::new(0),
            minted: Cell::new(false),
        }
    }
    pub(crate) fn wake(&self) -> WakeTally {
        self.calls.borrow_mut().clear();
        block_on(wake_with(self, "u", None))
    }
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
    fn tick(&self, call: String) {
        self.spent.set(self.spent.get() + 1);
        self.calls.borrow_mut().push(call);
    }
}

impl WakePort for FakeWake {
    async fn config(&self) -> Option<PushConfig> {
        self.spent.set(self.spent.get() + 1);
        Some(self.cfg.borrow().clone())
    }
    async fn tokens(&self, _devices: Option<&[String]>) -> Result<Vec<TokenRow>> {
        self.spent.set(self.spent.get() + 1);
        Ok(self.tokens.clone())
    }
    async fn direct(&self, project_id: &str, _sa: &str, token: &str) -> DirectSend {
        assert_eq!(project_id, "owner-proj");
        if !self.minted.replace(true) {
            self.spent.set(self.spent.get() + MINT);
        }
        self.tick(format!("direct:{token}"));
        (self.direct_answer)(token)
    }
    async fn relay(&self, url: &str, token: &str) -> Result<bool> {
        assert_eq!(url, "https://relay");
        self.tick(format!("relay:{token}"));
        (self.relay_answer)(token)
    }
    async fn delete_token(&self, device_id: &str) {
        self.tick(format!("delete:{device_id}"));
    }
    async fn record(&self, key: &'static str, verdict: ProjectVerdict) {
        self.tick(format!("record:{key}"));
        let mut c = self.cfg.borrow_mut();
        match key {
            KEY_OWN_REJECTED => c.rejected = Some(verdict),
            KEY_OWN_REACHED => c.reached = Some(verdict),
            other => panic!("unknown verdict key {other}"),
        }
    }
    fn now(&self) -> i64 {
        1_700_000_000
    }
    fn log(&self, _line: String) {}
}

/// FCM's answer for a token another project minted — what every published-app phone gets.
pub(crate) fn mismatch(_: &str) -> DirectSend {
    DirectSend::SenderMismatch
}
pub(crate) fn sent(_: &str) -> DirectSend {
    DirectSend::Sent
}
pub(crate) fn relay_ok(_: &str) -> Result<bool> {
    Ok(true)
}
pub(crate) fn relay_stale(_: &str) -> Result<bool> {
    Ok(false)
}

/// The K8 defect: a 403 SENDER_ID_MISMATCH is resent through the shared relay — this wake is not
/// lost — and the server records that its own project cannot reach these phones.
#[test]
fn a_sender_id_mismatch_is_resent_through_the_relay_and_recorded() {
    let f = FakeWake::own(1, mismatch, relay_ok);
    let t = f.wake();
    assert_eq!(f.calls(), ["direct:t0", "record:push_own_project_mismatch", "relay:t0"]);
    assert_eq!((t.ok, t.failed, t.relayed, t.rejected), (1, 0, 1, true));
    let cfg = f.cfg.borrow();
    assert!(cfg.own_rejected());
    assert_eq!(cfg.rejected.as_ref().unwrap().project, "owner-proj");
    assert_eq!(cfg.rejected.as_ref().unwrap().at, 1_700_000_000);
}

/// While the verdict stands, the next wake goes straight to the shared relay: no direct attempt.
#[test]
fn the_next_wake_goes_straight_to_the_relay() {
    let f = FakeWake::own(2, mismatch, relay_ok);
    f.wake();
    let t = f.wake();
    assert_eq!(f.calls(), ["relay:t0", "relay:t1"]);
    assert_eq!((t.ok, t.relayed, t.rejected), (2, 0, false));
}

/// Saving or clearing the credentials deletes the verdict (`CLEAR_VERDICTS_SQL`, tested against
/// the schema in `config_tests.rs`); the next wake tests the project again.
#[test]
fn after_a_save_the_next_wake_tests_the_project_again() {
    let f = FakeWake::own(1, mismatch, relay_ok);
    f.wake();
    f.cfg.borrow_mut().rejected = None;
    f.wake();
    assert_eq!(f.calls(), ["direct:t0", "record:push_own_project_mismatch", "relay:t0"]);
}

/// The rest of the same wake goes to the relay once the verdict is recorded: one direct attempt,
/// one record, however many devices.
#[test]
fn the_rest_of_the_wake_follows_the_verdict() {
    let f = FakeWake::own(3, mismatch, relay_ok);
    let t = f.wake();
    assert_eq!(
        f.calls(),
        ["direct:t0", "record:push_own_project_mismatch", "relay:t0", "relay:t1", "relay:t2"]
    );
    assert_eq!((t.ok, t.relayed), (3, 1));
}

/// Another 403 (a disabled API, a missing role) or a 5xx keeps today's behaviour: no relay, no
/// verdict, the token kept.
#[test]
fn other_403s_and_5xx_keep_todays_behaviour() {
    fn denied(_: &str) -> DirectSend {
        DirectSend::Failed("fcm: send 403".into())
    }
    fn unavailable(_: &str) -> DirectSend {
        DirectSend::Failed("fcm: send 503".into())
    }
    for answer in [denied as fn(&str) -> DirectSend, unavailable] {
        let f = FakeWake::own(1, answer, relay_ok);
        let t = f.wake();
        assert_eq!(f.calls(), ["direct:t0"]);
        assert_eq!((t.ok, t.failed, t.relayed, t.rejected), (0, 1, 0, false));
        assert!(f.cfg.borrow().rejected.is_none());
        f.wake();
        assert_eq!(f.calls(), ["direct:t0"], "still direct");
    }
}

/// The relay's own verdict on a resent wake holds: stale deletes the token.
#[test]
fn a_resent_wake_the_relay_calls_stale_deletes_the_token() {
    let f = FakeWake::own(1, mismatch, relay_stale);
    let t = f.wake();
    assert_eq!(f.calls(), ["direct:t0", "record:push_own_project_mismatch", "relay:t0", "delete:d0"]);
    assert_eq!(t.stale, 1);
}

/// With the relay switched off nothing can carry the wake: it fails, the verdict is still
/// recorded (the settings say why), and the next wake is off.
#[test]
fn with_the_relay_off_the_mismatch_is_recorded_and_the_wake_fails() {
    let f = FakeWake::own(1, mismatch, relay_ok);
    f.cfg.borrow_mut().relay_url = None;
    let t = f.wake();
    assert_eq!(f.calls(), ["direct:t0", "record:push_own_project_mismatch"]);
    assert_eq!((t.ok, t.failed, t.rejected), (0, 1, true));
    let t = f.wake();
    assert_eq!(f.calls(), Vec::<String>::new());
    assert_eq!(t.tokens, 0, "mode off");
}

/// A project that has woken a device is the owner's own build's. A published-app phone on that
/// server (a mixed fleet) is relayed wake by wake and never switches the server off its project.
#[test]
fn a_project_that_reached_a_device_is_never_switched_away() {
    let f = FakeWake::own(1, mismatch, relay_ok);
    f.cfg.borrow_mut().reached = Some(ProjectVerdict { at: 1, project: "owner-proj".into() });
    let t = f.wake();
    assert_eq!(f.calls(), ["direct:t0", "relay:t0"]);
    assert_eq!((t.ok, t.relayed, t.rejected), (1, 1, false));
    f.wake();
    assert_eq!(f.calls(), ["direct:t0", "relay:t0"], "still direct first");
}

/// The first device the project reaches is recorded once; later wakes write nothing.
#[test]
fn the_first_success_records_the_project_as_reached() {
    let f = FakeWake::own(2, sent, relay_ok);
    f.wake();
    assert_eq!(f.calls(), ["direct:t0", "record:push_own_project_reached", "direct:t1"]);
    f.wake();
    assert_eq!(f.calls(), ["direct:t0", "direct:t1"]);
}

/// A success earlier in the same wake is enough: the later mismatch is relayed, not recorded.
#[test]
fn a_success_earlier_in_the_wake_keeps_a_later_mismatch_from_switching() {
    fn own_build_then_published(token: &str) -> DirectSend {
        if token == "t0" { DirectSend::Sent } else { DirectSend::SenderMismatch }
    }
    let f = FakeWake::own(2, own_build_then_published, relay_ok);
    let t = f.wake();
    assert_eq!(
        f.calls(),
        ["direct:t0", "record:push_own_project_reached", "direct:t1", "relay:t1"]
    );
    assert_eq!((t.ok, t.relayed, t.rejected), (2, 1, false));
}

/// A server on the relay from the start never touches the own-project path.
#[test]
fn a_relay_server_is_unchanged() {
    let f = FakeWake::own(2, sent, relay_ok);
    f.cfg.borrow_mut().project_id = None;
    let t = f.wake();
    assert_eq!(f.calls(), ["relay:t0", "relay:t1"]);
    assert_eq!(t.ok, 2);
}
