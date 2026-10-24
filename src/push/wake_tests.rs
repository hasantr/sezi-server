//! The wake: its token reads against the real schema, and the REAL `wake_with` loop against a
//! fake port — the K8 route above all (a token Google refuses for the owner's own project).

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

/// A server's push state and its outside world. `record_reached` writes into `cfg` and
/// `route_via_relay` into `tokens`, so a second wake reads what the first one wrote — as D1 would
/// hand it back. Every call is charged to `spent` as the subrequest it is in production, the
/// first direct send with the OAuth mint (KV get, Google, KV put) on top: the worst case, a cold
/// isolate.
pub(crate) struct FakeWake {
    pub(crate) cfg: RefCell<PushConfig>,
    pub(crate) tokens: RefCell<Vec<TokenRow>>,
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
                reached: None,
            }),
            tokens: RefCell::new(
                (0..n)
                    .map(|i| TokenRow {
                        device_id: format!("d{i}"),
                        fcm_token: format!("t{i}"),
                        relay_project: None,
                        wake: None,
                        wake_lang: None,
                    })
                    .collect(),
            ),
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
    fn mark_of(&self, device: &str) -> Option<String> {
        self.tokens.borrow().iter().find(|r| r.device_id == device).and_then(|r| r.relay_project.clone())
    }
}

impl WakePort for FakeWake {
    async fn config(&self) -> Option<PushConfig> {
        self.spent.set(self.spent.get() + 1);
        Some(self.cfg.borrow().clone())
    }
    async fn tokens(&self, _devices: Option<&[String]>) -> Result<Vec<TokenRow>> {
        self.spent.set(self.spent.get() + 1);
        Ok(self.tokens.borrow().clone())
    }
    async fn direct(&self, project_id: &str, _sa: &str, token: &str, style: WakeStyle) -> DirectSend {
        assert_eq!(project_id, "owner-proj");
        if !self.minted.replace(true) {
            self.spent.set(self.spent.get() + MINT);
        }
        self.tick(format!("direct:{token}{}", style_mark(style)));
        (self.direct_answer)(token)
    }
    async fn relay(&self, url: &str, token: &str, style: WakeStyle) -> Result<bool> {
        assert_eq!(url, "https://relay");
        self.tick(format!("relay:{token}{}", style_mark(style)));
        (self.relay_answer)(token)
    }
    async fn delete_token(&self, device_id: &str) {
        self.tick(format!("delete:{device_id}"));
        self.tokens.borrow_mut().retain(|r| r.device_id != device_id);
    }
    async fn record_reached(&self, verdict: ProjectVerdict) {
        self.tick("record:reached".into());
        self.cfg.borrow_mut().reached = Some(verdict);
    }
    async fn route_via_relay(&self, row: &TokenRow, project_id: &str) {
        self.tick(format!("route:{}", row.device_id));
        for r in self.tokens.borrow_mut().iter_mut() {
            if r.device_id == row.device_id && r.fcm_token == row.fcm_token {
                r.relay_project = Some(project_id.to_string());
            }
        }
    }
    fn now(&self) -> i64 {
        1_700_000_000
    }
    fn log(&self, _line: String) {}
}

/// A data wake is logged as before; a visible one says so, so a test sees which style was sent.
fn style_mark(style: WakeStyle) -> String {
    match style {
        WakeStyle::Data => String::new(),
        WakeStyle::Visible(l) => format!(":visible-{}", l.code()),
    }
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
/// A mixed fleet: `t0` is the owner's own build, every other token the published app.
pub(crate) fn first_own_build(token: &str) -> DirectSend {
    if token == "t0" { DirectSend::Sent } else { DirectSend::SenderMismatch }
}

/// The K8 defect: a 403 SENDER_ID_MISMATCH is resent through the shared relay — this wake is not
/// lost — and THAT token is marked for the relay.
#[test]
fn a_sender_id_mismatch_is_resent_through_the_relay_and_the_token_marked() {
    let f = FakeWake::own(1, mismatch, relay_ok);
    let t = f.wake();
    assert_eq!(f.calls(), ["direct:t0", "relay:t0", "route:d0"]);
    assert_eq!((t.ok, t.failed, t.relayed, t.routed), (1, 0, 1, 1));
    assert_eq!(f.mark_of("d0").as_deref(), Some("owner-proj"));
}

/// A relay-routed token goes straight to the relay on every later wake: no direct attempt, no
/// second mark — until the device registers another token.
#[test]
fn a_relay_routed_token_never_goes_direct_again_until_re_registered() {
    let f = FakeWake::own(1, mismatch, relay_ok);
    f.wake();
    for _ in 0..3 {
        let t = f.wake();
        assert_eq!(f.calls(), ["relay:t0"]);
        assert_eq!((t.ok, t.relayed, t.routed), (1, 1, 0));
    }
    // The device registers a NEW token (`handlers::REGISTER_SQL` drops the mark): asked again.
    {
        let mut rows = f.tokens.borrow_mut();
        rows[0].fcm_token = "t0-new".into();
        rows[0].relay_project = None;
    }
    f.wake();
    assert_eq!(f.calls(), ["direct:t0-new", "relay:t0-new", "route:d0"]);
}

/// The mixed fleet: the owner's own build stays direct whatever the published-app phones beside
/// it get, and is never handed to the shared relay — not in the wake that marks the others, not
/// in any wake after.
#[test]
fn an_own_build_token_never_goes_to_the_relay() {
    let f = FakeWake::own(3, first_own_build, relay_ok);
    for _ in 0..3 {
        f.wake();
        let calls = f.calls();
        assert!(calls.contains(&"direct:t0".to_string()), "{calls:?}");
        assert!(!calls.contains(&"relay:t0".to_string()), "{calls:?}");
    }
    assert_eq!(f.mark_of("d0"), None);
    assert_eq!(f.mark_of("d1").as_deref(), Some("owner-proj"));
}

/// ADVERSARIAL REVIEW (2026-10-14), in its fixed meaning. Two wakes in flight at once on a fresh
/// own-build server — an own-build member's and a published-app member's, each in its own inbox
/// DO (D8), each reading the config before either wrote. Whatever both write, the own-build
/// device's next wake still goes direct and never to the relay: the published app's refusal is
/// recorded on ITS token, not on the server.
#[test]
fn adv_concurrent_wakes_never_move_an_own_build_device_to_the_relay() {
    let own_build = FakeWake::own(1, sent, relay_ok);
    let published = FakeWake::own(1, mismatch, relay_ok);
    own_build.wake();
    published.wake();
    // What D1 holds afterwards: the published wake's writes are on its own token row.
    assert_eq!(published.mark_of("d0").as_deref(), Some("owner-proj"));
    assert!(published.cfg.borrow().reached.is_none());
    // The own-build device's next wake, against the config both wakes left behind.
    own_build.wake();
    assert_eq!(own_build.calls(), ["direct:t0"]);
    assert!(matches!(own_build.cfg.borrow().send_mode(), Some(SendMode::Direct { .. })));
}

/// A mark measured against another project (the env var changed) says nothing about this one:
/// the token is asked again.
#[test]
fn a_mark_about_another_project_is_asked_again() {
    let f = FakeWake::own(1, sent, relay_ok);
    f.tokens.borrow_mut()[0].relay_project = Some("old-proj".into());
    f.wake();
    assert_eq!(f.calls(), ["direct:t0", "record:reached"]);
}

/// Another 403 (a disabled API, a missing role) or a 5xx keeps today's behaviour: no relay, no
/// mark, the token kept.
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
        assert_eq!((t.ok, t.failed, t.relayed, t.routed), (0, 1, 0, 0));
        assert_eq!(f.mark_of("d0"), None);
        f.wake();
        assert_eq!(f.calls(), ["direct:t0"], "still direct");
    }
}

/// The relay's own verdict on a resent wake holds: stale deletes the token, and no mark is
/// written on a row that is gone.
#[test]
fn a_resent_wake_the_relay_calls_stale_deletes_the_token() {
    let f = FakeWake::own(1, mismatch, relay_stale);
    let t = f.wake();
    assert_eq!(f.calls(), ["direct:t0", "relay:t0", "delete:d0"]);
    assert_eq!(t.stale, 1);
}

/// With the relay switched off nothing can carry the wake: it fails, the token is still marked
/// (the settings say why, and no direct send is wasted on it again), and its next wake fails at
/// once without a call.
#[test]
fn with_the_relay_off_the_token_is_marked_and_the_wake_fails() {
    let f = FakeWake::own(1, mismatch, relay_ok);
    f.cfg.borrow_mut().relay_url = None;
    let t = f.wake();
    assert_eq!(f.calls(), ["direct:t0", "route:d0"]);
    assert_eq!((t.ok, t.failed, t.routed), (0, 1, 1));
    let t = f.wake();
    assert_eq!(f.calls(), Vec::<String>::new());
    assert_eq!(t.failed, 1);
}

/// The first device the project reaches is recorded once (the owner's summary); later wakes
/// write nothing.
#[test]
fn the_first_success_records_the_project_as_reached() {
    let f = FakeWake::own(2, sent, relay_ok);
    f.wake();
    assert_eq!(f.calls(), ["direct:t0", "record:reached", "direct:t1"]);
    f.wake();
    assert_eq!(f.calls(), ["direct:t0", "direct:t1"]);
}

/// A server on the relay from the start never touches the own-project path, and a mark left
/// from an own project that was cleared since changes nothing.
#[test]
fn a_relay_server_is_unchanged() {
    let f = FakeWake::own(2, sent, relay_ok);
    f.cfg.borrow_mut().project_id = None;
    f.tokens.borrow_mut()[1].relay_project = Some("owner-proj".into());
    let t = f.wake();
    assert_eq!(f.calls(), ["relay:t0", "relay:t1"]);
    assert_eq!(t.ok, 2);
}

// ---- The statements, against the real schema ----

fn schema_with_token(token: &str) -> rusqlite::Connection {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('u', 'u@x', x'00', 1)",
        [],
    )
    .unwrap();
    db.execute(super::super::handlers::REGISTER_SQL, rusqlite::params!["u", "d0", token, "android", 1, 1, "data", None::<String>])
        .unwrap();
    db
}

fn mark(db: &rusqlite::Connection) -> Option<String> {
    db.query_row("SELECT relay_project FROM push_tokens WHERE device_id = 'd0'", [], |r| r.get(0))
        .unwrap()
}

/// The mark is written on the token it was measured for; registering the SAME token keeps it, a
/// NEW token drops it; saving the credentials drops every mark.
#[test]
fn a_mark_lives_with_its_token() {
    let db = schema_with_token("tok-a");
    db.execute(ROUTE_VIA_RELAY_SQL, rusqlite::params!["owner-proj", "u", "d0", "tok-a"]).unwrap();
    assert_eq!(mark(&db).as_deref(), Some("owner-proj"));
    // A mark for a token the device has replaced meanwhile writes nothing.
    db.execute(ROUTE_VIA_RELAY_SQL, rusqlite::params!["other", "u", "d0", "tok-old"]).unwrap();
    assert_eq!(mark(&db).as_deref(), Some("owner-proj"));
    db.execute(super::super::handlers::REGISTER_SQL, rusqlite::params!["u", "d0", "tok-a", "android", 2, 2, "data", None::<String>])
        .unwrap();
    assert_eq!(mark(&db).as_deref(), Some("owner-proj"), "the same token keeps its mark");
    db.execute(super::super::handlers::REGISTER_SQL, rusqlite::params!["u", "d0", "tok-b", "android", 3, 3, "data", None::<String>])
        .unwrap();
    assert_eq!(mark(&db), None, "a new token is asked again");
    db.execute(ROUTE_VIA_RELAY_SQL, rusqlite::params!["owner-proj", "u", "d0", "tok-b"]).unwrap();
    db.execute(super::super::config::CLEAR_TOKEN_ROUTES_SQL, []).unwrap();
    assert_eq!(mark(&db), None, "a save of the credentials asks every token again");
}

/// The token reads carry the mark.
#[test]
fn the_token_reads_carry_the_mark() {
    let db = schema_with_token("tok-a");
    db.execute(ROUTE_VIA_RELAY_SQL, rusqlite::params!["owner-proj", "u", "d0", "tok-a"]).unwrap();
    let one: Option<String> = db
        .query_row(DEVICE_TOKEN_SQL, ["u", "d0"], |r| r.get(2))
        .unwrap();
    let all: Option<String> = db.query_row(USER_TOKENS_SQL, ["u"], |r| r.get(2)).unwrap();
    assert_eq!((one.as_deref(), all.as_deref()), (Some("owner-proj"), Some("owner-proj")));
    let n: u32 = db
        .query_row(super::super::config::RELAY_ROUTED_COUNT_SQL, ["owner-proj"], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

// ---- How a token is woken (`style.rs`) ----

fn style_of(db: &rusqlite::Connection, one: bool) -> (Option<String>, Option<String>) {
    let read = |r: &rusqlite::Row<'_>| Ok((r.get(3)?, r.get(4)?));
    if one {
        db.query_row(DEVICE_TOKEN_SQL, ["u", "d0"], read).unwrap()
    } else {
        db.query_row(USER_TOKENS_SQL, ["u"], read).unwrap()
    }
}

/// A token registered before the column, or by a client that sends no `wake`, reads `data`; a
/// visible register is read back with its language; the next register as `data` clears both.
#[test]
fn the_token_reads_carry_the_wake_style() {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('u', 'u@x', x'00', 1)",
        [],
    )
    .unwrap();
    // The shape of every row written before 0051: no wake column named.
    db.execute(
        "INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at)
         VALUES ('u', 'd0', 'tok-a', 'android', 1, 1)",
        [],
    )
    .unwrap();
    assert_eq!(style_of(&db, true), (Some("data".into()), None));
    let register = |wake: &str, lang: Option<&str>| {
        db.execute(
            super::super::handlers::REGISTER_SQL,
            rusqlite::params!["u", "d0", "tok-a", "android", 2, 2, wake, lang],
        )
        .unwrap();
    };
    register("visible", Some("en"));
    for one in [true, false] {
        assert_eq!(style_of(&db, one), (Some("visible".into()), Some("en".into())));
    }
    register("data", None);
    assert_eq!(style_of(&db, false), (Some("data".into()), None));
}

/// The loop sends each token in its own style, direct and through the relay alike; a data token
/// beside a visible one is sent exactly as before.
#[test]
fn each_token_is_woken_in_its_own_style() {
    let f = FakeWake::own(2, mismatch, relay_ok);
    {
        let mut rows = f.tokens.borrow_mut();
        rows[1].wake = Some("visible".into());
        rows[1].wake_lang = Some("en".into());
    }
    f.wake();
    assert_eq!(
        f.calls(),
        ["direct:t0", "relay:t0", "route:d0", "direct:t1:visible-en", "relay:t1:visible-en", "route:d1"]
    );
    // A relay-only server: the same styles.
    f.cfg.borrow_mut().project_id = None;
    f.cfg.borrow_mut().service_account = None;
    f.wake();
    assert_eq!(f.calls(), ["relay:t0", "relay:t1:visible-en"]);
}
