//! The route itself: what a path segment is taken for, which answer a caller gets, that `/:invite`
//! shadows no other route, and the rate limit — run through `answer_with` against an in-memory
//! limiter, so what is counted where is measured rather than read.

use super::gate::{answer_with, ceiling_key, Answer, DoorPort};
use super::lookup::{DescribeRow, LookupKey};
use super::wants_json;
use crate::door_bucket::{Reservation, Reserved};
use crate::ratelimit::{door_miss_key, retry_after_s, Admission, DOOR_IP_CEILING, DOOR_MISS_LIMIT};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use worker::Result;

const NOW: i64 = 1_780_000_000;
const IP: &str = "203.0.113.7";

/// Run a future whose fakes never pend.
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

// ── What a segment is ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_code_in_any_spelling_is_a_code_for_both_callers() {
    for json in [false, true] {
        for typed in ["K7QM-4827", "k7qm-4827", "K7QM4827"] {
            assert_eq!(
                LookupKey::parse(typed, json),
                Some(LookupKey::Code("K7QM4827".into()))
            );
        }
    }
}

/// A token is looked up only from the app's POST body (`allow_token`): a path — a browser's or the
/// app's — is a code or nothing, so a bearer token never sits in a URL.
#[test]
fn a_token_is_looked_up_from_a_post_body_and_never_from_a_path() {
    let token = "AbCdEfGhIjKlMnOpQrStUv_-";
    assert_eq!(token.len(), 24);
    assert_eq!(
        LookupKey::parse(token, true),
        Some(LookupKey::Token(token.into()))
    );
    assert_eq!(LookupKey::parse(token, false), None);
    // And the GET handler asks for a path's key without tokens; only the POST body allows them.
    let src = include_str!("mod.rs");
    assert!(src.contains(concat!("LookupKey::parse(&segment, ", "false)")));
    assert_eq!(src.matches(concat!("LookupKey::parse(", "b.invite.trim(), true)")).count(), 1);
}

#[test]
fn what_is_neither_is_not_found_and_costs_nothing() {
    for json in [false, true] {
        for segment in [
            "favicon.ico",
            "robots.txt",
            "K7QM-482",
            "K0QM-4827",
            "AbCdEfGhIjKlMnOpQrStUv_",
            "AbCdEfGhIjKlMnOpQrStUv_-x",
            "AbCdEfGhIjKlMnOpQrStU.v_",
            "",
        ] {
            assert_eq!(LookupKey::parse(segment, json), None, "{segment:?}");
        }
    }
}

#[test]
fn only_a_caller_asking_for_json_and_not_html_gets_json() {
    assert!(wants_json(Some("application/json")));
    assert!(wants_json(Some("Application/JSON; charset=utf-8")));
    let firefox = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    assert!(!wants_json(Some(firefox)));
    assert!(!wants_json(Some("text/html, application/json")));
    assert!(!wants_json(Some("*/*")));
    assert!(!wants_json(None), "curl with no header gets the page");
}

// ── No collisions ─────────────────────────────────────────────────────────────────────────────

/// Every GET pattern registered in `lib.rs`, read from the source the router is built from.
fn get_routes() -> Vec<String> {
    let src = include_str!("../lib.rs");
    let needle = concat!(".get", "_async(\"");
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find(needle) {
        rest = &rest[at + needle.len()..];
        let end = rest.find('"').unwrap();
        out.push(rest[..end].to_string());
    }
    // `.get("/healthz", …)` is the one synchronous GET.
    out.push("/healthz".into());
    out
}

/// The whole GET table goes into the same matchit the worker router uses: it must accept it
/// (a conflict would panic the worker at its first request), every static path must still resolve
/// to itself, and a code to the invite page.
#[test]
fn the_invite_route_shadows_no_other_route() {
    let routes = get_routes();
    assert!(
        routes.iter().any(|r| r == "/:invite"),
        "the route is registered"
    );
    assert!(routes.len() > 30, "the scan found the table");
    let mut router = matchit::Router::new();
    for r in &routes {
        router
            .insert(r.as_str(), r.clone())
            .unwrap_or_else(|e| panic!("{r} conflicts: {e}"));
    }
    for r in routes.iter().filter(|r| !r.contains(':')) {
        assert_eq!(router.at(r).unwrap().value, r, "{r} is shadowed");
    }
    let hit = router.at("/K7QM-4827").unwrap();
    assert_eq!(hit.value, "/:invite");
    assert_eq!(hit.params.get("invite"), Some("K7QM-4827"));
    assert!(router.at("/K7QM-4827/extra").is_err(), "one segment only");
}

/// The other half: no static one-segment route could ever be read as a code, so a code the
/// generator mints can never be unreachable behind a route.
#[test]
fn no_one_segment_route_is_shaped_like_a_code() {
    for r in get_routes() {
        let segment = r.trim_start_matches('/');
        if !segment.contains('/') && !segment.starts_with(':') {
            assert_eq!(LookupKey::parse(segment, true), None, "{r}");
        }
    }
}

// ── The rate limit ────────────────────────────────────────────────────────────────────────────

/// An in-memory twin of both counters: the KV limiter's sliding window for the ceiling, the door
/// bucket's atomic reserve/refund for misses (one window, at `NOW`), and a count of lookups.
#[derive(Default)]
struct FakePort {
    hits: RefCell<HashMap<String, Vec<u64>>>,
    misses: RefCell<HashMap<String, usize>>,
    lookups: Cell<usize>,
    /// What the lookup finds: `Some` = a live personal invite, `None` = nothing.
    live: bool,
}

impl FakePort {
    fn live() -> Self {
        FakePort {
            live: true,
            ..Default::default()
        }
    }
    fn count(&self, key: &str) -> usize {
        self.hits.borrow().get(key).map_or(0, Vec::len)
    }
    fn missed(&self, bucket: &str) -> usize {
        self.misses.borrow().get(bucket).copied().unwrap_or(0)
    }
    fn window(&self, key: &str, window_s: u64) -> Vec<u64> {
        let now = NOW as u64;
        let mut map = self.hits.borrow_mut();
        let v = map.entry(key.to_string()).or_default();
        v.retain(|&t| t > now.saturating_sub(window_s));
        v.clone()
    }
}

impl FakePort {
    fn peek(&self, key: &str, max_hits: usize, window_s: u64) -> Admission {
        let hits = self.window(key, window_s);
        if hits.len() < max_hits {
            Admission::Allowed
        } else {
            Admission::Refused {
                retry_after_s: retry_after_s(&hits, max_hits, 1, window_s, NOW as u64),
            }
        }
    }
}

impl DoorPort for FakePort {
    async fn reserve_miss(&self, bucket: &str, limit: usize, now: i64) -> Reserved {
        let mut misses = self.misses.borrow_mut();
        let n = misses.entry(bucket.to_string()).or_default();
        if *n >= limit {
            return Reserved::Refused {
                retry_after_s: crate::door_bucket::retry_after(NOW, now),
            };
        }
        *n += 1;
        Reserved::Taken(Reservation {
            bucket: bucket.to_string(),
            window_start: NOW,
        })
    }
    async fn refund_miss(&self, reservation: &Reservation) {
        if let Some(n) = self.misses.borrow_mut().get_mut(&reservation.bucket) {
            *n = n.saturating_sub(1);
        }
    }
    async fn admit(&self, key: &str, max_hits: usize, window_s: u64) -> Admission {
        let refused = self.peek(key, max_hits, window_s);
        if refused == Admission::Allowed {
            self.hits
                .borrow_mut()
                .entry(key.to_string())
                .or_default()
                .push(NOW as u64);
        }
        refused
    }
    async fn lookup(&self, _key: &LookupKey, now: i64) -> Result<DescribeRow> {
        self.lookups.set(self.lookups.get() + 1);
        let mut row = DescribeRow {
            server_name: Some("Kampüs Sezi".into()),
            ..Default::default()
        };
        if self.live {
            row.kind = Some("personal".into());
            row.used = Some(0);
            row.expires_at = Some(now + 600);
            row.has_minter = Some(1);
        }
        Ok(row)
    }
}

fn ask(port: &FakePort, limited: bool) -> Answer {
    let key = LookupKey::Code("K7QM4827".into());
    block_on(answer_with(port, IP, &key, limited, NOW)).unwrap()
}

#[test]
fn an_unknown_code_is_unavailable_and_costs_one_miss_in_the_doors_shared_bucket() {
    let port = FakePort::default();
    assert_eq!(ask(&port, true), Answer::Unavailable);
    assert_eq!(
        port.missed(&door_miss_key(IP)),
        1,
        "redeem's bucket, not a new one"
    );
    assert_eq!(door_miss_key(IP), format!("auth:redeem:miss:{IP}"));
}

#[test]
fn a_usable_invite_costs_no_miss() {
    let port = FakePort::live();
    assert!(matches!(ask(&port, true), Answer::Usable(_)));
    assert_eq!(
        port.missed(&door_miss_key(IP)),
        0,
        "the reserved miss was given back"
    );
    assert_eq!(port.count(&ceiling_key(IP)), 1);
}

/// Thirty misses and the door is shut — before the database is asked, for a live code as much as
/// a dead one, so a guesser learns nothing more from this door than redeem would tell them.
#[test]
fn after_the_miss_limit_nothing_is_looked_up() {
    let port = FakePort::default();
    for _ in 0..DOOR_MISS_LIMIT {
        assert_eq!(ask(&port, true), Answer::Unavailable);
    }
    let lookups = port.lookups.get();
    assert!(matches!(ask(&port, true), Answer::Refused { retry_after_s } if retry_after_s > 0));
    assert_eq!(port.lookups.get(), lookups, "refused before the lookup");
    let live = FakePort::live();
    *live.misses.borrow_mut() = port.misses.borrow().clone();
    assert!(
        matches!(ask(&live, true), Answer::Refused { .. }),
        "a live code too"
    );
}

/// Misses collected at redeem shut this door as well: the two doors share one budget.
#[test]
fn misses_spent_at_redeem_shut_the_page_too() {
    let port = FakePort::live();
    port.misses
        .borrow_mut()
        .insert(door_miss_key(IP), DOOR_MISS_LIMIT);
    assert!(matches!(ask(&port, true), Answer::Refused { .. }));
    assert_eq!(port.lookups.get(), 0);
}

/// Reloading a live invite is bounded by the per-address ceiling, sized for a lecture hall
/// behind one NAT.
#[test]
fn plain_asking_is_bounded_by_the_ceiling() {
    let port = FakePort::live();
    for _ in 0..DOOR_IP_CEILING {
        assert!(matches!(ask(&port, true), Answer::Usable(_)));
    }
    assert!(matches!(ask(&port, true), Answer::Refused { .. }));
    const { assert!(DOOR_IP_CEILING >= 240, "a class of 120 asks twice each") };
}

#[test]
fn a_relay_that_is_not_prod_runs_unlimited_and_counts_nothing() {
    let port = FakePort::default();
    for _ in 0..DOOR_MISS_LIMIT * 2 {
        assert_eq!(ask(&port, false), Answer::Unavailable);
    }
    assert!(port.hits.borrow().is_empty());
    assert!(port.misses.borrow().is_empty());
}

/// Redeem keys its miss bucket through the same function — the shared budget cannot drift apart
/// by one door renaming its key. Source-level, as redeem needs a live `Env`.
#[test]
fn redeem_counts_its_misses_through_the_same_key() {
    let redeem = include_str!("../auth/invite.rs");
    assert!(redeem.contains(concat!("door_bucket::reserve_door(&db, ", "&ip,")));
    let bucket = include_str!("../door_bucket.rs");
    assert!(bucket.contains(concat!("crate::ratelimit::door_miss_", "buckets(ip)")));
}

/// Redeem reserves its miss before it looks anything up, as the page does — else concurrent
/// redeems outrun the budget exactly as the page used to. Source-level, for the same reason.
#[test]
fn redeem_reserves_its_miss_before_any_lookup() {
    let redeem = include_str!("../auth/invite.rs");
    let at = |needle: &str| {
        redeem
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} moved — re-point this guard"))
    };
    let reserve = at(concat!("crate::door_bucket::", "reserve_door(&db, &ip"));
    assert!(reserve < at(concat!("token_for_", "code(&db, &code)")));
    assert!(reserve < at(concat!("class_invite::kind_", "of(&db, &token)")));
    assert!(
        !redeem.contains(concat!("peek", "_env(")),
        "no KV peek of the miss bucket"
    );
}

// ── Critic (review/k6-critic): what the gate does under concurrency ──

/// A port whose lookup does not finish until `released` is set, so many requests can be in flight
/// between the miss bucket's peek and its charge — what a guesser firing requests in parallel gets.
struct SlowPort {
    inner: FakePort,
    released: Cell<bool>,
}

struct Gate<'a>(&'a Cell<bool>);

impl Future for Gate<'_> {
    type Output = ();
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if self.0.get() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }
}

impl DoorPort for SlowPort {
    async fn reserve_miss(&self, bucket: &str, limit: usize, now: i64) -> Reserved {
        self.inner.reserve_miss(bucket, limit, now).await
    }
    async fn refund_miss(&self, reservation: &Reservation) {
        self.inner.refund_miss(reservation).await
    }
    async fn admit(&self, key: &str, max_hits: usize, window_s: u64) -> Admission {
        self.inner.admit(key, max_hits, window_s).await
    }
    async fn lookup(&self, key: &LookupKey, now: i64) -> Result<DescribeRow> {
        Gate(&self.released).await;
        self.inner.lookup(key, now).await
    }
}

/// The miss bucket is peeked before the lookup and charged after it, so it bounds sequential
/// guessing only. A guesser with N requests in flight at once gets N lookups (N guesses) from one
/// address however small the bucket is — even against a strongly consistent store, which the KV
/// limiter is not. Holding the gate to its own claim ("a caller over it is turned away before the
/// lookup") needs the miss to be reserved BEFORE the lookup and refunded on a hit.
#[test]
fn concurrent_guesses_from_one_address_are_bounded_by_the_miss_limit() {
    let port = SlowPort {
        inner: FakePort::default(),
        released: Cell::new(false),
    };
    let key = LookupKey::Code("K7QM4827".into());
    let n = DOOR_MISS_LIMIT * 4;
    let mut futs: Vec<_> = (0..n)
        .map(|_| Box::pin(answer_with(&port, IP, &key, true, NOW)))
        .collect();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    // Every request is started before any lookup finishes. (The fix turns those past the budget
    // away at once, so a first poll may already be a refusal; a finished future is not polled
    // again.)
    let mut done = vec![false; n];
    let mut refused = 0;
    for (i, f) in futs.iter_mut().enumerate() {
        if let std::task::Poll::Ready(answer) = f.as_mut().poll(&mut cx) {
            assert!(matches!(answer, Ok(Answer::Refused { .. })), "{answer:?}");
            done[i] = true;
            refused += 1;
        }
    }
    port.released.set(true);
    let mut unavailable = 0;
    for (i, f) in futs.iter_mut().enumerate() {
        if done[i] {
            continue;
        }
        if let std::task::Poll::Ready(Ok(Answer::Unavailable)) = f.as_mut().poll(&mut cx) {
            unavailable += 1;
        }
    }
    assert_eq!(refused + unavailable, n, "every request answered");
    assert!(
        port.inner.lookups.get() <= DOOR_MISS_LIMIT,
        "{} lookups ({unavailable} answered misses) from one address in one window; the limit is {}",
        port.inner.lookups.get(),
        DOOR_MISS_LIMIT
    );
}

/// The page answers a usable and an unusable invite with the same status, so an embedding page
/// learns nothing from load and error events (adversarial review 2026-10-14, F5); a refusal is
/// still 429.
#[test]
fn the_html_page_status_is_the_same_for_a_hit_and_a_miss() {
    assert_eq!(super::page_status(&Answer::Unavailable), 200);
    assert_eq!(super::page_status(&Answer::Refused { retry_after_s: 5 }), 429);
    let src = include_str!("mod.rs");
    let handler = src.split("pub async fn invite_page").nth(1).unwrap();
    let handler = handler.split("pub(crate) fn page_status").next().unwrap();
    assert!(!handler.contains("with_status(404)"), "no HTML answer of a code-shaped path is a 404");
    assert!(src.contains("Answer::Unavailable | Answer::Usable(_) => 200"));
}

// ---- IPv6 (adversarial review 2026-10-14, F6) ----

/// One host owns a whole /64: every address in it spends the same budget, so rotating through
/// them gains nothing.
#[test]
fn every_address_of_one_ipv6_64_spends_one_budget() {
    let port = FakePort::default();
    let key = LookupKey::Code("K7QM4827".into());
    for i in 0..DOOR_MISS_LIMIT {
        let ip = format!("2001:db8:1:2::{:x}", i + 1);
        assert_eq!(block_on(answer_with(&port, &ip, &key, true, NOW)).unwrap(), Answer::Unavailable);
    }
    let fresh = "2001:db8:1:2:dead:beef:0:1";
    assert!(matches!(
        block_on(answer_with(&port, fresh, &key, true, NOW)).unwrap(),
        Answer::Refused { .. }
    ));
    assert_eq!(port.lookups.get(), DOOR_MISS_LIMIT);
}

/// One /48 holds 65,536 /64s: it gets four /64s' worth of misses in all, and a /64 that was
/// refused for its /48 is given its own miss back.
#[test]
fn an_ipv6_48_is_bounded_across_its_64s() {
    let port = FakePort::default();
    let key = LookupKey::Code("K7QM4827".into());
    let mut answered = 0;
    for net in 0..16u32 {
        for host in 0..DOOR_MISS_LIMIT {
            let ip = format!("2001:db8:7:{net:x}::{:x}", host + 1);
            if block_on(answer_with(&port, &ip, &key, true, NOW)).unwrap() == Answer::Unavailable {
                answered += 1;
            }
        }
    }
    assert_eq!(answered, crate::ratelimit::DOOR_PREFIX_MISS_LIMIT);
    // The fifth /64 was refused by the /48 alone: its own bucket holds nothing.
    assert_eq!(port.missed(&door_miss_key("2001:db8:7:4::1")), 0);
    // Another /48 is untouched.
    assert_eq!(
        block_on(answer_with(&port, "2001:db8:8::1", &key, true, NOW)).unwrap(),
        Answer::Unavailable
    );
}

#[test]
fn the_door_address_is_the_64_for_ipv6_and_the_address_for_ipv4() {
    use crate::ratelimit::door_address;
    assert_eq!(door_address("203.0.113.7"), "203.0.113.7");
    assert_eq!(door_address("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::/64");
    assert_eq!(door_address("2001:DB8:1:2::1"), "2001:db8:1:2::/64");
    assert_eq!(door_address("::ffff:203.0.113.7"), "203.0.113.7");
    assert_eq!(door_address("local"), "local");
    assert_eq!(crate::ratelimit::door_miss_buckets("203.0.113.7").len(), 1, "IPv4: no prefix tier");
}
