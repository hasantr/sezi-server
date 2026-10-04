//! The wait a refused caller is told (`Retry-After`). The KV half of the limiter needs a live
//! namespace; the arithmetic that decides the header does not, and it is the half a client counts
//! down from.

use super::{per_invite_limit, pick_client_ip, retry_after_s, DOOR_IP_CEILING};

/// Five hits in a five-minute window — a personal invite's redeem and verify limit.
const MAX: usize = 5;
const WINDOW: u64 = 300;

#[test]
fn the_wait_ends_when_the_oldest_hit_leaves_the_window() {
    // Hits at 100..=104, refused at 160: the one at 100 leaves at 400.
    let hits = [100, 101, 102, 103, 104];
    assert_eq!(retry_after_s(&hits, MAX, 1, WINDOW, 160), 240);
}

#[test]
fn the_order_the_hits_were_stored_in_does_not_matter() {
    let hits = [104, 100, 103, 101, 102];
    assert_eq!(retry_after_s(&hits, MAX, 1, WINDOW, 160), 240);
}

#[test]
fn a_heavier_request_waits_for_as_many_hits_as_it_weighs() {
    // Weight 2 needs two to leave: the second oldest, at 101, leaves at 401.
    let hits = [100, 101, 102, 103, 104];
    assert_eq!(retry_after_s(&hits, MAX, 2, WINDOW, 160), 241);
}

#[test]
fn the_wait_is_never_zero() {
    // The oldest hit leaves this very second; "0" would read as "now", which was just refused.
    let hits = [100, 101, 102, 103, 104];
    assert_eq!(retry_after_s(&hits, MAX, 1, WINDOW, 400), 1);
}

#[test]
fn a_weight_that_can_never_fit_waits_out_the_window() {
    assert_eq!(retry_after_s(&[], MAX, MAX + 1, WINDOW, 160), WINDOW);
}

// ── The door's keys and sizes ─────────────────────────────────────────────────────────────────

/// A lecture hall of 120 on one NAT gets in on the first try: the invite's window holds every seat
/// twice over, and the per-address ceiling sits above that.
#[test]
fn a_class_of_120_fits_both_windows() {
    assert_eq!(
        per_invite_limit(1),
        MAX,
        "a personal invite keeps today's five"
    );
    assert!(per_invite_limit(120) >= 240);
    const { assert!(DOOR_IP_CEILING >= 240) };
    assert_eq!(
        per_invite_limit(100_000),
        2_000,
        "and the window never opens without bound"
    );
}

fn headers(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |name| {
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_string())
    }
}

#[test]
fn on_cloudflare_the_address_is_cf_connecting_ip() {
    let cf = headers(&[("cf-connecting-ip", "203.0.113.7")]);
    assert_eq!(pick_client_ip(None, cf), "203.0.113.7");
    let cf6 = headers(&[("cf-connecting-ip", "2001:db8::1")]);
    assert_eq!(pick_client_ip(Some(""), cf6), "2001:db8::1");
    assert_eq!(pick_client_ip(None, headers(&[])), "local");
}

/// Behind a self-hosted proxy the configured header is the only truth: the LAST forwarded entry
/// (the one the proxy added), never a `cf-connecting-ip` a client can send itself.
#[test]
fn a_configured_proxy_header_is_trusted_and_nothing_else_is() {
    let xff = headers(&[
        ("x-forwarded-for", "6.6.6.6, 10.0.0.42"),
        ("cf-connecting-ip", "6.6.6.6"),
    ]);
    assert_eq!(pick_client_ip(Some("X-Forwarded-For"), xff), "10.0.0.42");
    let real = headers(&[("x-real-ip", " 10.0.0.43 ")]);
    assert_eq!(pick_client_ip(Some("x-real-ip"), real), "10.0.0.43");
    // Configured but absent or forged: the shared bucket, not the spoofable fallback.
    let spoof = headers(&[("cf-connecting-ip", "6.6.6.6")]);
    assert_eq!(pick_client_ip(Some("x-real-ip"), spoof), "local");
    let junk = headers(&[("x-real-ip", "auth:redeem:ip:evil")]);
    assert_eq!(pick_client_ip(Some("x-real-ip"), junk), "local");
}
