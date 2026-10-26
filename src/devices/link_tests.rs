//! Source-level guards over the authorization SHAPE of the three QR-link endpoints.
//!
//! The bug these pin was never inside a function's logic — it was in which middleware a handler
//! happened to call, and no behavioural test over one endpoint can see that the endpoint next to
//! it chose differently. `admin/mod.rs` carries the same kind of guard for the admin surface, and
//! `groups.rs` got one in the same pass; this is the device-link half.
//!
//! `include_str!` rather than reading from disk: it binds at COMPILE time, so renaming or moving
//! `link.rs` breaks the build instead of silently emptying the guard.

use super::link_start_buckets;

const LINK_SRC: &str = include_str!("link.rs");

/// `link-start` is pre-auth, and its only ceiling used to be fifty pending links for the whole
/// server: five addresses at the per-IP rate (10 a minute, a link living 120 s) kept it full, and
/// no one could link a device (audit 2026-10-26, note 1.2). Its budget is now per address — the
/// door's model (`ratelimit::door_miss_buckets`): no server-wide lever.
#[test]
fn one_address_cannot_spend_another_addresss_link_starts() {
    let keys = |ip: &str| link_start_buckets(ip).into_iter().map(|(k, _)| k).collect::<Vec<_>>();
    let (a, b) = (keys("203.0.113.7"), keys("198.51.100.9"));
    assert_eq!(a.len(), 1, "an IPv4 address has its own bucket only");
    assert!(a.iter().all(|k| !b.contains(k)), "{a:?} / {b:?}");
    // One IPv6 host owns its /64; a /48 is one site, bounded at a few /64s' worth.
    let v6 = keys("2001:db8:1:2:aaaa::1");
    assert_eq!(v6, keys("2001:db8:1:2:bbbb::9"), "one /64, one budget");
    assert_eq!(v6.len(), 2);
    assert_eq!(v6[1], keys("2001:db8:1:3::1")[1], "the /48 is shared across its /64s");
    assert_ne!(v6[0], keys("2001:db8:1:3::1")[0]);
    for (k, limit) in link_start_buckets("2001:db8::1") {
        assert!(k.starts_with("link:start"), "{k}: not a door miss bucket");
        assert!(limit > 0);
    }

    let src = handler_src("pub async fn link_start");
    assert!(
        !src.contains("COUNT(*)"),
        "link-start must not count every pending link on the server: that ceiling is a lever \
         anyone can pull to stop everyone linking"
    );
    let reserve = src.find("reserve_link_start(").expect("a per-address budget counted in D1");
    assert!(LINK_SRC.contains("crate::door_bucket::reserve("), "counted in D1, not the fail-open KV");
    let insert = src.find("INSERT INTO link_requests").expect("the insert");
    assert!(reserve < insert, "the budget is taken before the row is written");
    assert!(
        src.contains("DELETE FROM link_requests WHERE status='pending' AND expires_at"),
        "stale pending links are swept at start, not only by the daily cron"
    );
}

/// The text of one handler, from its signature up to the next top-level `fn`. Slicing to the
/// next item matters for the negative assertions: without it, a gate belonging to the handler
/// BELOW would satisfy a check about the handler above.
fn handler_src(signature: &str) -> &'static str {
    let at = LINK_SRC
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found in link.rs — re-point this guard"));
    let rest = &LINK_SRC[at + signature.len()..];
    let next = [rest.find("\npub async fn "), rest.find("\nasync fn ")]
        .into_iter()
        .flatten()
        .min();
    match next {
        Some(end) => &LINK_SRC[at..at + signature.len() + end],
        None => &LINK_SRC[at..],
    }
}

/// `link-approve` writes the device list through the same `validate_and_store_signed_list` as
/// `PUT /devices/list`, so the bare stateless JWT is not enough: a revoked device's access token
/// stays valid for ~15 minutes, and approving a link attaches a new device plus a 30-day refresh
/// token that outlives the revocation.
///
/// It takes the STRICTER gate of the two. `put_list` has to pair
/// `require_existing_account_auth` with `device_revoked`, because it is the call that creates the
/// first `devices` rows at registration and an active-device proof would deadlock that bootstrap.
/// An approver has no bootstrap: it is already the primary of an already-published list, which is
/// what created its row.
#[test]
fn link_approve_requires_an_active_unrevoked_device() {
    let src = handler_src("pub async fn link_approve");
    assert!(
        src.contains("require_active_auth("),
        "link-approve must gate on require_active_auth: it writes the device list, and the \
         approving device is by definition an already-linked primary, so there is no bootstrap \
         needing the looser put_list pairing"
    );
    // `require_active_auth(` does not contain `require_auth(` as a substring, and requiring the
    // `(` keeps a mention in prose from tripping the guard.
    assert!(
        !src.contains("require_auth("),
        "link-approve must NOT gate on the bare stateless JWT: require_auth checks a signature \
         and an expiry only, so a device revoked minutes ago could still approve a NEW device \
         onto the account for the rest of its access token's 15-minute life"
    );
}

/// `link-start` and `link-status` are unauthenticated ON PURPOSE, and must stay that way.
///
/// The device calling them does not have an account token yet — obtaining one is the entire point
/// of the flow — so requiring auth would not harden them, it would delete them. What stands in
/// for auth is proof-of-possession of the new device's Ed25519 private key (`link-start` signs
/// `ed_pub||x_pub`, `link-status` signs the `link_code` and is verified against the ed_pub stored
/// at start), plus a per-IP rate limit. Those two are the load-bearing parts, so they are pinned
/// here as well: a future edit that drops the signature check would leave a bare link_code as the
/// only thing between an attacker and a device token.
#[test]
fn link_start_and_link_status_stay_unauthenticated_but_keep_proof_and_rate_limit() {
    for signature in [
        "pub async fn link_start",
        "pub async fn link_status",
    ] {
        let src = handler_src(signature);
        assert!(
            !src.contains("require_auth(")
                && !src.contains("require_active_auth(")
                && !src.contains("require_existing_account_auth(")
                && !src.contains("extract_bearer("),
            "`{signature}` must stay unauthenticated — the new device has no token yet, and \
             demanding one breaks the flow that exists to issue it"
        );
        assert!(
            src.contains("check_rate_limit_env("),
            "`{signature}` is reachable pre-auth, so it must keep its rate limit"
        );
        assert!(
            src.contains(".verify("),
            "`{signature}` must keep its ed25519 proof-of-possession check — it is what stands in \
             for authentication here"
        );
    }
}
