//! Tests for `keys/handlers.rs` (split out per the 800-line ceiling; included via `#[path]`).
//! `super` = the `handlers` module, so `use super::X` reaches the handler surface unchanged.

use super::OTK_UNCONSUMED_COUNT_SQL;
use rusqlite::{params, Connection};

/// `include_str!` binds at compile time and resolves relative to THIS file, so `handlers.rs` is
/// the sibling next door. Renaming either file breaks the build instead of silently emptying the
/// guard.
const SRC: &str = include_str!("handlers.rs");

/// The handler source WITHOUT the test wiring at its foot.
///
/// The guards below assert that certain things are absent, and the sentences explaining WHY they
/// are absent necessarily name them. While this module sat inline at the bottom of `handlers.rs`
/// that was a live hazard — a guard tripping over its own prose — and it is gone with the split:
/// `SRC` is now a file that does not contain this test. Move this module back inline and the
/// hazard comes back, so the split is still stripped here and every guard matches on CODE (a SQL
/// string, a bind expression) rather than on words that could also appear in a comment.
fn code() -> &'static str {
    SRC.split("\n#[cfg(test)]")
        .next()
        .expect("split always yields a first element")
}

/// The source of ONE handler: from its signature to the start of the next item, or to the end of
/// the handler source when it is the last one.
///
/// The bound used to be END OF FILE unconditionally, which was correct only for as long as
/// `rotate_signed_prekey` happened to be the last function in `handlers.rs` — a coupling nothing
/// stated and nothing checked. Appending a handler below it would have silently widened the
/// guard until it was asserting about somebody else's code, and moving this module into its own
/// file takes away even the adjacency that might have made someone notice. So the bound is
/// written down instead of inherited from file order. Same shape as
/// `devices/link_tests.rs::handler_src`.
fn handler_body(signature: &str) -> &'static str {
    let src = code();
    let at = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found in handlers.rs — re-point this guard"));
    let rest = &src[at + signature.len()..];
    let next = [
        rest.find("\npub async fn "),
        rest.find("\nasync fn "),
        rest.find("\nfn "),
    ]
    .into_iter()
    .flatten()
    .min();
    match next {
        Some(end) => &src[at..at + signature.len() + end],
        None => &src[at..],
    }
}

/// The `''` SPK slot is gone, and must not come back.
///
/// It was the one slot nothing scoped: a device-less write landed there and a device-less
/// `auth::relogin` read it back as PROOF OF IDENTITY. Hardening it meant a policy function
/// (`device_less_spk_write_allowed`) deciding who still counted as the pre-multidevice
/// primary, plus a second anchor lookup against `users.identity_ed_pub` — and a documented
/// residual, because an account with no device list AND a NULL anchor had nothing to verify
/// the write against, so it was stored unverified.
///
/// Requiring a device on both sides removes the slot instead of guarding it. This is a
/// source-level guard rather than a behavioural test for the reason `auth::relogin`'s is:
/// the handler needs D1 and a live worker environment. The regression it catches is a
/// reintroduced `unwrap_or("")` on the write side, which raises no error and shows up only
/// as a relogin verifying against a key nobody signed for.
#[test]
fn there_is_no_device_less_signed_prekey_slot() {
    let body = handler_body("pub async fn rotate_signed_prekey");
    assert!(
        !body.contains("unwrap_or(\"\")"),
        "an SPK write must never fall back to the '' sentinel: that slot is what a \
         device-less relogin read as proof of identity"
    );
    // The anchor lookup is the CODE that reads the account-level key, not the prose above
    // explaining why it is gone.
    assert!(
        !body.contains("SELECT identity_ed_pub FROM users"),
        "the device-less anchor is gone with the slot it verified; a per-device write \
         anchors on devices.ed_pub, and re-adding the users fallback re-opens the \
         no-anchor accept"
    );
    assert!(
        body.contains("require_auth_device"),
        "the device must come from the TOKEN, so the row cannot land in another \
         device's slot or in no device's slot"
    );
}

fn pool(c: &Connection, user: &str, device: &str) -> i64 {
    c.query_row(OTK_UNCONSUMED_COUNT_SQL, params![user, device], |r| {
        r.get(0)
    })
    .unwrap()
}

/// `GET /keys/otks/count` must answer with the pool a peer could still be served from: only
/// unconsumed rows, only this user, only this device. Counting consumed rows would make an
/// exhausted pool look healthy, which is the failure this endpoint exists to expose.
#[test]
fn the_count_sees_only_this_devices_unconsumed_keys() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
        "CREATE TABLE one_time_prekeys(user_id TEXT, device_id TEXT, consumed INTEGER);
         INSERT INTO one_time_prekeys VALUES('u','dev-a',0),('u','dev-a',0),('u','dev-a',1),
                                            ('u','dev-b',0),
                                            ('other','dev-a',0);",
    )
    .unwrap();
    assert_eq!(pool(&c, "u", "dev-a"), 2, "consumed rows are not available to any peer");
    assert_eq!(pool(&c, "u", "dev-b"), 1, "a sibling device has its own pool");
    assert_eq!(pool(&c, "u", "dev-missing"), 0, "an unknown device holds nothing");
    assert_eq!(
        pool(&c, "u", "dev-a") + pool(&c, "u", "dev-b"),
        3,
        "no query ever spans users: 'other' is invisible from either device of 'u'"
    );
}

/// The read must land on the same pool `replenish` writes to, or a healthy device reads back
/// zero and the instrument reports a shrink that never happened.
///
/// `otk_pool_scope` used to be that agreement, mapping a device-less token onto the `''`
/// pool at both ends. Both ends now take the device straight from the token, so the guard is
/// that neither has re-acquired a sentinel of its own.
#[test]
fn the_count_and_the_replenish_address_the_same_pool() {
    let src = code();
    for name in ["pub async fn replenish", "pub async fn otk_count"] {
        let start = src.find(name).unwrap_or_else(|| panic!("{name} disappeared"));
        let body = &src[start..src.len().min(start + 4000)];
        assert!(
            body.contains("require_auth_device"),
            "{name} must scope its pool by the token's device"
        );
        assert!(
            !body.contains("unwrap_or(\"\")"),
            "{name} must not map a caller onto the '' pool: the read and the write would \
             agree with each other and with nothing that serves peers"
        );
    }
}
