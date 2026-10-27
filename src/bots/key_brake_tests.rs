//! The wrong-key brake: twenty refused keys a minute per address, no store written.

use super::*;

const T0: i64 = 1_761_200_000;

/// Before, an address could send wrong keys as fast as it liked, each one a D1 read.
#[test]
fn an_address_gets_twenty_wrong_keys_a_minute_and_then_waits() {
    let mut b = Brake::default();
    for i in 0..MISSES_PER_MINUTE {
        assert!(b.check("203.0.113.7", "bad", T0 + 1).is_ok(), "key {i}");
        b.miss("203.0.113.7", "bad", T0 + 1);
    }
    assert_eq!(b.check("203.0.113.7", "bad", T0 + 1), Err(60), "until its minute is over");
    assert_eq!(b.check("203.0.113.7", "another", T0 + 59), Err(2), "any unknown key");
    assert!(b.check("198.51.100.1", "bad", T0 + 1).is_ok(), "another address is not held by it");
    assert!(b.check("203.0.113.7", "bad", T0 + 61).is_ok(), "a new minute");
    b.miss("203.0.113.7", "bad", T0 + 61);
    assert!(b.check("203.0.113.7", "bad", T0 + 61).is_ok(), "one miss in the new window");
}

/// Programs that share an address (a relay that trusts no proxy header calls them all `local`):
/// one retrying an old key must not hold the others.
#[test]
fn a_key_that_opened_a_bot_passes_a_braked_address_until_it_stops_opening_one() {
    let mut b = Brake::default();
    b.good("working", T0);
    for _ in 0..MISSES_PER_MINUTE {
        b.miss("local", "old", T0 + 1);
    }
    assert!(b.check("local", "old", T0 + 2).is_err());
    assert!(b.check("local", "working", T0 + 2).is_ok(), "a known-good key is not braked");
    // Renewed: its lookup fails once, and from then on it is braked like any other.
    b.miss("local", "working", T0 + 3);
    assert!(b.check("local", "working", T0 + 3).is_err());
    // A good key passes for its time after it last opened a bot, not for ever.
    b.good("idle", T0);
    assert!(b.check("local", "idle", T0 + GOOD_FOR_S - 1).is_ok());
    for _ in 0..MISSES_PER_MINUTE {
        b.miss("local", "old", T0 + GOOD_FOR_S);
    }
    assert!(b.check("local", "idle", T0 + GOOD_FOR_S).is_err());
}

#[test]
fn both_tables_stay_bounded_and_keep_the_live_entries() {
    let mut b = Brake::default();
    for i in 0..(MAX_ADDRESSES * 2) {
        b.miss(&format!("10.0.{}.{}", i / 256, i % 256), "k", T0 + 1 + (i as i64 / 1_000));
        b.good(&format!("good{i}"), T0);
    }
    let (addresses, good) = b.len();
    assert!(addresses <= MAX_ADDRESSES && good <= MAX_GOOD, "{addresses} addresses, {good} keys");
    // Ended windows go first: a live one outlives a table full of ended ones.
    let mut c = Brake::default();
    for _ in 0..MISSES_PER_MINUTE {
        c.miss("hot", "k", T0);
    }
    for i in 0..MAX_ADDRESSES {
        c.miss(&format!("old{i}"), "k", T0 - 120);
    }
    c.miss("new", "k", T0);
    assert!(c.check("hot", "k", T0).is_err(), "a live window outlives ended ones");
}

/// The brake is asked before the lookup, only for a key that would cost one, and fed by its answer.
#[test]
fn the_brake_stands_before_the_key_lookup() {
    let api = include_str!("api.rs");
    let d = &api[api.find("pub async fn dispatch(").unwrap()..];
    let at = |s: &str| d.find(s).unwrap_or_else(|| panic!("{s}"));
    assert!(at("token::parse(") < at("key_brake::check("), "a malformed key is never counted");
    assert!(at("key_brake::check(") < at("token::authenticate("));
    assert!(at("token::authenticate(") < at("key_brake::miss("));
    assert!(at("key_brake::miss(") < at("\"unauthorized\""));
    assert!(at("\"unauthorized\"") < at("key_brake::good("));
    assert!(d.contains("door_address("), "an IPv6 sender is braked by its /64");
}
