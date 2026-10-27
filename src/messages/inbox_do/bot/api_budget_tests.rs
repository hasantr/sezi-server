//! The bot's call budget: a burst of 60, then 5 a second.

use super::*;

const T0: i64 = 1_761_200_000_000;

/// Run `n` calls at `now`, threading the bucket; how many were admitted.
fn calls(bucket: &mut Option<Bucket>, n: i64, now: i64) -> i64 {
    let mut ok = 0;
    for _ in 0..n {
        let (after, verdict) = take(*bucket, now);
        *bucket = Some(after);
        ok += i64::from(verdict.is_ok());
    }
    ok
}

/// A key holder calling in a loop used to be bounded by nothing but `sendMessage`'s limit.
#[test]
fn a_bot_gets_a_burst_of_sixty_then_five_a_second() {
    let mut b = None;
    assert_eq!(calls(&mut b, 100, T0), BURST, "a fresh bucket is full");
    assert_eq!(take(b, T0).1, Err(1), "the next call fits in a second");
    assert_eq!(calls(&mut b, 10, T0 + 1_000), PER_SECOND);
    // Sustained: a minute of calling as fast as it can admits 300 more, not one beyond.
    let mut admitted = 0;
    for ms in (1_010..=61_000).step_by(10) {
        admitted += calls(&mut b, 1, T0 + ms);
    }
    assert_eq!(admitted, 300);
}

#[test]
fn a_refusal_spends_nothing_and_an_idle_bot_refills_only_to_the_burst() {
    let mut b = None;
    calls(&mut b, BURST, T0);
    for _ in 0..1_000 {
        let (after, verdict) = take(b, T0 + 100);
        assert!(verdict.is_err());
        b = Some(after);
    }
    assert_eq!(calls(&mut b, 1, T0 + 200), 1, "200 ms is one call, however often it was refused");
    assert_eq!(calls(&mut b, 1_000, T0 + 3_600_000), BURST, "an hour idle is still one burst");
}

#[test]
fn the_bucket_survives_its_own_storage_and_a_bad_value_is_a_full_bucket() {
    let b = Bucket { milli: 12_345, at_ms: T0 };
    assert_eq!(Bucket::parse(Some(&b.to_kv())), Some(b));
    for bad in [None, Some(""), Some("x:y"), Some("5"), Some("-1:2")] {
        assert_eq!(Bucket::parse(bad), None, "{bad:?}");
    }
    // A clock that went back refills nothing and refuses nothing it would not have.
    let (after, verdict) = take(Some(Bucket { milli: 2_000, at_ms: T0 }), T0 - 5_000);
    assert!(verdict.is_ok());
    assert_eq!(after.milli, 1_000);
}

/// Every `/bot/v1/*` call takes from it — before the body is read or any method's own D1 work —
/// and a refusal is the send limit's own answer.
#[test]
fn every_method_takes_a_call_before_its_work() {
    let api = include_str!("../../../bots/api.rs");
    let d = &api[api.find("pub async fn dispatch(").unwrap()..];
    let at = |s: &str| d.find(s).unwrap_or_else(|| panic!("{s}"));
    assert!(at("\"disabled\"") < at("take_call("));
    assert!(at("take_call(") < at("mark_program_seen("));
    assert!(at("take_call(") < at("read_body("));
    assert!(at("take_call(") < at("match method.as_str()"));
    let route = include_str!("mod.rs");
    assert!(route.contains("(Method::Post, \"/bot/budget\") => self.bot_take_call()"));
}
