use super::*;

/// The place a relay runs is said only when known: the generator's var wins, a Cloudflare version
/// metadata binding means Cloudflare, and nothing at all is "unknown" — never a guess.
#[test]
fn hosting_is_said_only_when_known() {
    assert_eq!(hosting(Some("workerd"), false), Some("workerd"));
    assert_eq!(hosting(Some("workerd"), true), Some("workerd"), "the var wins");
    assert_eq!(hosting(Some("wrangler"), false), Some("wrangler"));
    assert_eq!(hosting(Some(" Workerd "), false), Some("workerd"));
    assert_eq!(hosting(None, true), Some("cloudflare"));
    assert_eq!(hosting(Some("cloudflare"), false), Some("cloudflare"));
    assert_eq!(hosting(None, false), None, "an old Cloudflare copy and a bare wrangler dev look alike");
    assert_eq!(hosting(Some("mars"), false), None, "an unknown word is no claim");
    assert_eq!(hosting(Some(""), true), Some("cloudflare"));
}

/// A commit stamp is a git sha or nothing; anything else in the build env is dropped.
#[test]
fn a_commit_is_a_sha_or_nothing() {
    assert_eq!(commit(Some("63985be3")), Some("63985be3".into()));
    assert_eq!(commit(Some("63985BE3a1b2c3d4e5f60718293a4b5c6d7e8f90")), Some("63985be3a1b2c3d4e5f60718293a4b5c6d7e8f90".into()));
    assert_eq!(commit(Some("abc")), None, "too short to name anything");
    assert_eq!(commit(Some("not-a-sha")), None);
    assert_eq!(commit(Some(&"a".repeat(41))), None);
    assert_eq!(commit(None), None);
}

/// `/healthz`'s migration word: `ok` once the schema is current, `failed:<name>` naming the
/// migration the schema could not reach, `unchecked` before the first attempt (or with no D1).
#[test]
fn the_migration_word() {
    assert_eq!(migration_status(true, None), "ok");
    assert_eq!(migration_status(false, Some("0057_registration_receipts")), "failed:0057_registration_receipts");
    assert_eq!(migration_status(false, None), "unchecked");
    // A later success clears an earlier failure: the caller passes no name then.
    assert_eq!(migration_status(true, Some("0057_x")), "ok");
}

/// The fields are additive: present keys with null values when unknown, so an old app ignores
/// them and a new one reads "unknown" — never a missing-key crash on either side.
#[test]
fn the_capabilities_fields() {
    let f = fields(Some("workerd"), None, None);
    assert_eq!(f["hosting"], "workerd");
    assert!(f["version_id"].is_null() && f["commit"].is_null());
    let f = fields(Some("cloudflare"), Some("6d0f…".into()), Some("63985be3".into()));
    assert_eq!((f["hosting"].as_str(), f["version_id"].as_str(), f["commit"].as_str()), (Some("cloudflare"), Some("6d0f…"), Some("63985be3")));
    let f = fields(None, Some(String::new()), None);
    assert!(f["hosting"].is_null() && f["version_id"].is_null(), "an empty id is no id");
}
