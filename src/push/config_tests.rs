//! Which way a wake goes, and what the owner's settings are told about devices the own project
//! cannot reach (K8).

use super::*;

fn rows(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn verdict(project: &str) -> String {
    serde_json::to_string(&ProjectVerdict { at: 1_700_000_000, project: project.into() }).unwrap()
}

fn own(extra: &[(&str, &str)]) -> PushConfig {
    let mut r = rows(&[(KEY_PROJECT_ID, "owner-proj"), (KEY_SERVICE_ACCOUNT, "{}")]);
    r.extend(rows(extra));
    PushConfig::resolve(EnvPush::default(), &r)
}

#[test]
fn an_own_project_goes_direct_with_the_relay_as_its_fallback() {
    let c = own(&[]);
    assert_eq!(c.mode(), PushMode::Own);
    match c.send_mode() {
        Some(SendMode::Direct { project_id, fallback, reached, .. }) => {
            assert_eq!(project_id, "owner-proj");
            assert_eq!(fallback.as_deref(), Some(DEFAULT_PUSH_RELAY_URL));
            assert!(!reached);
        }
        other => panic!("{other:?}"),
    }
}

/// The first K8 build's server-wide verdict routes nothing: a server that still holds the row
/// (before migration 0048 removes it) goes direct, token by token.
#[test]
fn the_legacy_server_wide_verdict_routes_nothing() {
    let v = verdict("owner-proj");
    let c = own(&[(LEGACY_KEY_OWN_REJECTED, &v)]);
    assert!(matches!(c.send_mode(), Some(SendMode::Direct { .. })));
}

/// A verdict measured against another project (the env var changed) says nothing about this one.
#[test]
fn a_verdict_about_another_project_is_ignored() {
    let v = verdict("old-proj");
    let c = own(&[(KEY_OWN_REACHED, &v)]);
    assert!(!c.own_reached());
}

#[test]
fn a_reached_project_is_marked_so_on_the_direct_mode() {
    let v = verdict("owner-proj");
    let c = own(&[(KEY_OWN_REACHED, &v)]);
    assert!(matches!(c.send_mode(), Some(SendMode::Direct { reached: true, .. })));
}

/// env wins per key, as before.
#[test]
fn env_wins_over_d1() {
    let env = EnvPush {
        project_id: Some("env-proj".into()),
        service_account: Some("{}".into()),
        relay_url: Some("off".into()),
    };
    let c = PushConfig::resolve(env, &rows(&[(KEY_PROJECT_ID, "d1-proj"), (KEY_RELAY_URL, "https://r")]));
    assert_eq!(c.project_id.as_deref(), Some("env-proj"));
    assert_eq!(c.relay_url, None);
}

/// A corrupt verdict row is no verdict.
#[test]
fn a_corrupt_verdict_is_none() {
    let c = own(&[(KEY_OWN_REACHED, "{not json")]);
    assert!(!c.own_reached());
}

// ---- The owner's summary ----

/// No device refused: the own project, nothing to say.
#[test]
fn a_summary_with_no_relayed_device_is_the_own_project() {
    let s = summarize(&own(&[]), 0);
    assert_eq!(s, PushStatus { mode: PushMode::Own, own_rejected: false, relay_routed: 0 });
}

/// Every device tried was refused and none reached: the published app's phones only. The mode
/// says what wakes them — the relay, or nothing with it off.
#[test]
fn a_summary_where_every_device_is_relayed_says_the_project_reaches_nobody() {
    let s = summarize(&own(&[]), 3);
    assert_eq!(s, PushStatus { mode: PushMode::Relay, own_rejected: true, relay_routed: 3 });
    let s = summarize(&own(&[(KEY_RELAY_URL, "off")]), 3);
    assert_eq!(s, PushStatus { mode: PushMode::Off, own_rejected: true, relay_routed: 3 });
}

/// A mixed fleet: the project reached a device, and N others are relayed.
#[test]
fn a_mixed_fleet_is_the_own_project_with_n_relayed() {
    let v = verdict("owner-proj");
    let s = summarize(&own(&[(KEY_OWN_REACHED, &v)]), 2);
    assert_eq!(s, PushStatus { mode: PushMode::Own, own_rejected: false, relay_routed: 2 });
}

/// Without own credentials a leftover mark means nothing.
#[test]
fn no_own_project_no_summary() {
    let c = PushConfig::resolve(EnvPush::default(), &[]);
    assert_eq!(summarize(&c, 4), PushStatus { mode: PushMode::Relay, own_rejected: false, relay_routed: 0 });
}

/// Saving or clearing the credentials runs `CLEAR_VERDICTS_SQL`: the verdicts go (the legacy one
/// too), every other row stays.
#[test]
fn saving_credentials_clears_the_verdicts() {
    let db = crate::test_schema::full_schema();
    let v = verdict("owner-proj");
    for (k, val) in [
        (KEY_PROJECT_ID, "owner-proj"),
        (KEY_SERVICE_ACCOUNT, "{}"),
        (LEGACY_KEY_OWN_REJECTED, v.as_str()),
        (KEY_OWN_REACHED, v.as_str()),
    ] {
        db.execute(RECORD_SQL, rusqlite::params![k, val, 1]).unwrap();
    }
    db.execute(CLEAR_VERDICTS_SQL, []).unwrap();
    let mut keys: Vec<String> = db
        .prepare("SELECT key FROM server_config")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    keys.sort();
    assert_eq!(keys, [KEY_PROJECT_ID, KEY_SERVICE_ACCOUNT]);
}

/// The literal keys in the clear statement are the constants.
#[test]
fn the_clear_statement_names_both_keys() {
    assert!(CLEAR_VERDICTS_SQL.contains(&format!("'{LEGACY_KEY_OWN_REJECTED}'")));
    assert!(CLEAR_VERDICTS_SQL.contains(&format!("'{KEY_OWN_REACHED}'")));
}

/// A verdict's write is an upsert: a second write replaces the value.
#[test]
fn a_verdict_write_replaces_the_previous_one() {
    let db = crate::test_schema::full_schema();
    db.execute(RECORD_SQL, rusqlite::params![KEY_OWN_REACHED, "a", 1]).unwrap();
    db.execute(RECORD_SQL, rusqlite::params![KEY_OWN_REACHED, "b", 2]).unwrap();
    let v: String = db
        .query_row("SELECT value FROM server_config WHERE key = ?1", [KEY_OWN_REACHED], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "b");
}

/// Migration 0048 removes the legacy verdict a server running the first K8 build wrote.
#[test]
fn the_migration_removes_the_legacy_verdict() {
    let sql = include_str!("../../migrations/0048_push_token_routes.sql");
    assert!(sql.contains(&format!("key = '{LEGACY_KEY_OWN_REJECTED}'")));
}
