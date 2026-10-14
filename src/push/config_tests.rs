//! Which way a wake goes, with and without a refused own project (K8).

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
    assert!(!c.own_rejected());
    match c.send_mode() {
        Some(SendMode::Direct { project_id, fallback, reached, .. }) => {
            assert_eq!(project_id, "owner-proj");
            assert_eq!(fallback.as_deref(), Some(DEFAULT_PUSH_RELAY_URL));
            assert!(!reached);
        }
        other => panic!("{other:?}"),
    }
}

/// The K8 defect's second half: once Google has refused the project for these phones, the next
/// wake goes straight to the shared relay — the owner's credentials stay stored.
#[test]
fn a_refused_own_project_routes_every_wake_through_the_relay() {
    let v = verdict("owner-proj");
    let c = own(&[(KEY_OWN_REJECTED, &v)]);
    assert!(c.own_rejected());
    assert_eq!(c.mode(), PushMode::Relay);
    assert_eq!(c.send_mode(), Some(SendMode::Relay { url: DEFAULT_PUSH_RELAY_URL.into() }));
    assert!(c.service_account.is_some(), "the owner's credentials are not touched");
}

/// With the relay switched off there is nothing to fall back to: the mode says so.
#[test]
fn a_refused_own_project_with_the_relay_off_is_off() {
    let v = verdict("owner-proj");
    let c = own(&[(KEY_OWN_REJECTED, &v), (KEY_RELAY_URL, "off")]);
    assert_eq!(c.mode(), PushMode::Off);
    assert!(c.own_rejected(), "the settings still say why");
}

/// A verdict measured against another project (the env var changed) says nothing about this one.
#[test]
fn a_verdict_about_another_project_is_ignored() {
    let v = verdict("old-proj");
    let c = own(&[(KEY_OWN_REJECTED, &v), (KEY_OWN_REACHED, &v)]);
    assert!(!c.own_rejected() && !c.own_reached());
    assert_eq!(c.mode(), PushMode::Own);
}

#[test]
fn a_reached_project_is_marked_so_on_the_direct_mode() {
    let v = verdict("owner-proj");
    let c = own(&[(KEY_OWN_REACHED, &v)]);
    assert!(matches!(c.send_mode(), Some(SendMode::Direct { reached: true, .. })));
}

/// Without own credentials a leftover verdict means nothing — not even to the settings line.
#[test]
fn no_own_project_no_rejection() {
    let v = verdict("owner-proj");
    let c = PushConfig::resolve(EnvPush::default(), &rows(&[(KEY_OWN_REJECTED, &v)]));
    assert!(!c.own_rejected());
    assert_eq!(c.mode(), PushMode::Relay);
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

/// A corrupt verdict row is no verdict — the next wake measures again.
#[test]
fn a_corrupt_verdict_is_none() {
    let c = own(&[(KEY_OWN_REJECTED, "{not json")]);
    assert!(!c.own_rejected());
    assert_eq!(c.mode(), PushMode::Own);
}

/// Saving or clearing the credentials runs `CLEAR_VERDICTS_SQL`: both verdicts go, every other
/// row stays, and the config read after it goes direct again (the lazy re-test).
#[test]
fn saving_credentials_clears_the_verdicts() {
    let db = crate::test_schema::full_schema();
    let v = verdict("owner-proj");
    for (k, val) in [
        (KEY_PROJECT_ID, "owner-proj"),
        (KEY_SERVICE_ACCOUNT, "{}"),
        (KEY_OWN_REJECTED, v.as_str()),
        (KEY_OWN_REACHED, v.as_str()),
    ] {
        db.execute(RECORD_SQL, rusqlite::params![k, val, 1]).unwrap();
    }
    db.execute(CLEAR_VERDICTS_SQL, []).unwrap();
    let mut stmt = db.prepare(READ_SQL).unwrap();
    let left: Vec<(String, String)> = stmt
        .query_map(
            [KEY_PROJECT_ID, KEY_SERVICE_ACCOUNT, KEY_RELAY_URL, KEY_OWN_REJECTED, KEY_OWN_REACHED],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut keys: Vec<&str> = left.iter().map(|(k, _)| k.as_str()).collect();
    keys.sort();
    assert_eq!(keys, [KEY_PROJECT_ID, KEY_SERVICE_ACCOUNT]);
    assert_eq!(PushConfig::resolve(EnvPush::default(), &left).mode(), PushMode::Own);
}

/// The literal keys in the clear statement are the constants.
#[test]
fn the_clear_statement_names_both_keys() {
    assert!(CLEAR_VERDICTS_SQL.contains(&format!("'{KEY_OWN_REJECTED}'")));
    assert!(CLEAR_VERDICTS_SQL.contains(&format!("'{KEY_OWN_REACHED}'")));
}

/// A verdict's write is an upsert: a second write replaces the value.
#[test]
fn a_verdict_write_replaces_the_previous_one() {
    let db = crate::test_schema::full_schema();
    db.execute(RECORD_SQL, rusqlite::params![KEY_OWN_REJECTED, "a", 1]).unwrap();
    db.execute(RECORD_SQL, rusqlite::params![KEY_OWN_REJECTED, "b", 2]).unwrap();
    let v: String = db
        .query_row("SELECT value FROM server_config WHERE key = ?1", [KEY_OWN_REJECTED], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "b");
}
