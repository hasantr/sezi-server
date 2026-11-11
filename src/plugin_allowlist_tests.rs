//! The allowlist's storage against the real schema, and the upload decision — with a fixed TEST
//! publisher key, never a real one.

use super::*;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use sezi_plugin_fmt::allowlist::AllowRule;
use sezi_plugin_fmt::app_manifest::key_id_of;
use sezi_plugin_fmt::plugin_bundle::unpack_bundle;
use sezi_plugin_fmt::plugin_bundle_v2::{pack_bundle_v2, signature_line, signing_message};

const HASH: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn rows(db: &rusqlite::Connection) -> Vec<AllowRow> {
    let mut stmt = db.prepare(READ_ROWS_SQL).unwrap();
    stmt.query_map([], |r| {
        Ok(DbRow {
            id: r.get(0)?,
            publisher_key: r.get(1)?,
            app_id: r.get(2)?,
            code_hash: r.get(3)?,
            max_caps: r.get(4)?,
            label: r.get(5)?,
            added_at: r.get(6)?,
        })
    })
    .unwrap()
    .map(|r| r.unwrap().to_row().expect("a row the rule holds"))
    .collect()
}

fn upsert(db: &rusqlite::Connection, key: Option<&str>, app: Option<&str>, hash: Option<&str>, caps: &str, label: &str) {
    db.execute(UPSERT_SQL, rusqlite::params![key, app, hash, caps, label, "owner", 1]).unwrap();
}

#[test]
fn rows_are_kept_once_per_rule_and_a_second_write_refreshes_them() {
    let db = crate::test_schema::full_schema();
    let key = key_id_of(&[1; 32]);
    upsert(&db, Some(&key), None, None, r#"["roster"]"#, "Acme");
    upsert(&db, Some(&key), None, None, r#"["roster","media"]"#, "Acme Tools");
    upsert(&db, Some(&key), Some("ext:acme/board"), None, "[]", "Board");
    upsert(&db, None, None, Some(HASH), "[]", "A page");
    let got = rows(&db);
    assert_eq!(got.len(), 3, "the same rule twice is one row");
    assert_eq!(got[0].label, "Acme Tools");
    assert!(got[0].max_caps.contains("media"));
    assert_eq!(got[2].rule, AllowRule::Hash { code_hash: HASH.into() });
    db.execute(DELETE_SQL, [got[0].id]).unwrap();
    assert_eq!(rows(&db).len(), 2);
}

#[test]
fn the_mode_key_absent_is_open() {
    assert_eq!(mode_of(None), Mode::Open);
    assert_eq!(mode_of(Some("allowlist")), Mode::Allowlist);
    assert_eq!(MODE_KEY, "plugin_policy_mode");
    assert!(READ_MODE_SQL.contains(MODE_KEY));
}

fn stored_mode(db: &rusqlite::Connection) -> Option<String> {
    db.query_row(READ_MODE_SQL, [], |r| r.get(0)).ok()
}

#[test]
fn a_server_starts_in_allowlist_at_its_first_claim_and_keeps_a_chosen_mode() {
    let db = crate::test_schema::full_schema();
    assert_eq!(mode_of(stored_mode(&db).as_deref()), Mode::Open, "before the claim: as every relay before");
    db.execute(SEED_FRESH_MODE_SQL, [7]).unwrap();
    assert_eq!(stored_mode(&db).as_deref(), Some("allowlist"));
    // The owner chose open; a later re-claim's seed does not overwrite it.
    db.execute(
        "INSERT INTO server_config (key, value, created_at) VALUES (?1, 'open', 8) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [MODE_KEY],
    )
    .unwrap();
    db.execute(SEED_FRESH_MODE_SQL, [9]).unwrap();
    assert_eq!(mode_of(stored_mode(&db).as_deref()), Mode::Open);
}

#[test]
fn only_the_first_owners_registration_seeds_the_mode() {
    let src = include_str!("auth/verify.rs");
    let at = src.find("SEED_FRESH_MODE_SQL").expect("verify seeds the mode");
    let before = &src[..at];
    assert!(before.rfind("if redeemed_genesis {").is_some_and(|i| at - i < 120), "only in the genesis branch");
}

/// A signed bundle and what an app presents for it.
fn presented_for(seed: u8, id: &str, caps: &str) -> (Presented, String) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let key_id = key_id_of(&key.verifying_key().to_bytes());
    let app = format!(
        r#"{{"sezi_app":1,"id":"{id}","name":"Board","version":"1.0.0","contract":{{"min":2}},"publisher":{{"key_id":"{key_id}","name":"Acme"}},"capabilities":{caps}}}"#
    )
    .into_bytes();
    let files = vec![("index.html".to_string(), b"<!doctype html>".to_vec())];
    let msg = signing_message(files.clone(), &app).unwrap();
    let sig = signature_line(&key_id, &key.sign(&msg).to_bytes());
    let tar = pack_bundle_v2(files, &app, &sig).unwrap();
    let v = unpack_bundle(&tar).unwrap().app.unwrap();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let p = Presented {
        code_hash: Some(HASH.into()),
        app: Some(b64.encode(&v.manifest_json)),
        sig: Some(v.signature.clone()),
        digest: Some(b64.encode(v.bundle_digest)),
        first_party: None,
    };
    (p, key_id)
}

fn list_of(rows: Vec<AllowRow>) -> Allowlist {
    Allowlist { mode: Mode::Allowlist, rows }
}

fn row(rule: AllowRule, caps: &[&str]) -> AllowRow {
    AllowRow { id: 1, rule, max_caps: caps.iter().map(|s| s.to_string()).collect(), label: String::new(), added_at: 0 }
}

#[test]
fn an_open_server_takes_every_upload_as_before() {
    assert_eq!(upload_decision(&Allowlist::default(), &Presented::default()), Ok(()));
}

#[test]
fn an_allowlist_server_refuses_an_upload_that_presents_nothing() {
    // An app from before C3: no headers. The refusal is a 400 it ends its op on.
    let list = list_of(vec![row(AllowRule::Hash { code_hash: HASH.into() }, &[])]);
    assert_eq!(upload_decision(&list, &Presented::default()), Err("plugin/not-approved"));
}

#[test]
fn a_first_party_apps_code_passes_an_empty_allowlist() {
    // A fresh server starts in `allowlist` with no rows: the Web Suite still goes in.
    let list = list_of(vec![]);
    let scene = Presented { first_party: Some("html:scene".into()), ..Presented::default() };
    assert_eq!(upload_decision(&list, &scene), Ok(()));
    // Only the first-party ids: anything else claimed that way is judged as before.
    let other = Presented { first_party: Some("html:u-1".into()), ..Presented::default() };
    assert_eq!(upload_decision(&list, &other), Err("plugin/not-approved"));
}

#[test]
fn a_signed_app_is_judged_by_its_verified_manifest() {
    let (p, key_id) = presented_for(7, "ext:acme/board", r#"{"roster":true}"#);
    let by_key = |caps: &[&str]| list_of(vec![row(AllowRule::Publisher { key_id: key_id.clone(), app_id: None }, caps)]);
    assert_eq!(upload_decision(&by_key(&["roster"]), &p), Ok(()));
    assert_eq!(upload_decision(&by_key(&[]), &p), Err("plugin/not-approved"), "past the ceiling");
    let other = list_of(vec![row(AllowRule::Publisher { key_id: key_id_of(&[9; 32]), app_id: None }, &["roster"])]);
    assert_eq!(upload_decision(&other, &p), Err("plugin/not-approved"), "another publisher");
    // A forged signature is no presentation at all: only the hash is left to judge.
    let mut forged = p.clone();
    forged.digest = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]));
    assert_eq!(upload_decision(&by_key(&["roster"]), &forged), Err("plugin/not-approved"));
}

#[test]
fn a_hash_row_approves_the_bundle_it_names() {
    let list = list_of(vec![row(AllowRule::Hash { code_hash: HASH.into() }, &[])]);
    let p = Presented { code_hash: Some(HASH.into()), ..Presented::default() };
    assert_eq!(upload_decision(&list, &p), Ok(()));
    let p = Presented { code_hash: Some("B".repeat(43)), ..Presented::default() };
    assert_eq!(upload_decision(&list, &p), Err("plugin/not-approved"));
}
