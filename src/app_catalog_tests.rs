//! The catalog's upload judgement and its storage against the real schema — bundles signed by a
//! fixed TEST key, never a real one.

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use sezi_plugin_fmt::allowlist::{AllowRow, AllowRule, Mode};
use sezi_plugin_fmt::app_manifest::key_id_of;
use sezi_plugin_fmt::plugin_bundle::pack_bundle;
use sezi_plugin_fmt::plugin_bundle_v2::{pack_bundle_v2, signature_line, signing_message};

fn signed(seed: u8, id: &str, caps: &str) -> (Vec<u8>, String) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let key_id = key_id_of(&key.verifying_key().to_bytes());
    let app = format!(
        r#"{{"sezi_app":1,"id":"{id}","name":"Board","version":"1.2.0","contract":{{"min":2}},"publisher":{{"key_id":"{key_id}","name":"Acme"}},"capabilities":{caps}}}"#
    )
    .into_bytes();
    let files = vec![("index.html".to_string(), b"<!doctype html>".to_vec())];
    let sig = signature_line(&key_id, &key.sign(&signing_message(files.clone(), &app).unwrap()).to_bytes());
    (pack_bundle_v2(files, &app, &sig).unwrap(), key_id)
}

fn allowlist(rows: Vec<AllowRow>) -> Allowlist {
    Allowlist { mode: Mode::Allowlist, rows }
}

fn by_key(key_id: &str, caps: &[&str]) -> AllowRow {
    AllowRow {
        id: 1,
        rule: AllowRule::Publisher { key_id: key_id.into(), app_id: None },
        max_caps: caps.iter().map(|s| s.to_string()).collect(),
        label: String::new(),
        added_at: 0,
    }
}

#[test]
fn a_signed_bundle_is_accepted_under_its_digest() {
    let (tar, key_id) = signed(7, "ext:acme/board", r#"{"roster":true}"#);
    let a = judge_upload(&tar, &Allowlist::default()).unwrap();
    assert_eq!(a.id, blake3::hash(&tar).to_hex().to_string());
    assert!(is_entry_id(&a.id));
    assert!(rule::is_code_hash(&a.code_hash), "the install wire's encoding");
    assert_eq!(a.app_id, "ext:acme/board");
    assert_eq!(a.name, "Board");
    assert_eq!(a.version, "1.2.0");
    assert_eq!(a.publisher_key, key_id);
    assert_eq!(a.publisher_name, "Acme");
    assert!(a.manifest.contains("\"roster\":true"));
}

#[test]
fn what_is_not_a_signed_bundle_is_refused() {
    assert_eq!(judge_upload(b"", &Allowlist::default()), Err(BAD_BUNDLE));
    assert_eq!(judge_upload(b"not a tar", &Allowlist::default()), Err(BAD_BUNDLE));
    let v1 = pack_bundle(vec![("index.html".into(), b"<p>x</p>".to_vec())], "index.html").unwrap();
    assert_eq!(judge_upload(&v1, &Allowlist::default()), Err(NOT_SIGNED));
    let (mut tar, _) = signed(7, "ext:acme/board", "{}");
    let last = tar.len() - 600;
    tar[last] ^= 1;
    assert!(judge_upload(&tar, &Allowlist::default()).is_err(), "a changed byte");
}

#[test]
fn an_allowlist_server_takes_only_what_it_approves() {
    let (tar, key_id) = signed(7, "ext:acme/board", r#"{"roster":true}"#);
    assert!(judge_upload(&tar, &allowlist(vec![by_key(&key_id, &["roster"])])).is_ok());
    assert_eq!(
        judge_upload(&tar, &allowlist(vec![by_key(&key_id, &[])])),
        Err(rule::NOT_APPROVED),
        "past the row's ceiling"
    );
    assert_eq!(judge_upload(&tar, &allowlist(vec![])), Err(rule::NOT_APPROVED));
}

#[test]
fn entry_ids_are_hex_digests_only() {
    assert!(is_entry_id(&"a".repeat(64)));
    assert!(!is_entry_id(&"A".repeat(64)));
    assert!(!is_entry_id("../x"));
    assert!(!is_entry_id(&"a".repeat(63)));
    assert_eq!(object_key(&"0".repeat(64)), format!("apps/{}.tar", "0".repeat(64)));
}

fn insert(db: &rusqlite::Connection, a: &Accepted, size: i64) {
    db.execute(
        INSERT_SQL,
        rusqlite::params![
            a.id, a.code_hash, a.app_id, a.name, a.version, a.publisher_key, a.publisher_name,
            a.manifest, size, "r2-primary", "owner", 5
        ],
    )
    .unwrap();
}

fn rows(db: &rusqlite::Connection) -> Vec<DbRow> {
    let mut stmt = db.prepare(LIST_SQL).unwrap();
    stmt.query_map([], |r| {
        Ok(DbRow {
            id: r.get(0)?,
            code_hash: r.get(1)?,
            app_id: r.get(2)?,
            name: r.get(3)?,
            version: r.get(4)?,
            publisher_key: r.get(5)?,
            publisher_name: r.get(6)?,
            manifest: r.get(7)?,
            size_bytes: r.get(8)?,
            added_at: r.get(9)?,
        })
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

#[test]
fn rows_are_kept_once_per_bundle_and_listed_with_their_manifest() {
    let db = crate::test_schema::full_schema();
    let (tar, _) = signed(7, "ext:acme/board", r#"{"roster":true}"#);
    let a = judge_upload(&tar, &Allowlist::default()).unwrap();
    insert(&db, &a, tar.len() as i64);
    insert(&db, &a, tar.len() as i64);
    let got = rows(&db);
    assert_eq!(got.len(), 1, "the same bundle twice is one entry");
    let store: String = db.query_row(STORE_SQL, [&a.id], |r| r.get(0)).unwrap();
    assert_eq!(store, "r2-primary");
    let v = view(&got);
    assert_eq!(v["entries"][0]["app_id"], "ext:acme/board");
    assert_eq!(v["entries"][0]["manifest"]["capabilities"]["roster"], true);
    db.execute(DELETE_SQL, [&a.id]).unwrap();
    assert!(rows(&db).is_empty());
    let n: i64 = db.query_row(COUNT_SQL, [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0);
}
