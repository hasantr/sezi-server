//! The allowlist rule, both halves' (relay and core) — with a fixed TEST key, never a real one.

use super::*;
use crate::app_manifest::key_id_of;
use crate::plugin_bundle::unpack_bundle;
use crate::plugin_bundle_v2::{pack_bundle_v2, signature_line, signing_message};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

fn names(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

const HASH: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const KEY: &str = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn publisher_row(app: Option<&str>, caps: &[&str]) -> AllowRow {
    AllowRow {
        id: 1,
        rule: AllowRule::Publisher { key_id: KEY.into(), app_id: app.map(str::to_string) },
        max_caps: names(caps),
        label: String::new(),
        added_at: 0,
    }
}

fn cand<'a>(id: &'a str, key: Option<&'a str>, hash: Option<&'a str>, g: &'a BTreeSet<String>) -> Candidate<'a> {
    Candidate { plugin_id: id, publisher_key_id: key, code_hash: hash, granted: g }
}

#[test]
fn open_approves_everything_and_an_empty_allowlist_nothing() {
    let g = names(&["roster"]);
    let c = cand("html:x", None, None, &g);
    assert!(Allowlist::default().approves(&c), "open is today's behaviour");
    let closed = Allowlist { mode: Mode::Allowlist, rows: vec![] };
    assert!(!closed.approves(&c));
    assert!(!closed.may_approve_unverified("ext:acme/a", None));
}

#[test]
fn a_publisher_row_approves_its_apps_up_to_its_ceiling() {
    let any = publisher_row(None, &["roster", "network:https://api.acme.example"]);
    let g = names(&["roster", "network", "network:https://api.acme.example"]);
    // `network` is granted beside every origin; a row naming the origin covers both.
    assert!(any.approves(&cand("ext:acme/a", Some(KEY), None, &g)));
    let elsewhere = names(&["network", "network:https://other.example"]);
    assert!(!any.approves(&cand("ext:acme/a", Some(KEY), None, &elsewhere)), "another origin");
    let g = names(&["roster"]);
    assert!(any.approves(&cand("ext:acme/a", Some(KEY), None, &g)));
    assert!(any.approves(&cand("ext:acme/b", Some(KEY), None, &g)), "every app of the key");
    assert!(!any.approves(&cand("ext:acme/a", Some("ed25519:other"), None, &g)), "another key");
    assert!(!any.approves(&cand("ext:acme/a", None, None, &g)), "no verified signature");
    let wider = names(&["roster", "media"]);
    assert!(!any.approves(&cand("ext:acme/a", Some(KEY), None, &wider)), "a grant past the row");

    let one = publisher_row(Some("ext:acme/a"), &["network"]);
    let g = names(&["network", "network:https://x.example", "network:https://y.example"]);
    assert!(one.approves(&cand("ext:acme/a", Some(KEY), None, &g)), "`network` = every origin");
    assert!(!one.approves(&cand("ext:acme/b", Some(KEY), None, &g)), "only the named app");
    assert!(one.may_approve_unverified("ext:acme/a", None));
    assert!(!one.may_approve_unverified("ext:acme/b", None));
}

#[test]
fn a_hash_row_approves_exactly_one_bundle() {
    let row = AllowRow {
        id: 2,
        rule: AllowRule::Hash { code_hash: HASH.into() },
        max_caps: BTreeSet::new(),
        label: "Board".into(),
        added_at: 0,
    };
    let none = BTreeSet::new();
    assert!(row.approves(&cand("html:u-1", None, Some(HASH), &none)));
    assert!(!row.approves(&cand("html:u-1", None, Some("other"), &none)));
    let net = names(&["network"]);
    assert!(!row.approves(&cand("html:u-1", None, Some(HASH), &net)), "its ceiling holds too");
    assert!(row.may_approve_unverified("ext:acme/z", Some(HASH)));
    assert!(!row.may_approve_unverified("ext:acme/z", None));
}

#[test]
fn a_mode_reads_leniently_and_writes_strictly() {
    assert_eq!(Mode::read(None), Mode::Open, "a relay from before C3");
    assert_eq!(Mode::read(Some("open")), Mode::Open);
    assert_eq!(Mode::read(Some("allowlist")), Mode::Allowlist);
    assert_eq!(Mode::read(Some("catalog")), Mode::Allowlist, "an unknown mode never opens");
    assert_eq!(Mode::parse_write("catalog"), Err(BAD_MODE));
    assert_eq!(Mode::parse_write("allowlist"), Ok(Mode::Allowlist));
}

#[test]
fn rows_round_trip_and_an_unreadable_one_is_skipped() {
    let row = publisher_row(Some("ext:acme/a"), &["media"]);
    assert_eq!(row_from_json(&row_to_json(&row)), Some(row.clone()));
    let v = json!({
        "mode": "allowlist",
        "allowed": [row_to_json(&row), {"id": 9}, {"publisher_key": KEY, "code_hash": HASH}],
        "later": true,
    });
    let list = allowlist_from_json(&v);
    assert_eq!(list.mode, Mode::Allowlist);
    assert_eq!(list.rows, vec![row]);
    assert_eq!(allowlist_from_json(&json!({"disabled": []})), Allowlist::default());
}

#[test]
fn a_written_row_is_checked() {
    let ok = json!({"publisher_key": KEY, "app_id": "ext:acme/a", "max_caps": ["roster", "network:https://a.example", "later.cap"], "label": "Acme"});
    assert!(check_new_row(&ok).is_ok(), "an unknown capability name is kept");
    for bad in [
        json!({}),
        json!({"publisher_key": KEY, "code_hash": HASH}),
        json!({"publisher_key": "ed25519:short"}),
        json!({"publisher_key": KEY, "app_id": "html:x"}),
        json!({"code_hash": "not a hash"}),
        json!({"code_hash": HASH, "app_id": "ext:acme/a"}),
        json!({"code_hash": HASH, "max_caps": ["network:http://a.example"]}),
        json!({"code_hash": HASH, "max_caps": "roster"}),
        json!({"code_hash": HASH, "label": "x".repeat(81)}),
    ] {
        assert_eq!(check_new_row(&bad), Err(BAD_ROW), "{bad}");
    }
    assert!(is_code_hash(HASH));
    assert!(!is_code_hash(&format!("{HASH}=")));
}

#[test]
fn caps_within_reads_network_as_every_origin() {
    assert!(caps_within(&names(&["network:https://a.example"]), &names(&["network"])));
    assert!(caps_within(&names(&["network", "network:https://a.example"]), &names(&["network:https://a.example"])));
    assert!(!caps_within(&names(&["network"]), &BTreeSet::new()));
    assert!(caps_within(&BTreeSet::new(), &BTreeSet::new()));
}

fn signed_bundle() -> (Vec<u8>, String) {
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let id = key_id_of(&key.verifying_key().to_bytes());
    let app = format!(
        r#"{{"sezi_app":1,"id":"ext:acme/board","name":"Board","version":"1.0.0","contract":{{"min":2}},"publisher":{{"key_id":"{id}","name":"Acme"}},"capabilities":{{"roster":true}}}}"#
    )
    .into_bytes();
    let files = vec![("index.html".to_string(), b"<!doctype html>".to_vec())];
    let msg = signing_message(files.clone(), &app).unwrap();
    let sig = signature_line(&id, &key.sign(&msg).to_bytes());
    (pack_bundle_v2(files, &app, &sig).unwrap(), id)
}

#[test]
fn what_an_upload_presents_opens_only_when_its_signature_verifies() {
    let (tar, key_id) = signed_bundle();
    let v = unpack_bundle(&tar).unwrap().app.unwrap();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let app = b64.encode(&v.manifest_json);
    let digest = b64.encode(v.bundle_digest);
    let p = open_presented(&app, &v.signature, &digest).unwrap();
    assert_eq!(p.app_id, "ext:acme/board");
    assert_eq!(p.publisher_key_id, key_id);
    assert_eq!(p.granted, names(&["roster"]));
    // Another digest (other files) or another manifest: the signature no longer covers it.
    let other = b64.encode([7u8; 32]);
    assert_eq!(open_presented(&app, &v.signature, &other), Err(NOT_APPROVED));
    let mut json = v.manifest_json.clone();
    json.push(b' ');
    assert_eq!(open_presented(&b64.encode(&json), &v.signature, &digest), Err(NOT_APPROVED));
    assert_eq!(open_presented("!!", &v.signature, &digest), Err(NOT_APPROVED));
    let huge = "A".repeat(MAX_PRESENTED_APP_BYTES * 2);
    assert_eq!(open_presented(&huge, &v.signature, &digest), Err(NOT_APPROVED));
}
