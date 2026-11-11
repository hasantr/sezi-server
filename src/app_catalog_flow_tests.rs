//! The catalog's routes against a media store double and the real D1 schema: add → fetch →
//! remove, the digest the bytes are kept and served under, an allowlist, a full catalog, and a Lite
//! relay with no store. Bundles are signed by a fixed TEST key, never a real one.

use super::*;
use crate::app_catalog::{COUNT_SQL, DELETE_SQL, INSERT_SQL, LIST_SQL, STORE_SQL};
use ed25519_dalek::{Signer, SigningKey};
use sezi_plugin_fmt::allowlist::{AllowRow, AllowRule, Mode};
use sezi_plugin_fmt::app_manifest::key_id_of;
use sezi_plugin_fmt::plugin_bundle_v2::{pack_bundle_v2, signature_line, signing_message};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;

/// Run a future whose doubles never pend.
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// The media store: objects by (store id, key). `full` refuses every write, `down` every read.
#[derive(Default)]
struct FakeBlobs {
    objects: RefCell<HashMap<(String, String), Vec<u8>>>,
    full: Cell<bool>,
    down: Cell<bool>,
}

impl FakeBlobs {
    fn has(&self, key: &str) -> bool {
        self.objects.borrow().keys().any(|(_, k)| k == key)
    }
}

impl CatalogBlobs for FakeBlobs {
    type PutErr = &'static str;

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<String, &'static str> {
        if self.full.get() {
            return Err("all_full");
        }
        self.objects.borrow_mut().insert(("r2-primary".into(), key.into()), bytes);
        Ok("r2-primary".into())
    }

    async fn get(&self, store_id: &str, key: &str) -> Result<Option<Vec<u8>>, ()> {
        if self.down.get() {
            return Err(());
        }
        Ok(self.objects.borrow().get(&(store_id.to_string(), key.to_string())).cloned())
    }

    async fn delete(&self, store_id: &str, key: &str) {
        self.objects.borrow_mut().remove(&(store_id.to_string(), key.to_string()));
    }
}

/// The table on SQLite with every migration applied — the schema D1 has.
struct SqlRows(rusqlite::Connection);

impl CatalogRows for SqlRows {
    async fn list(&self) -> Vec<DbRow> {
        let mut stmt = self.0.prepare(LIST_SQL).unwrap();
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

    async fn count(&self) -> Result<i64, String> {
        self.0.query_row(COUNT_SQL, [], |r| r.get(0)).map_err(|e| e.to_string())
    }

    async fn store_id_of(&self, id: &str) -> Option<String> {
        self.0.query_row(STORE_SQL, [id], |r| r.get(0)).ok()
    }

    async fn insert(&self, a: &Accepted, size: i64, store_id: &str, by: &str, at_ms: i64) -> Result<(), String> {
        self.0
            .execute(
                INSERT_SQL,
                rusqlite::params![
                    a.id, a.code_hash, a.app_id, a.name, a.version, a.publisher_key, a.publisher_name,
                    a.manifest, size, store_id, by, at_ms
                ],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        self.0.execute(DELETE_SQL, [id]).map(|_| ()).map_err(|e| e.to_string())
    }
}

fn rows() -> SqlRows {
    SqlRows(crate::test_schema::full_schema())
}

/// A bundle signed by TEST key `seed`, and its key id.
fn signed(seed: u8, id: &str, version: &str) -> (Vec<u8>, String) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let key_id = key_id_of(&key.verifying_key().to_bytes());
    let app = format!(
        r#"{{"sezi_app":1,"id":"{id}","name":"Board","version":"{version}","contract":{{"min":2}},"publisher":{{"key_id":"{key_id}","name":"Acme"}},"capabilities":{{"roster":true}}}}"#
    )
    .into_bytes();
    let files = vec![("index.html".to_string(), format!("<p>{version}</p>").into_bytes())];
    let sig = signature_line(&key_id, &key.sign(&signing_message(files.clone(), &app).unwrap()).to_bytes());
    (pack_bundle_v2(files, &app, &sig).unwrap(), key_id)
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn listed(o: Outcome<&'static str>) -> Vec<DbRow> {
    match o {
        Outcome::List(rows) => rows,
        other => panic!("expected the list, got {other:?}"),
    }
}

#[test]
fn an_added_bundle_is_served_under_its_digest_and_goes_with_its_row() {
    let (blobs, db) = (FakeBlobs::default(), rows());
    let (tar, _) = signed(7, "ext:acme/board", "1.0.0");
    let id = digest(&tar);
    let after_add = listed(block_on(add(Some(&blobs), &db, tar.clone(), &Allowlist::default(), "owner", 5)));
    assert_eq!(after_add.len(), 1);
    assert_eq!(after_add[0].id, id, "the entry is named by the BLAKE3 of its bytes");
    assert_eq!(after_add[0].size_bytes, tar.len() as i64);
    assert!(blobs.has(&object_key(&id)), "the bytes are in the store under apps/<id>.tar");

    assert_eq!(block_on(fetch(Some(&blobs), &db, &id)), Outcome::Bytes(tar.clone()), "byte for byte");
    assert_eq!(listed(block_on(list(Some(&blobs), &db))).len(), 1);

    // The same bundle again is the same entry, one object.
    assert_eq!(listed(block_on(add(Some(&blobs), &db, tar.clone(), &Allowlist::default(), "owner", 6))).len(), 1);
    assert_eq!(blobs.objects.borrow().len(), 1);

    assert!(listed(block_on(remove(Some(&blobs), &db, &id))).is_empty());
    assert!(!blobs.has(&object_key(&id)), "the bytes go with the row");
    assert_eq!(block_on(fetch(Some(&blobs), &db, &id)), Outcome::Refused(404, catalog::NOT_FOUND));
    // Removing what is not there answers the list.
    assert!(listed(block_on(remove(Some(&blobs), &db, &id))).is_empty());
}

#[test]
fn only_bytes_that_hash_to_the_entry_are_served() {
    let (blobs, db) = (FakeBlobs::default(), rows());
    let (tar, _) = signed(7, "ext:acme/board", "1.0.0");
    let id = digest(&tar);
    listed(block_on(add(Some(&blobs), &db, tar.clone(), &Allowlist::default(), "owner", 5)));
    // The object was replaced in the store behind the row (another bundle, damaged bytes).
    let (other, _) = signed(7, "ext:acme/board", "2.0.0");
    blobs.objects.borrow_mut().insert(("r2-primary".into(), object_key(&id)), other);
    assert_eq!(block_on(fetch(Some(&blobs), &db, &id)), Outcome::Refused(404, catalog::NOT_FOUND));
    // A store that does not answer is not "not found".
    blobs.down.set(true);
    assert_eq!(block_on(fetch(Some(&blobs), &db, &id)), Outcome::Refused(503, "storage_backend_unavailable"));
    // An id that is no digest never reaches the store.
    assert_eq!(block_on(fetch(Some(&blobs), &db, "../x")), Outcome::Refused(404, catalog::NOT_FOUND));
}

#[test]
fn what_is_refused_leaves_nothing_behind() {
    let (blobs, db) = (FakeBlobs::default(), rows());
    let (tar, key_id) = signed(7, "ext:acme/board", "1.0.0");
    // Not approved on an allowlist server.
    let none = Allowlist { mode: Mode::Allowlist, rows: vec![] };
    assert_eq!(
        block_on(add(Some(&blobs), &db, tar.clone(), &none, "owner", 5)),
        Outcome::Refused(400, "plugin/not-approved")
    );
    // Not a bundle.
    assert_eq!(
        block_on(add(Some(&blobs), &db, b"junk".to_vec(), &Allowlist::default(), "owner", 5)),
        Outcome::Refused(400, catalog::BAD_BUNDLE)
    );
    // The store has no room.
    blobs.full.set(true);
    assert_eq!(block_on(add(Some(&blobs), &db, tar.clone(), &Allowlist::default(), "owner", 5)), Outcome::PutFailed("all_full"));
    assert!(blobs.objects.borrow().is_empty());
    assert!(block_on(db.list()).is_empty(), "no row without its bytes");
    // Approved by its publisher's key: taken.
    blobs.full.set(false);
    let by_key = Allowlist {
        mode: Mode::Allowlist,
        rows: vec![AllowRow {
            id: 1,
            rule: AllowRule::Publisher { key_id, app_id: None },
            max_caps: ["roster".to_string()].into_iter().collect(),
            label: String::new(),
            added_at: 0,
        }],
    };
    assert_eq!(listed(block_on(add(Some(&blobs), &db, tar, &by_key, "owner", 5))).len(), 1);
}

#[test]
fn a_full_catalog_takes_no_new_bundle_but_the_same_one_again() {
    let (blobs, db) = (FakeBlobs::default(), rows());
    let (tar, _) = signed(7, "ext:acme/board", "1.0.0");
    listed(block_on(add(Some(&blobs), &db, tar.clone(), &Allowlist::default(), "owner", 5)));
    for i in 1..catalog::MAX_ENTRIES {
        db.0.execute(
            "INSERT INTO app_catalog (id, code_hash, app_id, name, version, publisher_key, publisher_name, \
             manifest, size_bytes, store_id, added_by, added_at) VALUES (?1, 'h', 'ext:a/b', 'n', '1.0.0', \
             'k', 'p', '{}', 1, 'r2-primary', 'o', 1)",
            [format!("{i:064x}")],
        )
        .unwrap();
    }
    let (next, _) = signed(7, "ext:acme/board", "1.1.0");
    assert_eq!(
        block_on(add(Some(&blobs), &db, next, &Allowlist::default(), "owner", 6)),
        Outcome::Refused(400, catalog::FULL)
    );
    assert_eq!(listed(block_on(add(Some(&blobs), &db, tar, &Allowlist::default(), "owner", 7))).len() as i64, catalog::MAX_ENTRIES);
}

#[test]
fn a_lite_relay_has_no_catalog() {
    let db = rows();
    let (tar, _) = signed(7, "ext:acme/board", "1.0.0");
    let id = digest(&tar);
    let lite: Option<&FakeBlobs> = None;
    let no = Outcome::Refused(503, "media_not_configured");
    assert_eq!(block_on(list(lite, &db)), no);
    assert_eq!(block_on(fetch(lite, &db, &id)), no);
    assert_eq!(block_on(add(lite, &db, tar, &Allowlist::default(), "owner", 5)), no);
    assert_eq!(block_on(remove(lite, &db, &id)), no);
    assert!(block_on(db.list()).is_empty(), "nothing was written");
}
