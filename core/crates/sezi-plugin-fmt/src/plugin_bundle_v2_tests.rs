//! The signed bundle: golden vectors (a fixed TEST key, fixed files — never a real key), the
//! round trip, every way a hostile bundle fails, and a seeded property run.

use super::*;
use crate::app_manifest::key_id_of;
use crate::plugin_bundle::{pack_bundle, unpack_bundle};
use ed25519_dalek::{Signer, SigningKey};

/// TEST ONLY. A publisher key made from a fixed seed so the vectors below are reproducible; it
/// signs nothing outside this file.
fn test_signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

const GOLDEN_SEED: u8 = 0x5e;

fn app_json(key_id: &str, version: &str) -> Vec<u8> {
    format!(
        r#"{{"sezi_app":1,"id":"ext:acme/standup","name":"Standup","version":"{version}","contract":{{"min":2}},"publisher":{{"key_id":"{key_id}","name":"Acme Tools"}},"capabilities":{{"roster":true,"network":{{"origins":["https://api.acme.example"]}}}},"collections":{{"entry":{{}},"ack":{{"shape":"per_member","needs_parent":true}}}}}}"#
    )
    .into_bytes()
}

fn files() -> Vec<(String, Vec<u8>)> {
    vec![
        ("index.html".into(), b"<!doctype html><script src=app.js></script>".to_vec()),
        ("app.js".into(), b"sezgi.ctx();".to_vec()),
    ]
}

fn signed(seed: u8, version: &str) -> (Vec<u8>, Vec<u8>, String) {
    let key = test_signer(seed);
    let id = key_id_of(&key.verifying_key().to_bytes());
    let app = app_json(&id, version);
    let msg = signing_message(files(), &app).unwrap();
    let sig = signature_line(&id, &key.sign(&msg).to_bytes());
    let tar = pack_bundle_v2(files(), &app, &sig).unwrap();
    (tar, app, sig)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The pinned vectors. A change here is a change to what every publisher's tool signs and what
/// every host verifies — never an incidental one.
#[test]
fn golden_vectors() {
    let key = test_signer(GOLDEN_SEED);
    assert_eq!(
        key_id_of(&key.verifying_key().to_bytes()),
        GOLDEN_KEY_ID,
        "the test key's id"
    );
    let (tar, app, sig) = signed(GOLDEN_SEED, "1.2.0");
    let msg = signing_message(files(), &app).unwrap();
    assert_eq!(hex(blake3::hash(&msg).as_bytes()), GOLDEN_MESSAGE_BLAKE3, "what is signed");
    assert_eq!(sig, GOLDEN_SIGNATURE_LINE, "Ed25519 is deterministic");
    assert_eq!(hex(blake3::hash(&tar).as_bytes()), GOLDEN_TAR_BLAKE3, "the bundle bytes");
    // And the pinned bundle opens.
    let b = unpack_bundle(&tar).unwrap();
    assert_eq!(b.manifest.v, 2);
    assert_eq!(hex(&b.app.unwrap().bundle_digest), GOLDEN_DIGEST);
}

const GOLDEN_KEY_ID: &str = "ed25519:gUZkDwJJOvT7xU_jM4jnXcLJN64LdyfMKyr7G3UZmj4";
const GOLDEN_MESSAGE_BLAKE3: &str =
    "17f12b1b9f0cc08fc63df67699f94f37e8c57beb486c5809a116e424afb18fb4";
const GOLDEN_SIGNATURE_LINE: &str = "ed25519:gUZkDwJJOvT7xU_jM4jnXcLJN64LdyfMKyr7G3UZmj4 \
    nfM3ZdcZWzCG-Q60qpQ2FpmRPP_n5zgpZc_P6j0fLs4EkXWXpUEazBAkHr2iiPbHjxeOI3-rGv1eVaRXr3uUCQ\n";
const GOLDEN_TAR_BLAKE3: &str =
    "2ca667a7044e8f55e029c8d8c85347626005b016003c2b99afe3f11978a158ec";
const GOLDEN_DIGEST: &str =
    "6c7e8c286c7fd235d218276d74bdcdd63203a7683747ee6c88a6f3a77b30f136";

#[test]
fn a_signed_bundle_round_trips_and_keeps_its_files_apart() {
    let (tar, app, _) = signed(3, "1.0.0");
    let b = unpack_bundle(&tar).unwrap();
    let v = b.app.as_ref().expect("a v2 bundle carries its app");
    assert_eq!(v.manifest_json, app);
    assert_eq!(v.manifest.id, "ext:acme/standup");
    assert_eq!(b.manifest.entrypoint, "index.html");
    let paths: Vec<_> = b.files.keys().map(String::as_str).collect();
    assert_eq!(paths, vec!["app.js", "index.html"], "the reserved entries are never files");
    // Deterministic: packing the same inputs again makes the same bytes.
    let (again, _, _) = signed(3, "1.0.0");
    assert_eq!(tar, again);
}

#[test]
fn v1_is_untouched() {
    let tar = pack_bundle(files(), "index.html").unwrap();
    // Pinned against the pack of the build before v2 existed (compared byte for byte when this
    // was written): a v1 bundle's bytes, and so its code hash and every member's consent, did
    // not move.
    assert_eq!(
        hex(blake3::hash(&tar).as_bytes()),
        "ea076f26d7a9ee52c73344c1eee5f400b23d5b1c5444098811aa28610405d6b9"
    );
    let b = unpack_bundle(&tar).unwrap();
    assert_eq!(b.manifest.v, 1);
    assert!(b.app.is_none() && b.manifest.app.is_none());
    let manifest = std::str::from_utf8(&tar[512..512 + 200]).unwrap();
    assert!(!manifest.contains("\"app\""), "a v1 manifest is written without the v2 field");
    // pack_any keeps v1 for a file set with no app manifest.
    assert_eq!(pack_any(files(), "index.html").unwrap(), tar);
}

#[test]
fn pack_any_takes_a_publishers_zip() {
    let (tar, app, sig) = signed(4, "2.0.0");
    let mut zip = files();
    zip.push((APP_MANIFEST_NAME.into(), app.clone()));
    zip.push((APP_SIGNATURE_NAME.into(), sig.into_bytes()));
    zip.reverse();
    assert_eq!(pack_any(zip, "").unwrap(), tar, "any packer reproduces the signed bytes");
    let mut unsigned = files();
    unsigned.push((APP_MANIFEST_NAME.into(), app));
    assert_eq!(
        pack_any(unsigned, "index.html").unwrap_err().to_string(),
        format!("malformed: {SIGNATURE_MISSING}"),
        "an app manifest with no signature is not quietly packed as v1"
    );
}

fn code(r: sezi_error::Result<impl std::fmt::Debug>) -> String {
    r.unwrap_err().to_string().trim_start_matches("malformed: ").to_string()
}

#[test]
fn signing_refuses_what_would_not_verify() {
    let key = test_signer(5);
    let id = key_id_of(&key.verifying_key().to_bytes());
    let app = app_json(&id, "1.0.0");
    let other = test_signer(6);
    let msg = signing_message(files(), &app).unwrap();
    // Signed by another key, under the manifest's key id.
    let forged = signature_line(&id, &other.sign(&msg).to_bytes());
    assert_eq!(code(pack_bundle_v2(files(), &app, &forged)), BAD_SIGNATURE);
    // Under another key id.
    let other_id = key_id_of(&other.verifying_key().to_bytes());
    let elsewhere = signature_line(&other_id, &other.sign(&msg).to_bytes());
    assert_eq!(code(pack_bundle_v2(files(), &app, &elsewhere)), SIGNATURE_KEY_MISMATCH);
    // A signature over other files.
    let mut more = files();
    more.push(("x.css".into(), b"p{}".to_vec()));
    let stale = signature_line(&id, &key.sign(&signing_message(more, &app).unwrap()).to_bytes());
    assert_eq!(code(pack_bundle_v2(files(), &app, &stale)), BAD_SIGNATURE);
    assert_eq!(code(pack_bundle_v2(files(), &app, "nonsense")), SIGNATURE_MISSING);
    // A file under a reserved name, an entry the files do not hold.
    let mut reserved = files();
    reserved.push((APP_SIGNATURE_NAME.into(), b"x".to_vec()));
    assert_eq!(code(pack_bundle_v2(reserved, &app, &forged)), RESERVED_NAME);
    let no_entry = vec![("app.js".to_string(), b"x".to_vec())];
    assert_eq!(code(pack_bundle_v2(no_entry, &app, &forged)), ENTRY_MISMATCH);
}

/// Replace one tar entry's content in place (same length), fixing nothing else — what a hostile
/// server or a corrupt blob can do.
fn patch_entry(tar: &[u8], name: &str, f: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    let mut a = tar::Archive::new(tar);
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        let p = String::from_utf8(e.path_bytes().into_owned()).unwrap();
        let mut c = Vec::new();
        std::io::Read::read_to_end(&mut e, &mut c).unwrap();
        if p == name {
            f(&mut c);
        }
        entries.push((p, c));
    }
    for (p, c) in &entries {
        write_tar_entry(&mut out, p, c).unwrap();
    }
    out.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));
    out
}

#[test]
fn a_hostile_bundle_does_not_open() {
    let (tar, _, _) = signed(7, "1.0.0");
    // A file changed: its BLAKE3 no longer matches (the v1 check, still first).
    let t = patch_entry(&tar, "app.js", |c| c[0] ^= 1);
    assert!(unpack_bundle(&t).is_err());
    // The app manifest changed — a capability widened by the server: its pin fails.
    let t = patch_entry(&tar, APP_MANIFEST_NAME, |c| {
        let s = String::from_utf8(c.clone()).unwrap().replace("\"roster\":true", "\"roster\":fals");
        *c = s.into_bytes();
    });
    assert_eq!(code(unpack_bundle(&t)), APP_MANIFEST_MISSING);
    // The bundle manifest re-pinned to a changed app manifest: the signature fails.
    let t = patch_entry(&tar, MANIFEST_NAME, |c| {
        let s = String::from_utf8(c.clone()).unwrap().replace("\"index.html\",\"files\"", "\"app.js\",\"files\"");
        *c = s.into_bytes();
    });
    assert!(unpack_bundle(&t).is_err());
    // The signature flipped.
    let t = patch_entry(&tar, APP_SIGNATURE_NAME, |c| {
        let i = c.len() - 3;
        c[i] = if c[i] == b'A' { b'B' } else { b'A' };
    });
    assert_eq!(code(unpack_bundle(&t)), BAD_SIGNATURE);
    // The signature removed.
    let mut a = tar::Archive::new(&tar[..]);
    let mut out = Vec::new();
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        let p = String::from_utf8(e.path_bytes().into_owned()).unwrap();
        let mut c = Vec::new();
        std::io::Read::read_to_end(&mut e, &mut c).unwrap();
        if p != APP_SIGNATURE_NAME {
            write_tar_entry(&mut out, &p, &c).unwrap();
        }
    }
    out.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));
    assert_eq!(code(unpack_bundle(&out)), SIGNATURE_MISSING);
}

#[test]
fn detached_verification_needs_only_the_digest_and_the_manifest() {
    let (tar, app, sig) = signed(8, "1.0.0");
    let digest = unpack_bundle(&tar).unwrap().app.unwrap().bundle_digest;
    let parsed = crate::app_manifest::parse_app_manifest(&app).unwrap();
    verify_detached(&digest, &app, &sig, &parsed).unwrap();
    let mut other = digest;
    other[0] ^= 1;
    assert!(verify_detached(&other, &app, &sig, &parsed).is_err());
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Every single-byte change anywhere in a signed bundle either fails to open or opens to the very
/// same files and app: no corruption is silently accepted as something else.
#[test]
fn property_no_byte_flip_opens_as_something_else() {
    let (tar, app, _) = signed(9, "1.0.0");
    let good = unpack_bundle(&tar).unwrap();
    let mut r = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..1500 {
        let mut t = tar.clone();
        let i = (r.next() % t.len() as u64) as usize;
        t[i] ^= 1 << (r.next() % 8);
        if let Ok(b) = unpack_bundle(&t) {
            assert_eq!(b.files, good.files, "byte {i}");
            assert_eq!(b.app.as_ref().map(|a| &a.manifest_json), Some(&app), "byte {i}");
        }
    }
}
