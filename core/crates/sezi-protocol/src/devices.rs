//! Multi-device: device identity + the signed device list (M1, `MULTI_DEVICE_PROTOCOL.md`).
//!
//! The WhatsApp star model: 1 primary + ≤4 linked devices; every device runs its OWN Olm
//! Account; the user's device list is signed with the PRIMARY's Ed25519 key → the server
//! CANNOT produce or modify the list contents (zero trust; §1).
//!
//! **device_id** (§2): the first 8 bytes of the `BLAKE3` hash of the device's raw Ed25519
//! public key (32B) → 16 lowercase hex characters. Self-certifying: a forged device_id is
//! meaningless because the signed list binds it to that device's `ed_pub`.
//!
//! **Signature model — JWS bytes (§3.1):** `doc_json` is produced by serde EXACTLY ONCE;
//! the signature is over the UTF-8 bytes of THAT string. Storage and transmission always
//! use the verbatim `doc_json` STRING. The verifier verifies the bytes AS RECEIVED and
//! NEVER re-serializes after parsing → so the whole "canonicalization difference" bug
//! class does not exist here. Parsing is only for reading AFTER verification.
//!
//! This module is PURE crypto/serde (no DB, no network): the kernel (produce/publish),
//! `device_store` (persist) and `client/api/devices.rs` (transport) all use it.
//!
//! **Error text is a stable CODE, not a sentence.** Every failure below is an
//! `Error::Crypto` whose payload starts with a kebab-case code under the `device/` namespace
//! (`device/signature-invalid`, `device/list-primary-ed-mismatch`, …), optionally followed by
//! `: <detail>` for diagnosis. This is the `backup/wrong-key` / `contact-v2/<kind>` shape and it
//! exists because the FRB waist has exactly ONE error channel (`Result<_, String>`): whatever a
//! verification failure says here is what a screen has to work with. A sentence in that channel
//! cannot be translated once it has left Rust, and anything reacting to it ends up matching
//! prose — which makes the WORDING of an error a de-facto contract. Codes may be ADDED; existing
//! ones must not be reworded. The detail after the colon is free-form, for humans and logs only.
//!
//! Note what is NOT a message: the `role` values (`"primary"`/`"linked"`), the serde field names
//! and every `DeviceEntry` value are WIRE — they are inside the bytes the signature covers.
//! Changing one of those breaks verification silently across versions.

use serde::{Deserialize, Serialize};
use vodozemac::olm::Account;
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

use sezi_error::{Error, Result};

/// Device-list document version (schema evolution inside the payload; §3.1 `v`).
pub const DEVICE_LIST_VERSION: u32 = 1;

/// Derive THIS DEVICE's `(device_id, ed_pub_b64)` pair from an effective
/// `(identity_blob, pickle_key)` pair — for the `device_id` + `identity_ed_pub_b64` that go into
/// outgoing register/login/replenish bodies.
///
/// The same identity resolution `build_my_device_list` performs, returning the pair rather than
/// the list. PURE crypto (no DB, no network). `pickle_key` must be 32 bytes.
pub fn my_device_identity(identity_blob: &str, pickle_key: &[u8]) -> Result<(String, String)> {
    use vodozemac::olm::{Account, AccountPickle};

    if pickle_key.len() != 32 {
        return Err(Error::Crypto(format!(
            "device/pickle-key-length: expected 32, got {}",
            pickle_key.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(pickle_key);
    let pickle = AccountPickle::from_encrypted(identity_blob, &key)
        .map_err(|e| Error::Crypto(format!("device/identity-blob-unreadable: {e}")))?;
    let account = Account::from(pickle);
    let ed_pub_b64 = vodozemac::base64_encode(account.identity_keys().ed25519.as_bytes());
    let device_id = device_id_from_ed25519_b64(&ed_pub_b64)?;
    Ok((device_id, ed_pub_b64))
}

/// Ed25519-sign raw bytes with an effective `(identity_blob, pickle_key)`. The SAME JWS-byte
/// model as `build_signed_device_list`, for signatures OUTSIDE the device list — the history-sync
/// state-packet body. PURE crypto. `pickle_key` must be 32 bytes.
pub fn sign_bytes_with_identity(
    identity_blob: &str,
    pickle_key: &[u8],
    msg: &[u8],
) -> Result<String> {
    use vodozemac::olm::AccountPickle;
    if pickle_key.len() != 32 {
        return Err(Error::Crypto(format!(
            "device/sign-pickle-key-length: expected 32, got {}",
            pickle_key.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(pickle_key);
    let pickle = AccountPickle::from_encrypted(identity_blob, &key)
        .map_err(|e| Error::Crypto(format!("device/sign-identity-blob-unreadable: {e}")))?;
    let account = Account::from(pickle);
    let sig = account.sign(msg);
    Ok(vodozemac::base64_encode(sig.to_bytes()))
}

/// Verify an Ed25519 signature over raw bytes against the expected pubkey — fail-closed,
/// identical to step 1 of `verify_device_list`. PURE crypto.
pub fn verify_bytes_sig(msg: &[u8], sig_b64: &str, ed_pub_b64: &str) -> Result<()> {
    let expected_bytes = vodozemac::base64_decode(ed_pub_b64)
        .map_err(|e| Error::Crypto(format!("device/verify-ed-pub-base64: {e}")))?;
    if expected_bytes.len() != 32 {
        return Err(Error::Crypto(format!(
            "device/verify-ed-pub-length: expected 32, got {}",
            expected_bytes.len()
        )));
    }
    let mut ed_arr = [0u8; 32];
    ed_arr.copy_from_slice(&expected_bytes);
    let ed_pub = Ed25519PublicKey::from_slice(&ed_arr)
        .map_err(|e| Error::Crypto(format!("device/verify-ed-pub-unreadable: {e}")))?;
    let sig_bytes = vodozemac::base64_decode(sig_b64)
        .map_err(|e| Error::Crypto(format!("device/verify-signature-base64: {e}")))?;
    let sig = Ed25519Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::Crypto(format!("device/verify-signature-unreadable: {e}")))?;
    ed_pub
        .verify(msg, &sig)
        .map_err(|e| Error::Crypto(format!("device/signature-invalid: {e}")))?;
    Ok(())
}

/// Extract the `primary` device's `ed_pub_b64` from a stored/verified device-list
/// `doc_json` (the M4 root of trust: the receiver verifies the state-packet signature
/// against the primary in its OWN list). A parse error / no primary → `None`.
pub fn primary_ed_from_doc(doc_json: &str) -> Option<String> {
    let doc: DeviceListDoc = serde_json::from_str(doc_json).ok()?;
    doc.devices
        .into_iter()
        .find(|d| d.role == "primary")
        .map(|d| d.ed_pub_b64)
}

/// Derive a peer's PRIMARY device_id from `ed_pub_b64`; `None` for an empty/short/corrupt
/// ed_pub, i.e. a genuine orphan.
///
/// **This must stay the SINGLE derivation function.** The runtime fan-out
/// (`device_fanout.rs`), the v7 migration backfill (`sezi-store`), the peer_devices seed and
/// `api_storage` all go through it, which is what makes the 16-hex string identical everywhere:
/// sender and receiver hold the same ed_pub from the pairing/contact card, so the wire device_id
/// and the receiver's own JWT device_id match deterministically. The
/// `'__primary__'`/`'__unresolved__'` sentinels belong to the `None` branch only.
pub fn primary_device_id_or_orphan(ed_pub_b64: &str) -> Option<String> {
    if ed_pub_b64.is_empty() {
        return None;
    }
    device_id_from_ed25519_b64(ed_pub_b64).ok()
}

/// Derive a device_id from the base64 of a raw 32B Ed25519 public key (§2):
/// `hex(BLAKE3(ed25519_pub_bytes)[0..8])` → 16 lowercase hex characters. Errors: corrupt
/// base64 / not 32 bytes (an invalid pubkey).
pub fn device_id_from_ed25519_b64(ed_pub_b64: &str) -> Result<String> {
    let bytes = vodozemac::base64_decode(ed_pub_b64)
        .map_err(|e| Error::Crypto(format!("device/ed-pub-base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Crypto(format!(
            "device/ed-pub-length: expected 32, got {}",
            bytes.len()
        )));
    }
    let hash = blake3::hash(&bytes);
    // The first 8 bytes → 16 hex characters (deterministic, lowercase hex).
    Ok(hex::encode(&hash.as_bytes()[..8]))
}

/// Human-comparable ROOT-OF-TRUST fingerprint (the M2-S3.2c FINGERPRINT GATE):
/// a grouped uppercase hex rendering (blocks of 4) of the 128-bit `BLAKE3` digest of the
/// primary's Ed25519 pubkey. The linked and the primary device display the SAME fingerprint
/// → the user compares them by eye → which catches a malicious server substituting
/// `primary_ed` (verification alone only establishes self-consistency; the real trust comes
/// from this manual comparison). On error (an empty/short/corrupt ed_pub) → an empty string
/// (the UI shows "could not compute fingerprint" and still asks for manual confirmation).
pub fn safety_fingerprint(ed_pub_b64: &str) -> String {
    let Ok(bytes) = vodozemac::base64_decode(ed_pub_b64) else {
        return String::new();
    };
    if bytes.len() != 32 {
        return String::new();
    }
    let hash = blake3::hash(&bytes);
    let hex = hex::encode_upper(&hash.as_bytes()[..16]);
    hex.as_bytes()
        .chunks(4)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A single device entry in the device list (§3.1). `role`: "primary" (exactly one; the
/// root of trust) | "linked" (≤4). `ed_pub_b64`/`x_pub_b64` come from that device's Olm
/// Account; `device_id` must match the derivation from `ed_pub_b64` (self-consistency, which
/// verify checks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: String,
    pub role: String,
    pub ed_pub_b64: String,
    pub x_pub_b64: String,
    pub label: String,
    pub added_at_ms: i64,
}

/// The canonical device-list document that gets signed (§3.1). `rev` is strictly increasing
/// (rollback protection, §3.2). The signature is over the UTF-8 bytes of this struct's serde
/// JSON string (the JWS model) — see `build_signed_device_list`/`verify_device_list`.
///
/// **`removed_devices` (Model-B Layer-1, signed tombstones / remove-wins):** records removed
/// devices POSITIVELY — it distinguishes "absent" (never added yet) from "removed"
/// (permanently dead). Even if `reconcile`'s re-PUT path pushes a stale list, a tombstoned
/// device CANNOT be resurrected (both the worker and the peer filter it out, fail-closed).
/// **Byte compatibility:** when empty it is not serialized (`skip_serializing_if`) → so
/// documents without tombstones (N=1 / nothing ever removed) are byte-for-byte IDENTICAL to
/// today's → the JWS signature compatibility holds and no migration is needed. The signature
/// covers the whole struct (including removed) → the server can neither add nor delete a
/// tombstone. **FIELD ORDER IS CRITICAL:** `removed_devices` must be LAST (after devices) —
/// skipping it when empty is what reproduces today's byte layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceListDoc {
    pub v: u32,
    pub user_id: String,
    pub rev: u64,
    pub devices: Vec<DeviceEntry>,
    /// Signed tombstones (removed devices). Empty → not serialized (byte compatibility).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_devices: Vec<DeviceEntry>,
}

/// Build a signed device list from `entries` (§3.1). The returned `(doc_json, sig_b64)`:
/// `doc_json` is the string serde produces EXACTLY ONCE; `sig_b64` is the signature over
/// that string's UTF-8 bytes via `account.sign` (= the primary's Ed25519 key). The CALLER
/// must guarantee that `account` owns the primary entry in the list (the kernel calls this
/// with the effective identity in `ensure_device_list_published`).
///
/// **Critical:** `doc_json` is stored and transmitted verbatim → so verification happens
/// over the SAME bytes. Do not re-serialize this string; carry the identical one everywhere.
pub fn build_signed_device_list(
    account: &Account,
    user_id: &str,
    rev: u64,
    entries: Vec<DeviceEntry>,
) -> Result<(String, String)> {
    let doc = DeviceListDoc {
        v: DEVICE_LIST_VERSION,
        user_id: user_id.to_string(),
        rev,
        devices: entries,
        removed_devices: Vec::new(),
    };
    sign_device_list_doc(account, &doc)
}

/// Sign a complete `DeviceListDoc` (tombstones included) using the JWS-byte model →
/// `(doc_json, sig_b64)`. This is the shared signing path for `build_signed_device_list`
/// (without tombstones) and for the tombstone-carrying
/// `build_device_list_with_added/removed`. `doc_json` is produced by serde EXACTLY ONCE; the
/// signature is over THAT string's UTF-8 bytes — and it is carried verbatim everywhere
/// (re-serialization is FORBIDDEN; see the module header, §3.1).
pub fn sign_device_list_doc(account: &Account, doc: &DeviceListDoc) -> Result<(String, String)> {
    // `?` alone would yield `Error::Json` here — the ONE failure in this module that would reach
    // the FRB waist as a serde sentence instead of a `device/` code, breaking the module header's
    // invariant. Practically unreachable (the doc is plain strings and integers), but the
    // invariant is only worth stating if it has no holes.
    let doc_json = serde_json::to_string(doc)
        .map_err(|e| Error::Crypto(format!("device/list-serialize: {e}")))?;
    let sig = account.sign(doc_json.as_bytes());
    let sig_b64 = vodozemac::base64_encode(sig.to_bytes());
    Ok((doc_json, sig_b64))
}

/// Verify and parse a signed device list (fail-closed, §3.2). `expected_primary_ed_b64` =
/// the peer's primary `ed_pub_b64` as stored at pairing time (the root of trust; §1).
///
/// Order (signature FIRST, contents SECOND):
///   1. Verify `sig_b64` over the `doc_json` bytes AS RECEIVED using the
///      `expected_primary` key (JWS — NO re-serialization).
///   2. Parse it; `v == DEVICE_LIST_VERSION`.
///   3. There must be EXACTLY ONE entry with `role == "primary"`.
///   4. The primary's `ed_pub_b64` == `expected_primary_ed_b64` (the signer is in the list
///      and matches the pairing root — self-consistency + the root-of-trust gate).
///   5. EVERY entry's `device_id` matches the derivation from its own `ed_pub_b64`.
///
/// On error = an `Error::Crypto` carrying a stable `device/list-*` code (plus an optional
/// `: <detail>` for logs); on success = the verified `DeviceListDoc`.
pub fn verify_device_list(
    doc_json: &str,
    sig_b64: &str,
    expected_primary_ed_b64: &str,
) -> Result<DeviceListDoc> {
    // 1) Signature — over the bytes AS RECEIVED, with the expected primary key.
    let expected_bytes = vodozemac::base64_decode(expected_primary_ed_b64)
        .map_err(|e| Error::Crypto(format!("device/list-expected-ed-pub-base64: {e}")))?;
    if expected_bytes.len() != 32 {
        return Err(Error::Crypto(format!(
            "device/list-expected-ed-pub-length: expected 32, got {}",
            expected_bytes.len()
        )));
    }
    let mut ed_arr = [0u8; 32];
    ed_arr.copy_from_slice(&expected_bytes);
    let ed_pub = Ed25519PublicKey::from_slice(&ed_arr)
        .map_err(|e| Error::Crypto(format!("device/list-expected-ed-pub-unreadable: {e}")))?;

    let sig_bytes = vodozemac::base64_decode(sig_b64)
        .map_err(|e| Error::Crypto(format!("device/list-signature-base64: {e}")))?;
    let sig = Ed25519Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::Crypto(format!("device/list-signature-unreadable: {e}")))?;
    ed_pub
        .verify(doc_json.as_bytes(), &sig)
        .map_err(|e| Error::Crypto(format!("device/list-signature-invalid: {e}")))?;

    // 2) Parse (only AFTER verification). The version gate.
    let doc: DeviceListDoc = serde_json::from_str(doc_json)
        .map_err(|e| Error::Crypto(format!("device/list-json-parse: {e}")))?;
    if doc.v != DEVICE_LIST_VERSION {
        return Err(Error::Crypto(format!(
            "device/list-unsupported-version: {}",
            doc.v
        )));
    }

    // 3) EXACTLY ONE primary.
    let primaries: Vec<&DeviceEntry> =
        doc.devices.iter().filter(|d| d.role == "primary").collect();
    if primaries.len() != 1 {
        return Err(Error::Crypto(format!(
            "device/list-primary-count: expected 1, got {}",
            primaries.len()
        )));
    }

    // 4) The primary's ed_pub == the expected root (the signer is in the list + it is the
    //    pairing root).
    if primaries[0].ed_pub_b64 != expected_primary_ed_b64 {
        return Err(Error::Crypto("device/list-primary-ed-mismatch".into()));
    }

    // 5) Every ACTIVE entry is self-consistent (device_id ← derived from ed_pub).
    for d in &doc.devices {
        let derived = device_id_from_ed25519_b64(&d.ed_pub_b64)?;
        if derived != d.device_id {
            return Err(Error::Crypto(format!(
                "device/list-device-id-mismatch: {} != {}",
                d.device_id, derived
            )));
        }
    }

    // 6) Every TOMBSTONE entry is self-consistent too (Model-B Layer-1: a removed-device
    //    record must not carry a forged device_id either — the peer/worker remove-wins logic
    //    trusts this device_id).
    for d in &doc.removed_devices {
        let derived = device_id_from_ed25519_b64(&d.ed_pub_b64)?;
        if derived != d.device_id {
            return Err(Error::Crypto(format!(
                "device/list-tombstone-device-id-mismatch: {} != {}",
                d.device_id, derived
            )));
        }
    }

    // 7) Disjoint: a device CANNOT be both active and tombstoned AT THE SAME TIME (an
    //    inconsistent list → ambiguity over "was it removed or does it remain"; reject,
    //    fail-closed). On a re-link `build_with_added` drops it from the tombstones → so this
    //    state only occurs in a corrupt/malicious list.
    for active in &doc.devices {
        if doc.removed_devices.iter().any(|r| r.device_id == active.device_id) {
            return Err(Error::Crypto(format!(
                "device/list-active-and-tombstoned: {}",
                active.device_id
            )));
        }
    }

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::olm::Account;

    /// Produce the (ed_pub_b64, x_pub_b64, device_id) triple from an Account (test fixture).
    fn keys_of(acc: &Account) -> (String, String, String) {
        let ed = vodozemac::base64_encode(acc.identity_keys().ed25519.as_bytes());
        let x = vodozemac::base64_encode(acc.identity_keys().curve25519.to_bytes());
        let did = device_id_from_ed25519_b64(&ed).unwrap();
        (ed, x, did)
    }

    fn primary_entry(acc: &Account) -> DeviceEntry {
        let (ed, x, did) = keys_of(acc);
        DeviceEntry {
            device_id: did,
            role: "primary".into(),
            ed_pub_b64: ed,
            x_pub_b64: x,
            label: "Primary".into(),
            added_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn device_id_deterministic_16_hex() {
        let acc = Account::new();
        let ed = vodozemac::base64_encode(acc.identity_keys().ed25519.as_bytes());
        let a = device_id_from_ed25519_b64(&ed).unwrap();
        let b = device_id_from_ed25519_b64(&ed).unwrap();
        assert_eq!(a, b, "deterministic");
        assert_eq!(a.len(), 16, "16 hex characters");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "hex only");
    }

    #[test]
    fn my_device_identity_matches_derivation() {
        // Pickle an account (the kernel's effective identity_blob pattern) → then resolve
        // (device_id, ed_pub) from it; it must equal the derivation straight from the account.
        let acc = Account::new();
        let key = [7u8; 32];
        let blob = acc.pickle().encrypt(&key);
        let (did, ed) = my_device_identity(&blob, &key).unwrap();
        let expected_ed = vodozemac::base64_encode(acc.identity_keys().ed25519.as_bytes());
        assert_eq!(ed, expected_ed, "ed_pub_b64 must match the derivation from the account");
        assert_eq!(
            did,
            device_id_from_ed25519_b64(&expected_ed).unwrap(),
            "device_id must match the derivation from ed_pub"
        );
    }

    #[test]
    fn my_device_identity_rejects_bad_key_len() {
        let acc = Account::new();
        let blob = acc.pickle().encrypt(&[1u8; 32]);
        // A pickle_key that is not 32 bytes → error.
        assert!(my_device_identity(&blob, &[1u8, 2, 3]).is_err());
    }

    #[test]
    fn device_id_rejects_bad_input() {
        assert!(device_id_from_ed25519_b64("!!!notbase64!!!").is_err());
        // Not 32 bytes (3 bytes).
        assert!(device_id_from_ed25519_b64(&vodozemac::base64_encode([1u8, 2, 3])).is_err());
    }

    #[test]
    fn roundtrip_verify_ok() {
        let acc = Account::new();
        let (ed, _x, _did) = keys_of(&acc);
        let entry = primary_entry(&acc);
        let (doc_json, sig_b64) =
            build_signed_device_list(&acc, "user-1", 1, vec![entry.clone()]).unwrap();
        let doc = verify_device_list(&doc_json, &sig_b64, &ed).unwrap();
        assert_eq!(doc.rev, 1);
        assert_eq!(doc.user_id, "user-1");
        assert_eq!(doc.devices.len(), 1);
        assert_eq!(doc.devices[0], entry);
    }

    #[test]
    fn roundtrip_two_devices_ok() {
        let primary = Account::new();
        let linked = Account::new();
        let (ed_p, _, _) = keys_of(&primary);
        let mut linked_entry = primary_entry(&linked);
        linked_entry.role = "linked".into();
        linked_entry.label = "Tablet".into();
        let entries = vec![primary_entry(&primary), linked_entry];
        let (doc_json, sig_b64) =
            build_signed_device_list(&primary, "u2", 3, entries).unwrap();
        let doc = verify_device_list(&doc_json, &sig_b64, &ed_p).unwrap();
        assert_eq!(doc.devices.len(), 2);
        assert_eq!(doc.rev, 3);
    }

    #[test]
    fn tampered_doc_json_rejected() {
        let acc = Account::new();
        let (ed, _x, _did) = keys_of(&acc);
        let (doc_json, sig_b64) =
            build_signed_device_list(&acc, "user-1", 1, vec![primary_entry(&acc)]).unwrap();
        // rev=1 → rev=2: tampers with a single byte (breaking the JWS byte match).
        let tampered = doc_json.replacen("\"rev\":1", "\"rev\":2", 1);
        assert_ne!(tampered, doc_json, "the tamper must actually change something");
        let err = verify_device_list(&tampered, &sig_b64, &ed).unwrap_err();
        assert!(
            err.to_string().contains("device/list-signature-invalid"),
            "a tampered doc must be rejected: {err}"
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let acc = Account::new();
        let other = Account::new();
        let (ed_other, _, _) = keys_of(&other);
        let (doc_json, sig_b64) =
            build_signed_device_list(&acc, "user-1", 1, vec![primary_entry(&acc)]).unwrap();
        // Signed with acc; the expected key belongs to ANOTHER device → signature
        // verification fails.
        let err = verify_device_list(&doc_json, &sig_b64, &ed_other).unwrap_err();
        assert!(
            err.to_string().contains("device/list-signature-invalid"),
            "the wrong key must be rejected: {err}"
        );
    }

    #[test]
    fn double_primary_rejected() {
        let primary = Account::new();
        let second = Account::new();
        let (ed_p, _, _) = keys_of(&primary);
        // Both entries have role="primary" (a rule violation).
        let mut second_entry = primary_entry(&second);
        second_entry.role = "primary".into();
        let entries = vec![primary_entry(&primary), second_entry];
        let (doc_json, sig_b64) =
            build_signed_device_list(&primary, "u", 1, entries).unwrap();
        let err = verify_device_list(&doc_json, &sig_b64, &ed_p).unwrap_err();
        assert!(
            err.to_string().contains("device/list-primary-count"),
            "a double primary must be rejected: {err}"
        );
    }

    #[test]
    fn device_id_mismatch_rejected() {
        let acc = Account::new();
        let (ed, _, _) = keys_of(&acc);
        let mut bad = primary_entry(&acc);
        bad.device_id = "0000000000000000".into(); // NOT derived from ed_pub
        let (doc_json, sig_b64) =
            build_signed_device_list(&acc, "u", 1, vec![bad]).unwrap();
        let err = verify_device_list(&doc_json, &sig_b64, &ed).unwrap_err();
        assert!(
            err.to_string().contains("device/list-device-id-mismatch"),
            "a device_id that does not match its derivation must be rejected: {err}"
        );
    }

    #[test]
    fn primary_ed_mismatch_rejected() {
        // The signature and the entry are VALID, but this is a different scenario where the
        // expected root is NOT the primary's key while still being the one used for signing:
        // swapping the primary's ed for another device's ed would also break the signature, so
        // there the signer and the primary entry stay consistent while expected differs →
        // check 1 (the signature) fails rather than check 4.
        // Hence this separate case: change the primary entry's ed and re-sign with the SAME
        // key → the signature passes but primary.ed != expected (the root-of-trust gate).
        let acc = Account::new();
        let imposter = Account::new();
        let (ed_acc, _, _) = keys_of(&acc);
        let (ed_imp, x_imp, did_imp) = keys_of(&imposter);
        // The primary inside the list = the imposter's keys (self-consistent), but it is
        // signed with acc (as if acc still held the signing authority).
        let entry = DeviceEntry {
            device_id: did_imp,
            role: "primary".into(),
            ed_pub_b64: ed_imp,
            x_pub_b64: x_imp,
            label: "Primary".into(),
            added_at_ms: 1,
        };
        let (doc_json, sig_b64) =
            build_signed_device_list(&acc, "u", 1, vec![entry]).unwrap();
        // The expected root = acc (as stored at pairing time). The signature is valid under
        // acc, BUT the list's primary.ed = the imposter → check 4 (primary ed == expected) fails.
        let err = verify_device_list(&doc_json, &sig_b64, &ed_acc).unwrap_err();
        assert!(
            err.to_string().contains("device/list-primary-ed-mismatch"),
            "a signer/primary mismatch must be rejected: {err}"
        );
    }

    #[test]
    fn state_sig_roundtrip_tamper_and_wrong_key() {
        // M4: the state-packet body signature (sign_bytes_with_identity ↔ verify_bytes_sig).
        let acc = Account::new();
        let key = [9u8; 32];
        let blob = acc.pickle().encrypt(&key);
        let (_did, ed) = my_device_identity(&blob, &key).unwrap();
        let msg = b"M4 state-packet canonical body";
        let sig = sign_bytes_with_identity(&blob, &key, msg).unwrap();
        // Correct bytes + correct root → passes.
        assert!(verify_bytes_sig(msg, &sig, &ed).is_ok());
        // A single-byte tamper → rejected (fail-closed).
        assert!(verify_bytes_sig(b"M4 state-packet canonical bXdy", &sig, &ed).is_err());
        // The wrong root (another device's ed) → rejected.
        let other = Account::new();
        let ed_other = vodozemac::base64_encode(other.identity_keys().ed25519.as_bytes());
        assert!(verify_bytes_sig(msg, &sig, &ed_other).is_err());
        // pickle_key ≠ 32 bytes → a signing error.
        assert!(sign_bytes_with_identity(&blob, &[1, 2, 3], msg).is_err());
    }

    #[test]
    fn primary_ed_extracted_from_doc() {
        // The M4 root of trust: the receiver extracts the primary ed from its own list.
        let primary = Account::new();
        let linked = Account::new();
        let (ed_p, _, _) = keys_of(&primary);
        let mut linked_entry = primary_entry(&linked);
        linked_entry.role = "linked".into();
        let entries = vec![primary_entry(&primary), linked_entry];
        let (doc_json, _sig) = build_signed_device_list(&primary, "u", 2, entries).unwrap();
        assert_eq!(primary_ed_from_doc(&doc_json).as_deref(), Some(ed_p.as_str()));
        // Corrupt JSON / no primary → None.
        assert_eq!(primary_ed_from_doc("{corrupt json"), None);
    }

    // ── Model-B Layer-1: signed tombstones (removed_devices) ───────────────────

    /// A self-consistent linked DeviceEntry from an Account (tombstone fixture).
    fn linked_entry_of(acc: &Account) -> DeviceEntry {
        let mut e = primary_entry(acc);
        e.role = "linked".into();
        e
    }

    #[test]
    fn empty_removed_omitted_byte_compat() {
        // CRITICAL: a document without tombstones is byte-for-byte IDENTICAL to today's layout
        // (skip_serializing_if → the "removed_devices" field never appears at all) → so old
        // signed lists still verify and no migration is needed. (The JWS signature's byte match
        // makes this compatibility mandatory.)
        let acc = Account::new();
        let (doc_json, _sig) =
            build_signed_device_list(&acc, "u", 1, vec![primary_entry(&acc)]).unwrap();
        assert!(
            !doc_json.contains("removed_devices"),
            "an empty tombstone list must not be serialized (byte compatibility): {doc_json}"
        );
    }

    #[test]
    fn tombstone_roundtrip_verify_ok() {
        // A document with tombstones: an active primary + a removed (tombstoned) linked device
        // → verify PASSES.
        let primary = Account::new();
        let removed = Account::new();
        let (ed_p, _, _) = keys_of(&primary);
        let doc = DeviceListDoc {
            v: DEVICE_LIST_VERSION,
            user_id: "u".into(),
            rev: 5,
            devices: vec![primary_entry(&primary)],
            removed_devices: vec![linked_entry_of(&removed)],
        };
        let (doc_json, sig_b64) = sign_device_list_doc(&primary, &doc).unwrap();
        assert!(
            doc_json.contains("removed_devices"),
            "a non-empty tombstone list is serialized"
        );
        let v = verify_device_list(&doc_json, &sig_b64, &ed_p).unwrap();
        assert_eq!(v.removed_devices.len(), 1);
        assert_eq!(v.devices.len(), 1);
    }

    #[test]
    fn tombstone_bad_device_id_rejected() {
        // The tombstone entry's device_id is NOT derived from ed_pub → rejected (a forged
        // tombstone cannot abuse remove-wins).
        let primary = Account::new();
        let removed = Account::new();
        let (ed_p, _, _) = keys_of(&primary);
        let mut bad = linked_entry_of(&removed);
        bad.device_id = "0000000000000000".into();
        let doc = DeviceListDoc {
            v: DEVICE_LIST_VERSION,
            user_id: "u".into(),
            rev: 5,
            devices: vec![primary_entry(&primary)],
            removed_devices: vec![bad],
        };
        let (doc_json, sig_b64) = sign_device_list_doc(&primary, &doc).unwrap();
        let err = verify_device_list(&doc_json, &sig_b64, &ed_p).unwrap_err();
        assert!(
            err.to_string()
                .contains("device/list-tombstone-device-id-mismatch"),
            "a forged tombstone device_id must be rejected: {err}"
        );
    }

    #[test]
    fn device_in_both_active_and_removed_rejected() {
        // The SAME device both active and tombstoned → inconsistent → rejected (fail-closed).
        let primary = Account::new();
        let dual = Account::new();
        let (ed_p, _, _) = keys_of(&primary);
        let doc = DeviceListDoc {
            v: DEVICE_LIST_VERSION,
            user_id: "u".into(),
            rev: 5,
            devices: vec![primary_entry(&primary), linked_entry_of(&dual)],
            removed_devices: vec![linked_entry_of(&dual)], // the same device!
        };
        let (doc_json, sig_b64) = sign_device_list_doc(&primary, &doc).unwrap();
        let err = verify_device_list(&doc_json, &sig_b64, &ed_p).unwrap_err();
        assert!(
            err.to_string().contains("device/list-active-and-tombstoned"),
            "a device that is both active and tombstoned must be rejected: {err}"
        );
    }
}
