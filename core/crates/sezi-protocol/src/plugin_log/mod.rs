//! Plugin/feed server log — CORE crypto + wire. `PLUGIN_FEED_LOG_SPEC.md`.
//!
//! This module is the CLIENT side of the server-log model for plugin/feed data: build a
//! record → **canonical signing bytes** → device-Ed25519 signature → AEAD encryption →
//! append to the worker; on sync → decrypt → verify the signature → fold. The server is
//! BLIND.

use sezi_error::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Field separator for the signing bytes (domain separation). A version string + NUL →
/// signatures from other contexts cannot be replayed into this context (a cross-protocol
/// attack guard).
const SIGN_DOMAIN: &[u8] = b"sezgi-plugin-log-v1\x00";

/// The canonical (signed + encrypted) plaintext of one plugin/feed log record.
/// `seq` is NOT HERE — the server assigns it and it is not part of the signature
/// (`PLUGIN_FEED_LOG_SPEC.md §1`). `author_*` is kernel-verified (my own user_id +
/// device); it goes onto the wire together with the signature, and the reader verifies it
/// with the pubkey from `device_key_history` → impersonation is impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLogRecordV1 {
    /// Schema version (= 1). Part of the signature → forward compatibility (the receiver
    /// rejects a version mismatch).
    pub v: u32,
    pub room_id: String,
    pub plugin_id: String,
    pub collection: String,
    /// Scoped as `u:<author_id>:...` (the squat guard is preserved — it is also enforced
    /// during the fold).
    pub record_id: String,
    pub parent_id: Option<String>,
    /// "put" | "delete".
    pub op: String,
    /// The plugin's opaque schema (the kernel does NOT parse it).
    pub fields_json: String,
    pub author_id: String,
    pub author_device_id: String,
    /// Per-author monotonic counter (gap/withhold detection — `PLUGIN_FEED_LOG_SPEC.md §8`).
    pub author_counter: u64,
    /// LWW clock for the fold (author-owned key; reuses `upsert_owned`).
    pub lamport: u64,
    pub created_at_ms: i64,
}

/// Length-prefixed field: `u32_be(len) || utf8(s)` → NO separator ambiguity (two different
/// field layouts can never produce the same byte sequence).
fn push_lp(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Optional field: an EXPLICIT presence flag (`0`=None, `1`+lp=Some) → `None` and
/// `Some("")` can NEVER produce the same bytes (a refinement of the spec's `?? ""`;
/// canonical-form rigor).
fn push_opt(out: &mut Vec<u8>, s: &Option<String>) {
    match s {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            push_lp(out, v);
        }
    }
}

impl PluginLogRecordV1 {
    /// The DETERMINISTIC byte sequence that gets signed (`PLUGIN_FEED_LOG_SPEC.md §1a`).
    /// NOT serde-JSON (field-order/whitespace non-determinism is forbidden) — built by
    /// hand, domain-separated and length-prefixed. **This format is irreversible**: if it
    /// changes after live data exists, old signatures can no longer be verified (it must be
    /// finalized before launch).
    pub fn canonical_sign_bytes(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(256);
        o.extend_from_slice(SIGN_DOMAIN);
        o.extend_from_slice(&self.v.to_be_bytes());
        push_lp(&mut o, &self.room_id);
        push_lp(&mut o, &self.plugin_id);
        push_lp(&mut o, &self.collection);
        push_lp(&mut o, &self.record_id);
        push_opt(&mut o, &self.parent_id);
        push_lp(&mut o, &self.op);
        push_lp(&mut o, &self.fields_json);
        push_lp(&mut o, &self.author_id);
        push_lp(&mut o, &self.author_device_id);
        o.extend_from_slice(&self.author_counter.to_be_bytes());
        o.extend_from_slice(&self.lamport.to_be_bytes());
        o.extend_from_slice(&self.created_at_ms.to_be_bytes());
        o
    }
}

/// Sign the record with the author's device Ed25519 key → `sig_b64`.
/// `identity_blob`/`pickle_key` = my own device's identity (available in the kernel).
/// PURE crypto (no DB, no network).
pub fn sign_record(
    rec: &PluginLogRecordV1,
    identity_blob: &str,
    pickle_key: &[u8],
) -> Result<String> {
    crate::devices::sign_bytes_with_identity(identity_blob, pickle_key, &rec.canonical_sign_bytes())
}

/// Verify the record's signature against the author's device pubkey (`author_ed_pub_b64`).
/// Fail-closed. The pubkey comes from `device_key_history`, which retains REMOVED devices too —
/// a record signed by a device that has since gone away must still verify.
pub fn verify_record(
    rec: &PluginLogRecordV1,
    sig_b64: &str,
    author_ed_pub_b64: &str,
) -> Result<()> {
    crate::devices::verify_bytes_sig(&rec.canonical_sign_bytes(), sig_b64, author_ed_pub_b64)
}

// ───────────────────────── AEAD (PluginEpochKey) ─────────────────────────

/// PluginEpochKey: the SHARED AEAD key per (room,plugin,epoch) (256-bit). A single
/// ciphertext serves every reader (a Megolm-style shared key; NOT per-recipient Olm). It is
/// distributed to active members over Olm, and a member leaving starts a new epoch.
pub type PluginEpochKey = [u8; 32];

/// XChaCha20-Poly1305 one-shot nonce (24 bytes → the chance of a random collision is
/// negligible; NOT the STREAM API — records are small, so one shot is enough).
pub const PLUGIN_LOG_NONCE_LEN: usize = 24;

/// Generate a new epoch key (CSPRNG).
pub fn generate_epoch_key() -> PluginEpochKey {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// The AEAD AAD (`PLUGIN_FEED_LOG_SPEC.md §1b`): not encrypted, so the server sees it and
/// enforces it (`author_*` must match the JWT). It binds the ciphertext to its context → a
/// malicious relay CANNOT move a ciphertext into another room/plugin/author context. `seq`
/// is absent (the server assigns it; the AAD must be client-known).
pub fn aad_bytes(
    room_id: &str,
    plugin_id: &str,
    key_epoch: u64,
    author_id: &str,
    author_device_id: &str,
    author_counter: u64,
) -> Vec<u8> {
    let mut o = Vec::with_capacity(96);
    push_lp(&mut o, room_id);
    push_lp(&mut o, plugin_id);
    o.extend_from_slice(&key_epoch.to_be_bytes());
    push_lp(&mut o, author_id);
    push_lp(&mut o, author_device_id);
    o.extend_from_slice(&author_counter.to_be_bytes());
    o
}

/// AEAD seal: encrypt `plaintext` with the epoch key + a random nonce, bound to `aad`.
/// Returns `(ciphertext (including the Poly1305 tag), nonce)`. The server CANNOT read the
/// ciphertext.
pub fn seal(
    key: &PluginEpochKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; PLUGIN_LOG_NONCE_LEN])> {
    let mut nonce = [0u8; PLUGIN_LOG_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("plugin-log seal: key length".into()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(format!("plugin-log seal: {e}")))?;
    Ok((ct, nonce))
}

/// AEAD open: decrypt the ciphertext and verify the AAD. `Err` if the tag does not match /
/// the AAD differs / the key is wrong (fail-closed). `PLUGIN_FEED_LOG_SPEC.md §1b`.
pub fn open(key: &PluginEpochKey, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != PLUGIN_LOG_NONCE_LEN {
        return Err(Error::Crypto("plugin-log open: nonce length".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("plugin-log open: key length".into()))?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(format!("plugin-log open: {e}")))
}

// ───────────────── compose (seal_record / open_entry) ─────────────────

/// The wire entry appended to the worker and received back on sync. **The signature lives
/// INSIDE the ciphertext**, so there is NO separate `sig_b64`: the authorship proof has to stay
/// invisible to the server. `aad_hash` is the server-visible integrity value; `prev/entry_hash`
/// form the fork chain (not yet populated). Field-compatible with the worker's
/// `PluginLogEntry` apart from sig_b64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEntry {
    pub plugin_id: String,
    pub author_id: String,
    pub author_device_id: String,
    pub key_epoch: i64,
    pub author_counter: i64,
    pub content_kind: String,
    #[serde(default)]
    pub ciphertext_b64: Option<String>,
    #[serde(default)]
    pub nonce_b64: Option<String>,
    /// R2 blob path for large content (a later slice; None in the inline case).
    #[serde(default)]
    pub blob_id: Option<String>,
    #[serde(default)]
    pub blob_hash: Option<String>,
    pub aad_hash: String,
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub entry_hash: Option<String>,
    pub uploaded_at_ms: i64,
}

/// The plaintext INSIDE the ciphertext: the record plus its signature (the server cannot
/// see it). On open it is decrypted and the signature is verified.
#[derive(Serialize, Deserialize)]
struct SealedPlaintext {
    record: PluginLogRecordV1,
    sig_b64: String,
}

/// SEAL the record: sign it (device Ed25519) → AEAD-encrypt the (record+signature)
/// plaintext with the epoch key → `SealedEntry`. `room_id` goes into the AAD (it is NOT
/// carried in the entry — it is known from the sync scope).
/// `created_at_ms` comes from the caller (host/kernel; there is no `Date.now` in core).
pub fn seal_record(
    rec: &PluginLogRecordV1,
    epoch_key: &PluginEpochKey,
    key_epoch: i64,
    identity_blob: &str,
    pickle_key: &[u8],
    uploaded_at_ms: i64,
) -> Result<SealedEntry> {
    let sig_b64 = sign_record(rec, identity_blob, pickle_key)?;
    let plaintext = serde_json::to_vec(&SealedPlaintext {
        record: rec.clone(),
        sig_b64,
    })
    .map_err(|e| Error::Crypto(format!("plugin-log seal: plaintext serialize: {e}")))?;
    let aad = aad_bytes(
        &rec.room_id,
        &rec.plugin_id,
        key_epoch as u64,
        &rec.author_id,
        &rec.author_device_id,
        rec.author_counter,
    );
    let (ct, nonce) = seal(epoch_key, &plaintext, &aad)?;
    let aad_hash = vodozemac::base64_encode(blake3::hash(&aad).as_bytes());
    Ok(SealedEntry {
        plugin_id: rec.plugin_id.clone(),
        author_id: rec.author_id.clone(),
        author_device_id: rec.author_device_id.clone(),
        key_epoch,
        author_counter: rec.author_counter as i64,
        content_kind: "inline".into(),
        ciphertext_b64: Some(vodozemac::base64_encode(ct)),
        nonce_b64: Some(vodozemac::base64_encode(nonce)),
        blob_id: None,
        blob_hash: None,
        aad_hash,
        prev_hash: None,
        entry_hash: None,
        uploaded_at_ms,
    })
}

/// OPEN a `SealedEntry`: rebuild the AAD (room comes from the sync scope) → AEAD-decrypt →
/// verify the signature (`author_ed_pub_b64` from `device_key_history`) → return the
/// verified record. Fail-closed: a wrong epoch key / an AAD mismatch (relay relocation) /
/// corrupt ciphertext / a bad signature → `Err` → the caller stops its cursor at that row.
/// It also cross-checks the entry meta against the record (defense in depth against
/// impersonation).
pub fn open_entry(
    entry: &SealedEntry,
    room_id: &str,
    epoch_key: &PluginEpochKey,
    author_ed_pub_b64: &str,
) -> Result<PluginLogRecordV1> {
    let aad = aad_bytes(
        room_id,
        &entry.plugin_id,
        entry.key_epoch as u64,
        &entry.author_id,
        &entry.author_device_id,
        entry.author_counter as u64,
    );
    let nonce_b64 = entry
        .nonce_b64
        .as_deref()
        .ok_or_else(|| Error::Crypto("plugin-log open: no nonce (inline expected)".into()))?;
    let ct_b64 = entry.ciphertext_b64.as_deref().ok_or_else(|| {
        Error::Crypto("plugin-log open: no ciphertext (the blob path does not exist yet)".into())
    })?;
    let nonce = vodozemac::base64_decode(nonce_b64)
        .map_err(|e| Error::Crypto(format!("plugin-log open: nonce b64: {e}")))?;
    let ct = vodozemac::base64_decode(ct_b64)
        .map_err(|e| Error::Crypto(format!("plugin-log open: ct b64: {e}")))?;
    let plaintext = open(epoch_key, &nonce, &ct, &aad)?;
    let sp: SealedPlaintext = serde_json::from_slice(&plaintext)
        .map_err(|e| Error::Crypto(format!("plugin-log open: plaintext parse: {e}")))?;
    verify_record(&sp.record, &sp.sig_b64, author_ed_pub_b64)?;
    // Defense in depth: the AAD meta (server-visible) must agree with the INSIDE of the
    // signed record; the room from the sync scope must also match the record's own room (so
    // a relay cannot inject it into a different room).
    if sp.record.plugin_id != entry.plugin_id
        || sp.record.author_id != entry.author_id
        || sp.record.author_device_id != entry.author_device_id
        || sp.record.author_counter != entry.author_counter as u64
        || sp.record.room_id != room_id
    {
        return Err(Error::Crypto(
            "plugin-log open: sealed-entry meta does not match the signed record".into(),
        ));
    }
    Ok(sp.record)
}

/// FORWARD-SECRECY TRY-ALL: try `entry` against ALL STORED keys of the epoch in turn
/// (glare → an epoch can hold more than one key; the server does not know which one sealed
/// it, and the AAD does not carry an epoch_id). The record is returned decrypted with
/// whichever key validates the AEAD tag. An EMPTY `keys` → fail-closed (`Err`). If none of
/// them opens it, the LAST error is returned (forged / wrong epoch → the caller SKIPS and
/// MOVES ON; the "no recoverable key" case is already STOPPED by the caller via
/// `keys.is_empty()`). The AAD STAYS bound to the epoch (the wire/AAD is UNCHANGED) — only
/// the key ATTEMPT is plural.
pub fn open_entry_try_keys(
    entry: &SealedEntry,
    room_id: &str,
    epoch_keys: &[PluginEpochKey],
    author_ed_pub_b64: &str,
) -> Result<PluginLogRecordV1> {
    let mut last_err = Error::Crypto("plugin-log open: no epoch key was tried (empty)".into());
    for key in epoch_keys {
        match open_entry(entry, room_id, key, author_ed_pub_b64) {
            Ok(rec) => return Ok(rec),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::olm::Account;

    fn rec() -> PluginLogRecordV1 {
        PluginLogRecordV1 {
            v: 1,
            room_id: "room-1".into(),
            plugin_id: "html:meydan".into(),
            collection: "post".into(),
            record_id: "u:alice:post-1".into(),
            parent_id: None,
            op: "put".into(),
            fields_json: r#"{"t":"selam"}"#.into(),
            author_id: "alice".into(),
            author_device_id: "dev-a".into(),
            author_counter: 3,
            lamport: 42,
            created_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn canonical_bytes_deterministic_and_domain_prefixed() {
        let r = rec();
        let a = r.canonical_sign_bytes();
        let b = r.clone().canonical_sign_bytes();
        assert_eq!(a, b, "the same record → the same bytes (deterministic)");
        assert!(a.starts_with(SIGN_DOMAIN), "the domain separator comes first");
    }

    #[test]
    fn canonical_bytes_change_with_every_field() {
        let base = rec().canonical_sign_bytes();
        // Change each field one at a time → the bytes MUST change (the field is signed).
        let mut muts: Vec<PluginLogRecordV1> = Vec::new();
        let mut m = rec();
        m.v = 2;
        muts.push(m);
        let mut m = rec();
        m.room_id = "room-2".into();
        muts.push(m);
        let mut m = rec();
        m.plugin_id = "html:x".into();
        muts.push(m);
        let mut m = rec();
        m.collection = "reply".into();
        muts.push(m);
        let mut m = rec();
        m.record_id = "u:alice:post-2".into();
        muts.push(m);
        let mut m = rec();
        m.parent_id = Some("u:alice:post-1".into());
        muts.push(m);
        let mut m = rec();
        m.op = "delete".into();
        muts.push(m);
        let mut m = rec();
        m.fields_json = r#"{"t":"x"}"#.into();
        muts.push(m);
        let mut m = rec();
        m.author_id = "bob".into();
        muts.push(m);
        let mut m = rec();
        m.author_device_id = "dev-b".into();
        muts.push(m);
        let mut m = rec();
        m.author_counter = 4;
        muts.push(m);
        let mut m = rec();
        m.lamport = 43;
        muts.push(m);
        let mut m = rec();
        m.created_at_ms = 1_700_000_000_001;
        muts.push(m);
        for m in muts {
            assert_ne!(
                base,
                m.canonical_sign_bytes(),
                "a changed field must change the bytes"
            );
        }
    }

    #[test]
    fn canonical_opt_none_vs_empty_differ() {
        // None and Some("") must not produce the SAME bytes (the presence flag).
        let mut a = rec();
        a.parent_id = None;
        let mut b = rec();
        b.parent_id = Some(String::new());
        assert_ne!(a.canonical_sign_bytes(), b.canonical_sign_bytes());
    }

    #[test]
    fn canonical_no_field_boundary_ambiguity() {
        // Shifting content between adjacent fields must not produce the same bytes (the
        // length-prefix guarantee).
        let mut a = rec();
        a.room_id = "ab".into();
        a.plugin_id = "c".into();
        let mut b = rec();
        b.room_id = "a".into();
        b.plugin_id = "bc".into();
        assert_ne!(a.canonical_sign_bytes(), b.canonical_sign_bytes());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let acc = Account::new();
        let key = [7u8; 32];
        let blob = acc.pickle().encrypt(&key);
        let ed_pub_b64 = vodozemac::base64_encode(acc.identity_keys().ed25519.as_bytes());
        let r = rec();
        let sig = sign_record(&r, &blob, &key).unwrap();
        assert!(
            verify_record(&r, &sig, &ed_pub_b64).is_ok(),
            "a correct signature must verify"
        );
    }

    #[test]
    fn verify_fails_on_tamper() {
        let acc = Account::new();
        let key = [7u8; 32];
        let blob = acc.pickle().encrypt(&key);
        let ed_pub_b64 = vodozemac::base64_encode(acc.identity_keys().ed25519.as_bytes());
        let r = rec();
        let sig = sign_record(&r, &blob, &key).unwrap();
        // Change the content → the signature must NO LONGER pass (tamper detection).
        let mut tampered = r.clone();
        tampered.fields_json = r#"{"t":"HACKED"}"#.into();
        assert!(verify_record(&tampered, &sig, &ed_pub_b64).is_err());
        // Change the author → must not pass (impersonation detection).
        let mut spoof = r.clone();
        spoof.author_id = "mallory".into();
        assert!(verify_record(&spoof, &sig, &ed_pub_b64).is_err());
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let acc = Account::new();
        let key = [7u8; 32];
        let blob = acc.pickle().encrypt(&key);
        let other = Account::new();
        let other_pub = vodozemac::base64_encode(other.identity_keys().ed25519.as_bytes());
        let r = rec();
        let sig = sign_record(&r, &blob, &key).unwrap();
        // Verifying with another device's pubkey → fails (wrong key).
        assert!(verify_record(&r, &sig, &other_pub).is_err());
    }

    #[test]
    fn aead_seal_open_roundtrip() {
        let key = generate_epoch_key();
        let pt = b"selam meydan";
        let aad = aad_bytes("room-1", "html:meydan", 1, "alice", "dev-a", 3);
        let (ct, nonce) = seal(&key, pt, &aad).unwrap();
        assert_ne!(
            ct.as_slice(),
            pt.as_slice(),
            "the ciphertext differs from the plaintext"
        );
        let out = open(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(out, pt, "decrypted == original");
    }

    #[test]
    fn aead_open_fails_wrong_key() {
        let key = generate_epoch_key();
        let other = generate_epoch_key();
        let aad = aad_bytes("r", "p", 1, "a", "d", 0);
        let (ct, nonce) = seal(&key, b"x", &aad).unwrap();
        assert!(open(&other, &nonce, &ct, &aad).is_err());
    }

    #[test]
    fn aead_open_fails_aad_mismatch() {
        let key = generate_epoch_key();
        let aad = aad_bytes("room-1", "html:meydan", 1, "alice", "dev-a", 3);
        let (ct, nonce) = seal(&key, b"x", &aad).unwrap();
        // A different context (author=mallory) → the AAD does not match → decryption fails
        // (the relay-relocation guard).
        let aad2 = aad_bytes("room-1", "html:meydan", 1, "mallory", "dev-a", 3);
        assert!(open(&key, &nonce, &ct, &aad2).is_err());
    }

    #[test]
    fn aead_open_fails_tampered_ciphertext() {
        let key = generate_epoch_key();
        let aad = aad_bytes("r", "p", 1, "a", "d", 0);
        let (mut ct, nonce) = seal(&key, b"hello", &aad).unwrap();
        ct[0] ^= 0xFF; // bit flip → the tag no longer matches
        assert!(open(&key, &nonce, &ct, &aad).is_err());
    }

    #[test]
    fn aead_nonce_unique_per_seal() {
        let key = generate_epoch_key();
        let aad = aad_bytes("r", "p", 1, "a", "d", 0);
        let (_, n1) = seal(&key, b"x", &aad).unwrap();
        let (_, n2) = seal(&key, b"x", &aad).unwrap();
        assert_ne!(n1, n2, "every seal uses a different nonce (random)");
    }

    fn mk_identity() -> (String, [u8; 32], String) {
        let acc = Account::new();
        let key = [9u8; 32];
        let blob = acc.pickle().encrypt(&key);
        let ed_pub = vodozemac::base64_encode(acc.identity_keys().ed25519.as_bytes());
        (blob, key, ed_pub)
    }

    #[test]
    fn compose_seal_open_roundtrip() {
        let (blob, key, ed_pub) = mk_identity();
        let epoch_key = generate_epoch_key();
        let r = rec();
        let sealed = seal_record(&r, &epoch_key, 1, &blob, &key, 1234).unwrap();
        assert_eq!(sealed.uploaded_at_ms, 1234);
        assert_eq!(sealed.content_kind, "inline");
        assert_eq!(sealed.author_id, "alice");
        let opened = open_entry(&sealed, &r.room_id, &epoch_key, &ed_pub).unwrap();
        assert_eq!(opened, r, "seal→open must return the record unchanged");
    }

    #[test]
    fn compose_open_fails_wrong_epoch_key() {
        let (blob, key, ed_pub) = mk_identity();
        let epoch_key = generate_epoch_key();
        let other_key = generate_epoch_key();
        let r = rec();
        let sealed = seal_record(&r, &epoch_key, 1, &blob, &key, 1).unwrap();
        assert!(open_entry(&sealed, &r.room_id, &other_key, &ed_pub).is_err());
    }

    #[test]
    fn compose_open_fails_wrong_author_pubkey() {
        let (blob, key, _ed) = mk_identity();
        let (_b2, _k2, other_pub) = mk_identity();
        let epoch_key = generate_epoch_key();
        let r = rec();
        let sealed = seal_record(&r, &epoch_key, 1, &blob, &key, 1).unwrap();
        // Correct epoch key (so it decrypts) but the wrong author pubkey → signature
        // verification fails (impersonation).
        assert!(open_entry(&sealed, &r.room_id, &epoch_key, &other_pub).is_err());
    }

    #[test]
    fn compose_open_fails_aad_binding_tamper() {
        let (blob, key, ed_pub) = mk_identity();
        let epoch_key = generate_epoch_key();
        let r = rec();
        let mut sealed = seal_record(&r, &epoch_key, 1, &blob, &key, 1).unwrap();
        // If the author_id that feeds the AAD is changed, open builds a different AAD → AEAD
        // decryption fails (a malicious relay cannot rebind the ciphertext to another author).
        sealed.author_id = "mallory".into();
        assert!(open_entry(&sealed, &r.room_id, &epoch_key, &ed_pub).is_err());
        // A different room sync scope → the room is in the AAD → it fails as well
        // (cross-room injection).
        let clean = seal_record(&r, &epoch_key, 1, &blob, &key, 1).unwrap();
        assert!(open_entry(&clean, "other-room", &epoch_key, &ed_pub).is_err());
    }

    /// FORWARD-SECRECY TRY-ALL (MANDATORY TEST #3, crypto layer): TWO keys on the same epoch
    /// due to glare, with the entry sealed by the SECOND one. `open_entry_try_keys` tries
    /// both → and opens it with the correct key (order does not matter). If no key opens it,
    /// Err; an empty list, Err.
    #[test]
    fn try_keys_opens_with_correct_glare_key() {
        let (blob, key, ed_pub) = mk_identity();
        let key_a = generate_epoch_key();
        let key_b = generate_epoch_key();
        let r = rec();
        // The entry is sealed with key_b (epoch=1; two keys on the same epoch = glare).
        let sealed = seal_record(&r, &key_b, 1, &blob, &key, 1).unwrap();
        // Whatever the order, try-all finds the correct key.
        let opened = open_entry_try_keys(&sealed, &r.room_id, &[key_a, key_b], &ed_pub).unwrap();
        assert_eq!(opened, r, "it opens with whichever of the glare keys is correct");
        let opened2 = open_entry_try_keys(&sealed, &r.room_id, &[key_b, key_a], &ed_pub).unwrap();
        assert_eq!(opened2, r, "the order does not matter");
        // Only the WRONG key(s) → Err (fail-closed).
        assert!(open_entry_try_keys(&sealed, &r.room_id, &[key_a], &ed_pub).is_err());
        // Empty list → Err.
        assert!(open_entry_try_keys(&sealed, &r.room_id, &[], &ed_pub).is_err());
    }
}
