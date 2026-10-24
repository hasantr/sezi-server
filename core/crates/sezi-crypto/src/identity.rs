use std::collections::HashMap;

use vodozemac::olm::{Account, IdentityKeys, OneTimeKeyGenerationResult};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature, KeyId};

/// Turn a slice into an exact 32-byte key (pickle / master-key validation).
pub fn to_key32(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!(
            "crypto/pickle-key-length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(bytes);
    Ok(k)
}

/// One long-lived identity per device. It wraps a vodozemac `Account` and delegates
/// all key management to it (Ed25519, Curve25519, OTKs, fallback keys).
pub struct Identity {
    pub(crate) account: Account,
    pub(crate) user_id: Option<String>,
}

/// The two public keys of an identity, in both encodings the rest of the code needs: hex for
/// human-facing display / logs, base64 for the wire (contact cards, the device list, peer pins).
#[derive(Debug, Clone)]
pub struct IdentityFingerprint {
    pub ed25519_hex: String,
    pub ed25519_b64: String,
    pub x25519_hex: String,
    pub x25519_b64: String,
}

/// Recover the public fingerprint from a stored account blob. Read-only: the account state is
/// not touched, nothing is published, and no key is generated.
pub fn fingerprint_from_blob(blob: &str, pickle_key: &[u8]) -> Result<IdentityFingerprint, String> {
    let key = to_key32(pickle_key)?;
    let pickle = vodozemac::olm::AccountPickle::from_encrypted(blob, &key)
        .map_err(|e| format!("crypto/identity-blob-unreadable: {e}"))?;
    Ok(Identity::from_parts(Account::from(pickle), None).fingerprint())
}

/// Test fixture: the account blob a device holds right after a SUCCESSFUL registration —
/// `otk_count` OTKs generated and marked published, plus a rotated signed prekey.
///
/// It is deliberately NOT the production registration path
/// (`kernel::runners::build_registration_material` + `finalize_registration_identity`). An
/// identity is only fixture SETUP for the tests that use this, and a second copy of the real
/// flow standing in for it is how the two drift apart.
///
/// The blob carries the ACCOUNT ONLY: `user_id` is not part of an `AccountPickle`, which is why
/// every caller passes it separately.
#[cfg(any(test, feature = "testkit"))]
pub fn registered_account_blob(pickle_key: &[u8], otk_count: u32) -> Result<String, String> {
    let key = to_key32(pickle_key)?;
    let mut id = Identity::generate();
    id.generate_otks(otk_count as usize);
    // Registration publishes a signed prekey too; generating it here keeps the fixture faithful
    // (the fallback key is part of the account state and Olm falls back to it when the OTKs run
    // out).
    let _ = id.rotate_signed_fallback_b64();
    id.mark_otks_published();
    Ok(id.account().pickle().encrypt(&key))
}

/// Derive a DETERMINISTIC, stable `prekey_id` from an OTK public key (first 8 bytes → u64 LE).
///
/// **It must be derived from the PUB, never from an enumeration index.** The worker does
/// `INSERT OR IGNORE (user, device, prekey_id)` and consumes with `UPDATE consumed=1` — it never
/// DELETES — so an index-based id makes every replenish batch reuse 1..N, collide, and be
/// silently ignored, leaving the server handing out OTK pubs whose private halves the sender's
/// Account has already rotated away. That is the field "unknown one-time key" failure. A
/// pub-derived id gets both directions right: different pub → different id, same pub → same id
/// (idempotent re-upload dedup). Curve25519 pubs are random, so a 64-bit collision is negligible.
pub fn otk_prekey_id(pub_key: &Curve25519PublicKey) -> u64 {
    let b = pub_key.to_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

impl Identity {
    pub fn generate() -> Self {
        Self { account: Account::new(), user_id: None }
    }

    pub fn signing_pubkey(&self) -> Ed25519PublicKey {
        self.account.ed25519_key()
    }

    pub fn diffie_pubkey(&self) -> Curve25519PublicKey {
        self.account.curve25519_key()
    }

    pub fn signing_pubkey_bytes(&self) -> [u8; 32] {
        *self.account.ed25519_key().as_bytes()
    }

    pub fn diffie_pubkey_bytes(&self) -> [u8; 32] {
        self.account.curve25519_key().to_bytes()
    }

    pub fn identity_keys(&self) -> IdentityKeys {
        self.account.identity_keys()
    }

    /// Both public keys in both encodings — see [`IdentityFingerprint`].
    pub fn fingerprint(&self) -> IdentityFingerprint {
        IdentityFingerprint {
            ed25519_hex: hex::encode(self.signing_pubkey_bytes()),
            ed25519_b64: vodozemac::base64_encode(self.signing_pubkey_bytes()),
            x25519_hex: hex::encode(self.diffie_pubkey_bytes()),
            x25519_b64: vodozemac::base64_encode(self.diffie_pubkey_bytes()),
        }
    }

    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    pub fn set_user_id(&mut self, id: String) {
        self.user_id = Some(id);
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Ed25519Signature {
        self.account.sign(msg)
    }

    /// Generates a fresh batch of OTKs; they still have to be published to the server.
    pub fn generate_otks(&mut self, count: usize) -> OneTimeKeyGenerationResult {
        self.account.generate_one_time_keys(count)
    }

    /// Generates a fallback (signed prekey) and returns the public key plus its
    /// Ed25519 signature (both base64). Olm's "fallback key" behaves like an SPK:
    /// it is used once the OTKs run out.
    pub fn rotate_signed_fallback_b64(&mut self) -> (String, String) {
        self.account.generate_fallback_key();
        let (_id, pub_key) = self
            .account
            .fallback_key()
            .into_iter()
            .next()
            .expect("fallback key just generated");
        let signature = self.account.sign(pub_key.as_bytes());
        (
            vodozemac::base64_encode(pub_key.to_bytes()),
            vodozemac::base64_encode(signature.to_bytes()),
        )
    }

    /// The OTKs not yet "published" — the ones still to be uploaded to the server.
    pub fn unpublished_otks(&self) -> HashMap<KeyId, Curve25519PublicKey> {
        self.account.one_time_keys()
    }

    /// Marks the pending OTKs as published (the server accepted them).
    pub fn mark_otks_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    /// The underlying Olm account.
    ///
    /// ⚠️ `pub` hands out the SECRET-BEARING account, and the type system no longer confines it to
    /// one crate. Nothing outside `messaging-core` depends on this crate today, so the exposure is
    /// unchanged in practice — but it is a promise now, not a guarantee.
    ///
    /// The right shape is not this. Callers only ever `pickle()` (six sites, usually straight into
    /// `.encrypt(key)`) or `sign()` (one site); both belong on `Identity`, leaving the account
    /// inside. That is an API change across nine call sites, so it is deferred rather than
    /// smuggled into an unrelated commit.
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Deterministic 32-byte seed for deriving the P2P (iroh) NodeId.
    ///
    /// The base64 of vodozemac's `Account::pickle()` output (an opaque blob
    /// covering the whole Ed25519 + Curve25519 secret state) is run through a
    /// BLAKE3 KDF. Same identity → same seed → same SecretKey → same NodeId.
    ///
    /// Domain separation: `new_derive_key("sezgi-p2p-node-v1")` — the iroh
    /// ed25519 key MUST be **different from the vodozemac Ed25519 signing
    /// key** (best practice; the same bytes under two protocols is a
    /// side-channel risk).
    ///
    /// v1 versioning: if the pickle format changes later, or another
    /// derivation is needed, derive a `-v2` and let old peers produce both
    /// seeds during a grace period.
    pub fn p2p_secret_seed(&self) -> [u8; 32] {
        // The `AccountPickle` is base64'd through vodozemac's pickle cipher: AES-256-CBC with
        // a truncated HMAC-SHA256 tag, both derived from the key below. NOT an AEAD, and the
        // difference matters here — CBC takes its IV from the same derivation, which is the
        // only reason a CONSTANT key produces DETERMINISTIC bytes at all. Under a nonce-based
        // AEAD this construction would either be non-deterministic or a nonce-reuse hazard.
        //
        // The key is not about confidentiality: it is a way to get those deterministic bytes,
        // and it is separate from the real pickle at rest. The base64 output is hashed by the
        // BLAKE3 KDF and dropped right here, so the ciphertext never leaves this function; that
        // — not the key being secret — is what makes a hard-coded key safe. The pickle itself
        // DOES carry the account's secret keys.
        const SEED_PICKLE_KEY: [u8; 32] = *b"sezgi-p2p-node-seed-keyv1-pickle";
        let pickle_b64 = self.account.pickle().encrypt(&SEED_PICKLE_KEY);
        let mut hasher = blake3::Hasher::new_derive_key("sezgi-p2p-node-v1");
        hasher.update(pickle_b64.as_bytes());
        let mut seed = [0u8; 32];
        hasher.finalize_xof().fill(&mut seed);
        seed
    }

    pub(crate) fn account_mut(&mut self) -> &mut Account {
        &mut self.account
    }

    /// Rebuild an identity from a restored account — used by backup restore, the auth runner, boot
    /// and the P2P runner. `pub` for the same reason as [`Identity::account`]: the split turned an
    /// intra-crate helper into a cross-crate one. Unlike `account`, this leaks nothing: it CONSUMES an
    /// account the caller already holds.
    pub fn from_parts(account: Account, user_id: Option<String>) -> Self {
        Self { account, user_id }
    }
}

/// Diagnostic: how many one-time-key PRIVATE halves this account still holds, and the highest key
/// id it knows about.
///
/// Exists because "the pre-key message contained an unknown one-time key" is unfalsifiable without
/// it. The server can be shown to hold a public OTK, under the right device, freshly uploaded — and
/// still the owner rejects it. Whether that is "the account holds nothing", "the account holds a
/// different generation" or "the account was rolled back past this key" needs the local side of the
/// comparison, and no other log line carries it.
///
/// Read out of the serialized pickle rather than the live account, because vodozemac keeps the
/// private key store `pub(super)`: `Account::one_time_keys()` returns only the UNPUBLISHED ones,
/// which is exactly the set that is empty after a successful upload and therefore says nothing.
/// `next_key_id` is the generation counter — a value far above the count means many keys were
/// generated and are gone, which is the fingerprint of a store that was rewound.
pub fn otk_inventory(identity_blob: &str, pickle_key: &[u8]) -> Result<(usize, u64), String> {
    let key = to_key32(pickle_key)?;
    let pickle = vodozemac::olm::AccountPickle::from_encrypted(identity_blob, &key)
        .map_err(|e| format!("crypto/identity-blob-unreadable: {e}"))?;
    let value = serde_json::to_value(&pickle).map_err(|e| format!("pickle serialize: {e}"))?;
    let otks = value.get("one_time_keys");
    let count = otks
        .and_then(|o| o.get("private_keys"))
        .and_then(|p| p.as_object())
        .map(|m| m.len())
        .unwrap_or(0);
    let next_id = otks
        .and_then(|o| o.get("next_key_id"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    Ok((count, next_id))
}

#[cfg(test)]
mod otk_inventory_tests {
    use super::*;

    /// The inventory must count what the account can actually DECRYPT with, which is the published
    /// keys too — not `Account::one_time_keys()`, which empties on publish.
    #[test]
    fn published_keys_still_count() {
        let key = [7u8; 32];
        let mut account = Account::new();
        account.generate_one_time_keys(12);
        let blob = account.pickle().encrypt(&key);
        let (before, next_before) = otk_inventory(&blob, &key).expect("inventory");
        assert_eq!(before, 12);
        assert_eq!(next_before, 12, "next_key_id tracks generations, not the live count");

        account.mark_keys_as_published();
        let blob = account.pickle().encrypt(&key);
        let (after, _) = otk_inventory(&blob, &key).expect("inventory");
        assert_eq!(
            after, 12,
            "publishing must not change the inventory — if it did, every device would reject the \
             very keys it just uploaded",
        );
    }

    /// An account that has generated many keys but holds few is the signature of a rewound store.
    #[test]
    fn the_generation_counter_outlives_the_keys() {
        let key = [9u8; 32];
        let mut account = Account::new();
        account.generate_one_time_keys(4);
        let old = account.pickle().encrypt(&key);
        account.generate_one_time_keys(4);
        let new = account.pickle().encrypt(&key);

        let (old_count, old_next) = otk_inventory(&old, &key).expect("old");
        let (new_count, new_next) = otk_inventory(&new, &key).expect("new");
        assert_eq!((old_count, old_next), (4, 4));
        assert_eq!((new_count, new_next), (8, 8));
        assert!(
            new_next > old_next,
            "restoring `old` over `new` would drop 4 keys the server may already serve",
        );
    }

    /// A wrong pickle key must be an error, not a silent zero — a zero would read as "the account
    /// has no keys" and send the diagnosis in exactly the wrong direction.
    #[test]
    fn a_wrong_key_is_an_error_not_a_zero() {
        let mut account = Account::new();
        account.generate_one_time_keys(3);
        let blob = account.pickle().encrypt(&[1u8; 32]);
        assert!(otk_inventory(&blob, &[2u8; 32]).is_err());
    }
}
