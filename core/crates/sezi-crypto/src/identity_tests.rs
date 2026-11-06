//! The P2P seed: what it depends on and what it must not. The link proof: what it signs.

use super::*;

/// The P2P seed by the 2061 formula: a BLAKE3 derive over the signature of a fixed context. What
/// a relay could compute from a signature it obtained.
fn seed_from_signature(sig: &Ed25519Signature) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("sezgi-p2p-node-v2");
    hasher.update(&sig.to_bytes());
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// v1 hashed the whole encrypted pickle, so every one-time key, every fallback rotation and every
/// change of vodozemac's pickle encoding gave the device a new NodeId. v2 and v3 depend on an
/// identity key alone.
#[test]
fn p2p_seed_survives_the_accounts_churn() {
    let mut id = Identity::generate();
    let seed = id.p2p_secret_seed().expect("seed");

    id.generate_otks(20);
    id.mark_otks_published();
    assert_eq!(seed, id.p2p_secret_seed().expect("seed"), "one-time keys");
    id.rotate_signed_fallback_b64();
    assert_eq!(seed, id.p2p_secret_seed().expect("seed"), "a new fallback key");

    let key = [7u8; 32];
    let blob = id.account().pickle().encrypt(&key);
    let pickle = vodozemac::olm::AccountPickle::from_encrypted(&blob, &key).expect("pickle opens");
    let restored = Identity::from_parts(Account::from(pickle), Some("user-x".into()));
    assert_eq!(seed, restored.p2p_secret_seed().expect("seed"), "a pickle round trip");
}

#[test]
fn p2p_seed_is_the_identitys_own() {
    let a = Identity::generate();
    let b = Identity::generate();
    let seed = a.p2p_secret_seed().expect("seed");
    assert_ne!(seed, b.p2p_secret_seed().expect("seed"), "another identity, another seed");
    // Never a public key, nor the 2061 seed.
    assert_ne!(seed, a.signing_pubkey_bytes());
    assert_ne!(seed, a.diffie_pubkey_bytes());
    assert_ne!(seed, seed_from_signature(&a.sign(b"sezgi-p2p-node-seed-v2")), "the v2 seed");
}

/// CRY-1: a relay chooses the `link_code` the new device signs. One that names the context the
/// 2061 seed signed must get nothing the seed can be computed from — neither through the tagged
/// proof (another message) nor through the legacy one (refused for a code of that shape).
#[test]
fn a_link_code_naming_the_old_seed_context_reveals_nothing_of_the_seed() {
    let id = Identity::generate();
    let hostile = "sezgi-p2p-node-seed-v2";
    let seed = id.p2p_secret_seed().expect("seed");

    let tagged = id.sign_link_proof(hostile);
    assert_ne!(seed, seed_from_signature(&tagged), "the tagged proof");
    assert_ne!(tagged.to_bytes(), id.sign(hostile).to_bytes(), "the tagged proof is not the raw one");
    assert!(id.sign_legacy_link_proof(hostile).is_none(), "no raw signature over a code no relay mints");
    // Even the raw signature, were some other path to hand it out, no longer yields the seed.
    assert_ne!(seed, seed_from_signature(&id.sign(hostile)), "the seed is no signature's hash");
}

/// The proofs verify against the identity key over exactly the bytes the relay checks.
#[test]
fn link_proofs_sign_what_the_relay_verifies() {
    let id = Identity::generate();
    let code = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";
    let key = id.signing_pubkey();
    let tagged = id.sign_link_proof(code);
    key.verify(&sezi_protocol::link_proof::link_proof_message(code), &tagged).expect("tagged");
    assert!(key.verify(code.as_bytes(), &tagged).is_err(), "the tagged proof is not the raw form");
    let legacy = id.sign_legacy_link_proof(code).expect("a relay-shaped code");
    key.verify(code.as_bytes(), &legacy).expect("legacy");
}
