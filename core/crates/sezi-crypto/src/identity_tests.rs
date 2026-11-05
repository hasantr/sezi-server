//! The P2P seed: what it depends on and what it must not.

use super::*;

/// v1 hashed the whole encrypted pickle, so every one-time key, every fallback rotation and every
/// change of vodozemac's pickle encoding gave the device a new NodeId. v2 depends on the identity
/// key alone.
#[test]
fn p2p_seed_survives_the_accounts_churn() {
    let mut id = Identity::generate();
    let seed = id.p2p_secret_seed();

    id.generate_otks(20);
    id.mark_otks_published();
    assert_eq!(seed, id.p2p_secret_seed(), "one-time keys");
    id.rotate_signed_fallback_b64();
    assert_eq!(seed, id.p2p_secret_seed(), "a new fallback key");

    let key = [7u8; 32];
    let blob = id.account().pickle().encrypt(&key);
    let pickle = vodozemac::olm::AccountPickle::from_encrypted(&blob, &key).expect("pickle opens");
    let restored = Identity::from_parts(Account::from(pickle), Some("user-x".into()));
    assert_eq!(seed, restored.p2p_secret_seed(), "a pickle round trip");
}

#[test]
fn p2p_seed_is_the_identitys_own() {
    let a = Identity::generate();
    let b = Identity::generate();
    assert_ne!(a.p2p_secret_seed(), b.p2p_secret_seed(), "another identity, another seed");
    // Never the signing key itself, under another protocol.
    assert_ne!(a.p2p_secret_seed(), a.signing_pubkey_bytes());
}
