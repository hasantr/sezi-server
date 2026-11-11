//! Fixed vectors for every RustCrypto primitive the relay calls directly, so a move of that
//! generation (sha2, hmac, pbkdf2, ed25519-dalek, chacha20poly1305) has to leave each one
//! byte-for-byte where it was. The vectors are the published ones (RFC 8032, RFC 4231, the
//! PBKDF2-HMAC-SHA256 set of RFC 7914's appendix), not values recorded from this build. The AEAD
//! and the S3 signature have theirs beside their code (`push/carry_tests.rs`, `sigv4.rs`), the
//! bot webhook's HMAC in `bots/webhook_tests.rs`.

use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// RFC 8032 §7.1, TEST 1: the secret key, its public key, and the signature of the empty message.
const ED_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ED_SIG_EMPTY: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

/// The same secret as a PKCS#8 v1 PEM (RFC 8410 §10.3, what `openssl genpkey` writes and an
/// operator may have set as the env secret): `302e020100300506032b657004220420 ‖ seed`.
const ED_PEM_V1: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n";

/// The v2 form (RFC 5958 OneAsymmetricKey, the public key appended as `[1]`) — what a
/// self-provisioned relay wrote and keeps in D1 (`self_provision.rs`, LF line endings):
/// `3051020101300506032b657004220420 ‖ seed ‖ 812100 ‖ public`.
const ED_PEM_V2: &str = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\ngSEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PRIVATE KEY-----\n";

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[test]
fn ed25519_signs_and_verifies_the_rfc_8032_vector() {
    let key = SigningKey::from_bytes(&arr::<32>(ED_SECRET));
    assert_eq!(hex::encode(key.verifying_key().to_bytes()), ED_PUBLIC);
    let sig = key.sign(b"");
    assert_eq!(hex::encode(sig.to_bytes()), ED_SIG_EMPTY);

    let public = VerifyingKey::from_bytes(&arr::<32>(ED_PUBLIC)).unwrap();
    let fixed = Signature::from_bytes(&arr::<64>(ED_SIG_EMPTY));
    assert!(public.verify(b"", &fixed).is_ok());
    assert!(public.verify_strict(b"", &fixed).is_ok());
    assert!(public.verify(b"x", &fixed).is_err());
}

#[test]
fn the_jwt_key_pem_reads_and_writes_as_before() {
    for pem in [ED_PEM_V1, ED_PEM_V2] {
        let key = crate::auth::jwt::parse_signing_pem(pem).expect("a stored PEM keeps opening");
        assert_eq!(hex::encode(key.verifying_key().to_bytes()), ED_PUBLIC);
    }
    let written = SigningKey::from_bytes(&arr::<32>(ED_SECRET)).to_pkcs8_pem(LineEnding::LF).unwrap();
    assert_eq!(written.as_str(), ED_PEM_V2);
}

#[test]
fn hmac_sha256_holds_rfc_4231_case_2() {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"Jefe").unwrap();
    mac.update(b"what do ya want for nothing?");
    let want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    let mut check = <Hmac<Sha256> as KeyInit>::new_from_slice(b"Jefe").unwrap();
    check.update(b"what do ya want for nothing?");
    assert_eq!(hex::encode(mac.finalize().into_bytes()), want);
    assert!(check.verify_slice(&hex::decode(want).unwrap()).is_ok());
}

#[test]
fn a_stored_code_hash_still_verifies() {
    // PBKDF2-HMAC-SHA256("password", "salt", c = 2, dkLen = 32), in the stored `pbk2$` form.
    let stored = "pbk2$2$c2FsdA$rk0Mla9rRtMtCt_5KPBt0CowP47zwlHf1uLYWpVHTEM";
    assert!(crate::auth::hashing::verify_code("password", stored));
    assert!(!crate::auth::hashing::verify_code("passwore", stored));
}

#[test]
fn sha256_hex_holds_the_fips_abc_vector() {
    assert_eq!(
        crate::auth::hashing::sha256_hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
