//! The FCM JWT's pure parts against a THROWAWAY RSA-2048 key made for these tests alone
//! (`tests/fixtures/fcm_test_key.pem`, `openssl genpkey` on 2026-11-05). It is no service
//! account's key and signs nothing anywhere; never put a real `FCM_SERVICE_ACCOUNT` key here. It
//! sits outside `src/` so the self-host template, which copies `src/`, does not ship a PEM.
//!
//! The signature itself is WebCrypto's and cannot be made on the host; the known answer below is
//! what `fcm_sign.rs` must produce, and was checked against it under Node's WebCrypto (the
//! module compiled to wasm unchanged) when the signer moved.

use sha2::{Digest, Sha256};

use super::*;

pub(crate) const TEST_KEY_PEM: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fcm_test_key.pem"));

/// The test key's PKCS#8 DER, as `openssl pkey -outform DER` writes it, by its SHA-256.
const TEST_KEY_DER_SHA256: &str = "f9ac0f61be44286745287fa7d37f860e1678a207d0ae1dbe19eb6af6fac2b873";

const EMAIL: &str = "fcm-test@example.invalid";
const NOW: u64 = 1_700_000_000;

/// Header and claims for `EMAIL` at `NOW`, base64url — the claims in the order the relay has
/// always sent them (aud, exp, iat, iss, scope).
pub(crate) const EXPECTED_SIGNING_INPUT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsImV4cCI6MTcwMDAwMzYwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJmY20tdGVzdEBleGFtcGxlLmludmFsaWQiLCJzY29wZSI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvZmlyZWJhc2UubWVzc2FnaW5nIn0";

/// The RS256 (PKCS#1 v1.5, deterministic) signature of `EXPECTED_SIGNING_INPUT` under the test
/// key, base64url. Recorded twice before the signer moved to WebCrypto: by
/// `openssl dgst -sha256 -sign`, and by the relay's own `rsa`-crate path, which agreed.
pub(crate) const EXPECTED_SIGNATURE_B64U: &str = "BIDjG9DnViHbKCYWV-TXHstgMVuTc1HT65PQJQVFgF6ywOxVHTkaQRMMTTUn_mhKycn7sN5utolVZuVV0KCuAn2WNgdjX5KlYzAIQq6jLSjnauXXFzJLlFx-waVivoYeOxaMYCGsZp2kv72-UvNLR0jeildgoquchVVC0ydRY26TDq9YKXePXg3gYDrBjQIotEH1njAUMrvUGo1igxhmDp3fsxaz0_FnMYYkWai37zI8Lxlwr3dptHPrOztuvb1-Jjktk1eQfQ0Lf8GZpbPP71tr1deEjz6aomjXsqR6wvBxWG3MaBr3zM_yeyzI4PcrjdQlkLe9WA_jhhrMknKDkA";

fn der_sha256(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

#[test]
fn signing_input_is_the_shape_google_has_always_had() {
    assert_eq!(signing_input(EMAIL, NOW), EXPECTED_SIGNING_INPUT);
    let claims = crate::utils::b64u_decode(EXPECTED_SIGNING_INPUT.split('.').nth(1).unwrap()).unwrap();
    assert_eq!(
        String::from_utf8(claims).unwrap(),
        r#"{"aud":"https://oauth2.googleapis.com/token","exp":1700003600,"iat":1700000000,"iss":"fcm-test@example.invalid","scope":"https://www.googleapis.com/auth/firebase.messaging"}"#
    );
}

#[test]
fn assemble_appends_the_signature_base64url() {
    let sig = crate::utils::b64u_decode(EXPECTED_SIGNATURE_B64U).unwrap();
    assert_eq!(sig.len(), 256);
    let jwt = assemble(EXPECTED_SIGNING_INPUT, &sig);
    assert_eq!(jwt, format!("{EXPECTED_SIGNING_INPUT}.{EXPECTED_SIGNATURE_B64U}"));
    assert_eq!(jwt.split('.').count(), 3);
    assert!(!jwt.contains('=') && !jwt.contains('+') && !jwt.contains('/'));
}

#[test]
fn pem_becomes_the_der_openssl_writes() {
    assert_eq!(der_sha256(&pkcs8_der(TEST_KEY_PEM).unwrap()), TEST_KEY_DER_SHA256);
}

#[test]
fn escaped_newlines_from_the_service_account_json_are_restored() {
    // As the key sits inside the JSON string once `serde_json` has read it when the newlines
    // arrived double-escaped: literal backslash-n.
    let escaped = TEST_KEY_PEM.replace('\n', "\\n");
    assert!(!escaped.contains('\n'));
    assert_eq!(der_sha256(&pkcs8_der(&escaped).unwrap()), TEST_KEY_DER_SHA256);
    // Surrounding whitespace and CRLF line ends are tolerated too.
    let crlf = format!("  \n{}\n", TEST_KEY_PEM.replace('\n', "\r\n"));
    assert_eq!(der_sha256(&pkcs8_der(&crlf).unwrap()), TEST_KEY_DER_SHA256);
}

#[test]
fn a_service_account_json_key_round_trips() {
    // The real secret's shape: JSON with the PEM's newlines as `\n` escapes.
    let sa = serde_json::json!({ "client_email": EMAIL, "private_key": TEST_KEY_PEM }).to_string();
    let v: serde_json::Value = serde_json::from_str(&sa).unwrap();
    let der = pkcs8_der(v["private_key"].as_str().unwrap()).unwrap();
    assert_eq!(der_sha256(&der), TEST_KEY_DER_SHA256);
}

#[test]
fn not_a_pkcs8_pem_is_refused() {
    let pkcs1 = TEST_KEY_PEM
        .replace("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")
        .replace("END PRIVATE KEY", "END RSA PRIVATE KEY");
    assert!(pkcs8_der(&pkcs1).is_err());
    assert!(pkcs8_der("").is_err());
    assert!(pkcs8_der("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----").is_err());
    assert!(pkcs8_der("-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----").is_err());
}
