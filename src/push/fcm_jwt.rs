//! The pure half of the service-account JWT the relay trades with Google for an FCM access token
//! (`fcm.rs` `get_access_token`): the PEM key turned into the PKCS#8 DER the signer imports, the
//! signing input (header and claims, base64url), and the assembled token. No I/O, no clock, no
//! JavaScript — so all of it is tested on the host (`fcm_jwt_tests.rs`); only the RS256
//! signature itself is made by the platform (`fcm_sign.rs`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::utils::b64u_encode;

/// The JWT header, byte for byte as Google has always been sent it.
const HEADER: &[u8] = br#"{"alg":"RS256","typ":"JWT"}"#;

/// What the token asks Google for: sending FCM messages, nothing else.
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const AUDIENCE: &str = "https://oauth2.googleapis.com/token";

/// How long the assertion is valid; Google caps it at one hour.
pub(crate) const ASSERTION_LIFETIME_S: u64 = 3600;

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

/// `base64url(header) "." base64url(claims)` — the bytes the RS256 signature covers.
pub(crate) fn signing_input(client_email: &str, now: u64) -> String {
    let claims = serde_json::json!({
        "iss": client_email,
        "scope": SCOPE,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + ASSERTION_LIFETIME_S,
    })
    .to_string();
    format!("{}.{}", b64u_encode(HEADER), b64u_encode(claims.as_bytes()))
}

/// The finished JWT: the signing input and its signature, base64url.
pub(crate) fn assemble(signing_input: &str, signature: &[u8]) -> String {
    format!("{}.{}", signing_input, b64u_encode(signature))
}

/// A service account's `private_key` (PEM, PKCS#8 — `BEGIN PRIVATE KEY`) as the DER WebCrypto's
/// `importKey("pkcs8", …)` takes. Inside the service account's JSON the line breaks may arrive
/// `\n`-escaped; they are restored first. A PKCS#1 key (`BEGIN RSA PRIVATE KEY`) is refused, as
/// the parser before this one refused it: Google issues PKCS#8.
pub(crate) fn pkcs8_der(private_key: &str) -> Result<Vec<u8>, String> {
    let pem = private_key.replace("\\n", "\n");
    let pem = pem.trim();
    let body = pem
        .strip_prefix(PEM_BEGIN)
        .and_then(|rest| rest.strip_suffix(PEM_END))
        .ok_or_else(|| "fcm: private_key is not a PKCS#8 PEM".to_string())?;
    let b64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("fcm: private_key base64: {e}"))?;
    if der.is_empty() {
        return Err("fcm: private_key is empty".to_string());
    }
    Ok(der)
}

#[cfg(test)]
#[path = "fcm_jwt_tests.rs"]
mod tests;
