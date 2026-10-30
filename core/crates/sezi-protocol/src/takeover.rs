//! What a linked device and its relay agree on when the device takes over a lost primary
//! (`docs/PRIMARY_DEVICE_LOSS_PLAN.md` §4.2): the six-digit code the device shows and the admin
//! types, and the box the relay seals the escrow secret `R` into.
//!
//! Both halves are pure and build for wasm on their own, because the relay runs them too: the
//! relay derives the same code to check the admin's answer, and seals `R` to the request's
//! one-time key when it is approved.
//!
//! **The code names one request.** It is derived from the request id the relay minted AND the
//! one-time key the device sent with it, so a code read off one device approves that device's
//! request and no other. It is a check that the admin talked to whoever holds the device, not a
//! secret against the relay — the relay can compute it, and does.
//!
//! **The release box** is an ephemeral X25519 key agreement with the request's one-time public
//! key, a BLAKE3 key derivation bound to both public halves, and XChaCha20-Poly1305:
//! `b64(eph_pub[32] ‖ nonce[24] ‖ ciphertext)`. Only the device that made the request holds the
//! one-time secret, so `R` reaches nobody else even through a proxy or a log that sees the answer.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey};

use sezi_error::{Error, Result};

/// The BLAKE3 context of the code derivation. Changing it changes every code.
const CODE_CONTEXT: &str = "sezi takeover code v1";
/// The BLAKE3 context of the release-box key.
const RELEASE_CONTEXT: &str = "sezi takeover release v1";
/// How many digits the code has.
pub const CODE_DIGITS: usize = 6;
const NONCE_LEN: usize = 24;

/// The code a takeover request shows: six digits, zero-padded.
pub fn takeover_code(request_id: &str, one_time_pub_b64: &str) -> String {
    let mut material = Vec::with_capacity(request_id.len() + one_time_pub_b64.len() + 1);
    material.extend_from_slice(request_id.as_bytes());
    // A separator, so ("ab", "c") and ("a", "bc") cannot name the same code.
    material.push(0);
    material.extend_from_slice(one_time_pub_b64.as_bytes());
    let digest = blake3::derive_key(CODE_CONTEXT, &material);
    let n = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")) % 1_000_000;
    format!("{n:06}")
}

/// Is `typed` the code of this request? Spaces and dashes in what the admin typed are ignored
/// (the device shows it as `482 193`).
pub fn code_matches(request_id: &str, one_time_pub_b64: &str, typed: &str) -> bool {
    let digits: String = typed.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    digits.len() == CODE_DIGITS && digits == takeover_code(request_id, one_time_pub_b64)
}

/// A fresh one-time key pair for a request: the secret's bytes (kept by the device until the
/// request ends) and the public half in base64 (sent with the request).
pub fn new_one_time_key() -> ([u8; 32], String) {
    let secret = Curve25519SecretKey::new();
    let public = Curve25519PublicKey::from(&secret).to_base64();
    (*secret.to_bytes(), public)
}

/// What the relay releases on approval, inside the box: the escrow's id and its secret `R`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedShare {
    pub escrow_id: String,
    pub r_b64: String,
}

fn release_key(shared: &[u8; 32], eph_pub: &[u8; 32], one_time_pub: &[u8; 32]) -> [u8; 32] {
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(shared);
    material[32..64].copy_from_slice(eph_pub);
    material[64..].copy_from_slice(one_time_pub);
    blake3::derive_key(RELEASE_CONTEXT, &material)
}

/// Seal `plaintext` to a request's one-time public key (the relay's side).
pub fn seal_to_one_time_key(one_time_pub_b64: &str, plaintext: &[u8]) -> Result<String> {
    let their = Curve25519PublicKey::from_base64(one_time_pub_b64)
        .map_err(|_| Error::Malformed("takeover one-time key"))?;
    let eph = Curve25519SecretKey::new();
    let eph_pub = Curve25519PublicKey::from(&eph);
    let shared = eph
        .diffie_hellman(&their)
        .ok_or(Error::Malformed("takeover one-time key is not contributory"))?;
    let key = release_key(shared.as_bytes(), eph_pub.as_bytes(), their.as_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(&key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: eph_pub.as_bytes() })
        .map_err(|e| Error::Crypto(format!("takeover seal: {e}")))?;
    let mut out = Vec::with_capacity(32 + NONCE_LEN + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(vodozemac::base64_encode(out))
}

/// Open a box sealed by [`seal_to_one_time_key`] with the request's one-time secret (the device's
/// side). A box for another key, or one changed on the way, does not open.
pub fn open_with_one_time_key(one_time_secret: &[u8; 32], sealed_b64: &str) -> Result<Vec<u8>> {
    let bytes = vodozemac::base64_decode(sealed_b64).map_err(|_| Error::Malformed("takeover box"))?;
    if bytes.len() < 32 + NONCE_LEN + 16 {
        return Err(Error::Malformed("takeover box is too short"));
    }
    let eph_pub: [u8; 32] = bytes[..32].try_into().expect("32 bytes");
    let nonce = &bytes[32..32 + NONCE_LEN];
    let ct = &bytes[32 + NONCE_LEN..];
    let secret = Curve25519SecretKey::from_slice(one_time_secret);
    let mine = Curve25519PublicKey::from(&secret);
    let shared = secret
        .diffie_hellman(&Curve25519PublicKey::from_bytes(eph_pub))
        .ok_or(Error::Malformed("takeover box key is not contributory"))?;
    let key = release_key(shared.as_bytes(), &eph_pub, mine.as_bytes());
    XChaCha20Poly1305::new(&key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &eph_pub })
        .map_err(|_| Error::Crypto("takeover/release-unreadable".into()))
}

#[cfg(test)]
#[path = "takeover_tests.rs"]
mod tests;
