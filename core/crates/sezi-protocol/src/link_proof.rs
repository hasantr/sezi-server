//! The bytes a new device signs while it polls `link-status` (the QR device link).
//!
//! The `link_code` is chosen by the RELAY. Until CRY-1 (2026-11-06) the device signed it raw with
//! its identity Ed25519 key, which made that key a signing oracle over any string the relay
//! cared to name: a relay answering `link-start` with `link_code = "sezgi-p2p-node-seed-v2"` got
//! the exact signature the P2P seed of 2061 was derived from. Ed25519 is deterministic, so one
//! answer was enough.
//!
//! Two forms exist on the wire, both carried in the same `proof_b64` field:
//! - **tagged** (this build on): `ed.sign(LINK_PROOF_TAG || link_code)`. No other message the
//!   identity key signs starts with this tag, so the relay learns a signature it can use for
//!   nothing else.
//! - **legacy** (apps before this build, and relays before this build only verify it):
//!   `ed.sign(link_code)`. A new app falls back to it only after the relay refused the tagged
//!   form (an old relay), and only over a code of the exact shape an honest relay mints
//!   ([`is_relay_minted_link_code`]) — 43 base64url characters. Nothing else the identity key
//!   signs has that shape (signed prekeys are 32 raw bytes, the start PoP 64, device lists and
//!   history packets are JSON, contact cards are 117/149 binary bytes, the relogin challenge has
//!   a `:`), so even the legacy form gives a hostile relay nothing reusable.
//!
//! A relay of this build accepts either form (`worker-rs/src/devices/link.rs`).

/// Prefixed to the `link_code` before signing. The NUL ends the tag, so no code can extend it.
pub const LINK_PROOF_TAG: &[u8] = b"sezi-device-link-v1\0";

/// The length of a relay-minted `link_code`: 32 random bytes in unpadded base64url.
pub const RELAY_LINK_CODE_LEN: usize = 43;

/// What the tagged proof signs: [`LINK_PROOF_TAG`] followed by the code's bytes.
pub fn link_proof_message(link_code: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(LINK_PROOF_TAG.len() + link_code.len());
    msg.extend_from_slice(LINK_PROOF_TAG);
    msg.extend_from_slice(link_code.as_bytes());
    msg
}

/// Whether `link_code` has the shape an honest relay mints (`b64u_encode(random_bytes(32))`):
/// exactly [`RELAY_LINK_CODE_LEN`] characters of the unpadded base64url alphabet. Only such a
/// code is ever signed in the legacy, untagged form.
pub fn is_relay_minted_link_code(link_code: &str) -> bool {
    link_code.len() == RELAY_LINK_CODE_LEN
        && link_code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag is a wire contract with every relay: pinned byte for byte.
    #[test]
    fn the_tag_is_pinned() {
        assert_eq!(LINK_PROOF_TAG, b"sezi-device-link-v1\x00");
        assert_eq!(link_proof_message("abc"), b"sezi-device-link-v1\x00abc".to_vec());
    }

    #[test]
    fn only_a_relay_shaped_code_passes() {
        let minted = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";
        assert_eq!(minted.len(), RELAY_LINK_CODE_LEN);
        assert!(is_relay_minted_link_code(minted));
        // The context the seed of 2061 signed, and other things a relay might name.
        for bad in [
            "sezgi-p2p-node-seed-v2",
            "",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCd",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEf",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdE",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCd=",
            "sezgi-relogin:user:1700000000000000000000000",
            "{\"devices\":[],\"rev\":1,\"user_id\":\"xxxxxxxx\"}",
        ] {
            assert!(!is_relay_minted_link_code(bad), "{bad:?}");
        }
    }
}
