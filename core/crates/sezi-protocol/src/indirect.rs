//! An Olm payload too big for one relay envelope (Hasan, 2026-11-01: "something that cannot get
//! under 64 KB will come one day" — the answer must be general, not per-kind compression).
//!
//! The relay keeps its queue for small E2E frames and refuses an envelope over
//! [`RELAY_ENVELOPE_MAX`] with a 400 (`worker-rs/src/messages/handlers.rs`, `inbox_do/ws.rs`); files
//! go through its media store. So a payload that would make a larger envelope takes the media
//! store too: the sender deflates the whole encoded `ChatPayload`, encrypts it under a fresh key
//! (`sezi-file`'s XChaCha20 STREAM, as an attachment is), uploads it scoped to the recipient, and
//! sends in its place a small [`crate::inner::InnerMessage::Indirect`] naming it. The receiver
//! fetches, checks, opens and dispatches the payload inside exactly as if it had come inline, from
//! the same sender on the same session. Only a payload that the relay would have refused takes
//! this way, so nothing that fits today changes on the wire.

use serde::{Deserialize, Serialize};

/// The relay's ceiling on one `envelope_b64`, in bytes — the same number on HTTP `/messages/send`
/// and the socket's `send`.
pub const RELAY_ENVELOPE_MAX: usize = 64 * 1024;

/// The largest encoded `ChatPayload` sent inline. MEASURED, not estimated
/// (`kernel/indirect/package_tests.rs`): the envelope is base64 of a JSON envelope holding the
/// base64 of an Olm message, so it is about 16/9 of the payload plus a fixed header — a 32 KiB
/// payload makes an envelope of ~58.5 KB as a PreKey message, leaving ~7 KB of the relay's
/// 64 KB as headroom. Anything larger goes indirect.
pub const INLINE_PAYLOAD_MAX: usize = 32 * 1024;

/// Where an indirect payload is and how to open it. Carried inside Olm, so the relay that stores
/// the blob never sees the key.
///
/// The blob is `deflate(ChatPayload JSON)` encrypted with `sezi-file`'s STREAM under `key_b64` /
/// `nonce_b64` / `chunk_size`; `size` is the deflated length (the STREAM plaintext), `len` and
/// `sha256_b64` the ciphertext's length and SHA-256, checked before anything is decrypted.
/// `kind_hint` names the payload's kind for logs only — the receiver believes the kind it opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectRef {
    pub media_id: String,
    pub key_b64: String,
    pub nonce_b64: String,
    pub chunk_size: u32,
    pub size: u64,
    pub len: u64,
    pub sha256_b64: String,
    #[serde(default)]
    pub kind_hint: String,
}
