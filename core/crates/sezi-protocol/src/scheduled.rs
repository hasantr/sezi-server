//! Scheduled messages (Hasan, 2026-11-09; `docs/SCHEDULED_MESSAGES_PLAN.md`): a message the RELAY
//! holds and releases at a time, sealed under a one-time key instead of the ratchet.
//!
//! The sender makes a random key `K` and a schedule id `S` (a UUID, also the message's
//! `msg_uid`), frames the `ChatPayload` as every payload is framed ([`crate::payload_frame`]) and
//! seals it with XChaCha20-Poly1305 under `K` ([`seal`]). The associated data ([`Aad`]) binds the
//! format, `S`, the sender's user and device, the conversation and the release time, so a relay that
//! holds the ciphertext can neither read it nor move it: to another chat, another time, another
//! sender. `K` travels at once, over Olm, inside `InnerMessage::ScheduledKey`; the ciphertext
//! travels to the relay, which releases it at the time as a [`crate::envelope::WireEnvelope`] of
//! kind 3 naming `S`.
//!
//! Pure: no I/O, no clock (every time is a parameter), builds for wasm.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{rand_core::UnwrapErr, rngs::SysRng, Rng};
use zeroize::Zeroize;

/// The format tag that opens the associated data. A later format names another.
pub const FORMAT: &str = "sezi-scheduled/1";
/// How far ahead a message may be scheduled: a year and a day.
pub const MAX_AHEAD_MS: i64 = 366 * 24 * 3600 * 1000;
/// How soon a message may be scheduled: anything sooner is just a send.
pub const MIN_AHEAD_MS: i64 = 5_000;
/// How long a receiver keeps a key (or an early ciphertext) past its release time, waiting for
/// the other half — then it is dropped.
pub const KEY_GRACE_MS: i64 = 7 * 24 * 3600 * 1000;
/// How long a cancel for an id this device holds nothing of is remembered. A known id's tombstone
/// lasts until its release time plus [`KEY_GRACE_MS`]: past that, no key is kept and nothing opens.
pub const UNKNOWN_TOMBSTONE_MS: i64 = KEY_GRACE_MS;
/// How far in the past a release time may be when the message is handed to the relay (a device that
/// was offline at the time): further, and it is refused — on the relay and before the upload.
pub const LATE_SKEW_MS: i64 = 10 * 60 * 1000;
/// The most keys one sender may have WAITING on this device (a delivered or cancelled id does not
/// count: re-review N1), the most of their cancelled ids kept as tombstones, the most released
/// ciphertexts of theirs waiting for a key, and the most candidates kept for one id before its key
/// says which is genuine (re-review N3).
pub const MAX_RECORDS_PER_SENDER: usize = 2 * MAX_PENDING;
pub const MAX_TOMBSTONES_PER_SENDER: usize = 1_000;
pub const MAX_ORPHANS_PER_SENDER: usize = 20;
pub const MAX_CANDIDATES_PER_ID: usize = 3;
/// How long a SHOWN id is remembered: the message's row (named by sender and id) already stops a
/// second insert; this only spares a second open.
pub const DELIVERED_TOMBSTONE_MS: i64 = 24 * 3600 * 1000;
/// A release that opens this much before its time is held until the time — a clock skew allowed
/// for, not an early delivery.
pub const EARLY_SKEW_MS: i64 = 2 * 60 * 1000;
/// The most messages one account may have waiting at its relay (the relay enforces it too).
pub const MAX_PENDING: usize = 100;
/// The most devices one schedule may be released to (the relay enforces it too).
pub const MAX_TARGET_DEVICES: usize = 200;
/// The key's length.
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// A one-time key as it travels inside `InnerMessage::ScheduledKey` (base64). Its `Debug` never
/// prints it — an inner message logged whole must not leak a key — and its text is wiped on drop.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct KeyB64(pub String);

impl std::fmt::Debug for KeyB64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyB64(<redacted>)")
    }
}

impl Drop for KeyB64 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// What the sealed payload is bound to. Built by the sender from what it schedules and by every
/// receiver from what the AUTHENTICATED key message said — never from the relay's frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad<'a> {
    pub schedule_id: &'a str,
    pub sender: &'a str,
    pub sender_device: &'a str,
    /// For a 1:1, the RECIPIENT's user id; for a room, the room id.
    pub conversation: &'a str,
    pub room: bool,
    pub release_at_ms: i64,
}

impl Aad<'_> {
    /// The bytes: each field length-prefixed (u32 big endian), so no two different tuples encode
    /// the same.
    pub fn bytes(&self) -> Vec<u8> {
        let conversation = if self.room {
            format!("r:{}", self.conversation)
        } else {
            format!("d:{}", self.conversation)
        };
        let release = self.release_at_ms.to_string();
        let mut out = Vec::new();
        for field in [FORMAT, self.schedule_id, self.sender, self.sender_device, &conversation, &release] {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }
}

/// Why a sealed payload did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// Not base64, or shorter than a nonce and a tag.
    Malformed,
    /// The key is not this one, or the ciphertext or what it is bound to was changed.
    Tag,
    /// It opened but its frame did not.
    Frame,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "scheduled/malformed",
            Self::Tag => "scheduled/tag",
            Self::Frame => "scheduled/frame",
        })
    }
}

/// The digest of a sealed payload as the relay holds it: BLAKE3 of the decoded bytes, hex. `None`
/// for anything that is not base64.
///
/// It travels inside each target's own `ScheduledKey`, over Olm — pairwise and authenticated as
/// the sender's device to that target alone. `K` is shared by every target, so the AEAD alone
/// proves only "someone holding K"; the digest the sender told THIS device says which one
/// ciphertext is the sender's, and a co-target who seals other words under `K` cannot change it.
/// Deliberately no signature (Hasan, 2026-11-10): a scheduled message stays as deniable as any Sezi
/// message, since Olm authenticates without leaving a third party anything to verify.
pub fn sealed_digest(sealed_b64: &str) -> Option<String> {
    let raw = vodozemac::base64_decode(sealed_b64).ok()?;
    Some(blake3::hash(&raw).to_hex().to_string())
}

/// Is `d` a digest as [`sealed_digest`] writes them?
pub fn valid_digest(d: &str) -> bool {
    d.len() == 64 && d.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A fresh one-time key.
pub fn new_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    UnwrapErr(SysRng).fill_bytes(&mut key);
    key
}

/// A fresh schedule id: a random (version 4) UUID, also the message's `msg_uid`.
pub fn new_schedule_id() -> String {
    let mut b = [0u8; 16];
    UnwrapErr(SysRng).fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Is `id` a schedule id as [`new_schedule_id`] makes them (lowercase hex UUID)?
pub fn valid_schedule_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// Seal `payload` (the encoded `ChatPayload`) under `key`, bound to `aad`: base64 of
/// `nonce ‖ ciphertext`. The payload is framed first, so its length says only its bucket.
pub fn seal(key: &[u8; KEY_LEN], aad: &Aad<'_>, payload: &[u8]) -> String {
    let mut nonce = [0u8; NONCE_LEN];
    UnwrapErr(SysRng).fill_bytes(&mut nonce);
    let framed = crate::payload_frame::seal(payload);
    let ct = XChaCha20Poly1305::new(&(*key).into())
        .encrypt(&XNonce::from(nonce), Payload { msg: &framed, aad: &aad.bytes() })
        .expect("XChaCha20-Poly1305 seals any length this side of 2^38 bytes");
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    vodozemac::base64_encode(blob)
}

/// Open what [`seal`] made: the payload bytes, or why not.
pub fn open(key: &[u8; KEY_LEN], aad: &Aad<'_>, sealed_b64: &str) -> Result<Vec<u8>, OpenError> {
    let blob = vodozemac::base64_decode(sealed_b64).map_err(|_| OpenError::Malformed)?;
    if blob.len() < NONCE_LEN + 16 {
        return Err(OpenError::Malformed);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let mut framed = XChaCha20Poly1305::new(&(*key).into())
        .decrypt(
            &XNonce::try_from(nonce).map_err(|_| OpenError::Malformed)?,
            Payload { msg: ct, aad: &aad.bytes() },
        )
        .map_err(|_| OpenError::Tag)?;
    let out = crate::payload_frame::open(&framed).map(|p| p.into_owned()).map_err(|_| OpenError::Frame);
    framed.zeroize();
    out
}

/// A key as it travels (base64), read back into its bytes; `None` for anything that is not one.
pub fn key_from_b64(b64: &str) -> Option<[u8; KEY_LEN]> {
    let mut bytes = vodozemac::base64_decode(b64).ok()?;
    let key = <[u8; KEY_LEN]>::try_from(bytes.as_slice()).ok();
    bytes.zeroize();
    key
}

/// The key, as it travels.
pub fn key_to_b64(key: &[u8; KEY_LEN]) -> String {
    vodozemac::base64_encode(key)
}

/// May a message be scheduled for `release_at_ms`, at `now_ms`?
pub fn valid_release(release_at_ms: i64, now_ms: i64) -> bool {
    release_at_ms >= now_ms.saturating_add(MIN_AHEAD_MS) && release_at_ms <= now_ms.saturating_add(MAX_AHEAD_MS)
}

/// May a receiver believe a key for `release_at_ms`, at `now_ms`? Not one already past its grace,
/// nor one further ahead than any sender may schedule (with the skew).
pub fn believable_release(release_at_ms: i64, now_ms: i64) -> bool {
    release_at_ms > now_ms.saturating_sub(KEY_GRACE_MS)
        && release_at_ms <= now_ms.saturating_add(MAX_AHEAD_MS + EARLY_SKEW_MS)
}

/// Is a release that opened at `now_ms` early — to be held until `release_at_ms`?
pub fn is_early(release_at_ms: i64, now_ms: i64) -> bool {
    now_ms < release_at_ms.saturating_sub(EARLY_SKEW_MS)
}

#[cfg(test)]
#[path = "scheduled_tests.rs"]
mod tests;
