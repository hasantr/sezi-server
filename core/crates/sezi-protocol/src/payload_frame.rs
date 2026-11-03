//! The framed Olm/Megolm plaintext (Hasan, 2026-11-01): a payload is deflated when that pays and
//! padded to a fixed bucket, so a ciphertext's length says only which bucket its message is in.
//!
//! A payload has always been the `ChatPayload` JSON itself, so its first byte is `{`. A framed one
//! starts with [`MAGIC`], a byte no UTF-8 text can start with, and a reader tells the two apart by
//! that byte alone:
//!
//! ```text
//! MAGIC (0xF5) · flags (bit 0: the body is raw-deflated) · body length (u32, big endian) · body ·
//! zero padding up to the next multiple of BUCKET (256) bytes
//! ```
//!
//! **Who gets it.** Only a device that said it reads it (`olm_frame` in its caps announcement,
//! `kernel/olm_frame.rs`); everyone else gets today's bytes. [`open`] reads both, so a current
//! build reads a framed payload from anyone and a plain one from everyone.
//!
//! **What is deflated.** A payload of at least [`COMPRESS_MIN`] bytes whose deflated body is at
//! least 10% smaller; the rest travel as they are (still padded). Media never comes here: file
//! bytes travel through the media store, only their manifest is a payload.
//!
//! **The cap.** A body inflates to at most [`MAX_INFLATED`] bytes — the inbound payload ceiling —
//! so a small frame cannot ask for unbounded memory.

use crate::inner::MAX_INBOUND_PAYLOAD_BYTES;

/// The first byte of a framed payload. 0xF5–0xFF never occur in UTF-8, so no JSON starts here.
pub const MAGIC: u8 = 0xF5;
/// A framed payload's length is a multiple of this.
pub const BUCKET: usize = 256;
/// Below this a payload is never deflated: the saving would not cross a bucket.
pub const COMPRESS_MIN: usize = 1024;
/// The most a body inflates to.
pub const MAX_INFLATED: usize = MAX_INBOUND_PAYLOAD_BYTES;

const FLAG_DEFLATED: u8 = 0b0000_0001;
const HEADER: usize = 6;

/// Frame `plain`: deflated when that saves at least 10% of a payload of [`COMPRESS_MIN`] bytes or
/// more, then padded to a multiple of [`BUCKET`].
pub fn seal(plain: &[u8]) -> Vec<u8> {
    let deflated = (plain.len() >= COMPRESS_MIN)
        .then(|| miniz_oxide::deflate::compress_to_vec(plain, 6))
        .filter(|d| d.len() * 10 <= plain.len() * 9);
    let (flags, body) = match &deflated {
        Some(d) => (FLAG_DEFLATED, d.as_slice()),
        None => (0, plain),
    };
    let len = HEADER + body.len();
    let padded = len.div_ceil(BUCKET) * BUCKET;
    let mut out = Vec::with_capacity(padded);
    out.push(MAGIC);
    out.push(flags);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out.resize(padded, 0);
    out
}

/// Is this a framed payload (rather than the plain JSON every older sender writes)?
pub fn is_framed(bytes: &[u8]) -> bool {
    bytes.first() == Some(&MAGIC)
}

/// Why a framed payload does not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Shorter than its header or than the body it announces.
    Truncated,
    /// A flag this build does not know.
    UnknownFlags(u8),
    /// The body does not inflate, or inflates past [`MAX_INFLATED`].
    Inflate,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("payload-frame/truncated"),
            Self::UnknownFlags(b) => write!(f, "payload-frame/unknown-flags-{b:#04x}"),
            Self::Inflate => f.write_str("payload-frame/inflate"),
        }
    }
}

/// The payload inside: a plain one as it is, a framed one stripped of its padding and inflated.
pub fn open(bytes: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>, FrameError> {
    if !is_framed(bytes) {
        return Ok(std::borrow::Cow::Borrowed(bytes));
    }
    if bytes.len() < HEADER {
        return Err(FrameError::Truncated);
    }
    let flags = bytes[1];
    if flags & !FLAG_DEFLATED != 0 {
        return Err(FrameError::UnknownFlags(flags));
    }
    let len = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    let body = bytes.get(HEADER..HEADER.checked_add(len).ok_or(FrameError::Truncated)?).ok_or(FrameError::Truncated)?;
    if flags & FLAG_DEFLATED == 0 {
        return Ok(std::borrow::Cow::Borrowed(body));
    }
    miniz_oxide::inflate::decompress_to_vec_with_limit(body, MAX_INFLATED)
        .map(std::borrow::Cow::Owned)
        .map_err(|_| FrameError::Inflate)
}

#[cfg(test)]
#[path = "payload_frame_tests.rs"]
mod tests;
