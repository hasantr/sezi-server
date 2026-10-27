//! Group-library parts: one random key per library item, and an independently encrypted part for
//! every `part_size` bytes of its plaintext (docs/CAMPUS_PLAN.md, Wave D step 2).
//!
//! **Why parts, and why derived keys.** A recording is cut at the BYTE level into parts that are
//! uploaded, retried and fetched one at a time — so a failed upload repeats one part rather than
//! the hour, and playback can begin before the last part exists on this device. Each part is
//! sealed under its OWN key and nonce prefix, derived with HKDF-SHA256 from the item's single
//! 32-byte [`ItemKey`] and the part's index. The record that names the parts therefore carries ONE
//! key however long the recording is, and a part cannot be opened as any other part: the relay
//! could swap two objects, but the swapped bytes fail authentication instead of playing in the
//! wrong place.
//!
//! **The framing is STREAM-BE32, exactly.** Inside a part the plaintext is cut into
//! [`PART_CHUNK_SIZE`] chunks, and chunk `c` is XChaCha20-Poly1305 under the nonce
//! `prefix(19) ‖ BE32(c) ‖ last-flag(1)` with no associated data — byte for byte what
//! `chacha20poly1305::aead::stream::EncryptorBE32` produces, which `part_tests.rs` proves by opening
//! a part with this crate's ordinary `decrypt_in_memory`. It is spelled out here instead of going
//! through `EncryptorBE32` because that API can only advance its counter one call at a time, and a
//! part has to be decryptable from a CHUNK boundary: a download that stopped halfway through a part
//! resumes with `Range: bytes=N-` from the first chunk it does not have, and the chunk counter has
//! to start there too.
//!
//! **Streaming.** [`PartDecryptor`] takes ciphertext in whatever pieces the network delivers and
//! hands back each chunk's plaintext the moment its tag verifies. Every byte it returns is
//! authentic and in its right place; what it cannot know until [`PartDecryptor::finish`] is that
//! nothing was cut off at the end, and what no part can know is that the whole item is the one its
//! author published — that is the record's whole-file BLAKE3, checked by the caller once every
//! part is on the device.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use sezi_error::{Error, Result};

/// Plaintext bytes per STREAM chunk inside a part. The same 64 KiB the in-memory attachment path
/// uses: small enough that a player is fed within one chunk of the first byte arriving, large
/// enough that the 16-byte tag costs 0.02 %.
pub const PART_CHUNK_SIZE: usize = 64 * 1024;

/// The largest `part_size` a library item may declare. The relay accepts 33 MiB per object
/// (`worker-rs/src/room_library.rs`, `MAX_OBJECT_BYTES`): a 32 MiB part plus at most 8 KiB of tags
/// fits with room to spare, and anything larger could never be uploaded.
pub const MAX_PART_SIZE: u64 = 32 * 1024 * 1024;

/// The smallest `part_size`: one chunk. Below it a part would be all overhead.
pub const MIN_PART_SIZE: u64 = PART_CHUNK_SIZE as u64;

const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
/// XChaCha20-Poly1305 nonce (24) − BE32 counter (4) − last flag (1).
const NONCE_PREFIX_SIZE: usize = 19;

/// HKDF `info` prefix. Versioned so a change to the derivation can never be read back as the old
/// one: an item sealed under v2 would simply fail authentication under v1, not decrypt to garbage.
const PART_INFO: &[u8] = b"sezi/library/part/v1";

/// The one secret of a library item. Random, never reused, and the only key the item's record
/// carries; every part key is derived from it.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemKey([u8; KEY_SIZE]);

// Never print key material, not even in a debug log.
impl std::fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemKey(..)")
    }
}

impl ItemKey {
    /// A fresh key from the OS RNG.
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// The key as the record carries it: unpadded base64, the encoding every other key in the
    /// wire format uses (`FileManifest::key_b64`).
    pub fn to_b64(&self) -> String {
        vodozemac::base64_encode(self.0)
    }

    /// Parse a record's `key_b64`. Anything that is not exactly 32 bytes is refused: a record is
    /// untrusted input until it validates.
    pub fn from_b64(b64: &str) -> Result<Self> {
        let bytes = vodozemac::base64_decode(b64).map_err(|_| Error::Malformed("item key b64"))?;
        if bytes.len() != KEY_SIZE {
            return Err(Error::Malformed("item key length"));
        }
        let mut k = [0u8; KEY_SIZE];
        k.copy_from_slice(&bytes);
        Ok(Self(k))
    }

    /// Part `index`'s own key and nonce prefix: HKDF-SHA256 with no salt (the input is already a
    /// uniformly random key), `info = "sezi/library/part/v1" ‖ BE32(index)`, 51 bytes of output.
    fn part_secret(&self, index: u32) -> PartSecret {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut info = Vec::with_capacity(PART_INFO.len() + 4);
        info.extend_from_slice(PART_INFO);
        info.extend_from_slice(&index.to_be_bytes());
        let mut okm = [0u8; KEY_SIZE + NONCE_PREFIX_SIZE];
        // 51 bytes is far below HKDF-SHA256's 8160-byte ceiling, so `expand` cannot fail.
        hk.expand(&info, &mut okm)
            .expect("51 bytes is a valid HKDF-SHA256 output length");
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&okm[..KEY_SIZE]);
        let mut prefix = [0u8; NONCE_PREFIX_SIZE];
        prefix.copy_from_slice(&okm[KEY_SIZE..]);
        PartSecret { key, prefix }
    }
}

/// A derived part key and nonce prefix.
struct PartSecret {
    key: [u8; KEY_SIZE],
    prefix: [u8; NONCE_PREFIX_SIZE],
}

impl PartSecret {
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.key.into())
    }

    /// The STREAM-BE32 nonce of chunk `chunk`.
    fn nonce(&self, chunk: u32, last: bool) -> XNonce {
        let mut n = [0u8; 24];
        n[..NONCE_PREFIX_SIZE].copy_from_slice(&self.prefix);
        n[NONCE_PREFIX_SIZE..NONCE_PREFIX_SIZE + 4].copy_from_slice(&chunk.to_be_bytes());
        n[23] = u8::from(last);
        n.into()
    }
}

/// How many parts an item of `size` bytes has at `part_size`. At least one: an empty file is one
/// empty part, so "every part is on the device" has a part to be true about.
pub fn part_count(size: u64, part_size: u64) -> u64 {
    if part_size == 0 {
        return 0;
    }
    size.div_ceil(part_size).max(1)
}

/// The plaintext length of part `index`, or `None` past the last part.
pub fn part_plain_len(size: u64, part_size: u64, index: u64) -> Option<u64> {
    if index >= part_count(size, part_size) {
        return None;
    }
    let start = index * part_size;
    Some(size.saturating_sub(start).min(part_size))
}

/// Chunks in a part of `plain_len` bytes — at least one, so an empty part still carries a tag.
fn chunk_count(plain_len: u64) -> u64 {
    plain_len.div_ceil(PART_CHUNK_SIZE as u64).max(1)
}

/// The ciphertext length of a part of `plain_len` plaintext bytes: one tag per chunk.
pub fn part_ciphertext_len(plain_len: u64) -> u64 {
    plain_len + chunk_count(plain_len) * TAG_SIZE as u64
}

/// Where chunk `chunk` starts inside a part's ciphertext — the `Range` offset a resumed download
/// asks the relay for. Every chunk before the last is full, so the arithmetic is exact.
pub fn chunk_ciphertext_offset(chunk: u64) -> u64 {
    chunk * (PART_CHUNK_SIZE + TAG_SIZE) as u64
}

/// The chunk counter must fit the 4-byte field of the nonce. A part is at most
/// [`MAX_PART_SIZE`] = 512 chunks, so this only ever refuses a nonsense length.
fn checked_chunks(plain_len: u64) -> Result<u32> {
    u32::try_from(chunk_count(plain_len)).map_err(|_| Error::Malformed("part too long"))
}

/// Seal part `index` of an item. The output is [`part_ciphertext_len`]`(plaintext.len())` bytes.
pub fn encrypt_part(key: &ItemKey, index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let chunks = checked_chunks(plaintext.len() as u64)?;
    let secret = key.part_secret(index);
    let cipher = secret.cipher();
    let mut out = Vec::with_capacity(part_ciphertext_len(plaintext.len() as u64) as usize);
    for c in 0..chunks {
        let start = c as usize * PART_CHUNK_SIZE;
        let end = (start + PART_CHUNK_SIZE).min(plaintext.len());
        let last = c + 1 == chunks;
        let sealed = cipher
            .encrypt(&secret.nonce(c, last), &plaintext[start..end])
            .map_err(|e| Error::Crypto(format!("library part seal: {e}")))?;
        out.extend_from_slice(&sealed);
    }
    Ok(out)
}

/// Open a whole part at once. `plain_len` is what the record says this part holds, and the
/// ciphertext has to be exactly the length that implies — a part one byte short or long is refused
/// before any decryption.
pub fn decrypt_part(
    key: &ItemKey,
    index: u32,
    ciphertext: &[u8],
    plain_len: u64,
) -> Result<Vec<u8>> {
    if ciphertext.len() as u64 != part_ciphertext_len(plain_len) {
        return Err(Error::Malformed("library part length"));
    }
    let mut dec = PartDecryptor::new(key, index, plain_len)?;
    let mut out = Vec::with_capacity(plain_len as usize);
    dec.push(ciphertext, &mut out)?;
    dec.finish()?;
    Ok(out)
}

/// Incremental decryption of one part, fed by the network.
///
/// Holds at most one chunk of ciphertext between calls. Bytes arriving after the last chunk are an
/// error rather than ignored: a body longer than the record says is not this part.
pub struct PartDecryptor {
    secret: PartSecret,
    plain_len: u64,
    chunks: u32,
    next: u32,
    buf: Vec<u8>,
}

impl PartDecryptor {
    /// Decrypt part `index` from its first byte.
    pub fn new(key: &ItemKey, index: u32, plain_len: u64) -> Result<Self> {
        Self::resume_at(key, index, plain_len, 0)
    }

    /// Decrypt part `index` starting at chunk `start_chunk` — the ciphertext fed in must begin at
    /// [`chunk_ciphertext_offset`]`(start_chunk)`. A resume point past the last chunk is refused.
    pub fn resume_at(key: &ItemKey, index: u32, plain_len: u64, start_chunk: u64) -> Result<Self> {
        let chunks = checked_chunks(plain_len)?;
        if start_chunk >= chunks as u64 {
            return Err(Error::Malformed("library part resume past the end"));
        }
        Ok(Self {
            secret: key.part_secret(index),
            plain_len,
            chunks,
            next: start_chunk as u32,
            buf: Vec::with_capacity(PART_CHUNK_SIZE + TAG_SIZE),
        })
    }

    /// The chunk the next byte fed in belongs to.
    pub fn next_chunk(&self) -> u64 {
        self.next as u64
    }

    /// Ciphertext length of chunk `c`: full chunks before the last, the remainder at the end.
    fn chunk_ct_len(&self, c: u32) -> usize {
        if c + 1 < self.chunks {
            PART_CHUNK_SIZE + TAG_SIZE
        } else {
            let before = (self.chunks as u64 - 1) * PART_CHUNK_SIZE as u64;
            (self.plain_len - before) as usize + TAG_SIZE
        }
    }

    /// Feed ciphertext; append the plaintext of every chunk it completes to `out`.
    pub fn push(&mut self, mut bytes: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let cipher = self.secret.cipher();
        while !bytes.is_empty() {
            if self.next >= self.chunks {
                return Err(Error::Malformed("library part longer than declared"));
            }
            let want = self.chunk_ct_len(self.next);
            let take = (want - self.buf.len()).min(bytes.len());
            self.buf.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buf.len() == want {
                let last = self.next + 1 == self.chunks;
                let plain = cipher
                    .decrypt(&self.secret.nonce(self.next, last), self.buf.as_slice())
                    .map_err(|e| Error::Crypto(format!("library part open: {e}")))?;
                out.extend_from_slice(&plain);
                self.buf.clear();
                self.next += 1;
            }
        }
        Ok(())
    }

    /// Every chunk arrived and verified, nothing is left over. The truncation check: a body that
    /// stopped at a chunk boundary decrypts cleanly chunk by chunk and is caught only here.
    pub fn finish(self) -> Result<()> {
        if self.next == self.chunks && self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("library part truncated"))
        }
    }
}

/// Test-only: a part's derived key and nonce prefix as a `FileManifest` would carry them — what
/// lets the tests prove the framing is STREAM-BE32 by opening a part with `decrypt_in_memory`.
#[cfg(test)]
pub(crate) fn part_secret_b64(key: &ItemKey, index: u32) -> (String, String) {
    let s = key.part_secret(index);
    (vodozemac::base64_encode(s.key), vodozemac::base64_encode(s.prefix))
}

#[cfg(test)]
#[path = "part_tests.rs"]
mod tests;
