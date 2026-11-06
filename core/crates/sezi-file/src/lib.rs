//! File crypto — chunk-by-chunk AEAD with XChaCha20-Poly1305 STREAM (BE32).
//!
//! - 32-byte random file key (unique per file)
//! - 19-byte random STREAM nonce (BE32 = 24 - 5)
//! - chunked: 64 KiB plaintext → 64 KiB + 16-byte tag for the in-memory path, 1 MiB for the
//!   streaming file-to-file path (`CHUNK_SIZE_STREAMING`, which is what `encrypt_file_to_file`
//!   uses)
//! - The last chunk is marked via `encrypt_last`, which is what defends against truncation
//!
//! The manifest travels E2E over Olm; the server only ever sees encrypted bytes, and the content
//! cannot be opened without the manifest.
//!
//! ⚠ **wasm:** the in-memory crypto compiles and runs there. The file-path I/O does not panic
//! either — `std::fs` on wasm32 returns `Err` — and no OPFS runtime is wanted, because web
//! attachments stage plaintext in the `media_blobs` table and never touch a path: the kernel is
//! given BYTES, and a download with no `media_dir` returns plaintext rather than refusing.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aead_stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{aead::KeyInit, XChaCha20Poly1305};
use rand::{rand_core::UnwrapErr, rngs::SysRng, Rng};
use tokio_util::sync::CancellationToken;

use sezi_transfer::progress::{emit_bytes, TransferStep};
use sezi_error::{Error, Result};

/// The group library's keyed parts: one key per item, a derived key per part, STREAM-BE32 inside.
pub mod part;

/// Chunk size for `encrypt_in_memory` (the CF small-file path). Fixed for back-compat, and
/// adequate because CF media is ≤50 MB.
const CHUNK_SIZE: usize = 64 * 1024;
/// Chunk size for `encrypt_file_to_file` (the P2P streaming path). Crypto throughput matches
/// 64 KiB, but 500 MB becomes ~500 progress events instead of enough to throttle the UI, and the
/// syscall count drops.
const CHUNK_SIZE_STREAMING: usize = 1024 * 1024;
/// BufReader/BufWriter capacity — kept equal to chunk_size so one read is one chunk.
const IO_BUF_SIZE: usize = 1024 * 1024;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
/// XChaCha20-Poly1305 nonce (24) − BE32 counter+last (5) = 19.
const STREAM_NONCE_SIZE: usize = 19;

/// Re-exported for the many existing `crate::file::FileManifest` paths. It is DEFINED in `inner`
/// because it is a WIRE type, and defining it here would make the protocol crate depend on this
/// one — which pulls in `sezi_transfer`, tokio and a global `CancellationToken` registry. A
/// protocol module must not inherit that.
pub use sezi_protocol::inner::FileManifest;

/// Encrypts the plaintext and returns manifest+ciphertext. `media_id` comes back empty; the caller
/// fills it in after the upload.
pub fn encrypt_in_memory(
    plaintext: &[u8],
    filename: &str,
    content_type: &str,
) -> Result<(FileManifest, Vec<u8>)> {
    let (key, nonce) = fresh_key_and_nonce();
    encrypt_in_memory_keyed(plaintext, &key, &nonce, filename, content_type)
}

/// A fresh key and STREAM nonce for [`encrypt_in_memory_keyed`], base64 as a manifest carries
/// them.
pub fn fresh_key_and_nonce() -> (String, String) {
    let mut key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; STREAM_NONCE_SIZE];
    UnwrapErr(SysRng).fill_bytes(&mut key);
    UnwrapErr(SysRng).fill_bytes(&mut nonce);
    (vodozemac::base64_encode(key), vodozemac::base64_encode(nonce))
}

/// [`encrypt_in_memory`] under a key and nonce chosen earlier (base64): the same bytes in give
/// the same ciphertext out. For an upload that is RETRIED under one object id — a relay that
/// already holds the object answers success without taking the bytes again, so a retry that
/// re-encrypted under a new key would hand out a key the stored object does not open.
pub fn encrypt_in_memory_keyed(
    plaintext: &[u8],
    key_b64: &str,
    nonce_b64: &str,
    filename: &str,
    content_type: &str,
) -> Result<(FileManifest, Vec<u8>)> {
    let key: [u8; KEY_SIZE] = vodozemac::base64_decode(key_b64)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| Error::Crypto("bad key".into()))?;
    let nonce: [u8; STREAM_NONCE_SIZE] = vodozemac::base64_decode(nonce_b64)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| Error::Crypto("bad nonce".into()))?;

    let cipher = XChaCha20Poly1305::new(&key.into());
    let mut encryptor = EncryptorBE32::from_aead(cipher, (&nonce).into());

    let cap = plaintext.len() + (plaintext.len() / CHUNK_SIZE + 1) * TAG_SIZE;
    let mut out = Vec::with_capacity(cap);

    let mut iter = plaintext.chunks(CHUNK_SIZE);
    match iter.next() {
        Some(mut current) => loop {
            match iter.next() {
                Some(next) => {
                    let ct = encryptor
                        .encrypt_next(current)
                        .map_err(|e| Error::Crypto(format!("aead next: {e}")))?;
                    out.extend_from_slice(&ct);
                    current = next;
                }
                None => {
                    let ct = encryptor
                        .encrypt_last(current)
                        .map_err(|e| Error::Crypto(format!("aead last: {e}")))?;
                    out.extend_from_slice(&ct);
                    break;
                }
            }
        },
        None => {
            // Empty file — still produce one tag so integrity is preserved.
            let ct = encryptor
                .encrypt_last(&[][..])
                .map_err(|e| Error::Crypto(format!("aead empty: {e}")))?;
            out.extend_from_slice(&ct);
        }
    }

    let manifest = FileManifest {
        v: 1,
        media_id: String::new(),
        key_b64: vodozemac::base64_encode(key),
        nonce_b64: vodozemac::base64_encode(nonce),
        chunk_size: CHUNK_SIZE as u32,
        size: plaintext.len() as u64,
        content_type: content_type.to_string(),
        filename: filename.to_string(),
    };
    Ok((manifest, out))
}

/// Avatar decryption: rebuilds the manifest from the combined `key_b64` (base64(key32 ‖ nonce19),
/// as carried on the `ProfileAvatar` wire) plus the declared size. `chunk_size` is `CHUNK_SIZE`
/// because an avatar always goes through `encrypt_in_memory`. Verifying the sha256 is the CALLER's
/// job (`avatars.rs`) — this is crypto only.
pub fn decrypt_avatar(combined_key_b64: &str, size: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let packed = vodozemac::base64_decode(combined_key_b64)
        .map_err(|_| Error::Malformed("avatar key b64"))?;
    if packed.len() != KEY_SIZE + STREAM_NONCE_SIZE {
        return Err(Error::Malformed("avatar key length"));
    }
    let manifest = FileManifest {
        v: 1,
        media_id: String::new(),
        key_b64: vodozemac::base64_encode(&packed[..KEY_SIZE]),
        nonce_b64: vodozemac::base64_encode(&packed[KEY_SIZE..]),
        chunk_size: CHUNK_SIZE as u32,
        size,
        content_type: "application/octet-stream".to_string(),
        filename: "avatar".to_string(),
    };
    decrypt_in_memory(&manifest, ciphertext)
}

pub fn decrypt_in_memory(manifest: &FileManifest, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if manifest.v != 1 {
        return Err(Error::Malformed("manifest version"));
    }
    let key = vodozemac::base64_decode(&manifest.key_b64)
        .map_err(|_| Error::Malformed("manifest key b64"))?;
    if key.len() != KEY_SIZE {
        return Err(Error::Malformed("manifest key length"));
    }
    let nonce = vodozemac::base64_decode(&manifest.nonce_b64)
        .map_err(|_| Error::Malformed("manifest nonce b64"))?;
    if nonce.len() != STREAM_NONCE_SIZE {
        return Err(Error::Malformed("manifest nonce length"));
    }
    // Manifest-driven so one decryptor opens both 64 KiB and 1 MiB chunked files. The upper
    // bound is DoS protection.
    let chunk_size = manifest.chunk_size as usize;
    if chunk_size == 0 || chunk_size > 64 * 1024 * 1024 {
        return Err(Error::Malformed("manifest chunk_size"));
    }

    let mut key_arr = [0u8; KEY_SIZE];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; STREAM_NONCE_SIZE];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = XChaCha20Poly1305::new(&key_arr.into());
    let mut decryptor = DecryptorBE32::from_aead(cipher, (&nonce_arr).into());

    let chunk_ct_size = chunk_size + TAG_SIZE;

    // `manifest.size` is PEER CONTROLLED (it rides inside `InnerMessage::File`) and must never
    // reach `Vec::with_capacity` unvalidated: `u64::MAX` panics, and a large representable value
    // fails the allocation, which is `handle_alloc_error` → `abort()` — a process kill no
    // `catch_unwind` turns into a retry. The ceiling comes from the ciphertext actually handed
    // over, since STREAM emits exactly one 16-byte tag per chunk. Such a manifest would fail the
    // size check at the end of this function anyway; this only moves the failure BEFORE the
    // allocation.
    let chunk_count = ciphertext.len().div_ceil(chunk_ct_size);
    let max_plaintext = ciphertext.len().saturating_sub(chunk_count.saturating_mul(TAG_SIZE));
    if manifest.size > max_plaintext as u64 {
        return Err(Error::Malformed("manifest size exceeds ciphertext"));
    }
    // Clamped too, so nothing hostile reaches the allocator even if that bound is relaxed later.
    let mut out = Vec::with_capacity((manifest.size as usize).min(max_plaintext));

    let mut iter = ciphertext.chunks(chunk_ct_size);
    match iter.next() {
        Some(mut current) => loop {
            match iter.next() {
                Some(next) => {
                    let plain = decryptor
                        .decrypt_next(current)
                        .map_err(|e| Error::Crypto(format!("aead-d next: {e}")))?;
                    out.extend_from_slice(&plain);
                    current = next;
                }
                None => {
                    let plain = decryptor
                        .decrypt_last(current)
                        .map_err(|e| Error::Crypto(format!("aead-d last: {e}")))?;
                    out.extend_from_slice(&plain);
                    break;
                }
            }
        },
        None => return Err(Error::Malformed("empty ciphertext")),
    }

    if out.len() as u64 != manifest.size {
        return Err(Error::Malformed("size mismatch after decrypt"));
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────
//  Streaming (file-to-file) AEAD — the P2P large-file path. No bytes cross FRB: Rust is given an
//  input path and an output path. RAM stays at roughly five chunk buffers (~5 MiB) regardless of
//  file size, against the 4× file size a single-shot approach costs.
// ─────────────────────────────────────────────────────────────────────────

/// Streaming AEAD encrypt, input_path → output_path, under a fresh random key and nonce.
///
/// On cancel the `.part` file is left behind; the caller deletes it while cleaning up the outbox.
///
/// It once took a resume offset and a caller-chosen key and nonce, so that a resumed encrypt gave
/// byte-identical ciphertext (the same iroh ticket). No caller ever resumed — every one passed
/// `0, None, None` — and a fixed key and nonce handed to a second file would have reused the
/// STREAM nonce under one key (FIL-1, removed 2026-11-06).
pub fn encrypt_file_to_file(
    input_path: &Path,
    output_path: &Path,
    filename: &str,
    content_type: &str,
    progress_key: Option<&str>,
    cancel: Option<&CancellationToken>,
) -> Result<FileManifest> {
    let chunk_size = CHUNK_SIZE_STREAMING;
    let t_start = std::time::Instant::now();
    let mut t_read_ns: u128 = 0;
    let mut t_aead_ns: u128 = 0;
    let mut t_write_ns: u128 = 0;
    let mut t_emit_ns: u128 = 0;

    let mut key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; STREAM_NONCE_SIZE];
    UnwrapErr(SysRng).fill_bytes(&mut key);
    UnwrapErr(SysRng).fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(&key.into());
    let mut encryptor = EncryptorBE32::from_aead(cipher, (&nonce).into());

    let input_size = std::fs::metadata(input_path)?.len();
    let mut input = BufReader::with_capacity(IO_BUF_SIZE, File::open(input_path)?);

    let part_path = part_path_for(output_path);
    let _ = std::fs::remove_file(&part_path);
    let mut output = BufWriter::with_capacity(IO_BUF_SIZE, File::create(&part_path)?);

    let mut bytes_done = 0u64;
    let mut buf = vec![0u8; chunk_size];

    if input_size == 0 {
        // Empty file — still produce a single tag so integrity is preserved.
        let ct = encryptor
            .encrypt_last(&[][..])
            .map_err(|e| Error::Crypto(format!("aead empty: {e}")))?;
        output.write_all(&ct)?;
    } else {
        let t_r = std::time::Instant::now();
        let first_n = read_exact_or_eof(&mut input, &mut buf)?;
        t_read_ns += t_r.elapsed().as_nanos();
        if first_n == 0 {
            // The file shrank to nothing after its size was read: finalize with an empty chunk,
            // and the size check on the other end refuses it.
            let ct = encryptor
                .encrypt_last(&[][..])
                .map_err(|e| Error::Crypto(format!("aead trailing empty: {e}")))?;
            output.write_all(&ct)?;
        } else {
            let mut current = buf[..first_n].to_vec();
            loop {
                check_cancel(cancel)?;
                let t_r2 = std::time::Instant::now();
                let next_n = read_exact_or_eof(&mut input, &mut buf)?;
                t_read_ns += t_r2.elapsed().as_nanos();
                if next_n > 0 {
                    let t_a = std::time::Instant::now();
                    let ct = encryptor
                        .encrypt_next(&current[..])
                        .map_err(|e| Error::Crypto(format!("aead next: {e}")))?;
                    t_aead_ns += t_a.elapsed().as_nanos();
                    let t_w = std::time::Instant::now();
                    output.write_all(&ct)?;
                    t_write_ns += t_w.elapsed().as_nanos();
                    bytes_done += current.len() as u64;
                    let t_e = std::time::Instant::now();
                    emit_progress(progress_key, TransferStep::Encrypting, bytes_done, input_size);
                    t_emit_ns += t_e.elapsed().as_nanos();
                    current = buf[..next_n].to_vec();
                } else {
                    let t_a = std::time::Instant::now();
                    let ct = encryptor
                        .encrypt_last(&current[..])
                        .map_err(|e| Error::Crypto(format!("aead last: {e}")))?;
                    t_aead_ns += t_a.elapsed().as_nanos();
                    let t_w = std::time::Instant::now();
                    output.write_all(&ct)?;
                    t_write_ns += t_w.elapsed().as_nanos();
                    bytes_done += current.len() as u64;
                    emit_progress(progress_key, TransferStep::Encrypting, bytes_done, input_size);
                    break;
                }
            }
        }
    }

    output.flush()?;
    drop(output);
    std::fs::rename(&part_path, output_path)?;

    let total_ms = t_start.elapsed().as_millis();
    let mb = input_size as f64 / (1024.0 * 1024.0);
    let mbps = if total_ms > 0 { mb / (total_ms as f64 / 1000.0) } else { 0.0 };
    log::info!(
        target: "file-encrypt-timing",
        "size_mb={:.1} total_ms={} mbps={:.1} read_ms={} aead_ms={} write_ms={} emit_ms={}",
        mb, total_ms, mbps,
        t_read_ns / 1_000_000,
        t_aead_ns / 1_000_000,
        t_write_ns / 1_000_000,
        t_emit_ns / 1_000_000,
    );

    Ok(FileManifest {
        v: 1,
        media_id: String::new(),
        key_b64: vodozemac::base64_encode(key),
        nonce_b64: vodozemac::base64_encode(nonce),
        chunk_size: chunk_size as u32,
        size: input_size,
        content_type: content_type.to_string(),
        filename: filename.to_string(),
    })
}

/// Streaming AEAD decrypt, input_path → output_path. On cancel the `.part` is DELETED: there is
/// deliberately no decrypt resume, because resuming the iroh ciphertext is enough and decryption
/// is cheap to redo from scratch.
pub fn decrypt_file_to_file(
    manifest: &FileManifest,
    input_path: &Path,
    output_path: &Path,
    progress_key: Option<&str>,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
    if manifest.v != 1 {
        return Err(Error::Malformed("manifest version"));
    }
    let chunk_size = manifest.chunk_size as usize;
    if chunk_size == 0 || chunk_size > 64 * 1024 * 1024 {
        return Err(Error::Malformed("manifest chunk_size"));
    }
    let key = vodozemac::base64_decode(&manifest.key_b64)
        .map_err(|_| Error::Malformed("manifest key b64"))?;
    if key.len() != KEY_SIZE {
        return Err(Error::Malformed("manifest key length"));
    }
    let nonce = vodozemac::base64_decode(&manifest.nonce_b64)
        .map_err(|_| Error::Malformed("manifest nonce b64"))?;
    if nonce.len() != STREAM_NONCE_SIZE {
        return Err(Error::Malformed("manifest nonce length"));
    }
    let mut key_arr = [0u8; KEY_SIZE];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; STREAM_NONCE_SIZE];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = XChaCha20Poly1305::new(&key_arr.into());
    let mut decryptor = DecryptorBE32::from_aead(cipher, (&nonce_arr).into());

    let chunk_ct_size = chunk_size + TAG_SIZE;
    let plain_size = manifest.size;

    let mut input = BufReader::with_capacity(IO_BUF_SIZE, File::open(input_path)?);

    let part_path = part_path_for(output_path);
    let _ = std::fs::remove_file(&part_path);
    let output_file = File::create(&part_path)?;
    let mut output = BufWriter::with_capacity(IO_BUF_SIZE, output_file);

    let mut bytes_done: u64 = 0;
    let mut buf = vec![0u8; chunk_ct_size];

    let first_n = read_exact_or_eof(&mut input, &mut buf)?;
    if first_n == 0 {
        let _ = std::fs::remove_file(&part_path);
        return Err(Error::Malformed("empty ciphertext"));
    }
    let mut current = buf[..first_n].to_vec();
    let res: Result<()> = loop {
        if let Err(e) = check_cancel(cancel) {
            break Err(e);
        }
        let next_n = match read_exact_or_eof(&mut input, &mut buf) {
            Ok(n) => n,
            Err(e) => break Err(e.into()),
        };
        if next_n > 0 {
            match decryptor.decrypt_next(&current[..]) {
                Ok(plain) => {
                    if let Err(e) = output.write_all(&plain) {
                        break Err(e.into());
                    }
                    bytes_done += plain.len() as u64;
                    emit_progress(progress_key, TransferStep::Decrypting, bytes_done, plain_size);
                    current = buf[..next_n].to_vec();
                }
                Err(e) => break Err(Error::Crypto(format!("aead-d next: {e}"))),
            }
        } else {
            match decryptor.decrypt_last(&current[..]) {
                Ok(plain) => {
                    if let Err(e) = output.write_all(&plain) {
                        break Err(e.into());
                    }
                    bytes_done += plain.len() as u64;
                    emit_progress(progress_key, TransferStep::Decrypting, bytes_done, plain_size);
                    break Ok(());
                }
                Err(e) => break Err(Error::Crypto(format!("aead-d last: {e}"))),
            }
        }
    };

    if let Err(e) = res {
        drop(output);
        let _ = std::fs::remove_file(&part_path);
        return Err(e);
    }

    if bytes_done != plain_size {
        drop(output);
        let _ = std::fs::remove_file(&part_path);
        return Err(Error::Malformed("size mismatch after decrypt"));
    }

    output.flush()?;
    drop(output);
    std::fs::rename(&part_path, output_path)?;
    Ok(())
}

// ─── helpers ──────────────────────────────────────────────────────────────

fn part_path_for(output_path: &Path) -> PathBuf {
    let mut s = output_path.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

fn check_cancel(cancel: Option<&CancellationToken>) -> Result<()> {
    if let Some(token) = cancel {
        if token.is_cancelled() {
            return Err(Error::Cancelled);
        }
    }
    Ok(())
}

fn emit_progress(key: Option<&str>, step: TransferStep, done: u64, total: u64) {
    if let Some(k) = key {
        emit_bytes(k, step, done, total);
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
