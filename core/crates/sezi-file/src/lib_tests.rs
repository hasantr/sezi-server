//! Tests for `lib.rs`, included through `#[path]` — `super` is the crate root.

use super::*;

#[test]
fn roundtrip_small() {
    let plain = b"hello sezgi - file";
    let (m, ct) = encrypt_in_memory(plain, "test.txt", "text/plain").unwrap();
    let out = decrypt_in_memory(&m, &ct).unwrap();
    assert_eq!(out, plain);
}

#[test]
fn roundtrip_multi_chunk() {
    let plain = vec![7u8; CHUNK_SIZE * 3 + 17];
    let (m, ct) = encrypt_in_memory(&plain, "x.bin", "application/octet-stream").unwrap();
    assert!(ct.len() > plain.len());
    let out = decrypt_in_memory(&m, &ct).unwrap();
    assert_eq!(out, plain);
}

#[test]
fn empty_file_still_roundtrips() {
    let (m, ct) = encrypt_in_memory(&[], "e.bin", "application/octet-stream").unwrap();
    assert_eq!(ct.len(), TAG_SIZE);
    let out = decrypt_in_memory(&m, &ct).unwrap();
    assert!(out.is_empty());
}

#[test]
fn tamper_detected() {
    let (m, mut ct) = encrypt_in_memory(b"hello", "h.txt", "text/plain").unwrap();
    ct[0] ^= 0x01;
    assert!(decrypt_in_memory(&m, &ct).is_err());
}

#[test]
fn legacy_64k_manifest_still_decrypts() {
    // The guard for the day CHUNK_SIZE is raised: decryption must take the size from
    // manifest.chunk_size, so files written at 64 KiB still open.
    let plain = vec![3u8; 64 * 1024 * 2 + 5];
    let (m, ct) = encrypt_in_memory(&plain, "old.bin", "application/octet-stream").unwrap();
    assert_eq!(m.chunk_size, 64 * 1024);
    let out = decrypt_in_memory(&m, &ct).unwrap();
    assert_eq!(out, plain);
}

#[test]
fn rejects_zero_chunk_size() {
    let (mut m, ct) = encrypt_in_memory(b"abc", "x.txt", "text/plain").unwrap();
    m.chunk_size = 0;
    assert!(decrypt_in_memory(&m, &ct).is_err());
}

#[test]
fn rejects_oversized_chunk_size() {
    let (mut m, ct) = encrypt_in_memory(b"abc", "x.txt", "text/plain").unwrap();
    m.chunk_size = 128 * 1024 * 1024; // 128 MiB > the 64 MiB limit
    assert!(decrypt_in_memory(&m, &ct).is_err());
}

#[test]
fn rejects_manifest_size_larger_than_ciphertext() {
    // `size` is peer-controlled (it arrives inside `InnerMessage::File`) and used to be handed
    // straight to `Vec::with_capacity`: `u64::MAX` panics, and a large representable value
    // aborts the process via `handle_alloc_error`. The ciphertext bounds the plaintext — one
    // 16-byte tag per chunk — so anything above that ceiling must be refused before allocating.
    let (mut m, ct) = encrypt_in_memory(b"abc", "x.txt", "text/plain").unwrap();

    m.size = u64::MAX;
    assert!(matches!(decrypt_in_memory(&m, &ct), Err(Error::Malformed(_))));

    // One byte over the ceiling is still refused (a single chunk → a single tag).
    m.size = (ct.len() - TAG_SIZE + 1) as u64;
    assert!(matches!(decrypt_in_memory(&m, &ct), Err(Error::Malformed(_))));

    // ...and the honest size still opens the file (the bound is not over-tight).
    m.size = 3;
    assert_eq!(decrypt_in_memory(&m, &ct).unwrap(), b"abc");
}

// ─── file-to-file streaming tests ─────────────────────────────────

fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    // unique per test invocation: pid + thread_id + name
    let pid = std::process::id();
    let tid = format!("{:?}", std::thread::current().id());
    let tid = tid.replace(|c: char| !c.is_ascii_alphanumeric(), "");
    p.push(format!("sezgi-filetest-{pid}-{tid}-{name}"));
    p
}

fn write_random_file(path: &Path, size: usize) {
    let mut f = std::fs::File::create(path).unwrap();
    // A counter, not real randomness: these tests check byte equality, not AEAD security.
    let mut buf = vec![0u8; 8192];
    let mut remaining = size;
    let mut counter: u64 = 0;
    while remaining > 0 {
        for chunk in buf.chunks_mut(8) {
            if chunk.len() == 8 {
                chunk.copy_from_slice(&counter.to_le_bytes());
                counter += 1;
            }
        }
        let n = remaining.min(buf.len());
        f.write_all(&buf[..n]).unwrap();
        remaining -= n;
    }
}

fn read_all(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn cleanup(paths: &[&Path]) {
    for p in paths {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(part_path_for(p));
    }
}

#[test]
fn roundtrip_file_to_file_3mb() {
    let plain_path = tmp_path("r3mb-plain");
    let ct_path = tmp_path("r3mb-ct");
    let out_path = tmp_path("r3mb-out");
    cleanup(&[&plain_path, &ct_path, &out_path]);

    write_random_file(&plain_path, 3 * 1024 * 1024 + 123);
    let m = encrypt_file_to_file(
        &plain_path, &ct_path, "test.bin", "application/octet-stream",
        None, None, 0, None, None,
    )
    .unwrap();
    assert_eq!(m.chunk_size, CHUNK_SIZE_STREAMING as u32);
    assert_eq!(m.size, 3 * 1024 * 1024 + 123);

    decrypt_file_to_file(&m, &ct_path, &out_path, None, None).unwrap();
    let plain = read_all(&plain_path);
    let out = read_all(&out_path);
    assert_eq!(out.len(), plain.len());
    assert_eq!(out, plain);

    cleanup(&[&plain_path, &ct_path, &out_path]);
}

#[test]
fn roundtrip_chunk_boundary_exact() {
    // Exactly chunk_size * 3 (either `encrypt_last` must be empty or the last chunk
    // must be completely full — in the STREAM construction the final tag is always
    // emitted either way)
    let plain_path = tmp_path("rcb-plain");
    let ct_path = tmp_path("rcb-ct");
    let out_path = tmp_path("rcb-out");
    cleanup(&[&plain_path, &ct_path, &out_path]);

    write_random_file(&plain_path, CHUNK_SIZE_STREAMING * 3);
    let m = encrypt_file_to_file(
        &plain_path, &ct_path, "x", "x", None, None, 0, None, None,
    )
    .unwrap();
    decrypt_file_to_file(&m, &ct_path, &out_path, None, None).unwrap();
    assert_eq!(read_all(&plain_path), read_all(&out_path));

    cleanup(&[&plain_path, &ct_path, &out_path]);
}

#[test]
fn decrypt_rejects_truncated_ciphertext() {
    let plain_path = tmp_path("trc-plain");
    let ct_path = tmp_path("trc-ct");
    let out_path = tmp_path("trc-out");
    cleanup(&[&plain_path, &ct_path, &out_path]);

    write_random_file(&plain_path, CHUNK_SIZE_STREAMING * 2 + 17);
    let m = encrypt_file_to_file(
        &plain_path, &ct_path, "x", "x", None, None, 0, None, None,
    )
    .unwrap();

    // Truncate the CT so the last chunk is missing (cut 1.5 chunks in half)
    let ct_bytes = read_all(&ct_path);
    std::fs::write(&ct_path, &ct_bytes[..(CHUNK_SIZE_STREAMING + TAG_SIZE)]).unwrap();

    let res = decrypt_file_to_file(&m, &ct_path, &out_path, None, None);
    assert!(res.is_err(), "truncated CT decrypt etmemeli");
    // The `.part` file must have been cleaned up
    assert!(!part_path_for(&out_path).exists());
    // The final output file must not have been created
    assert!(!out_path.exists());

    cleanup(&[&plain_path, &ct_path, &out_path]);
}

#[test]
fn cancel_mid_encrypt_keeps_part_for_resume() {
    let plain_path = tmp_path("can-plain");
    let ct_path = tmp_path("can-ct");
    cleanup(&[&plain_path, &ct_path]);

    write_random_file(&plain_path, CHUNK_SIZE_STREAMING * 4);
    let token = CancellationToken::new();
    token.cancel(); // cancel immediately

    let res = encrypt_file_to_file(
        &plain_path, &ct_path, "x", "x", None, Some(&token), 0, None, None,
    );
    match res {
        Err(Error::Cancelled) => {}
        other => panic!("expected Cancelled, got {other:?}"),
    }
    // The final output must not be created; the `.part` must remain for an outbound resume.
    assert!(!ct_path.exists(), "the final output must not be written");
    // The `.part` file may have been created with the first chunk written (cancel is
    // checked after the first chunk read). Whether it survives or not, this test only
    // guarantees the absence of the final output.

    cleanup(&[&plain_path, &ct_path]);
}

#[test]
fn resume_encrypt_with_fixed_key_nonce_matches_oneshot() {
    // With the same plaintext + the same fixed key+nonce:
    // (a) single-shot encrypt → ct_full
    // (b) encrypt to 50% + resume from 50% → ct_resumed
    // Expectation: ct_full == ct_resumed (byte-for-byte; the same BLAKE3 hash)
    let plain_path = tmp_path("res-plain");
    let ct_full = tmp_path("res-ct-full");
    let ct_resumed = tmp_path("res-ct-resumed");
    cleanup(&[&plain_path, &ct_full, &ct_resumed]);

    write_random_file(&plain_path, CHUNK_SIZE_STREAMING * 4 + 333);

    // Generate a random key+nonce, base64-encode them
    let mut key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; STREAM_NONCE_SIZE];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);
    let key_b64 = vodozemac::base64_encode(key);
    let nonce_b64 = vodozemac::base64_encode(nonce);

    // (a) single-shot
    let _m_full = encrypt_file_to_file(
        &plain_path, &ct_full, "x", "x",
        None, None, 0, Some(&key_b64), Some(&nonce_b64),
    )
    .unwrap();
    let bytes_full = read_all(&ct_full);

    // (b) The interrupted encrypt, simulated: take the first 2 chunks of the single-shot result
    // as the `.part` — the same fixed key and nonce make them what an interrupted run would have
    // left — then resume from there.
    let part = part_path_for(&ct_resumed);
    let two_chunks = 2 * (CHUNK_SIZE_STREAMING + TAG_SIZE);
    std::fs::write(&part, &bytes_full[..two_chunks]).unwrap();

    let _m_res = encrypt_file_to_file(
        &plain_path, &ct_resumed, "x", "x",
        None, None,
        (2 * CHUNK_SIZE_STREAMING) as u64,
        Some(&key_b64), Some(&nonce_b64),
    )
    .unwrap();
    let bytes_resumed = read_all(&ct_resumed);

    assert_eq!(
        bytes_full.len(),
        bytes_resumed.len(),
        "the resumed ciphertext has a different length"
    );
    assert_eq!(bytes_full, bytes_resumed, "not equal byte for byte");

    cleanup(&[&plain_path, &ct_full, &ct_resumed]);
}

#[test]
fn fixed_key_nonce_mismatched_pair_rejected() {
    let plain_path = tmp_path("mis-plain");
    let ct_path = tmp_path("mis-ct");
    cleanup(&[&plain_path, &ct_path]);

    write_random_file(&plain_path, 100);
    let key_b64 = vodozemac::base64_encode([0u8; KEY_SIZE]);

    let res = encrypt_file_to_file(
        &plain_path, &ct_path, "x", "x",
        None, None, 0, Some(&key_b64), None,
    );
    assert!(matches!(res, Err(Error::Malformed(_))));

    cleanup(&[&plain_path, &ct_path]);
}
