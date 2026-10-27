//! Tests for `part.rs`, included through `#[path]`.

use super::*;
use crate::{decrypt_in_memory, FileManifest};

const C: usize = PART_CHUNK_SIZE;

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + 7) as u8).collect()
}

#[test]
fn every_boundary_length_roundtrips() {
    let key = ItemKey::generate();
    for len in [0, 1, C - 1, C, C + 1, 2 * C, 3 * C + 17] {
        let plain = sample(len);
        let ct = encrypt_part(&key, 4, &plain).unwrap();
        assert_eq!(ct.len() as u64, part_ciphertext_len(len as u64), "len {len}");
        assert_eq!(decrypt_part(&key, 4, &ct, len as u64).unwrap(), plain, "len {len}");
    }
}

/// The property the derivation exists for: part i's bytes are not part j's, so a relay that swaps
/// two objects produces an authentication failure, never audio from the wrong minute.
#[test]
fn part_i_cannot_be_opened_as_part_j() {
    let key = ItemKey::generate();
    let plain = sample(C + 100);
    let ct = encrypt_part(&key, 0, &plain).unwrap();
    for j in [1u32, 2, u32::MAX] {
        assert!(decrypt_part(&key, j, &ct, plain.len() as u64).is_err(), "opened as part {j}");
    }
    assert_eq!(decrypt_part(&key, 0, &ct, plain.len() as u64).unwrap(), plain);
}

#[test]
fn identical_plaintext_seals_differently_per_part() {
    let key = ItemKey::generate();
    let plain = sample(100);
    assert_ne!(encrypt_part(&key, 0, &plain).unwrap(), encrypt_part(&key, 1, &plain).unwrap());
}

#[test]
fn another_items_key_cannot_open_a_part() {
    let plain = sample(500);
    let ct = encrypt_part(&ItemKey::generate(), 0, &plain).unwrap();
    assert!(decrypt_part(&ItemKey::generate(), 0, &ct, 500).is_err());
}

#[test]
fn tampering_is_detected() {
    let key = ItemKey::generate();
    let plain = sample(2 * C + 5);
    let mut ct = encrypt_part(&key, 0, &plain).unwrap();
    let mid = ct.len() / 2;
    ct[mid] ^= 0x01;
    assert!(decrypt_part(&key, 0, &ct, plain.len() as u64).is_err());
}

/// Two whole chunks swapped inside a part: each still carries a valid tag for SOME position, and
/// the position-bound nonce is what refuses them.
#[test]
fn reordered_chunks_are_refused() {
    let key = ItemKey::generate();
    let plain = sample(3 * C);
    let ct = encrypt_part(&key, 0, &plain).unwrap();
    let w = C + 16;
    let mut swapped = ct.clone();
    swapped[..w].copy_from_slice(&ct[w..2 * w]);
    swapped[w..2 * w].copy_from_slice(&ct[..w]);
    assert!(decrypt_part(&key, 0, &swapped, plain.len() as u64).is_err());
}

/// A body cut off exactly at a chunk boundary decrypts chunk by chunk — every chunk it has is
/// genuine — and is caught at `finish`, which is why the streaming caller must call it.
#[test]
fn truncation_at_a_chunk_boundary_is_caught_by_finish() {
    let key = ItemKey::generate();
    let plain = sample(2 * C + 9);
    let ct = encrypt_part(&key, 0, &plain).unwrap();
    let cut = &ct[..C + 16];
    let mut dec = PartDecryptor::new(&key, 0, plain.len() as u64).unwrap();
    let mut out = Vec::new();
    dec.push(cut, &mut out).unwrap();
    assert_eq!(out, &plain[..C], "the chunks that did arrive are served");
    assert!(dec.finish().is_err(), "a part that stopped early must not finish");
    assert!(decrypt_part(&key, 0, cut, plain.len() as u64).is_err());
}

/// A non-final chunk presented as the last one: the flag in the nonce refuses it, which is what
/// stops a relay from passing off the first half of a part as all of it.
#[test]
fn a_truncated_part_cannot_pass_as_a_shorter_one() {
    let key = ItemKey::generate();
    let plain = sample(2 * C);
    let ct = encrypt_part(&key, 0, &plain).unwrap();
    assert!(decrypt_part(&key, 0, &ct[..C + 16], C as u64).is_err());
}

#[test]
fn trailing_bytes_are_refused() {
    let key = ItemKey::generate();
    let plain = sample(10);
    let mut ct = encrypt_part(&key, 0, &plain).unwrap();
    ct.push(0);
    assert!(decrypt_part(&key, 0, &ct, 10).is_err());
    let mut dec = PartDecryptor::new(&key, 0, 10).unwrap();
    assert!(dec.push(&ct, &mut Vec::new()).is_err());
}

/// The network delivers in arbitrary pieces; the plaintext must not depend on where they fall.
#[test]
fn streaming_in_odd_pieces_matches_the_whole() {
    let key = ItemKey::generate();
    let plain = sample(3 * C + 333);
    let ct = encrypt_part(&key, 9, &plain).unwrap();
    for piece in [1usize, 7, 16, C - 3, C + 16, C + 17, 5 * C] {
        let mut dec = PartDecryptor::new(&key, 9, plain.len() as u64).unwrap();
        let mut out = Vec::new();
        for p in ct.chunks(piece) {
            dec.push(p, &mut out).unwrap();
        }
        dec.finish().unwrap();
        assert_eq!(out, plain, "piece size {piece}");
    }
}

/// A resumed download starts mid-part: the relay is asked for `bytes=offset-` and the counter
/// starts at that chunk. What comes out is the plaintext from that chunk on.
#[test]
fn decryption_resumes_at_a_chunk_boundary() {
    let key = ItemKey::generate();
    let plain = sample(4 * C + 1);
    let ct = encrypt_part(&key, 2, &plain).unwrap();
    for start in 0..5u64 {
        let off = chunk_ciphertext_offset(start) as usize;
        let mut dec = PartDecryptor::resume_at(&key, 2, plain.len() as u64, start).unwrap();
        assert_eq!(dec.next_chunk(), start);
        let mut out = Vec::new();
        dec.push(&ct[off..], &mut out).unwrap();
        dec.finish().unwrap();
        assert_eq!(out, &plain[start as usize * C..], "resume at chunk {start}");
    }
    assert!(PartDecryptor::resume_at(&key, 2, plain.len() as u64, 5).is_err());
}

/// The framing is standard STREAM-BE32: this crate's ordinary decryptor, handed the derived key and
/// nonce prefix, opens a library part. If the hand-built nonce ever drifted from the `aead` crate's
/// layout this is the test that says so.
#[test]
fn a_part_is_plain_stream_be32_under_its_derived_key() {
    let key = ItemKey::generate();
    for len in [0usize, 5, C, 2 * C + 3] {
        let plain = sample(len);
        let ct = encrypt_part(&key, 7, &plain).unwrap();
        let (key_b64, nonce_b64) = part_secret_b64(&key, 7);
        let manifest = FileManifest {
            v: 1,
            media_id: String::new(),
            key_b64,
            nonce_b64,
            chunk_size: C as u32,
            size: len as u64,
            content_type: "application/octet-stream".into(),
            filename: "part".into(),
        };
        assert_eq!(decrypt_in_memory(&manifest, &ct).unwrap(), plain, "len {len}");
    }
}

#[test]
fn the_key_travels_as_unpadded_base64_and_nothing_else_parses() {
    let key = ItemKey::generate();
    let b64 = key.to_b64();
    assert!(!b64.contains('='));
    assert_eq!(ItemKey::from_b64(&b64).unwrap(), key);
    assert!(ItemKey::from_b64("").is_err());
    assert!(ItemKey::from_b64("not base64!").is_err());
    assert!(ItemKey::from_b64(&vodozemac::base64_encode([1u8; 31])).is_err());
    assert!(!format!("{key:?}").contains(&b64), "Debug must not print the key");
}

#[test]
fn part_arithmetic() {
    let ps = 4 * 1024 * 1024u64;
    assert_eq!(part_count(0, ps), 1);
    assert_eq!(part_count(1, ps), 1);
    assert_eq!(part_count(ps, ps), 1);
    assert_eq!(part_count(ps + 1, ps), 2);
    assert_eq!(part_count(10, 0), 0);
    assert_eq!(part_plain_len(ps + 1, ps, 0), Some(ps));
    assert_eq!(part_plain_len(ps + 1, ps, 1), Some(1));
    assert_eq!(part_plain_len(ps + 1, ps, 2), None);
    assert_eq!(part_plain_len(0, ps, 0), Some(0));
    assert_eq!(part_ciphertext_len(0), 16);
    assert_eq!(part_ciphertext_len(C as u64), C as u64 + 16);
    assert_eq!(part_ciphertext_len(C as u64 + 1), C as u64 + 1 + 32);
    // The largest part the record may declare still fits the relay's 33 MiB object ceiling.
    assert!(part_ciphertext_len(MAX_PART_SIZE) <= 33 * 1024 * 1024);
}
