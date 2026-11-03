//! Unit tests for `payload_frame.rs`, included via `#[path]`, so `super` is that module.

use super::*;

fn json_of(len: usize) -> Vec<u8> {
    let body: String = "hello sezi ".repeat(len / 11 + 1)[..len].to_string();
    format!(r#"{{"kind":"text","body":"{body}"}}"#).into_bytes()
}

#[test]
fn a_plain_payload_is_read_as_it_always_was() {
    let plain = json_of(40);
    assert!(!is_framed(&plain));
    assert_eq!(open(&plain).unwrap().as_ref(), plain.as_slice());
}

#[test]
fn every_framed_payload_fills_whole_buckets_and_opens_to_what_went_in() {
    for len in [0usize, 1, 249, 250, 251, 1_000, 1_023, 1_024, 4_000, 20_000] {
        let plain = json_of(len);
        let framed = seal(&plain);
        assert!(is_framed(&framed));
        assert_eq!(framed.len() % BUCKET, 0, "len {len}");
        assert_eq!(open(&framed).unwrap().as_ref(), plain.as_slice(), "len {len}");
    }
}

#[test]
fn small_payloads_of_different_lengths_look_the_same() {
    let a = seal(&json_of(10));
    let b = seal(&json_of(200));
    assert_eq!(a.len(), b.len(), "both fill one bucket");
    assert_eq!(a.len(), BUCKET);
}

#[test]
fn only_a_large_payload_that_shrinks_by_a_tenth_is_deflated() {
    let repetitive = json_of(4_000);
    let framed = seal(&repetitive);
    assert_eq!(framed[1] & 1, 1, "deflated");
    assert!(framed.len() < repetitive.len());
    // Just under the threshold: never deflated, whatever it would save.
    assert_eq!(seal(&json_of(COMPRESS_MIN - 40))[1] & 1, 0);
    // Large but incompressible (already random): kept as it is.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let noise: Vec<u8> = (0..4_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let framed = seal(&noise);
    assert_eq!(framed[1] & 1, 0, "not worth it");
    assert_eq!(open(&framed).unwrap().as_ref(), noise.as_slice());
}

#[test]
fn a_damaged_frame_or_a_bomb_does_not_open() {
    let framed = seal(&json_of(4_000));
    assert_eq!(open(&framed[..4]), Err(FrameError::Truncated));
    let mut long = framed.clone();
    long[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(open(&long), Err(FrameError::Truncated));
    let mut flags = framed;
    flags[1] = 0b10;
    assert_eq!(open(&flags), Err(FrameError::UnknownFlags(0b10)));
    // A body that inflates past the cap: refused, not allocated.
    let bomb = vec![b'a'; MAX_INFLATED + 1];
    let framed = seal(&bomb);
    assert_eq!(framed[1] & 1, 1);
    assert_eq!(open(&framed), Err(FrameError::Inflate));
}
