use super::*;

fn aad() -> Aad<'static> {
    Aad {
        schedule_id: "0f8fad5b-d9cb-469f-a165-70867728950e",
        sender: "alice",
        sender_device: "dev-a",
        conversation: "bob",
        room: false,
        release_at_ms: 1_800_000_000_000,
    }
}

const PAYLOAD: &[u8] = br#"{"v":1,"kind":"text","body":"good morning"}"#;

#[test]
fn a_sealed_payload_opens_with_its_key_and_aad() {
    let key = new_key();
    let sealed = seal(&key, &aad(), PAYLOAD);
    assert_eq!(open(&key, &aad(), &sealed).unwrap(), PAYLOAD);
}

/// T1: what the relay holds is ciphertext. Nothing of the text, and a length that says only the
/// bucket (the frame pads to 256 bytes).
#[test]
fn the_held_blob_is_ciphertext_only() {
    let key = new_key();
    let sealed = seal(&key, &aad(), PAYLOAD);
    let raw = vodozemac::base64_decode(&sealed).unwrap();
    assert!(!raw.windows(7).any(|w| w == b"morning"), "plaintext leaked into the held blob");
    assert!(!sealed.contains("morning"));
    assert_eq!(raw.len(), NONCE_LEN + crate::payload_frame::BUCKET + 16, "one bucket, a nonce and a tag");
    let longer = seal(&key, &aad(), br#"{"v":1,"kind":"text","body":"good morning, and a little more"}"#);
    assert_eq!(vodozemac::base64_decode(&longer).unwrap().len(), raw.len(), "the length says only the bucket");
}

/// T2: a key other than the sender's opens nothing — a ciphertext anyone else seals fails the tag.
#[test]
fn a_forged_blob_does_not_open() {
    let key = new_key();
    let forged = seal(&new_key(), &aad(), PAYLOAD);
    assert_eq!(open(&key, &aad(), &forged), Err(OpenError::Tag));
    let mut raw = vodozemac::base64_decode(seal(&key, &aad(), PAYLOAD)).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    assert_eq!(open(&key, &aad(), &vodozemac::base64_encode(raw)), Err(OpenError::Tag));
    assert_eq!(open(&key, &aad(), "not base64 at all!"), Err(OpenError::Malformed));
    assert_eq!(open(&key, &aad(), "AAAA"), Err(OpenError::Malformed));
}

/// T3: every field of the associated data is bound — a relay that moves the message to another
/// chat, another time, another sender or device, or a room of the same name, fails the tag.
#[test]
fn the_aad_binds_every_field() {
    let key = new_key();
    let sealed = seal(&key, &aad(), PAYLOAD);
    let moved = [
        Aad { schedule_id: "1f8fad5b-d9cb-469f-a165-70867728950e", ..aad() },
        Aad { sender: "mallory", ..aad() },
        Aad { sender_device: "dev-m", ..aad() },
        Aad { conversation: "carol", ..aad() },
        Aad { room: true, ..aad() },
        Aad { release_at_ms: 1_800_000_000_001, ..aad() },
    ];
    for other in moved {
        assert_eq!(open(&key, &other, &sealed), Err(OpenError::Tag), "{other:?} opened");
    }
}

/// The length prefixes keep two different tuples from encoding the same bytes.
#[test]
fn the_aad_encoding_is_unambiguous() {
    let a = Aad { sender: "ab", sender_device: "c", ..aad() }.bytes();
    let b = Aad { sender: "a", sender_device: "bc", ..aad() }.bytes();
    assert_ne!(a, b);
}

#[test]
fn schedule_ids_are_uuids_and_keys_round_trip() {
    for _ in 0..50 {
        let id = new_schedule_id();
        assert!(valid_schedule_id(&id), "{id}");
    }
    assert_ne!(new_schedule_id(), new_schedule_id());
    assert!(!valid_schedule_id("0F8FAD5B-D9CB-469F-A165-70867728950E"));
    assert!(!valid_schedule_id("../../etc/passwd"));
    assert!(!valid_schedule_id(""));
    let key = new_key();
    assert_eq!(key_from_b64(&key_to_b64(&key)), Some(key));
    assert_eq!(key_from_b64("AAAA"), None);
    assert_ne!(new_key(), new_key());
}

#[test]
fn the_release_windows() {
    let now = 1_800_000_000_000;
    assert!(!valid_release(now, now), "now is a send, not a schedule");
    assert!(valid_release(now + MIN_AHEAD_MS, now));
    assert!(valid_release(now + MAX_AHEAD_MS, now));
    assert!(!valid_release(now + MAX_AHEAD_MS + 1, now));
    assert!(believable_release(now - KEY_GRACE_MS + 1, now));
    assert!(!believable_release(now - KEY_GRACE_MS, now));
    assert!(!believable_release(now + MAX_AHEAD_MS + EARLY_SKEW_MS + 1, now));
    assert!(is_early(now + EARLY_SKEW_MS + 1, now));
    assert!(!is_early(now + EARLY_SKEW_MS, now), "inside the skew is on time");
    assert!(!is_early(now - 1, now));
}

/// Review finding 1: K is shared, so the AEAD alone lets any holder seal a forgery under the
/// sender's AAD. The digest of the one ciphertext the sender sealed — told pairwise over Olm — is
/// what tells it apart.
#[test]
fn the_digest_tells_the_senders_one_ciphertext_from_a_forgery_under_k() {
    let key = new_key();
    let genuine = seal(&key, &aad(), PAYLOAD);
    let digest = sealed_digest(&genuine).unwrap();
    assert!(valid_digest(&digest));
    assert!(!valid_digest("not-a-digest"));
    let forged = seal(&key, &aad(), br#"{"v":1,"kind":"text","body":"pay mallory"}"#);
    assert!(open(&key, &aad(), &forged).is_ok(), "the AEAD alone cannot tell");
    assert_ne!(sealed_digest(&forged).unwrap(), digest);
    assert_eq!(sealed_digest("not base64!"), None);
}

