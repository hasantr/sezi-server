//! A framed payload (`sezi_protocol::payload_frame`) crossing Olm and Megolm: what the receiver
//! reads is what was sent, a plain payload still reads, and a framed ciphertext's length says only
//! its bucket.

use crate::megolm::{create_group_session, decrypt_from_room, encrypt_to_room_framed, import_inbound_group_session};
use crate::messaging::*;
use sezi_protocol::inner::InnerMessage;
use vodozemac::olm::Account;

const KEY: [u8; 32] = [3u8; 32];

fn text(body: &str) -> InnerMessage {
    InnerMessage::Text { body: body.into() }
}

/// (sender blob, receiver blob, receiver x, one otk)
fn pair() -> (String, String, String, String) {
    let sender = Account::new();
    let mut receiver = Account::new();
    receiver.generate_one_time_keys(1);
    let otk = receiver.one_time_keys().into_values().next().unwrap().to_base64();
    receiver.mark_keys_as_published();
    let x = receiver.identity_keys().curve25519.to_base64();
    (sender.pickle().encrypt(&KEY), receiver.pickle().encrypt(&KEY), x, otk)
}

fn send(from: &str, x: &str, otk: Option<&str>, session: Option<&str>, body: &str, frame: bool) -> EncryptedMessage {
    encrypt_inner_to_peer_framed(
        from.to_string(),
        KEY.to_vec(),
        x.to_string(),
        otk.map(str::to_string),
        session.map(str::to_string),
        text(body),
        None,
        None,
        Some("uid-1".into()),
        serde_json::Value::Null,
        frame,
    )
    .unwrap()
}

#[test]
fn a_framed_olm_payload_reads_and_its_length_says_only_the_bucket() {
    let (alice, bob, bob_x, otk) = pair();
    let first = send(&alice, &bob_x, Some(&otk), None, "hi", true);
    let got = decrypt_payload_from_peer_sessions(&bob, &KEY, &[], first.envelope_b64.clone(), None).unwrap();
    assert!(matches!(got.payload.inner, InnerMessage::Text { ref body } if body == "hi"));
    assert_eq!(got.payload.msg_uid.as_deref(), Some("uid-1"));
    let bob_session = got.new_session_blob;
    let mut alice_session = first.new_session_blob;

    // Two normal frames of very different (small) lengths: the same envelope size.
    let short = send(&alice, &bob_x, None, Some(&alice_session), "ok", true);
    alice_session = short.new_session_blob.clone();
    let long = send(&alice, &bob_x, None, Some(&alice_session), &"x".repeat(180), true);
    assert_eq!(short.envelope_b64.len(), long.envelope_b64.len());
    let read = decrypt_payload_from_peer_sessions(&bob, &KEY, std::slice::from_ref(&bob_session), short.envelope_b64, None).unwrap();
    let read = decrypt_payload_from_peer_sessions(&bob, &KEY, &[read.new_session_blob], long.envelope_b64, None).unwrap();
    assert!(matches!(read.payload.inner, InnerMessage::Text { ref body } if body.len() == 180));

    // A plain frame on the same session still reads (an older sender, or `frame = false`).
    let plain = send(&alice, &bob_x, None, Some(&long.new_session_blob), "plain", false);
    let read = decrypt_payload_from_peer_sessions(&bob, &KEY, &[read.new_session_blob], plain.envelope_b64, None).unwrap();
    assert!(matches!(read.payload.inner, InnerMessage::Text { ref body } if body == "plain"));
}

#[test]
fn a_large_framed_payload_is_smaller_on_the_wire() {
    let (alice, bob, bob_x, otk) = pair();
    let body = "the same words again and again ".repeat(200);
    let framed = send(&alice, &bob_x, Some(&otk), None, &body, true);
    let (alice2, _, bob2_x, otk2) = pair();
    let plain = send(&alice2, &bob2_x, Some(&otk2), None, &body, false);
    assert!(framed.envelope_b64.len() * 2 < plain.envelope_b64.len(), "deflated");
    let got = decrypt_payload_from_peer_sessions(&bob, &KEY, &[], framed.envelope_b64, None).unwrap();
    assert!(matches!(got.payload.inner, InnerMessage::Text { body: ref b } if *b == body));
}

#[test]
fn a_framed_room_payload_reads() {
    let k = KEY.to_vec();
    let created = create_group_session(k.clone()).unwrap();
    let inbound = import_inbound_group_session(created.session_key_b64, k.clone()).unwrap();
    let enc = encrypt_to_room_framed(
        created.session_pickle,
        k.clone(),
        text("hello room"),
        None,
        None,
        Some("g-1".into()),
        serde_json::Value::Null,
        true,
    )
    .unwrap();
    let dec = decrypt_from_room(inbound.inbound_pickle, k, enc.envelope_b64).unwrap();
    assert!(matches!(dec.payload.inner, InnerMessage::Text { ref body } if body == "hello room"));
    assert_eq!(dec.payload.msg_uid.as_deref(), Some("g-1"));
}
