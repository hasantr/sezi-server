//! A 1:1 message's `ext` crossing Olm whole — the twin of `megolm.rs`'s
//! `ext_reaches_the_room_with_and_without_forwarded`.
//!
//! B07: an attachment's caption, album slot and voice data stopped at the sender's own row, because
//! `encrypt_inner_to_peer_uid` built a fresh payload whose `ext` could only ever receive the
//! forwarded flag. The two lanes build their payloads separately, so one passing says nothing about
//! the other.

use crate::messaging::*;
use sezi_protocol::inner::{ChatPayload, InnerMessage, VoiceNoteMeta};
use vodozemac::olm::Account;

/// One end: a pickled account, plus what a peer needs to open a session onto it.
struct Party {
    blob: String,
    key: [u8; 32],
    x_pub: String,
    otk: String,
}

fn party(seed: u8) -> Party {
    let mut account = Account::new();
    account.generate_one_time_keys(1);
    let x_pub = account.identity_keys().curve25519.to_base64();
    let otk = account
        .one_time_keys()
        .into_values()
        .next()
        .expect("one one-time key")
        .to_base64();
    account.mark_keys_as_published();
    let key = [seed; 32];
    Party { blob: account.pickle().encrypt(&key), key, x_pub, otk }
}

/// `from` opens a session onto `to` and sends `inner` with `ext`; `to` decrypts it.
fn round_trip(from: &Party, to: &Party, inner: InnerMessage, ext: serde_json::Value) -> ChatPayload {
    let sent = encrypt_inner_to_peer_uid(
        from.blob.clone(),
        from.key.to_vec(),
        to.x_pub.clone(),
        Some(to.otk.clone()),
        None,
        inner,
        None,
        None,
        Some("out-1".into()),
        ext,
    )
    .expect("encrypt");
    decrypt_payload_from_peer_sessions(&to.blob, &to.key, &[], sent.envelope_b64, None)
        .expect("decrypt")
        .payload
}

fn photo() -> InnerMessage {
    InnerMessage::Text { body: "a photo".into() }
}

fn media(payload: ChatPayload) -> ChatPayload {
    payload.with_media_meta(Some("the class"), Some("album-1"), Some(0), Some(2))
}

#[test]
fn ext_reaches_the_peer_with_and_without_forwarded() {
    let (a, b) = (party(1), party(2));
    let ext = media(ChatPayload::new(None, None, photo()))
        .with_voice(&VoiceNoteMeta { duration_ms: 4_300, waveform: vec![0, 40, 255] })
        .ext;
    let got = round_trip(&a, &b, photo(), ext.clone());
    assert_eq!(got.ext, ext, "the whole `ext`, not a whitelist of it");
    assert_eq!(got.caption().as_deref(), Some("the class"));
    assert_eq!(got.album_index(), Some(0));
    assert_eq!(got.voice().map(|v| v.waveform), Some(vec![0, 40, 255]));
    assert!(!got.is_forwarded(), "metadata alone is not a forward");
    assert_eq!(got.msg_uid.as_deref(), Some("out-1"), "and the correlation id still travels");

    let (c, d) = (party(3), party(4));
    let forwarded = media(ChatPayload::new(None, None, photo())).with_forwarded().ext;
    let got = round_trip(&c, &d, photo(), forwarded);
    assert!(got.is_forwarded());
    assert_eq!(
        got.caption().as_deref(),
        Some("the class"),
        "the flag sits beside the caption; it does not replace it"
    );
}

/// No metadata stays no metadata: `Null` is left off the wire, so an ordinary message's payload is
/// byte-for-byte what it was before `ext` travelled.
#[test]
fn an_empty_ext_stays_off_the_wire() {
    let (a, b) = (party(5), party(6));
    let got = round_trip(&a, &b, photo(), serde_json::Value::Null);
    assert!(got.ext.is_null());
    assert!(!String::from_utf8(got.encode()).unwrap().contains("\"ext\""));
}
