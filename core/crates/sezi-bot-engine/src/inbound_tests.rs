//! Reading a member's frames: the ack, the pair-ack answer, the identity check, and the account
//! left alone on the hot path.

use sezi_protocol::inner::{ChatPayload, InnerMessage};
use vodozemac::olm::OlmMessage;

use crate::testutil::{bot, delivered, pair, Member, KEY};
use crate::{on_envelope, BotStore, Effect, Inbound, PAIR_ACK_MARKER};

fn text(body: &str, uid: &str) -> ChatPayload {
    let mut p = ChatPayload::new(None, None, InnerMessage::Text { body: body.into() });
    p.msg_uid = Some(uid.into());
    p.ext = serde_json::json!({ "forwarded": true });
    p
}

#[test]
fn a_prekey_pair_ack_opens_a_session_and_is_answered_once_on_it() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    m.open_to(&mut b);
    let env = m.send(&crate::direct::pair_ack_payload());
    let x = m.x_pub();
    let effects = on_envelope(&mut b.store, &KEY, &b.id, &env, Some(&x), 10);

    assert_eq!(effects[0], Effect::Ack { remote_id: env.remote_id, success: true, uid: None });
    assert_eq!(effects.last(), Some(&Effect::Update(Inbound::PairAck { from: "user-m".into() })));
    match &effects[1] {
        Effect::Deliver { user_id, device_id, msg_uid, .. } => {
            assert_eq!((user_id.as_str(), device_id.as_str()), ("user-m", m.device.as_str()));
            assert_eq!(msg_uid, &None);
        }
        other => panic!("expected the answer, got {other:?}"),
    }
    assert_eq!(effects.len(), 3, "{effects:?}");

    let answer = delivered(&effects);
    let (payload, was_prekey) = m.receive(&answer[0]);
    assert!(!was_prekey, "the answer rides the session the member opened, never a new one");
    assert!(matches!(payload.inner, InnerMessage::Text { ref body } if body == PAIR_ACK_MARKER));
    assert!(b.store.current_session("user-m", &m.device).is_some());
}

#[test]
fn a_text_is_acked_with_its_msg_uid_and_handed_over_whole() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 10);
    let env = m.send(&text("hello bot", "loc-1"));
    let effects = on_envelope(&mut b.store, &KEY, &b.id, &env, Some(&m.x_pub()), 20);
    assert_eq!(
        effects,
        vec![
            Effect::Ack { remote_id: env.remote_id, success: true, uid: Some("loc-1".into()) },
            Effect::Update(Inbound::Text {
                from: "user-m".into(),
                device: m.device.clone(),
                msg_uid: Some("loc-1".into()),
                body: "hello bot".into(),
                ext: serde_json::json!({ "forwarded": true }),
            }),
        ]
    );
}

#[test]
fn a_frame_a_session_reads_never_unpickles_the_account() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 10);
    // An account nobody can unpickle: any path that reached for it would fail the frame.
    b.store.account = Some("not a pickle".into());
    let env = m.send(&text("still readable", "loc-2"));
    let effects = on_envelope(&mut b.store, &KEY, &b.id, &env, None, 20);
    assert!(matches!(effects[0], Effect::Ack { success: true, .. }), "{effects:?}");
}

#[test]
fn a_prekey_from_another_identity_opens_nothing() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    let impostor = Member::new("user-x");
    m.open_to(&mut b);
    let env = m.send(&text("hi", "loc-1"));
    let account_before = b.store.account.clone();
    for expected in [Some(impostor.x_pub()), None] {
        let effects = on_envelope(&mut b.store, &KEY, &b.id, &env, expected.as_deref(), 10);
        assert_eq!(effects, vec![Effect::Ack { remote_id: env.remote_id, success: false, uid: None }]);
    }
    assert!(b.store.sessions("user-m", &m.device).is_empty(), "no session from a mismatched key");
    assert_eq!(b.store.account, account_before, "no one-time key consumed");
}

#[test]
fn an_unknown_kind_is_acked_and_dropped() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 10);
    let env = m.send_raw(br#"{"schema_version":1,"kind":"something_from_the_future","x":1}"#);
    let effects = on_envelope(&mut b.store, &KEY, &b.id, &env, None, 20);
    assert_eq!(
        effects,
        vec![
            Effect::Ack { remote_id: env.remote_id, success: true, uid: None },
            Effect::Update(Inbound::Ignored("unknown")),
        ]
    );
}

#[test]
fn a_room_envelope_is_acked_and_dropped() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 10);
    let mut env = m.send(&text("to the room", "g-1"));
    env.group_id = Some("room-1".into());
    let effects = on_envelope(&mut b.store, &KEY, &b.id, &env, None, 20);
    assert_eq!(effects[0], Effect::Ack { remote_id: env.remote_id, success: true, uid: None });
    assert_eq!(effects[1], Effect::Update(Inbound::Ignored("room_envelope")));
}

/// INV-11: a frame that fails retires the session to the archive; a frame already in flight on it
/// is still read there, and the session it was read on becomes current again.
#[test]
fn a_retired_session_still_reads_what_was_in_flight() {
    let mut b = bot("user-z"); // higher than the member: no re-pair of its own
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 10);
    let in_flight = m.send(&text("sent before the failure", "loc-1"));

    let mut garbled = m.send(&text("lost", "loc-2"));
    garbled.envelope_b64 = "%%%".into();
    let effects = on_envelope(&mut b.store, &KEY, &b.id, &garbled, None, 20);
    assert_eq!(effects, vec![Effect::Ack { remote_id: garbled.remote_id, success: false, uid: None }]);
    assert!(b.store.current_session("user-m", &m.device).is_none(), "retired");
    assert_eq!(b.store.sessions("user-m", &m.device).len(), 1, "kept in the archive");

    let effects = on_envelope(&mut b.store, &KEY, &b.id, &in_flight, None, 30);
    assert!(matches!(effects[0], Effect::Ack { success: true, .. }), "{effects:?}");
    assert!(b.store.current_session("user-m", &m.device).is_some(), "promoted back");
}

/// The member's messages are PreKey until it hears from the bot; every one of them is read by the
/// session the first one opened, so the account is not touched again.
#[test]
fn prekey_frames_on_one_session_open_it_once() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    m.open_to(&mut b);
    let first = m.send(&text("one", "loc-1"));
    let second = m.send(&text("two", "loc-2"));
    let x = m.x_pub();
    on_envelope(&mut b.store, &KEY, &b.id, &first, Some(&x), 10);
    let account_after_first = b.store.account.clone();
    let bytes = vodozemac::base64_decode(&second.envelope_b64).unwrap();
    let wire: sezi_protocol::envelope::WireEnvelope = serde_json::from_slice(&bytes).unwrap();
    assert!(matches!(wire.to_olm().unwrap(), OlmMessage::PreKey(_)));
    let effects = on_envelope(&mut b.store, &KEY, &b.id, &second, Some(&x), 20);
    assert!(matches!(effects[0], Effect::Ack { success: true, .. }), "{effects:?}");
    assert_eq!(b.store.account, account_after_first, "the second frame needed no account");
    assert_eq!(b.store.sessions("user-m", &m.device).len(), 1);
}
