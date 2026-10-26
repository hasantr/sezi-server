//! What reaches a bot program, and what is dropped.

use sezi_protocol::inner::{ChatPayload, InnerMessage};

use super::{classify, PAIR_ACK_MARKER};
use crate::Inbound;

fn of(inner: InnerMessage) -> ChatPayload {
    ChatPayload::new(None, None, inner)
}

#[test]
fn only_a_prekey_pair_ack_is_a_pair_ack() {
    let p = of(InnerMessage::Text { body: PAIR_ACK_MARKER.into() });
    assert_eq!(classify(&p, "u", "d", true), Inbound::PairAck { from: "u".into() });
    assert_eq!(classify(&p, "u", "d", false), Inbound::Ignored("pair_ack"));
}

#[test]
fn system_markers_are_not_text() {
    for body in ["__sezgi/sys/p2p-caps/v1:{}", "__sezgi/sys/delete-msg/v1:x", "__sezgi/sys/self-pair-ack/v1"] {
        let p = of(InnerMessage::Text { body: body.into() });
        assert_eq!(classify(&p, "u", "d", false), Inbound::Ignored("system_marker"), "{body}");
    }
}

#[test]
fn rich_text_reaches_the_program_as_its_words() {
    let mut p = of(InnerMessage::RichText { delta_json: "[]".into(), plain_text: "bold words".into() });
    p.msg_uid = Some("loc-9".into());
    match classify(&p, "u", "d", false) {
        Inbound::Text { body, msg_uid, .. } => {
            assert_eq!(body, "bold words");
            assert_eq!(msg_uid.as_deref(), Some("loc-9"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_room_key_request_names_its_room() {
    let p = of(InnerMessage::RoomKeyRequest { room_id: "r1".into(), session_id: None });
    assert_eq!(classify(&p, "u", "d", false), Inbound::RoomKeyRequest { from: "u".into(), room_id: "r1".into(), session_id: None });
}

#[test]
fn kernel_chatter_and_local_only_kinds_are_dropped() {
    let typing: InnerMessage =
        serde_json::from_value(serde_json::json!({ "kind": "typing", "ts": 1 })).expect("typing");
    assert_eq!(classify(&of(typing), "u", "d", false), Inbound::Ignored("typing"));
    assert_eq!(classify(&of(InnerMessage::Unknown), "u", "d", false), Inbound::Ignored("unknown"));
    let html = of(InnerMessage::HtmlMessage { html: "<b>x</b>".into() });
    assert_eq!(classify(&html, "u", "d", false), Inbound::Ignored("unsupported"));
}
