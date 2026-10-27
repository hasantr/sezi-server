//! What reaches a bot program, and what is dropped.

use sezi_protocol::inner::{ChatPayload, FileManifest, InnerMessage};

use super::{classify, MAX_FILES_PER_MESSAGE, PAIR_ACK_MARKER};
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

fn manifest(media_id: &str) -> FileManifest {
    FileManifest {
        v: 1,
        media_id: media_id.into(),
        key_b64: "k".into(),
        nonce_b64: "n".into(),
        chunk_size: 65_536,
        size: 1_234,
        content_type: "application/pdf".into(),
        filename: "zabit.pdf".into(),
    }
}

/// H3: before, a file was `Ignored("unsupported")` — acked, so the member saw "delivered", and
/// dropped, so nothing happened. Now it reaches the host whole: the manifest that opens it, the
/// caption, and the member's `msg_uid`.
#[test]
fn a_file_is_classified_with_its_manifest_and_caption() {
    let mut p = of(InnerMessage::File(manifest("media-1"))).with_media_meta(Some("the minutes"), None, None, None);
    p.msg_uid = Some("loc-f".into());
    match classify(&p, "u", "d", false) {
        Inbound::File { from, device, msg_uid, manifests, caption, .. } => {
            assert_eq!((from.as_str(), device.as_str()), ("u", "d"));
            assert_eq!(msg_uid.as_deref(), Some("loc-f"));
            assert_eq!(manifests, vec![manifest("media-1")], "the key travels to the host");
            assert_eq!(caption.as_deref(), Some("the minutes"));
        }
        other => panic!("a file was not classified as one: {other:?}"),
    }
}

#[test]
fn an_album_is_one_file_update_of_bounded_size() {
    let many: Vec<FileManifest> = (0..MAX_FILES_PER_MESSAGE + 3).map(|i| manifest(&format!("m{i}"))).collect();
    match classify(&of(InnerMessage::FileGroup { manifests: many }), "u", "d", false) {
        Inbound::File { manifests, caption, .. } => {
            assert_eq!(manifests.len(), MAX_FILES_PER_MESSAGE);
            assert_eq!(manifests[0].media_id, "m0");
            assert_eq!(caption, None);
        }
        other => panic!("{other:?}"),
    }
    // Nothing the host could fetch: an empty group, or a manifest naming no relay blob.
    let empty = of(InnerMessage::FileGroup { manifests: vec![] });
    assert_eq!(classify(&empty, "u", "d", false), Inbound::Ignored("empty_file"));
    let no_blob = of(InnerMessage::File(manifest("")));
    assert_eq!(classify(&no_blob, "u", "d", false), Inbound::Ignored("empty_file"));
}
