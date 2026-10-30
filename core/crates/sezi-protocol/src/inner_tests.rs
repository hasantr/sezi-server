//! inner.rs wire tests — media meta, broad roundtrip, byte-golden. Wired with `#[path]` so the
//! module stays under `crate::inner` and `use super::*` reaches the types under test.
use super::*;


/// The forwarded flag survives the wire, and its ABSENCE reads as "ordinary".
///
/// That second half is the load-bearing one: every message ever sent before this field existed,
/// and every message from a client that does not know it, decodes with no `ext.forwarded` at all.
/// If absence were anything but false, the app would start telling people that ordinary messages
/// had been forwarded — a claim about what someone did, made up out of a missing field.
#[test]
fn forwarded_survives_the_wire_and_absence_means_no() {
    let plain = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() });
    assert!(!plain.is_forwarded(), "a fresh payload is not a forward");
    let decoded = ChatPayload::decode(&plain.encode()).unwrap();
    assert!(!decoded.is_forwarded(), "and it does not become one on the way");
    // Not written to the wire at all when false — `ext` stays absent, so an old client sees
    // exactly the JSON it saw before this field existed.
    let json = String::from_utf8(plain.encode()).unwrap();
    assert!(!json.contains("forwarded"), "a non-forward costs no bytes: {json}");

    let fwd = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() })
        .with_forwarded();
    let decoded = ChatPayload::decode(&fwd.encode()).unwrap();
    assert!(decoded.is_forwarded(), "the flag has to reach the other side");
}

/// Forwarding a message that carries media meta must not erase it. `with_media_meta` REPLACES
/// `ext` wholesale, so a helper that did the same would silently drop the caption — the kind of
/// loss that shows up as "my caption vanished" long after the change that caused it.
#[test]
fn forwarded_merges_into_ext_instead_of_replacing_it() {
    let p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() })
        .with_media_meta(Some("a caption"), Some("alb-1"), Some(0), Some(2))
        .with_forwarded();
    let d = ChatPayload::decode(&p.encode()).unwrap();
    assert!(d.is_forwarded());
    assert_eq!(d.caption().as_deref(), Some("a caption"), "the caption survived");
    assert_eq!(d.album_id().as_deref(), Some("alb-1"));
}

/// A malformed `ext` degrades to "ordinary", never to an error. `ext` is attacker-influenced —
/// it arrives inside a message from someone else — so a string where a bool belongs must not
/// become a truthy forward marker.
#[test]
fn a_non_boolean_forwarded_is_not_a_forward() {
    let mut p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() });
    p.ext = serde_json::json!({ "forwarded": "yes" });
    assert!(!p.is_forwarded());
    p.ext = serde_json::json!({ "forwarded": 1 });
    assert!(!p.is_forwarded());
    p.ext = serde_json::Value::String("not an object".into());
    assert!(!p.is_forwarded());
}

#[test]
fn caption_album_roundtrip_via_ext() {
    let p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() })
        .with_media_meta(Some("  hello  "), Some("alb-1"), Some(2), Some(5));
    // caption is trimmed; the album fields survive.
    let enc = p.encode();
    let d = ChatPayload::decode(&enc).unwrap();
    assert_eq!(d.caption().as_deref(), Some("hello"));
    assert_eq!(d.album_id().as_deref(), Some("alb-1"));
    assert_eq!(d.album_index(), Some(2));
    assert_eq!(d.album_count(), Some(5));
}

#[test]
fn empty_meta_leaves_ext_null_forward_compat() {
    // Empty caption and no album → ext is not written (clean JSON for old clients).
    let p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() })
        .with_media_meta(Some("   "), None, None, None);
    assert!(p.ext.is_null());
    assert_eq!(p.caption(), None);
    assert_eq!(p.album_id(), None);
    // No "ext"/"caption"/"album_id" field may appear in the JSON at all.
    let json = String::from_utf8(p.encode()).unwrap();
    assert!(!json.contains("caption") && !json.contains("album_id") && !json.contains("\"ext\""));
}

#[test]
fn album_fields_skipped_without_album_id() {
    // caption present but no album_id → album_index/count are not written.
    let p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() })
        .with_media_meta(Some("cap"), None, Some(3), Some(4));
    assert_eq!(p.caption().as_deref(), Some("cap"));
    assert_eq!(p.album_id(), None);
    assert_eq!(p.album_index(), None);
    assert_eq!(p.album_count(), None);
}

/// Group-oriented control messages always require fan-out (never primary-only), while
/// 1:1/request/self-state/content messages do not. Guarding the classification is what keeps
/// dispatch deriving its targeting from the `inner` kind rather than from the call site — the
/// structural close of the `SendControl` primary-only bug class.
#[test]
fn requires_device_fanout_classification() {
    let mk_install = |room: Option<String>| InnerMessage::PluginInstall {
        plugin_id: "p".into(),
        name: "n".into(),
        icon: "i".into(),
        html: String::new(),
        version: 1,
        code_ref: None,
        mode: "persistent".into(),
        room,
        web_enabled: false,
        policy_rev: 0,
    };
    let mk_record = |room: Option<String>| InnerMessage::PluginRecord {
        plugin_id: "p".into(),
        collection: "c".into(),
        record_id: "id".into(),
        parent_id: None,
        op: "put".into(),
        fields_json: "{}".into(),
        lamport: 1,
        room,
    };
    let mk_activity = |room: Option<String>| InnerMessage::Activity {
        plugin_id: "p".into(),
        activity_id: "a".into(),
        seq: 1,
        event: ActivityEvent::Join,
        payload: "{}".into(),
        scope: match room {
            Some(room_id) => ActivityWireScope::Room { room_id },
            None => ActivityWireScope::Direct,
        },
        reads_batch: false,
    };

    // Group-oriented → fan-out is mandatory.
    let fanout_true: Vec<InnerMessage> = vec![
        InnerMessage::RoomKeyShare {
            room_id: "r".into(),
            session_id: "s".into(),
            session_key_b64: "k".into(),
        },
        InnerMessage::GroupReceipt {
            room_id: "r".into(),
            msg_uids: vec!["u".into()],
            read: true,
        },
        InnerMessage::GroupJoinAccepted { room_id: "r".into() },
        InnerMessage::GroupMembershipChanged { room_id: "r".into() },
        InnerMessage::PluginEpochKeyShare {
            room: "r".into(),
            plugin: "p".into(),
            epoch: 0,
            key_b64: "k".into(),
        },
        InnerMessage::PluginRecordSnapshot {
            room: "r".into(),
            records: vec![],
        },
        InnerMessage::PluginRemoved {
            room: "r".into(),
            plugin_id: "p".into(),
        },
        mk_record(Some("r".into())),
        mk_activity(Some("r".into())),
        mk_install(Some("r".into())),
        // A 1:1 file's download acks: the sending device may be a linked one.
        InnerMessage::MediaReceived { media_id: "m".into() },
        InnerMessage::P2pBlobReceived {
            ticket_hash: "h".into(),
            device: None,
        },
        // The room session asked for is the outbound session of whichever device sent it.
        InnerMessage::RoomKeyRequest {
            room_id: "r".into(),
            session_id: None,
        },
    ];
    for m in &fanout_true {
        assert!(
            m.requires_device_fanout(),
            "a group-oriented inner must require fan-out: {}",
            m.fanout_kind_label()
        );
        assert_ne!(
            m.fanout_kind_label(),
            "other",
            "a fan-out inner must carry its own label: {m:?}"
        );
    }

    // 1:1 / request-pull / self-state / content → stays primary-only (no fan-out).
    let fanout_false: Vec<InnerMessage> = vec![
        InnerMessage::Text { body: "hi".into() },
        InnerMessage::PluginSnapshotRequest { room: "r".into() },
        InnerMessage::PluginInstallRequest { room: "r".into() },
        InnerMessage::CallSignal {
            call_id: "c".into(),
            signal_type: "invite".into(),
            data: "{}".into(),
        },
        mk_record(None),
        mk_activity(None),
        mk_install(None),
    ];
    for m in &fanout_false {
        assert!(
            !m.requires_device_fanout(),
            "a 1:1/request/self inner must stay primary-only: {m:?}"
        );
    }
}

#[test]
fn plugin_removed_roundtrip() {
    // Delete-propagation: kind="plugin_removed" + room/plugin_id roundtrip + snake_case tag.
    let m = InnerMessage::PluginRemoved {
        room: "room-1".into(),
        plugin_id: "html:abc".into(),
    };
    let json = serde_json::to_string(&m).unwrap();
    assert!(
        json.contains("\"kind\":\"plugin_removed\""),
        "snake_case tag: {json}"
    );
    let back: InnerMessage = serde_json::from_str(&json).unwrap();
    match back {
        InnerMessage::PluginRemoved { room, plugin_id } => {
            assert_eq!(room, "room-1");
            assert_eq!(plugin_id, "html:abc");
        }
        other => panic!("expected PluginRemoved, got {other:?}"),
    }
}

#[test]
fn activity_event_control_roundtrip() {
    for (variant, json) in [
        (ActivityEvent::Invite, r#"{"type":"invite"}"#),
        (ActivityEvent::Join, r#"{"type":"join"}"#),
        (ActivityEvent::Leave, r#"{"type":"leave"}"#),
    ] {
        let encoded = serde_json::to_string(&variant).unwrap();
        assert_eq!(encoded, json, "encode mismatch for {variant:?}");
        let decoded: ActivityEvent = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, variant);
    }
}

#[test]
fn activity_event_domain_roundtrip() {
    let ev = ActivityEvent::Domain {
        name: "note".into(),
    };
    let encoded = serde_json::to_string(&ev).unwrap();
    assert_eq!(encoded, r#"{"type":"domain","name":"note"}"#);
    let decoded: ActivityEvent = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, ev);
}

#[test]
fn outbound_copy_roundtrip() {
    // M2-S3.1: self-copy variant kind="outbound_copy" + the copied payload, carried whole.
    let copied = ChatPayload::new(
        Some("th-1".into()),
        Some("Topic".into()),
        InnerMessage::Text { body: "hi".into() },
    )
    .with_forwarded();
    let oc = InnerMessage::OutboundCopy {
        peer_id: "peer-bob".into(),
        sent_at_ms: 1_700_000_000_000,
        origin_local_id: "abc-123".into(),
        payload: Box::new(copied),
    };
    // The real wire path: the copy is itself the inner of a self-Olm ChatPayload.
    let wire = ChatPayload::new(None, None, oc).encode();
    let json = String::from_utf8(wire.clone()).unwrap();
    assert!(json.contains("\"kind\":\"outbound_copy\""), "snake_case tag: {json}");
    // The copied message keeps its own flatten/tag (kind=text).
    assert!(json.contains("\"kind\":\"text\""), "nested inner kind: {json}");
    let back = ChatPayload::decode(&wire).expect("the copy must decode inside a ChatPayload");
    assert!(back.ext.is_null() && back.thread_id.is_none(), "the outer envelope stays bare");
    match back.inner {
        InnerMessage::OutboundCopy { peer_id, sent_at_ms, origin_local_id, payload } => {
            assert_eq!(peer_id, "peer-bob");
            assert_eq!(sent_at_ms, 1_700_000_000_000);
            assert_eq!(origin_local_id, "abc-123");
            assert!(matches!(payload.inner, InnerMessage::Text { ref body } if body == "hi"));
            assert_eq!(payload.thread_id.as_deref(), Some("th-1"), "the thread travels");
            assert!(payload.is_forwarded(), "and so does the copied message's ext");
        }
        other => panic!("expected OutboundCopy, got {other:?}"),
    }
}

#[test]
fn room_key_gossip_roundtrip() {
    // M-1b: roundtrip of the gossip variant kind="room_key_gossip" plus the origin fields.
    let g = InnerMessage::RoomKeyGossip {
        origin_user_id: "alice".into(),
        origin_device_id: "dev-a1".into(),
        room_id: "room-1".into(),
        session_id: "sess-9".into(),
        session_key_b64: "AAAAkey".into(),
    };
    let json = serde_json::to_string(&g).unwrap();
    assert!(json.contains("\"kind\":\"room_key_gossip\""), "snake_case tag: {json}");
    let back: InnerMessage = serde_json::from_str(&json).unwrap();
    match back {
        InnerMessage::RoomKeyGossip {
            origin_user_id, origin_device_id, room_id, session_id, session_key_b64,
        } => {
            assert_eq!(origin_user_id, "alice");
            assert_eq!(origin_device_id, "dev-a1");
            assert_eq!(room_id, "room-1");
            assert_eq!(session_id, "sess-9");
            assert_eq!(session_key_b64, "AAAAkey");
        }
        other => panic!("expected RoomKeyGossip, got {other:?}"),
    }
}

#[test]
fn group_outbound_copy_roundtrip() {
    // G3: roundtrip of the group self-copy variant kind="group_outbound_copy" + the copied
    // payload, carried whole.
    let copied = ChatPayload::new(
        Some("th-1".into()),
        Some("Topic".into()),
        InnerMessage::Text { body: "hello group".into() },
    )
    .with_msg_uid("local-42");
    let goc = InnerMessage::GroupOutboundCopy {
        room_id: "room-7".into(),
        origin_local_id: "local-42".into(),
        sent_at_ms: 1_700_000_000_001,
        payload: Box::new(copied),
    };
    let json = serde_json::to_string(&goc).unwrap();
    assert!(json.contains("\"kind\":\"group_outbound_copy\""), "snake_case tag: {json}");
    assert!(json.contains("\"kind\":\"text\""), "nested inner kind: {json}");
    let back: InnerMessage = serde_json::from_str(&json).unwrap();
    match back {
        InnerMessage::GroupOutboundCopy { room_id, origin_local_id, sent_at_ms, payload } => {
            assert_eq!(room_id, "room-7");
            assert_eq!(origin_local_id, "local-42");
            assert_eq!(sent_at_ms, 1_700_000_000_001);
            assert_eq!(payload.thread_id.as_deref(), Some("th-1"));
            assert_eq!(payload.thread_title.as_deref(), Some("Topic"));
            assert!(matches!(payload.inner, InnerMessage::Text { ref body } if body == "hello group"));
        }
        other => panic!("expected GroupOutboundCopy, got {other:?}"),
    }
}

// Regression guard for serde flatten field collisions: a GroupOutboundCopy flattened inside a
// ChatPayload — the real wire path — must survive the roundtrip. An inner field sharing a name
// with an outer ChatPayload field (msg_uid/thread_id/ext) decodes as "missing field" — and the
// copied message's OWN thread and `ext` must come back from inside `payload`, not be captured by
// the outer envelope's.
#[test]
fn group_outbound_copy_survives_chatpayload_flatten_roundtrip() {
    let copied = ChatPayload::new(
        Some("th-1".into()),
        None,
        InnerMessage::Text { body: "group message".into() },
    )
    .with_msg_uid("local-42")
    .with_media_meta(Some("a caption"), Some("album-1"), Some(0), Some(2));
    let goc = InnerMessage::GroupOutboundCopy {
        room_id: "room-7".into(),
        origin_local_id: "local-42".into(),
        sent_at_ms: 1_700_000_000_001,
        payload: Box::new(copied),
    };
    // The run_send_self_state path: the outer ChatPayload has no thread/msg_uid (None) → flatten.
    let payload = ChatPayload::new(None, None, goc);
    let bytes = payload.encode();
    let back = ChatPayload::decode(&bytes).expect("the flattened ChatPayload must decode");
    assert!(back.msg_uid.is_none() && back.thread_id.is_none() && back.ext.is_null());
    match back.inner {
        InnerMessage::GroupOutboundCopy { origin_local_id, payload, .. } => {
            assert_eq!(origin_local_id, "local-42", "origin_local_id must stay an inner field (no collision)");
            assert_eq!(payload.thread_id.as_deref(), Some("th-1"), "the copy keeps its own thread");
            assert_eq!(payload.msg_uid.as_deref(), Some("local-42"));
            assert_eq!(payload.caption().as_deref(), Some("a caption"), "and its own ext");
            assert_eq!(payload.album_count(), Some(2));
            assert!(matches!(payload.inner, InnerMessage::Text { ref body } if body == "group message"));
        }
        other => panic!("expected GroupOutboundCopy after flatten, got {other:?}"),
    }
}

#[test]
fn read_self_sync_roundtrip() {
    // Layer-4c: roundtrip of the sibling read-sync variant kind="read_self_sync" + msg_uids.
    let rss = InnerMessage::ReadSelfSync {
        peer_id: "peer-carol".into(),
        msg_uids: vec!["loc-1".into(), "loc-2".into()],
    };
    let json = serde_json::to_string(&rss).unwrap();
    assert!(json.contains("\"kind\":\"read_self_sync\""), "snake_case tag: {json}");
    let back: InnerMessage = serde_json::from_str(&json).unwrap();
    match back {
        InnerMessage::ReadSelfSync { peer_id, msg_uids } => {
            assert_eq!(peer_id, "peer-carol");
            assert_eq!(msg_uids, vec!["loc-1".to_string(), "loc-2".to_string()]);
        }
        other => panic!("expected ReadSelfSync, got {other:?}"),
    }
}

#[test]
fn delete_self_sync_roundtrip() {
    // Roundtrip of the "delete for everyone" sibling-sync variant kind="delete_self_sync" and its
    // fields.
    let dss = InnerMessage::DeleteSelfSync {
        peer_id: "peer-carol".into(),
        origin_local_id: "origin-9".into(),
    };
    let json = serde_json::to_string(&dss).unwrap();
    assert!(json.contains("\"kind\":\"delete_self_sync\""), "snake_case tag: {json}");
    let back: InnerMessage = serde_json::from_str(&json).unwrap();
    match back {
        InnerMessage::DeleteSelfSync { peer_id, origin_local_id } => {
            assert_eq!(peer_id, "peer-carol");
            assert_eq!(origin_local_id, "origin-9");
        }
        other => panic!("expected DeleteSelfSync, got {other:?}"),
    }
}

// Regression guard for serde flatten field collisions (twin of the GroupOutboundCopy test):
// on the real wire path DeleteSelfSync is flattened inside a `ChatPayload`. Had the field been
// named `msg_uid` it would have been captured by `ChatPayload.msg_uid` and the inner field would
// degrade to a "missing field"; the name `origin_local_id` prevents that. This test covers that
// exact path (ChatPayload encode→decode).
#[test]
fn delete_self_sync_survives_chatpayload_flatten_roundtrip() {
    let dss = InnerMessage::DeleteSelfSync {
        peer_id: "carol".into(),
        origin_local_id: "origin-9".into(),
    };
    // The SendSelfState path: the outer ChatPayload has no thread/msg_uid (None) → flatten.
    let payload = ChatPayload::new(None, None, dss);
    let bytes = payload.encode();
    let back = ChatPayload::decode(&bytes).expect("the flattened ChatPayload must decode");
    match back.inner {
        InnerMessage::DeleteSelfSync { peer_id, origin_local_id } => {
            assert_eq!(peer_id, "carol");
            assert_eq!(origin_local_id, "origin-9", "origin_local_id must stay an inner field (no collision)");
        }
        other => panic!("expected DeleteSelfSync after flatten, got {other:?}"),
    }
    // The outer ChatPayload.msg_uid must not swallow the inner field (it stays None; the inner
    // origin_local_id is separate).
    assert!(back.msg_uid.is_none(), "ChatPayload.msg_uid must stay None (it did not swallow the inner field)");
}

/// "Get it from there": the request and its answer cross the self-Olm path flattened inside a
/// `ChatPayload` — no field may collide with the payload's own (`msg_uid`, `thread_id`, `ext`).
#[test]
fn own_file_request_and_offer_survive_the_chatpayload_flatten() {
    let manifest = FileManifest {
        v: 1,
        media_id: String::new(),
        key_b64: "a2V5".into(),
        nonce_b64: "bm9uY2U".into(),
        chunk_size: 65536,
        size: 600 * 1024 * 1024,
        content_type: "video/mp4".into(),
        filename: "lesson.mp4".into(),
    };
    let request = InnerMessage::OwnFileRequest { peer_id: "room-1".into(), origin_local_id: "loc-9".into() };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("\"kind\":\"own_file_request\""), "snake_case tag: {json}");
    match ChatPayload::decode(&ChatPayload::new(None, None, request).encode()).unwrap().inner {
        InnerMessage::OwnFileRequest { peer_id, origin_local_id } => {
            assert_eq!((peer_id.as_str(), origin_local_id.as_str()), ("room-1", "loc-9"));
        }
        other => panic!("expected OwnFileRequest, got {other:?}"),
    }
    let offer = InnerMessage::OwnFileOffer {
        peer_id: "room-1".into(),
        origin_local_id: "loc-9".into(),
        ticket: "blobticket-9".into(),
        manifest: manifest.clone(),
        seeded_for_ms: Some(3_600_000),
    };
    let back = ChatPayload::decode(&ChatPayload::new(None, None, offer).encode()).unwrap();
    match back.inner {
        InnerMessage::OwnFileOffer { peer_id, origin_local_id, ticket, manifest: m, seeded_for_ms } => {
            assert_eq!((peer_id.as_str(), origin_local_id.as_str()), ("room-1", "loc-9"));
            assert_eq!(ticket, "blobticket-9");
            assert_eq!(m, manifest);
            assert_eq!(seeded_for_ms, Some(3_600_000));
        }
        other => panic!("expected OwnFileOffer, got {other:?}"),
    }
    assert!(back.msg_uid.is_none());
}

#[test]
fn room_key_request_roundtrip() {
    // P1 crypto-selfheal: RoomKeyRequest wire roundtrip + snake_case tag (fwd-compat).
    let req = InnerMessage::RoomKeyRequest {
        room_id: "room-42".into(),
        session_id: Some("sid-7".into()),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"kind\":\"room_key_request\""), "snake_case tag: {json}");
    let back: InnerMessage = serde_json::from_str(&json).unwrap();
    match back {
        InnerMessage::RoomKeyRequest { room_id, session_id } => {
            assert_eq!(room_id, "room-42");
            assert_eq!(session_id.as_deref(), Some("sid-7"));
        }
        other => panic!("expected RoomKeyRequest, got {other:?}"),
    }
    // Forward compatibility: an old client (no session_id field) degrades to None.
    let old: InnerMessage =
        serde_json::from_str(r#"{"kind":"room_key_request","room_id":"r2"}"#).unwrap();
    assert!(matches!(old, InnerMessage::RoomKeyRequest { session_id: None, .. }));
}

#[test]
fn chat_payload_msg_uid_set_for_1to1_via_encrypt_path() {
    // Layer-4c: once msg_uid is set on a 1:1 payload it appears on the wire and survives decode.
    let mut p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() });
    p.msg_uid = Some("origin-local-1".into());
    let bytes = p.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""msg_uid":"origin-local-1""#), "json: {json}");
    assert_eq!(
        ChatPayload::decode(&bytes).unwrap().msg_uid.as_deref(),
        Some("origin-local-1")
    );
}

#[test]
fn device_state_packet_and_request_roundtrip() {
    // M4: serde roundtrip of the state packet (signed history) and the request (the pull trigger).
    let p = InnerMessage::DeviceStatePacket {
        payload_b64: "AAEC".into(),
        sig_b64: "c2ln".into(),
    };
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("\"kind\":\"device_state_packet\""), "tag: {json}");
    match serde_json::from_str::<InnerMessage>(&json).unwrap() {
        InnerMessage::DeviceStatePacket { payload_b64, sig_b64 } => {
            assert_eq!(payload_b64, "AAEC");
            assert_eq!(sig_b64, "c2ln");
        }
        other => panic!("expected DeviceStatePacket, got {other:?}"),
    }
    // Request: since_ms/request_id None → the fields are not serialized (skip_serializing_if).
    let r = InnerMessage::DeviceStateRequest { since_ms: None, request_id: None };
    let rj = serde_json::to_string(&r).unwrap();
    assert!(rj.contains("\"kind\":\"device_state_request\""), "tag: {rj}");
    assert!(!rj.contains("since_ms"), "a None field must not be serialized: {rj}");
    assert!(!rj.contains("request_id"), "a None request_id must not be serialized: {rj}");
    assert!(matches!(
        serde_json::from_str::<InnerMessage>(&rj).unwrap(),
        InnerMessage::DeviceStateRequest { since_ms: None, request_id: None }
    ));
    // #22: request_id Some → appears on the wire and roundtrips (the link correlation nonce).
    let rq = InnerMessage::DeviceStateRequest {
        since_ms: None,
        request_id: Some("lnk-srv-42".into()),
    };
    let rqj = serde_json::to_string(&rq).unwrap();
    assert!(rqj.contains(r#""request_id":"lnk-srv-42""#), "request_id wire: {rqj}");
    assert!(matches!(
        serde_json::from_str::<InnerMessage>(&rqj).unwrap(),
        InnerMessage::DeviceStateRequest { request_id: Some(ref r), .. } if r == "lnk-srv-42"
    ));
    // Old-APK forward compatibility: an old request without request_id still parses.
    let legacy: InnerMessage =
        serde_json::from_str(r#"{"kind":"device_state_request","since_ms":5}"#).unwrap();
    assert!(matches!(
        legacy,
        InnerMessage::DeviceStateRequest { since_ms: Some(5), request_id: None }
    ));
    // Old-APK forward compatibility: an unknown kind → Unknown (no crash).
    let unknown: InnerMessage =
        serde_json::from_str(r#"{"kind":"device_state_packet_v999","x":1}"#).unwrap();
    assert!(matches!(unknown, InnerMessage::Unknown));
}

#[test]
fn activity_event_wire_name() {
    assert_eq!(ActivityEvent::Invite.wire_name(), "invite");
    assert_eq!(ActivityEvent::Join.wire_name(), "join");
    assert_eq!(ActivityEvent::Leave.wire_name(), "leave");
    assert_eq!(
        ActivityEvent::Domain {
            name: "doc".into()
        }
        .wire_name(),
        "doc"
    );
}

#[test]
fn activity_event_is_control() {
    assert!(ActivityEvent::Invite.is_control());
    assert!(ActivityEvent::Join.is_control());
    assert!(ActivityEvent::Leave.is_control());
    assert!(!ActivityEvent::Domain {
        name: "x".into()
    }
    .is_control());
}

#[test]
fn activity_event_from_wire_controls() {
    assert_eq!(
        ActivityEvent::from_wire("invite", None).unwrap(),
        ActivityEvent::Invite
    );
    assert_eq!(
        ActivityEvent::from_wire("join", Some("ignored")).unwrap(),
        ActivityEvent::Join
    );
    assert_eq!(
        ActivityEvent::from_wire("leave", None).unwrap(),
        ActivityEvent::Leave
    );
}

#[test]
fn activity_event_from_wire_domain() {
    let ev = ActivityEvent::from_wire("domain", Some("note")).unwrap();
    assert_eq!(
        ev,
        ActivityEvent::Domain {
            name: "note".into()
        }
    );
}

#[test]
fn activity_event_from_wire_errors() {
    assert!(ActivityEvent::from_wire("unknown", None).is_err());
    assert!(ActivityEvent::from_wire("domain", None).is_err());
    assert!(ActivityEvent::from_wire("domain", Some("")).is_err());
}

#[test]
fn inner_message_activity_roundtrip() {
    let msg = InnerMessage::Activity {
        plugin_id: "piano".into(),
        activity_id: "act-1".into(),
        seq: 42,
        event: ActivityEvent::Domain {
            name: "note".into(),
        },
        payload: r#"{"note":60}"#.into(),
        scope: ActivityWireScope::Room { room_id: "room-1".into() },
        reads_batch: true,
    };
    let bytes = msg.encode();
    let decoded = InnerMessage::decode(&bytes).unwrap();
    if let InnerMessage::Activity {
        plugin_id,
        activity_id,
        seq,
        event,
        payload,
        scope,
        reads_batch,
    } = decoded
    {
        assert_eq!(plugin_id, "piano");
        assert_eq!(activity_id, "act-1");
        assert_eq!(seq, 42);
        assert_eq!(
            event,
            ActivityEvent::Domain {
                name: "note".into()
            }
        );
        assert_eq!(payload, r#"{"note":60}"#);
        assert_eq!(scope, ActivityWireScope::Room { room_id: "room-1".into() });
        assert!(reads_batch);
    } else {
        panic!("expected Activity variant");
    }
}

/// The scope is a required statement on the wire (B01): `{"type":"direct"}` or
/// `{"type":"room","room_id":…}`, and an Activity that leaves it off — what every build before
/// 2026-10-06 sent for a 1:1 — does not decode at all, so "no room" can never be read as "1:1".
#[test]
fn an_activity_states_its_scope_and_one_without_it_is_refused() {
    let direct = InnerMessage::Activity {
        plugin_id: "note".into(),
        activity_id: "act-x".into(),
        seq: 0,
        event: ActivityEvent::Join,
        payload: "{}".into(),
        scope: ActivityWireScope::Direct,

        reads_batch: false,
    };
    let json = String::from_utf8(direct.encode()).unwrap();
    assert!(json.contains(r#""scope":{"type":"direct"}"#), "json: {json}");
    let room = InnerMessage::Activity {
        plugin_id: "note".into(),
        activity_id: "act-x".into(),
        seq: 0,
        event: ActivityEvent::Join,
        payload: "{}".into(),
        scope: ActivityWireScope::Room { room_id: "g1".into() },

        reads_batch: false,
    };
    let json = String::from_utf8(room.encode()).unwrap();
    assert!(json.contains(r#""scope":{"type":"room","room_id":"g1"}"#), "json: {json}");

    let old = br#"{"kind":"activity","plugin_id":"note","activity_id":"act-x","seq":0,"event":{"type":"leave"},"payload":"{}"}"#;
    assert!(InnerMessage::decode(old).is_err(), "a scope-less Activity must not decode");
    let old_room = br#"{"kind":"activity","plugin_id":"note","activity_id":"act-x","seq":0,"event":{"type":"leave"},"payload":"{}","room":"g1"}"#;
    assert!(InnerMessage::decode(old_room).is_err(), "nor the retired optional `room`");
}

#[test]
fn inner_message_unknown_variant_catches_new_tags() {
    // A `kind` a newer client sends that we do not know yet — an old client must parse it as
    // Unknown, and decode must not panic.
    let future_payload = r#"{"kind":"group_message","group_id":"g1","ciphertext":"AAAA"}"#;
    let decoded = InnerMessage::decode(future_payload.as_bytes())
        .expect("unknown kind should decode as Unknown variant");
    assert!(
        matches!(decoded, InnerMessage::Unknown),
        "expected Unknown variant, got {decoded:?}"
    );
}

#[test]
fn chat_payload_schema_version_defaults_to_v1() {
    // An old sender that never wrote schema_version must parse with default=1.
    let legacy = r#"{"kind":"text","body":"hello"}"#;
    let payload = ChatPayload::decode(legacy.as_bytes()).unwrap();
    assert_eq!(payload.schema_version, WIRE_SCHEMA_VERSION);
    assert!(payload.ext.is_null());
    assert!(matches!(payload.inner, InnerMessage::Text { .. }));
}

#[test]
fn chat_payload_roundtrip_with_schema_and_ext() {
    let mut p = ChatPayload::new(
        Some("thr-1".into()),
        None,
        InnerMessage::Text { body: "x".into() },
    );
    p.ext = serde_json::json!({"reply_to": "msg-42"});
    let bytes = p.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    // schema_version must appear on the wire
    assert!(json.contains(r#""schema_version":1"#), "json: {json}");
    // ext must appear on the wire
    assert!(json.contains(r#""reply_to":"msg-42""#), "json: {json}");
    let decoded = ChatPayload::decode(&bytes).unwrap();
    assert_eq!(decoded.schema_version, 1);
    assert_eq!(decoded.ext["reply_to"], "msg-42");
}

#[test]
fn chat_payload_omits_null_ext_on_encode() {
    // ext = Null → the field must not appear in the wire output (bandwidth).
    let p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() });
    let json = String::from_utf8(p.encode()).unwrap();
    assert!(!json.contains(r#""ext""#), "ext should be omitted, json: {json}");
    // schema_version is still written (the default value has no skip_serializing_if).
    assert!(json.contains(r#""schema_version":1"#));
}

#[test]
fn chat_payload_forward_compat_unknown_kind() {
    // When an old client sees a new "kind" the ChatPayload must degrade to Unknown while still
    // carrying thread_id / schema_version.
    let future = r#"{"schema_version":2,"thread_id":"t-9","kind":"voice_note","duration_ms":3000}"#;
    let decoded = ChatPayload::decode(future.as_bytes()).unwrap();
    assert_eq!(decoded.schema_version, 2);
    assert_eq!(decoded.thread_id.as_deref(), Some("t-9"));
    assert!(matches!(decoded.inner, InnerMessage::Unknown));
}

#[test]
fn inner_message_room_key_share_roundtrip() {
    let msg = InnerMessage::RoomKeyShare {
        room_id: "room-1".into(),
        session_id: "sess-abc".into(),
        session_key_b64: "AgAAAAA...".into(),
    };
    let bytes = msg.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""kind":"room_key_share""#), "json: {json}");
    let decoded = InnerMessage::decode(&bytes).unwrap();
    match decoded {
        InnerMessage::RoomKeyShare { room_id, session_id, session_key_b64 } => {
            assert_eq!(room_id, "room-1");
            assert_eq!(session_id, "sess-abc");
            assert_eq!(session_key_b64, "AgAAAAA...");
        }
        other => panic!("expected RoomKeyShare, got {other:?}"),
    }
}

#[test]
fn inner_message_call_signal_roundtrip() {
    let msg = InnerMessage::CallSignal {
        call_id: "call-xyz".into(),
        signal_type: "invite".into(),
        data: "v=0\r\no=- 0 0 IN IP4 0.0.0.0...".into(),
    };
    let bytes = msg.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""kind":"call_signal""#), "json: {json}");
    let decoded = InnerMessage::decode(&bytes).unwrap();
    match decoded {
        InnerMessage::CallSignal { call_id, signal_type, data } => {
            assert_eq!(call_id, "call-xyz");
            assert_eq!(signal_type, "invite");
            assert!(data.starts_with("v=0"));
        }
        other => panic!("expected CallSignal, got {other:?}"),
    }
}

#[test]
fn inner_message_plugin_install_roundtrip() {
    let msg = InnerMessage::PluginInstall {
        plugin_id: "html:shared-list".into(),
        name: "Shared List".into(),
        icon: "checklist_rounded".into(),
        html: "<!doctype html><body>x</body>".into(),
        version: 1,
        mode: "instant".into(),
        room: Some("g-aile".into()),
        code_ref: None,
        web_enabled: true,
        policy_rev: 7,
    };
    let bytes = msg.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""kind":"plugin_install""#), "json: {json}");
    let decoded = InnerMessage::decode(&bytes).unwrap();
    match decoded {
        InnerMessage::PluginInstall {
            plugin_id, name, icon, html, version, mode, room, code_ref, web_enabled, policy_rev,
        } => {
            assert_eq!(plugin_id, "html:shared-list");
            assert_eq!(name, "Shared List");
            assert_eq!(icon, "checklist_rounded");
            assert!(html.contains("doctype"));
            assert_eq!(version, 1);
            assert_eq!(mode, "instant");
            assert_eq!(room.as_deref(), Some("g-aile"));
            assert!(code_ref.is_none(), "legacy: no code_ref");
            assert!(web_enabled, "FAZ-A: web_enabled roundtrip");
            assert_eq!(policy_rev, 7, "FAZ-A: policy_rev roundtrip");
        }
        other => panic!("expected PluginInstall, got {other:?}"),
    }
}

#[test]
fn inner_message_plugin_install_code_ref_roundtrip() {
    // serde roundtrip of a PluginInstall carrying a server-stored code pointer (Faz-4
    // server-code): html is empty (the code now lives in R2) and code_ref is populated.
    let msg = InnerMessage::PluginInstall {
        plugin_id: "html:shared-list".into(),
        name: "Shared List".into(),
        icon: "checklist_rounded".into(),
        html: String::new(),
        version: 3,
        mode: "persistent".into(),
        room: Some("g-aile".into()),
        code_ref: Some(PluginCodeRefV1 {
            blob_id: "pb-abc".into(),
            blob_hash_b64: "CT".into(),
            code_hash_b64: "PT".into(),
            key_b64: "KEY".into(),
            nonce_b64: "NCE".into(),
            chunk_size: 65536,
            size: 42,
            entrypoint: String::new(),
            enc: "xchacha20poly1305-stream".into(),
        }),
        web_enabled: false,
        policy_rev: 0,
    };
    let bytes = msg.encode();
    let decoded = InnerMessage::decode(&bytes).unwrap();
    match decoded {
        InnerMessage::PluginInstall { html, code_ref, .. } => {
            assert!(html.is_empty(), "server-stored: html is empty");
            let cr = code_ref.expect("code_ref must survive");
            assert_eq!(cr.blob_id, "pb-abc");
            assert_eq!(cr.code_hash_b64, "PT");
            assert_eq!(cr.size, 42);
            assert_eq!(cr.enc, "xchacha20poly1305-stream");
        }
        other => panic!("expected PluginInstall, got {other:?}"),
    }
}

/// A plugin_install from an old sender (no mode field) → serde defaults to "persistent" (the safe
/// side of backward compatibility).
#[test]
fn inner_message_plugin_install_legacy_mode_default() {
    let legacy = r#"{"kind":"plugin_install","plugin_id":"html:x","name":"X",
        "icon":"widgets_outlined","html":"<body>x</body>","version":1}"#;
    let decoded = InnerMessage::decode(legacy.as_bytes()).unwrap();
    match decoded {
        InnerMessage::PluginInstall { mode, room, web_enabled, policy_rev, .. } => {
            assert_eq!(mode, "persistent", "an old message must default to persistent");
            assert_eq!(room, None, "an old message has no room field → None default");
            assert!(!web_enabled, "PHASE-A: an old message has no web_enabled → false (fail-closed)");
            assert_eq!(policy_rev, 0, "PHASE-A: an old message has no policy_rev → 0");
        }
        other => panic!("expected PluginInstall, got {other:?}"),
    }
}

#[test]
fn inner_message_plugin_record_snapshot_roundtrip() {
    let msg = InnerMessage::PluginRecordSnapshot {
        room: "room-1".into(),
        records: vec![
            SnapshotRecord {
                plugin_id: "html:list".into(),
                collection: "item".into(),
                record_id: "r1".into(),
                parent_id: None,
                fields_json: r#"{"t":"milk"}"#.into(),
                lamport: 7,
                author_id: "alice".into(),
                deleted: false,
            },
            SnapshotRecord {
                plugin_id: "html:list".into(),
                collection: "item".into(),
                record_id: "r2".into(),
                parent_id: Some("r1".into()),
                fields_json: "{}".into(),
                lamport: 9,
                author_id: "bob".into(),
                deleted: true,
            },
        ],
    };
    let bytes = msg.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""kind":"plugin_record_snapshot""#), "json: {json}");
    let decoded = InnerMessage::decode(&bytes).unwrap();
    match decoded {
        InnerMessage::PluginRecordSnapshot { room, records } => {
            assert_eq!(room, "room-1");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].author_id, "alice");
            assert_eq!(records[0].parent_id, None);
            assert!(records[1].deleted);
            assert_eq!(records[1].parent_id.as_deref(), Some("r1"));
            assert_eq!(records[1].lamport, 9);
        }
        other => panic!("expected PluginRecordSnapshot, got {other:?}"),
    }
}

#[test]
fn inner_message_plugin_epoch_key_share_roundtrip() {
    let msg = InnerMessage::PluginEpochKeyShare {
        room: "g-aile".into(),
        plugin: "html:meydan".into(),
        epoch: 0,
        key_b64: "QUJDREVGR0g=".into(),
    };
    let bytes = msg.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""kind":"plugin_epoch_key_share""#), "json: {json}");
    match InnerMessage::decode(&bytes).unwrap() {
        InnerMessage::PluginEpochKeyShare { room, plugin, epoch, key_b64 } => {
            assert_eq!(room, "g-aile");
            assert_eq!(plugin, "html:meydan");
            assert_eq!(epoch, 0);
            assert_eq!(key_b64, "QUJDREVGR0g=");
        }
        other => panic!("expected PluginEpochKeyShare, got {other:?}"),
    }
}

#[test]
fn inner_message_group_receipt_roundtrip() {
    let msg = InnerMessage::GroupReceipt {
        room_id: "room-1".into(),
        msg_uids: vec!["out-9".into(), "out-10".into()],
        read: true,
    };
    let bytes = msg.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""kind":"group_receipt""#), "json: {json}");
    match InnerMessage::decode(&bytes).unwrap() {
        InnerMessage::GroupReceipt { room_id, msg_uids, read } => {
            assert_eq!(room_id, "room-1");
            assert_eq!(msg_uids, vec!["out-9".to_string(), "out-10".to_string()]);
            assert!(read);
        }
        other => panic!("expected GroupReceipt, got {other:?}"),
    }
}

#[test]
fn chat_payload_msg_uid_roundtrip_and_omitted_when_none() {
    // Group message: msg_uid set → appears on the wire and comes back on decode.
    let g = ChatPayload::new(None, None, InnerMessage::Text { body: "g".into() })
        .with_msg_uid("out-42");
    let bytes = g.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(json.contains(r#""msg_uid":"out-42""#), "json: {json}");
    assert_eq!(ChatPayload::decode(&bytes).unwrap().msg_uid.as_deref(), Some("out-42"));

    // 1:1 message: msg_uid None → not written to the wire (skip_if), compatible with old clients.
    let d = ChatPayload::new(None, None, InnerMessage::Text { body: "d".into() });
    let json = String::from_utf8(d.encode()).unwrap();
    assert!(!json.contains("msg_uid"), "msg_uid omitted, json: {json}");
}

#[test]
fn inner_message_activity_control_roundtrip() {
    let msg = InnerMessage::Activity {
        plugin_id: "note".into(),
        activity_id: "act-x".into(),
        seq: 0,
        event: ActivityEvent::Leave,
        payload: "{}".into(),
        scope: ActivityWireScope::Direct,

        reads_batch: false,
    };
    let bytes = msg.encode();
    let json = String::from_utf8(bytes.clone()).unwrap();
    // Pin the serde JSON shape we ship over Olm:
    // top level "kind":"activity", nested "event":{"type":"leave"}.
    assert!(json.contains(r#""kind":"activity""#));
    assert!(json.contains(r#""event":{"type":"leave"}"#));
    let decoded = InnerMessage::decode(&bytes).unwrap();
    if let InnerMessage::Activity { event, .. } = decoded {
        assert_eq!(event, ActivityEvent::Leave);
    } else {
        panic!("expected Activity variant");
    }
}
#[test]
fn chat_payload_text_wire_byte_snapshot() {
    let p = ChatPayload::new(
        Some("t1".into()),
        Some("General".into()),
        InnerMessage::Text {
            body: "hello".into(),
        },
    )
    .with_msg_uid("u1");
    let bytes = p.encode();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        r#"{"schema_version":1,"thread_id":"t1","thread_title":"General","msg_uid":"u1","kind":"text","body":"hello"}"#
    );
    // decode → re-encode == the original bytes (inverse-stable).
    assert_eq!(ChatPayload::decode(&bytes).unwrap().encode(), bytes);
}

#[test]
fn inner_message_wire_byte_snapshots() {
    assert_eq!(
        String::from_utf8(InnerMessage::Text { body: "hi".into() }.encode()).unwrap(),
        r#"{"kind":"text","body":"hi"}"#
    );
    assert_eq!(
        String::from_utf8(
            InnerMessage::Location {
                latitude: 1.5,
                longitude: 2.5,
                label: None,
                accuracy: None,
            }
            .encode()
        )
        .unwrap(),
        r#"{"kind":"location","latitude":1.5,"longitude":2.5}"#
    );
    assert_eq!(
        String::from_utf8(InnerMessage::HtmlMessage { html: "<b>y</b>".into() }.encode())
            .unwrap(),
        r#"{"kind":"html_message","html":"<b>y</b>"}"#
    );
}

#[test]
fn activity_event_wire_byte_snapshots() {
    assert_eq!(
        String::from_utf8(serde_json::to_vec(&ActivityEvent::Invite).unwrap()).unwrap(),
        r#"{"type":"invite"}"#
    );
    assert_eq!(
        String::from_utf8(
            serde_json::to_vec(&ActivityEvent::Domain {
                name: "note".into()
            })
            .unwrap()
        )
        .unwrap(),
        r#"{"type":"domain","name":"note"}"#
    );
}

/// A heartbeat from a client built before `active` existed must read as a START.
///
/// `#[serde(default)]` on a `bool` yields `false`, which would make every older peer's heartbeat
/// decode as a STOP — the indicator would simply never appear against them, with nothing in any
/// log to say why. Hence the explicit default, and hence this test.
#[test]
fn an_older_clients_typing_still_means_started() {
    let wire = br#"{"kind":"typing","ts":1753400000000}"#;
    match serde_json::from_slice::<InnerMessage>(wire).expect("old wire must parse") {
        InnerMessage::Typing { active, ts, room } => {
            assert!(active, "a missing flag means the sender only ever sent heartbeats");
            assert_eq!(ts, 1753400000000);
            assert!(room.is_none());
        }
        other => panic!("expected Typing, got {other:?}"),
    }
}

/// A heartbeat is byte-identical to what shipped before the flag, so the common case — one frame
/// every three seconds — costs nothing new on the wire and an older client sees what it always saw.
/// `corpus/golden_wire_v1.json` is the other half of this claim: it was recorded before the field
/// existed and still replays.
#[test]
fn a_heartbeat_puts_no_new_bytes_on_the_wire() {
    let json = serde_json::to_string(&InnerMessage::Typing {
        room: None,
        ts: 1753400000000,
        active: true,
    })
    .unwrap();
    assert_eq!(json, r#"{"kind":"typing","ts":1753400000000}"#);
}

/// Only the stop carries the flag, and it round-trips.
#[test]
fn a_stop_is_carried_and_read_back() {
    let stop = InnerMessage::Typing { room: None, ts: 1753400000000, active: false };
    let json = serde_json::to_string(&stop).unwrap();
    assert!(json.contains(r#""active":false"#), "{json}");
    match serde_json::from_str::<InnerMessage>(&json).unwrap() {
        InnerMessage::Typing { active, .. } => assert!(!active),
        other => panic!("expected Typing, got {other:?}"),
    }
}

/// A voice note's length and waveform survive the wire, beside a caption, and anything a
/// sender could malform reads as "no voice meta" rather than an error.
#[test]
fn voice_meta_roundtrip_and_rejects_malformed() {
    let meta = VoiceNoteMeta { duration_ms: 12_340, waveform: vec![0, 40, 255, 128] };
    let p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() })
        .with_media_meta(Some("caption"), None, None, None)
        .with_voice(&meta);
    let d = ChatPayload::decode(&p.encode()).unwrap();
    assert_eq!(d.voice(), Some(meta));
    assert_eq!(d.caption().as_deref(), Some("caption"), "the caption is kept beside it");

    let with_ext = |voice: serde_json::Value| {
        let mut p = ChatPayload::new(None, None, InnerMessage::Text { body: "x".into() });
        p.ext = serde_json::json!({ "voice": voice });
        p.voice()
    };
    assert_eq!(with_ext(serde_json::json!({ "ms": 3_600_001u64, "wave": [] })), None, "too long");
    assert_eq!(with_ext(serde_json::json!({ "ms": 1000, "wave": [300] })), None, "level past 255");
    let long: Vec<u8> = vec![1; VoiceNoteMeta::MAX_BARS + 1];
    assert_eq!(with_ext(serde_json::json!({ "ms": 1000, "wave": long })), None, "too many bars");
    assert_eq!(with_ext(serde_json::json!({ "wave": [1] })), None, "no length");
}

fn library_card() -> LibraryCardRef {
    LibraryCardRef {
        room_id: "room-1".into(),
        author_id: "ayse".into(),
        item_id: "aaaaaaaaaaaaaaaaaaaaaa".into(),
        title: "Week 4 · Stacks".into(),
        item_kind: "recording".into(),
        media: "audio".into(),
        duration_ms: Some(3_840_000),
    }
}

/// The library card's field names are the wire format, pinned, and it survives a round trip in a
/// group payload beside its `msg_uid`.
#[test]
fn library_card_roundtrip_and_wire_names() {
    let p = ChatPayload::new(None, None, InnerMessage::LibraryCard(library_card()))
        .with_msg_uid("lib-1");
    let json: serde_json::Value = serde_json::from_slice(&p.encode()).unwrap();
    assert_eq!(json["kind"], "library_card");
    for key in ["room_id", "author_id", "item_id", "title", "item_kind", "media", "duration_ms"] {
        assert!(json.get(key).is_some(), "{key} missing: {json}");
    }
    match ChatPayload::decode(&p.encode()).unwrap().inner {
        InnerMessage::LibraryCard(c) => assert_eq!(c, library_card()),
        other => panic!("expected LibraryCard, got {other:?}"),
    }
    // A card with no length (a material) leaves the field out rather than writing null.
    let mut material = library_card();
    material.duration_ms = None;
    let json = String::from_utf8(InnerMessage::LibraryCard(material).encode()).unwrap();
    assert!(!json.contains("duration_ms"), "{json}");
}

/// What a build that predates the card does with one: the whole message lands in the catch-all,
/// title and all, so it is stored and shown as an unsupported message — never a decode failure
/// that would stall the room. The enum below has the shape such a build has: no `LibraryCard`.
#[test]
fn an_older_build_reads_a_library_card_as_unknown() {
    #[derive(Debug, serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum OlderInner {
        Text { body: String },
        #[serde(other)]
        Unknown,
    }
    let wire = InnerMessage::LibraryCard(library_card()).encode();
    let old: OlderInner = serde_json::from_slice(&wire).expect("an older build still decodes it");
    assert!(matches!(old, OlderInner::Unknown), "got {old:?}");
}

/// A reaction inside a payload: its fields survive the flatten beside the payload's own
/// `msg_uid`, a removal leaves `emoji` off the wire, and only my own devices' copy says
/// `conversation`.
#[test]
fn a_reaction_round_trips_beside_the_payloads_msg_uid() {
    let r = InnerMessage::Reaction {
        target_uid: "loc-1".into(),
        target_by: "u-mert".into(),
        emoji: Some("👍".into()),
        at_ms: 1_790_000_000_000,
        conversation: None,
    };
    let p = ChatPayload::new(None, None, r).with_msg_uid("rx-1");
    let json = String::from_utf8(p.encode()).unwrap();
    assert!(json.contains(r#""kind":"reaction""#), "{json}");
    assert!(!json.contains("conversation"), "{json}");
    let back = ChatPayload::decode(json.as_bytes()).unwrap();
    assert_eq!(back.msg_uid.as_deref(), Some("rx-1"));
    match back.inner {
        InnerMessage::Reaction { target_uid, target_by, emoji, at_ms, conversation } => {
            assert_eq!(target_uid, "loc-1");
            assert_eq!(target_by, "u-mert");
            assert_eq!(emoji.as_deref(), Some("👍"));
            assert_eq!(at_ms, 1_790_000_000_000);
            assert_eq!(conversation, None);
        }
        other => panic!("expected Reaction, got {other:?}"),
    }
    let removal = InnerMessage::Reaction {
        target_uid: "loc-1".into(),
        target_by: "u-mert".into(),
        emoji: None,
        at_ms: 2,
        conversation: Some("room-1".into()),
    };
    let json = String::from_utf8(removal.encode()).unwrap();
    assert!(!json.contains("emoji"), "{json}");
    assert!(json.contains(r#""conversation":"room-1""#), "{json}");
}

/// An older build lands a reaction in its catch-all — no decode failure that would stall the
/// conversation (what it then shows is that build's `Unknown` row).
#[test]
fn an_older_build_reads_a_reaction_as_unknown() {
    #[derive(Debug, serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum OlderInner {
        Text { body: String },
        #[serde(other)]
        Unknown,
    }
    let wire = InnerMessage::Reaction {
        target_uid: "u".into(),
        target_by: "b".into(),
        emoji: Some("❤️".into()),
        at_ms: 1,
        conversation: None,
    }
    .encode();
    let old: OlderInner = serde_json::from_slice(&wire).expect("an older build still decodes it");
    assert!(matches!(old, OlderInner::Unknown), "got {old:?}");
}

/// A room delete keeps its target's two names beside the payload's own `msg_uid`, and an older
/// build lands it in its catch-all rather than failing the decrypt chain.
#[test]
fn a_room_delete_round_trips_and_an_older_build_reads_unknown() {
    let d = InnerMessage::RoomDelete { target_uid: "loc-1".into(), target_by: "u-mert".into() };
    let p = ChatPayload::new(None, None, d).with_msg_uid("del-1");
    let json = String::from_utf8(p.encode()).unwrap();
    assert!(json.contains(r#""kind":"room_delete""#), "{json}");
    let back = ChatPayload::decode(json.as_bytes()).unwrap();
    assert_eq!(back.msg_uid.as_deref(), Some("del-1"));
    match back.inner {
        InnerMessage::RoomDelete { target_uid, target_by } => {
            assert_eq!(target_uid, "loc-1");
            assert_eq!(target_by, "u-mert");
        }
        other => panic!("expected RoomDelete, got {other:?}"),
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum OlderInner {
        Text { body: String },
        #[serde(other)]
        Unknown,
    }
    let old: OlderInner = serde_json::from_str(&json).expect("an older build still decodes it");
    assert!(matches!(old, OlderInner::Unknown), "got {old:?}");
}

/// An edit carries its whole new content nested under its own `kind`, beside the payload's own
/// `msg_uid`, and only the self-copy says `conversation`.
#[test]
fn an_edit_round_trips_with_its_content_nested() {
    let e = InnerMessage::MessageEdit {
        target_uid: "loc-1".into(),
        target_by: "u-mert".into(),
        content: Box::new(InnerMessage::Text { body: "fixed".into() }),
        mentions: Vec::new(),
        at_ms: 1_790_000_000_000,
        conversation: None,
    };
    let p = ChatPayload::new(None, None, e).with_msg_uid("ed-1");
    let json = String::from_utf8(p.encode()).unwrap();
    assert!(json.contains(r#""kind":"message_edit""#), "{json}");
    assert!(json.contains(r#""content":{"kind":"text","body":"fixed"}"#), "{json}");
    assert!(json.contains(r#""invisible":true"#), "{json}");
    assert!(!json.contains("mentions") && !json.contains("conversation"), "{json}");
    let back = ChatPayload::decode(json.as_bytes()).unwrap();
    assert_eq!(back.msg_uid.as_deref(), Some("ed-1"));
    assert!(back.invisible && !back.drops_silently(), "a build that knows it reads it");
    match back.inner {
        InnerMessage::MessageEdit { target_uid, target_by, content, at_ms, conversation, .. } => {
            assert_eq!((target_uid.as_str(), target_by.as_str()), ("loc-1", "u-mert"));
            assert!(matches!(*content, InnerMessage::Text { ref body } if body == "fixed"));
            assert_eq!(at_ms, 1_790_000_000_000);
            assert_eq!(conversation, None);
        }
        other => panic!("expected MessageEdit, got {other:?}"),
    }
}

/// A kind this build does not know, sent by a build that marked it invisible, is dropped
/// silently; an unknown kind without the mark is still the "Unsupported message" row it was.
/// A visible message never carries the mark, so its payload is byte for byte what it was.
#[test]
fn an_unknown_invisible_kind_drops_silently_and_a_visible_one_does_not() {
    let marked = br#"{"kind":"some_later_control","invisible":true,"x":1}"#;
    let p = ChatPayload::decode(marked).unwrap();
    assert!(matches!(p.inner, InnerMessage::Unknown));
    assert!(p.drops_silently());
    let unmarked = br#"{"kind":"some_later_card","x":1}"#;
    assert!(!ChatPayload::decode(unmarked).unwrap().drops_silently());
    let text = ChatPayload::new(None, None, InnerMessage::Text { body: "hi".into() });
    let json = String::from_utf8(text.encode()).unwrap();
    assert!(!json.contains("invisible"), "{json}");
    assert!(ChatPayload::new(None, None, InnerMessage::Reaction {
        target_uid: "u".into(),
        target_by: "b".into(),
        emoji: None,
        at_ms: 1,
        conversation: None,
    })
    .invisible);
    let delete = InnerMessage::RoomDelete { target_uid: "u".into(), target_by: "b".into() };
    assert!(ChatPayload::new(None, None, delete).invisible);
}

/// The two takeover controls (`docs/PRIMARY_DEVICE_LOSS_PLAN.md`) round-trip and carry the
/// invisible mark, so a build that predates them drops them instead of drawing junk.
#[test]
fn the_takeover_controls_are_invisible_and_round_trip() {
    let copy = InnerMessage::EscrowCopy { escrow_id: "esc-1".into(), copy_b64: "U1pHQg".into() };
    let json = String::from_utf8(ChatPayload::new(None, None, copy).encode()).unwrap();
    assert!(json.contains(r#""kind":"escrow_copy""#) && json.contains(r#""invisible":true"#), "{json}");
    match ChatPayload::decode(json.as_bytes()).unwrap().inner {
        InnerMessage::EscrowCopy { escrow_id, copy_b64 } => {
            assert_eq!((escrow_id.as_str(), copy_b64.as_str()), ("esc-1", "U1pHQg"));
        }
        other => panic!("expected EscrowCopy, got {other:?}"),
    }
    let notice = InnerMessage::TakeoverNotice { request_id: "tko-1".into() };
    let json = String::from_utf8(ChatPayload::new(None, None, notice).encode()).unwrap();
    assert!(json.contains(r#""kind":"takeover_notice""#) && json.contains(r#""invisible":true"#), "{json}");
    // What a build that does not know them sees: an invisible unknown, dropped silently.
    let older = json.replace("takeover_notice", "some_kind_this_build_lacks");
    assert!(ChatPayload::decode(older.as_bytes()).unwrap().drops_silently());
}
