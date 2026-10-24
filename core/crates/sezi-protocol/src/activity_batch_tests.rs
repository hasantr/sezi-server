use super::*;
use crate::inner::ChatPayload;

/// `InnerMessage` has no `PartialEq`; its JSON is what the wire carries anyway.
fn json(inner: &InnerMessage) -> serde_json::Value {
    serde_json::to_value(inner).expect("serialises")
}

fn item(seq: u64, scope: ActivityWireScope) -> ActivityBatchItem {
    ActivityBatchItem {
        plugin_id: "draw".into(),
        activity_id: "act-1".into(),
        seq,
        event: ActivityEvent::Domain { name: "stroke".into() },
        payload: format!("{{\"p\":{seq}}}"),
        scope,
    }
}

/// A batch survives the trip through the envelope payload, in order.
#[test]
fn a_batch_round_trips_through_the_chat_payload() {
    let events = vec![item(1, ActivityWireScope::Direct), item(2, ActivityWireScope::Direct)];
    let chat = ChatPayload::new(None, None, InnerMessage::ActivityBatch { events: events.clone() });
    let back = ChatPayload::decode(&chat.encode()).expect("decodes");
    let InnerMessage::ActivityBatch { events: got } = back.inner else {
        panic!("not a batch: {:?}", back.inner);
    };
    assert_eq!(got, events);
}

/// The capability flag costs an older receiver nothing: written only when set, and an event
/// without it (an older sender's) reads as one that does not batch.
#[test]
fn the_flag_is_absent_unless_set_and_defaults_to_false() {
    let single = |reads_batch| InnerMessage::Activity {
        plugin_id: "draw".into(),
        activity_id: "act-1".into(),
        seq: 1,
        event: ActivityEvent::Join,
        payload: "{}".into(),
        scope: ActivityWireScope::Direct,
        reads_batch,
    };
    let old = String::from_utf8(ChatPayload::new(None, None, single(false)).encode()).unwrap();
    assert!(!old.contains("reads_batch"), "an unset flag must not reach the wire: {old}");
    let back = ChatPayload::decode(old.as_bytes()).expect("decodes");
    assert_eq!(json(&back.inner), json(&single(false)));
    let new = ChatPayload::new(None, None, single(true)).encode();
    assert_eq!(json(&ChatPayload::decode(&new).expect("decodes").inner), json(&single(true)));
}

/// What lets an OLDER receiver read a current sender's event: a field it does not know is
/// ignored, as `reads_batch` is by a build from before it — shown here with a field nobody knows.
#[test]
fn an_unknown_field_on_an_activity_is_ignored() {
    let json = br#"{"kind":"activity","plugin_id":"draw","activity_id":"act-1","seq":3,"event":{"type":"join"},"payload":"{}","scope":{"type":"direct"},"from_the_future":true}"#;
    let back = ChatPayload::decode(json).expect("decodes");
    assert!(matches!(back.inner, InnerMessage::Activity { seq: 3, reads_batch: false, .. }));
}

/// A batch holding one of a room's events reaches every device of the recipient, as a single
/// room event does; a batch of 1:1 events alone is classified like a 1:1 event.
#[test]
fn a_batch_fans_out_when_any_event_is_a_rooms() {
    let room = ActivityWireScope::Room { room_id: "g".into() };
    let direct = InnerMessage::ActivityBatch { events: vec![item(1, ActivityWireScope::Direct)] };
    let mixed = InnerMessage::ActivityBatch {
        events: vec![item(1, ActivityWireScope::Direct), item(2, room)],
    };
    assert!(!direct.requires_device_fanout());
    assert!(mixed.requires_device_fanout());
}

/// `from_single` carries every field of the event across, and nothing else qualifies.
#[test]
fn from_single_takes_an_activity_and_only_an_activity() {
    let single = InnerMessage::Activity {
        plugin_id: "draw".into(),
        activity_id: "act-1".into(),
        seq: 7,
        event: ActivityEvent::Domain { name: "stroke".into() },
        payload: "{\"p\":7}".into(),
        scope: ActivityWireScope::Direct,
        reads_batch: true,
    };
    assert_eq!(ActivityBatchItem::from_single(&single), Some(item(7, ActivityWireScope::Direct)));
    assert_eq!(ActivityBatchItem::from_single(&InnerMessage::Text { body: "x".into() }), None);
    assert!(batch_wire_len(&[item(1, ActivityWireScope::Direct)]) < 200);
}
