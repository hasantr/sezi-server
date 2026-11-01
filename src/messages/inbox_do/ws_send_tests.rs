//! The WS `send` frame's `silent` and `urgent` flags, from the frame to the recipient inbox's
//! `/notify` body.

use super::super::NotifyBody;
use super::{ws_notify_payload, ws_send_wake};
use crate::push::coalesce::WakeIntent;
use serde_json::json;

#[test]
fn only_a_json_true_counts() {
    assert_eq!(ws_send_wake(&json!({ "type": "send", "silent": true })), WakeIntent::Silent);
    assert_eq!(ws_send_wake(&json!({ "type": "send", "urgent": true })), WakeIntent::Urgent);
    assert_eq!(ws_send_wake(&json!({ "type": "send", "silent": false })), WakeIntent::Ordinary);
    // An older client sends neither field: an ordinary wake, as every WS send was before.
    assert_eq!(ws_send_wake(&json!({ "type": "send" })), WakeIntent::Ordinary);
    // Anything else is not a promise: an ordinary wake.
    assert_eq!(ws_send_wake(&json!({ "type": "send", "silent": "true" })), WakeIntent::Ordinary);
    assert_eq!(ws_send_wake(&json!({ "type": "send", "urgent": 1 })), WakeIntent::Ordinary);
    // Urgent implies a wake: a ring that wakes nobody is the failure the flag exists for.
    assert_eq!(ws_send_wake(&json!({ "silent": true, "urgent": true })), WakeIntent::Urgent);
}

/// The flags reach the recipient's inbox as the HTTP path's do — `silent` is the field
/// `notify_inner` persists on the row (so the backstop skips it), and both are what the
/// `/notify` arm reads before waking.
#[test]
fn the_flags_reach_the_inboxs_notify_body() {
    for (wake, silent, urgent) in [
        (WakeIntent::Silent, true, false),
        (WakeIntent::Ordinary, false, false),
        (WakeIntent::Urgent, false, true),
    ] {
        let body = ws_notify_payload("s", "sd", "r", Some("rd"), "ZW52ZWxvcGU=", wake, false);
        let parsed: NotifyBody = serde_json::from_str(&body).unwrap();
        assert_eq!((parsed.silent, parsed.urgent), (silent, urgent));
        assert!(!parsed.live);
        assert_eq!(parsed.recipient_device_id.as_deref(), Some("rd"));
        assert_eq!(parsed.recipient_id.as_deref(), Some("r"));
        assert_eq!(parsed.sender_device_id.as_deref(), Some("sd"));
        assert_eq!(parsed.group_id, None, "the WS path is 1:1 only");
    }
    // A body from an older worker carries neither: an ordinary wake.
    let parsed: NotifyBody =
        serde_json::from_str(r#"{"sender_id":"s","envelope_b64":"e"}"#).unwrap();
    assert!(!parsed.silent && !parsed.urgent);
}

/// The `/notify` arm wakes only for a stored, not-live, non-silent envelope and passes the
/// urgency on — and the WS arm no longer wakes anybody itself. Needles split with `concat!` so
/// they cannot match themselves.
#[test]
fn a_silent_ws_send_wakes_nobody() {
    let inbox = include_str!("mod.rs");
    assert!(
        inbox.contains(concat!("if !delivered_live && !notified.deduped && ", "!body.silent && !body.live {")),
        "the /notify arm must not wake for a silent or a live envelope"
    );
    assert!(inbox.contains(concat!("urgent: body", ".urgent")), "the /notify arm drops urgency");
    let ws = include_str!("ws.rs");
    assert!(!ws.contains(concat!("maybe_push", "_wake(")), "the WS arm wakes nobody itself");
    assert!(ws.contains(concat!("[push] skipped (silent ws)", " 1:1")));
    assert!(ws.contains(concat!("[push] waking ws", " 1:1")));
}

/// A WS `send` frame's `live` (the core's typing indicator) reaches the recipient inbox's
/// `/notify` body; an older client's frame, without it, is stored as always (`live_frames.rs`).
#[test]
fn the_live_flag_reaches_the_inboxs_notify_body() {
    use super::ws_send_live;
    assert!(ws_send_live(&json!({ "type": "send", "live": true, "silent": true })));
    assert!(!ws_send_live(&json!({ "type": "send", "silent": true })));
    assert!(!ws_send_live(&json!({ "type": "send", "live": "true" })), "only a JSON true");
    for live in [true, false] {
        let body =
            ws_notify_payload("s", "sd", "r", Some("rd"), "ZW52ZWxvcGU=", WakeIntent::Silent, live);
        let parsed: NotifyBody = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.live, live);
        assert!(parsed.silent, "a live frame is silent control traffic to an older inbox too");
    }
}

/// The inbox decides before it stores: the drop check sits ahead of the INSERT and after the
/// dedup lookup, and a pushed live row is deleted again (`live_frames.rs`). Source-level, as the
/// DO's storage cannot run here; needles split with `concat!`.
#[test]
fn a_live_envelope_is_judged_before_it_is_stored() {
    let src = include_str!("message.rs");
    let dedup = src.find(concat!("self.dedup_lookup(", "sender_id")).expect("dedup lookup");
    let drop = src.find(concat!("fate == live_frames::LiveFate::", "Drop")).expect("drop check");
    let insert = src.find(concat!("INSERT INTO pending (sender_id, ", "envelope_b64")).expect("insert");
    let push_only = src.find(concat!("fate == live_frames::LiveFate::", "PushOnly")).expect("delete");
    assert!(dedup < drop && drop < insert && insert < push_only, "the live decision moved");
    let inbox = include_str!("mod.rs");
    let dropped = inbox.find(concat!("if notified.", "dropped {")).expect("the dropped answer");
    let bot = inbox.find(concat!("return self.", "bot_notified(id)")).expect("the bot branch");
    assert!(dropped < bot, "a dropped envelope must not reach a bot's reader");
}
