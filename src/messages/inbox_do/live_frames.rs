//! Live-only frames: an envelope worth something only to a device that is connected right now.
//!
//! The sender marks a 1:1 send `live: true` (today only the typing indicator, the core's
//! `wake_hint`). Such an envelope is pushed to a recipient device whose socket is genuinely live
//! (`ws_is_fresh`) and is otherwise DROPPED: no `pending` row, no wake, no backstop, nothing
//! flushed on the next connect. Typing to a device that is not there is worthless, and stored it
//! sat ahead of the text that followed — the phone could then not read that text from its push,
//! because the push said a row from the same sender device was queued ahead of it (`older`,
//! measured on a POCO 2026-11-01: 28 of 29 carried frames refused).
//!
//! A pushed live frame needs a relay id the recipient can ack, so its row is written (which mints
//! a fresh AUTOINCREMENT id, never reused) and deleted again straight after the push. The
//! recipient's ack then finds nothing to delete, and so forwards no `delivered` receipt to the
//! sender — the receipt chain a typing frame used to set off is gone with it.
//!
//! The sender still gets one ack per device. A dropped device's ack names [`LIVE_DROPPED_ID`]
//! (0, an id AUTOINCREMENT never hands out) and says `dropped: true`; the core treats it as sent.
//! An older relay ignores `live` and stores the envelope as the silent control frame it also is;
//! an older app never sets it. A group send is never live (Megolm goes through `/notify-member`).

/// The id a dropped live envelope is acked with: `pending.id` is AUTOINCREMENT from 1, so 0
/// names no row anywhere.
pub(crate) const LIVE_DROPPED_ID: i64 = 0;

/// What the inbox does with one envelope for one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveFate {
    /// Store it until acked — every envelope that is not live.
    Store,
    /// Push it to the live socket, and keep no row.
    PushOnly,
    /// No live socket: nothing is stored, pushed or woken.
    Drop,
}

/// `live` is the sender's flag, `group` whether it is a room's envelope (never live), and
/// `any_fresh_target` whether a socket of the target device sent a frame within the liveness
/// window.
pub(crate) fn live_fate(live: bool, group: bool, any_fresh_target: bool) -> LiveFate {
    match (live && !group, any_fresh_target) {
        (false, _) => LiveFate::Store,
        (true, true) => LiveFate::PushOnly,
        (true, false) => LiveFate::Drop,
    }
}

/// The `/notify` answer: the row id and whether a live socket took it, plus `dropped` for a live
/// envelope nobody was there for (written only then, so every other answer is what it was).
pub(crate) fn notify_answer(id: i64, delivered_live: bool, dropped: bool) -> serde_json::Value {
    let mut v = serde_json::json!({ "id": id, "delivered_live": delivered_live });
    if dropped {
        v["dropped"] = serde_json::Value::Bool(true);
    }
    v
}

/// One device's entry in a send's `acks` (HTTP `/messages/send` and the WS `send_ack_batch`).
pub(crate) fn ack_item(device_id: Option<&str>, id: i64, dropped: bool) -> serde_json::Value {
    let mut v = serde_json::json!({ "device_id": device_id, "id": id });
    if dropped {
        v["dropped"] = serde_json::Value::Bool(true);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a live 1:1 envelope is ever kept out of `pending`; a group's is stored whatever it
    /// says, and an ordinary one is stored whether or not anyone is connected.
    #[test]
    fn only_a_live_one_to_one_envelope_skips_the_queue() {
        assert_eq!(live_fate(false, false, false), LiveFate::Store);
        assert_eq!(live_fate(false, false, true), LiveFate::Store);
        assert_eq!(live_fate(true, false, true), LiveFate::PushOnly);
        assert_eq!(live_fate(true, false, false), LiveFate::Drop);
        assert_eq!(live_fate(true, true, false), LiveFate::Store, "a room's envelope is never live");
        assert_eq!(live_fate(true, true, true), LiveFate::Store);
    }

    /// The answers an older caller parses are unchanged; only a dropped one says so, under the id
    /// no row has.
    #[test]
    fn a_dropped_envelope_is_acked_under_the_id_no_row_has() {
        assert_eq!(
            notify_answer(7, true, false),
            serde_json::json!({ "id": 7, "delivered_live": true })
        );
        assert_eq!(
            notify_answer(LIVE_DROPPED_ID, false, true),
            serde_json::json!({ "id": 0, "delivered_live": false, "dropped": true })
        );
        assert_eq!(ack_item(Some("d1"), 9, false), serde_json::json!({ "device_id": "d1", "id": 9 }));
        assert_eq!(
            ack_item(Some("d1"), LIVE_DROPPED_ID, true),
            serde_json::json!({ "device_id": "d1", "id": 0, "dropped": true })
        );
    }

    /// The flag is read from both send bodies: HTTP's `SendBody` and the WS frame.
    #[test]
    fn the_flag_reaches_the_inboxs_notify_body() {
        let parsed: super::super::NotifyBody =
            serde_json::from_str(r#"{"sender_id":"s","envelope_b64":"e","live":true,"silent":true}"#)
                .unwrap();
        assert!(parsed.live && parsed.silent);
        let older: super::super::NotifyBody =
            serde_json::from_str(r#"{"sender_id":"s","envelope_b64":"e"}"#).unwrap();
        assert!(!older.live, "a body from an older worker is never live");
    }
}
