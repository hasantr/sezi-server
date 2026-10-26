//! What only a bot receives, and what a bot must never be sent (`docs/BOTS_BUILD.md` §2.6–2.7).
//!
//! A member's kernel sends a bot a [`InnerMessage::BotCall`] or [`InnerMessage::BotTap`]; no relay
//! or kernel routes either to a human. One that reaches a human kernel anyway is a bug or a
//! forgery, so its inbound paths ack it and drop it, beside the local-only kinds.
//!
//! The other direction is the rule of the whole bot design: a bot reads only what is addressed to
//! it. [`InnerMessage::carries_room_secret`] names every inner that would let its reader open, or
//! read, a room's traffic; the kernel's dispatch refuses to send any of them to a bot.

use crate::inner::{ActivityWireScope, InnerMessage};

impl InnerMessage {
    /// Is this addressed to a bot only? `true` → a human kernel acks and drops it, never stores
    /// it (`kernel/inbound_control.rs` and `kernel/groups.rs`, beside `is_local_only`).
    pub fn is_bot_bound(&self) -> bool {
        matches!(self, InnerMessage::BotCall { .. } | InnerMessage::BotTap { .. })
    }

    /// Does this carry a room's secret — a key that opens the room's messages or its plugin
    /// data, or the room's own content? `true` → never sent to a bot (`kernel/bots.rs`, at the
    /// dispatch choke points, `bot/room-secret-refused`).
    ///
    /// The doc's list (a room key, its gossip, a plugin epoch key, a history snapshot, a room's
    /// plugin record) plus everything else that is a room's and not the bot's: my plaintext copy
    /// of a room message (`GroupOutboundCopy`, which only my own devices should ever get), a
    /// room's plugin install (its code key), and a room's co-presence events. A bot is called
    /// with a [`InnerMessage::BotCall`], which is the one room-derived thing it may read.
    pub fn carries_room_secret(&self) -> bool {
        match self {
            InnerMessage::RoomKeyShare { .. }
            | InnerMessage::RoomKeyGossip { .. }
            | InnerMessage::GroupOutboundCopy { .. }
            | InnerMessage::PluginEpochKeyShare { .. }
            | InnerMessage::PluginRecordSnapshot { .. }
            | InnerMessage::PluginRecord { room: Some(_), .. }
            | InnerMessage::PluginInstall { room: Some(_), .. }
            | InnerMessage::Activity { scope: ActivityWireScope::Room { .. }, .. } => true,
            InnerMessage::ActivityBatch { events } => {
                events.iter().any(|e| e.scope.room_id().is_some())
            }
            // A room's typing presence says who is writing there right now.
            InnerMessage::Typing { room: Some(_), .. } => true,
            // A room call's signal: its join carries the call's SFU frame key pairwise, the rest
            // say who is in the room's call. A bot is never a call participant.
            InnerMessage::CallSignal { data, .. } => serde_json::from_str::<serde_json::Value>(data)
                .ok()
                .is_some_and(|v| v.get("room_id").is_some_and(|r| !r.is_null())),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_bot_kinds_are_bot_bound_and_they_round_trip() {
        let call = InnerMessage::BotCall {
            room_id: "r".into(),
            msg_uid: "m".into(),
            body: "/hatirlat yarin".into(),
            lang: None,
            utc_offset_min: Some(180),
        };
        let json = serde_json::to_string(&call).unwrap();
        assert!(json.contains("\"kind\":\"bot_call\""), "{json}");
        let back: InnerMessage = serde_json::from_str(&json).unwrap();
        assert!(back.is_bot_bound());
        let tap: InnerMessage =
            serde_json::from_str(r#"{"kind":"bot_tap","origin_msg_uid":"m","action_id":"ok"}"#).unwrap();
        assert!(tap.is_bot_bound());
        assert!(!InnerMessage::Text { body: "hi".into() }.is_bot_bound());
        assert!(!InnerMessage::Unknown.is_bot_bound());
    }

    #[test]
    fn room_keys_and_room_data_carry_a_room_secret_and_a_call_does_not() {
        let key = InnerMessage::RoomKeyShare {
            room_id: "r".into(),
            session_id: "s".into(),
            session_key_b64: "k".into(),
        };
        assert!(key.carries_room_secret());
        let epoch = InnerMessage::PluginEpochKeyShare {
            room: "r".into(),
            plugin: "p".into(),
            epoch: 1,
            key_b64: "k".into(),
        };
        assert!(epoch.carries_room_secret());
        let record = |room: Option<&str>| InnerMessage::PluginRecord {
            plugin_id: "p".into(),
            collection: "c".into(),
            record_id: "x".into(),
            parent_id: None,
            op: "put".into(),
            fields_json: "{}".into(),
            lamport: 1,
            room: room.map(Into::into),
        };
        assert!(record(Some("r")).carries_room_secret());
        assert!(!record(None).carries_room_secret(), "a 1:1 record is the pair's own");
        let snapshot = InnerMessage::PluginRecordSnapshot { room: "r".into(), records: vec![] };
        assert!(snapshot.carries_room_secret());
        // What a member deliberately sends a bot: its call, a text, a pair-level request.
        let call = InnerMessage::BotCall {
            room_id: "r".into(),
            msg_uid: "m".into(),
            body: "yarın 10:00".into(),
            lang: None,
            utc_offset_min: None,
        };
        assert!(!call.carries_room_secret());
        assert!(!InnerMessage::Text { body: "hi".into() }.carries_room_secret());
        let ask = InnerMessage::RoomKeyRequest { room_id: "r".into(), session_id: None };
        assert!(!ask.carries_room_secret(), "asking a bot for ITS key gives it nothing");
        // A room call's join (its SFU frame key) and a room's typing are the room's.
        let join = |data: &str| InnerMessage::CallSignal {
            call_id: "c".into(),
            signal_type: "join".into(),
            data: data.into(),
        };
        assert!(join(r#"{"room_id":"r","frame_key":"k"}"#).carries_room_secret());
        assert!(!join(r#"{"sdp":"…"}"#).carries_room_secret(), "a 1:1 call names no room");
        assert!(!join("not json").carries_room_secret());
        let typing = |room: Option<&str>| InnerMessage::Typing {
            room: room.map(Into::into),
            ts: 1,
            active: true,
        };
        assert!(typing(Some("r")).carries_room_secret());
        assert!(!typing(None).carries_room_secret());
    }

    #[test]
    fn a_room_bot_notice_is_local_only() {
        let notice = InnerMessage::RoomBotNotice {
            bot_id: "b".into(),
            event: "added".into(),
            by: Some("a".into()),
        };
        assert!(notice.is_local_only());
        let json = serde_json::to_string(&notice).unwrap();
        assert!(json.contains("\"kind\":\"room_bot_notice\""), "{json}");
        let removed: InnerMessage =
            serde_json::from_str(r#"{"kind":"room_bot_notice","bot_id":"b","event":"removed"}"#)
                .unwrap();
        assert!(matches!(
            removed,
            InnerMessage::RoomBotNotice { ref bot_id, ref event, by: None }
                if bot_id == "b" && event == "removed"
        ));
    }

    /// Both travel inside a `ChatPayload`, which flattens the inner beside its own `msg_uid`: a
    /// variant field of that name would be shadowed and the frame would not decode.
    #[test]
    fn both_survive_the_payload_they_travel_in() {
        use crate::inner::ChatPayload;
        let call = InnerMessage::BotCall {
            room_id: "r".into(),
            msg_uid: "loc-7".into(),
            body: "@bot yarın kaçta?".into(),
            lang: Some("tr".into()),
            utc_offset_min: Some(180),
        };
        let tap = InnerMessage::BotTap { room_id: None, msg_uid: "b-1".into(), action_id: "yes".into() };
        for inner in [call, tap] {
            let back = ChatPayload::decode(&ChatPayload::new(None, None, inner.clone()).encode()).unwrap();
            // InnerMessage has no PartialEq: compare what it serializes to.
            assert_eq!(serde_json::to_value(&back.inner).unwrap(), serde_json::to_value(&inner).unwrap());
            assert_eq!(back.msg_uid, None);
        }
    }
}
