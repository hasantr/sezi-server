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
            // A room's scheduled message key opens a message the room will read; its cancel names
            // one the room was to read.
            InnerMessage::ScheduledKey { room: true, .. } | InnerMessage::ScheduledCancel { room: true, .. } => true,
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

impl InnerMessage {
    /// The room a frame that travels over 1:1 Olm BELONGS to — `None` for anything of a pair's
    /// own. A room's secrets (every kind [`InnerMessage::carries_room_secret`] names) and the asks
    /// that bring one (`RoomKeyRequest`, `PluginEpochRequest`, `PluginSnapshotRequest`,
    /// `PluginInstallRequest`), and everything else a room sends pairwise: a group's read and
    /// delivery receipts, its accept and membership notices, a plugin's removal, a room's
    /// co-presence, typing, live location and call signalling (a group call's join, leave, and
    /// its per-pair offers, answers and candidates all carry `room_id`).
    ///
    /// The kernel lets such a frame from someone I blocked through when the room is one we are
    /// both active in and they an active member of (P1, Hasan 2026-11-10/11: blocking stops 1:1
    /// only, so everything that belongs to a shared group works as for anyone — `kernel/
    /// blocked_rooms.rs`); every other frame from them stays dropped. A batch of co-presence
    /// events names a room only when all of it is one.
    ///
    /// The match is EXHAUSTIVE on purpose: a new kind is not a pair's own by default — whoever
    /// adds one decides here whether a room sends it pairwise.
    pub fn room_scope(&self) -> Option<String> {
        let room = match self {
            InnerMessage::RoomKeyShare { room_id, .. }
            | InnerMessage::RoomKeyGossip { room_id, .. }
            | InnerMessage::RoomKeyRequest { room_id, .. }
            | InnerMessage::GroupOutboundCopy { room_id, .. }
            | InnerMessage::GroupReceipt { room_id, .. }
            | InnerMessage::GroupJoinAccepted { room_id }
            | InnerMessage::GroupMembershipChanged { room_id } => room_id.clone(),
            InnerMessage::PluginEpochKeyShare { room, .. }
            | InnerMessage::PluginEpochRequest { room, .. }
            | InnerMessage::PluginRecordSnapshot { room, .. }
            | InnerMessage::PluginSnapshotRequest { room }
            | InnerMessage::PluginInstallRequest { room, .. }
            | InnerMessage::PluginRemoved { room, .. } => room.clone(),
            InnerMessage::PluginRecord { room: Some(room), .. }
            | InnerMessage::PluginInstall { room: Some(room), .. }
            | InnerMessage::Typing { room: Some(room), .. } => room.clone(),
            InnerMessage::Activity { scope: ActivityWireScope::Room { room_id }, .. } => room_id.clone(),
            InnerMessage::ActivityBatch { events } => {
                let first = events.first()?.scope.room_id()?;
                if events.iter().any(|e| e.scope.room_id() != Some(first)) {
                    return None;
                }
                first.to_string()
            }
            InnerMessage::ScheduledKey { room: true, conversation: Some(c), .. }
            | InnerMessage::ScheduledCancel { room: true, conversation: Some(c), .. } => c.clone(),
            // A room's live location goes per member over Olm and names the room; a 1:1 one names
            // nothing from a peer (`kernel/live_location.rs`).
            InnerMessage::LiveLocationUpdate { conversation: Some(c), .. } => c.clone(),
            InnerMessage::CallSignal { data, .. } => serde_json::from_str::<serde_json::Value>(data)
                .ok()?
                .get("room_id")?
                .as_str()?
                .to_string(),
            // A pair's own: 1:1 content and its receipts, a 1:1 call, the 1:1 halves of typing,
            // co-presence, plugins, scheduled messages and live location; reactions, edits, pins
            // and deletes, which a room sends over its Megolm, never pairwise. A group P2P file's
            // download ack names no room here; the kernel finds it from the offer it acks.
            InnerMessage::Text { .. }
            | InnerMessage::File(_)
            | InnerMessage::FileGroup { .. }
            | InnerMessage::RichText { .. }
            | InnerMessage::HtmlMessage { .. }
            | InnerMessage::Location { .. }
            | InnerMessage::LinkPreview { .. }
            | InnerMessage::Activity { .. }
            | InnerMessage::CallLog { .. }
            | InnerMessage::P2pBlobOffer { .. }
            | InnerMessage::P2pBlobReceived { .. }
            | InnerMessage::MediaReceived { .. }
            | InnerMessage::StateDigest { .. }
            | InnerMessage::Typing { room: None, .. }
            | InnerMessage::PluginRecord { room: None, .. }
            | InnerMessage::PluginInstall { room: None, .. }
            | InnerMessage::ScheduledKey { .. }
            | InnerMessage::ScheduledCancel { .. }
            | InnerMessage::LiveLocationUpdate { conversation: None, .. }
            | InnerMessage::Reaction { .. }
            | InnerMessage::RoomDelete { .. }
            | InnerMessage::MessageEdit { .. }
            | InnerMessage::Pin { .. }
            | InnerMessage::LibraryCard(_)
            | InnerMessage::ProfileAvatar { .. }
            // Local rows only, refused on arrival.
            | InnerMessage::RoomAccessNotice { .. }
            | InnerMessage::CallRecordingNotice { .. }
            | InnerMessage::PluginAddedNotice { .. }
            | InnerMessage::RoomBotNotice { .. }
            // A bot's.
            | InnerMessage::BotCall { .. }
            | InnerMessage::BotTap { .. }
            // My own devices' only.
            | InnerMessage::OutboundCopy { .. }
            | InnerMessage::DeviceStatePacket { .. }
            | InnerMessage::DeviceStateRequest { .. }
            | InnerMessage::ReadSelfSync { .. }
            | InnerMessage::DeleteSelfSync { .. }
            | InnerMessage::OwnFileRequest { .. }
            | InnerMessage::OwnFileOffer { .. }
            | InnerMessage::EscrowCopy { .. }
            | InnerMessage::TakeoverNotice { .. }
            | InnerMessage::HistoryPageRequest { .. }
            | InnerMessage::HistoryPageAnswer { .. }
            // Judged once fetched (`kernel/indirect/receive.rs`).
            | InnerMessage::Indirect(_)
            | InnerMessage::Unknown => return None,
        };
        (!room.is_empty()).then_some(room)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P1 (Hasan, 2026-11-10: blocking stops 1:1 only): every room secret names its room, and so
    /// does every ask for one; nothing of the pair's own does. The kernel admits such a frame from
    /// someone I blocked only for a room we are both active in.
    #[test]
    fn every_room_secret_and_every_ask_for_one_names_its_room() {
        let secrets = [
            InnerMessage::RoomKeyShare { room_id: "r".into(), session_id: "s".into(), session_key_b64: "k".into() },
            InnerMessage::PluginEpochKeyShare { room: "r".into(), plugin: "p".into(), epoch: 1, key_b64: "k".into() },
            InnerMessage::PluginRecordSnapshot { room: "r".into(), records: vec![] },
            InnerMessage::Typing { room: Some("r".into()), ts: 1, active: true },
            InnerMessage::CallSignal { call_id: "c".into(), signal_type: "join".into(), data: r#"{"room_id":"r"}"#.into() },
            serde_json::from_str(r#"{"kind":"scheduled_key","schedule_id":"x","key":"k","release_at_ms":1,"digest":"d","conversation":"r","room":true}"#).unwrap(),
            serde_json::from_str(r#"{"kind":"scheduled_cancel","schedule_id":"x","conversation":"r","room":true}"#).unwrap(),
        ];
        for s in &secrets {
            assert!(s.carries_room_secret(), "{s:?}");
            assert_eq!(s.room_scope().as_deref(), Some("r"), "{s:?}");
        }
        let asks = [
            InnerMessage::RoomKeyRequest { room_id: "r".into(), session_id: None },
            InnerMessage::PluginEpochRequest { room: "r".into(), plugin: "p".into(), floor: 1 },
            InnerMessage::PluginSnapshotRequest { room: "r".into() },
        ];
        for a in &asks {
            assert_eq!(a.room_scope().as_deref(), Some("r"), "{a:?}");
        }
        // Everything else a room sends pairwise (Hasan, 2026-11-11: everything of a shared group
        // works as for anyone): its receipts, its notices, a plugin's removal, a group call's
        // signalling of every kind, a room's live location.
        let room = [
            InnerMessage::GroupReceipt { room_id: "r".into(), msg_uids: vec!["m".into()], read: true, reads: vec![] },
            InnerMessage::GroupJoinAccepted { room_id: "r".into() },
            InnerMessage::GroupMembershipChanged { room_id: "r".into() },
            InnerMessage::PluginRemoved { room: "r".into(), plugin_id: "p".into() },
            InnerMessage::CallSignal { call_id: "g".into(), signal_type: "leave".into(), data: r#"{"room_id":"r"}"#.into() },
            InnerMessage::CallSignal { call_id: "g".into(), signal_type: "ice".into(), data: r#"{"room_id":"r","c":1}"#.into() },
            InnerMessage::LiveLocationUpdate {
                target_uid: "m".into(),
                target_by: "u".into(),
                latitude: 1.0,
                longitude: 2.0,
                accuracy: None,
                at_ms: 1,
                stopped: false,
                conversation: Some("r".into()),
            },
        ];
        for k in &room {
            assert_eq!(k.room_scope().as_deref(), Some("r"), "{k:?}");
        }
        // A pair's own stays a pair's own, whatever room it claims: a reaction, an edit or a pin
        // over Olm is the 1:1's (a room sends those over its Megolm).
        let own = [
            InnerMessage::Text { body: "hi".into() },
            InnerMessage::Typing { room: None, ts: 1, active: true },
            InnerMessage::CallSignal { call_id: "c".into(), signal_type: "invite".into(), data: r#"{"sdp":"x"}"#.into() },
            InnerMessage::CallSignal { call_id: "c".into(), signal_type: "answer".into(), data: "{}".into() },
            serde_json::from_str(r#"{"kind":"scheduled_key","schedule_id":"x","key":"k","release_at_ms":1,"digest":"d","conversation":"r","room":false}"#).unwrap(),
            InnerMessage::StateDigest { delivered_upto: 1, read_upto: 1, reply: false },
            InnerMessage::MediaReceived { media_id: "m".into() },
            InnerMessage::Reaction { target_uid: "m".into(), target_by: "u".into(), emoji: None, at_ms: 1, conversation: Some("r".into()) },
            InnerMessage::Pin { target_uid: "m".into(), target_by: "u".into(), pinned: true, until_ms: None, at_ms: 1, conversation: Some("r".into()) },
            InnerMessage::MessageEdit {
                target_uid: "m".into(),
                target_by: "u".into(),
                content: Box::new(InnerMessage::Text { body: "x".into() }),
                mentions: vec![],
                at_ms: 1,
                conversation: Some("r".into()),
            },
            InnerMessage::LiveLocationUpdate {
                target_uid: "m".into(),
                target_by: "u".into(),
                latitude: 1.0,
                longitude: 2.0,
                accuracy: None,
                at_ms: 1,
                stopped: true,
                conversation: None,
            },
            InnerMessage::RoomDelete { target_uid: "m".into(), target_by: "u".into() },
        ];
        for o in &own {
            assert_eq!(o.room_scope(), None, "{o:?}");
        }
    }

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
