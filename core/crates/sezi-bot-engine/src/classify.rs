//! What a decrypted 1:1 payload means to a bot.
//!
//! A bot program sees text and nothing else in Phase 1. Everything a member's kernel sends a
//! contact on its own — capability announcements, state digests, an avatar, typing, the receipts
//! of a file — is read, acked and dropped, exactly as a kernel treats a kind it does not know
//! (`InnerMessage::Unknown`, acked so it does not pile up in the relay's retries).

use sezi_protocol::inner::{ChatPayload, InnerMessage};

use crate::Inbound;

/// The body of the pairing/self-heal marker (`messaging_core::kernel::PAIR_ACK_MARKER`, mirrored
/// here because this crate cannot depend on the kernel; the wire scenarios assert the two agree).
/// An Olm message carrying it (re-)establishes a session and is invisible in every UI.
pub const PAIR_ACK_MARKER: &str = "__sezgi/sys/pair-ack/v1";

/// Every kernel system marker starts with this (pair-ack, the sibling re-pair markers, P2P caps,
/// delete-for-everyone). None of them is content.
pub const SYSTEM_MARKER_PREFIX: &str = "__sezgi/sys/";

/// Classify a payload from `from`'s device `device`. `was_prekey` is whether it arrived as an
/// Olm PreKey message: only a PreKey pair-ack opens a session, so only it is a
/// [`Inbound::PairAck`]; a Normal one is the far side's answer to ours and needs nothing.
pub(crate) fn classify(payload: &ChatPayload, from: &str, device: &str, was_prekey: bool) -> Inbound {
    let text = |body: &str| Inbound::Text {
        from: from.to_owned(),
        device: device.to_owned(),
        msg_uid: payload.msg_uid.clone(),
        body: body.to_owned(),
        ext: payload.ext.clone(),
    };
    match &payload.inner {
        InnerMessage::Text { body } if body == PAIR_ACK_MARKER => {
            if was_prekey {
                Inbound::PairAck { from: from.to_owned() }
            } else {
                Inbound::Ignored("pair_ack")
            }
        }
        InnerMessage::Text { body } if body.starts_with(SYSTEM_MARKER_PREFIX) => {
            Inbound::Ignored("system_marker")
        }
        InnerMessage::Text { body } => text(body),
        // A formatted message reaches the program as its plain words: the delta is a UI format.
        InnerMessage::RichText { plain_text, .. } => text(plain_text),
        InnerMessage::RoomKeyRequest { room_id, session_id } => Inbound::RoomKeyRequest {
            from: from.to_owned(),
            room_id: room_id.clone(),
            session_id: session_id.clone(),
        },
        // A member's room message that called the bot, copied to it 1:1 (Phase 3). The host
        // still checks the room is one of the bot's and `from` an active member of it.
        InnerMessage::BotCall { room_id, msg_uid, body, lang, utc_offset_min } => Inbound::Call {
            from: from.to_owned(),
            room_id: room_id.clone(),
            msg_uid: msg_uid.clone(),
            body: body.clone(),
            lang: lang.clone(),
            utc_offset_min: *utc_offset_min,
        },
        // Something that carries a room's secret, sent to a bot: a member's kernel never does
        // (BOTS_BUILD §2.7), so this is a bug or a forgery. Read, acked and NEVER imported — the
        // engine has no store for another sender's key — and named so a test can see it arrive.
        InnerMessage::RoomKeyShare { .. }
        | InnerMessage::RoomKeyGossip { .. }
        | InnerMessage::PluginEpochKeyShare { .. }
        | InnerMessage::PluginRecordSnapshot { .. }
        | InnerMessage::PluginRecord { room: Some(_), .. }
        | InnerMessage::GroupOutboundCopy { .. } => Inbound::Ignored("room_secret"),
        InnerMessage::StateDigest { .. } => Inbound::Ignored("state_digest"),
        InnerMessage::Typing { .. } => Inbound::Ignored("typing"),
        InnerMessage::ProfileAvatar { .. } => Inbound::Ignored("avatar"),
        InnerMessage::MediaReceived { .. } | InnerMessage::P2pBlobReceived { .. } => {
            Inbound::Ignored("receipt")
        }
        InnerMessage::Unknown => Inbound::Ignored("unknown"),
        inner if inner.is_local_only() => Inbound::Ignored("local_only"),
        _ => Inbound::Ignored("unsupported"),
    }
}

#[cfg(test)]
#[path = "classify_tests.rs"]
mod tests;
