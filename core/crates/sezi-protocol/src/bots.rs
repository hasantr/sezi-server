//! What only a bot receives (`docs/BOTS_BUILD.md` §2.6). A member's kernel sends a bot a
//! [`InnerMessage::BotCall`] or [`InnerMessage::BotTap`]; no relay or kernel routes either to a
//! human. One that reaches a human kernel anyway is a bug or a forgery, so its inbound paths ack
//! it and drop it, beside the local-only kinds.

use crate::inner::InnerMessage;

impl InnerMessage {
    /// Is this addressed to a bot only? `true` → a human kernel acks and drops it, never stores
    /// it (`kernel/inbound_control.rs` and `kernel/groups.rs`, beside `is_local_only`).
    pub fn is_bot_bound(&self) -> bool {
        matches!(self, InnerMessage::BotCall { .. } | InnerMessage::BotTap { .. })
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
            serde_json::from_str(r#"{"kind":"bot_tap","msg_uid":"m","action_id":"ok"}"#).unwrap();
        assert!(tap.is_bot_bound());
        assert!(!InnerMessage::Text { body: "hi".into() }.is_bot_bound());
        assert!(!InnerMessage::Unknown.is_bot_bound());
    }
}
