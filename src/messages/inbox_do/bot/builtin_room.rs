//! A built-in bot called in a room (docs/BOTS_BUILD.md, "Phase 3 adjustments"): where its words
//! go.
//!
//! - **The answer goes into the room**, as the bot's own Megolm post replying to the call
//!   (`ext.reply`), and so do the relay's own lines about it — a failure, "Kaydedildi." when a row
//!   from the call lands, the sheet's "written late" / "gave up".
//! - **Except an AI bot's row proposal and its confirmation**, which are the caller's alone: the
//!   proposal goes 1:1 to the caller, and their "evet" / "hayır" is read in their 1:1 chat with the
//!   bot (`builtin_run.rs` settles proposals on 1:1 messages only). Nobody else in the room can
//!   confirm a row, and the room is not filled with drafts.
//! - **An AI bot's context is per (room, member)** ([`context_key`]): what a member asked in one
//!   room is not the context of their 1:1 chat or of another room. The daily cap stays per member.
//!
//! A row or proposal remembers the call it came from as [`RoomRef`] (`room_json` in
//! `bot_ai_proposals` / `bot_sheet_jobs`); the sheet POST names that room (`builtin_sheet.rs`).

use super::builtin_sheet::SheetRoom;
use super::*;
use sezi_protocol::reply::ReplyRef;

/// The room call a built-in bot is answering.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(super) struct RoomRef {
    pub(super) id: String,
    pub(super) name: String,
    /// The call's `msg_uid` in the room, which the answer replies to.
    pub(super) call_uid: String,
}

impl RoomRef {
    /// The room of a `call` update (`updates::call_update`); `None` for anything else.
    pub(super) fn of_update(update: &serde_json::Value) -> Option<Self> {
        let s = |p: &str| update.pointer(p).and_then(|v| v.as_str()).filter(|v| !v.is_empty());
        if update.get("kind").and_then(|k| k.as_str()) != Some("call") || s("/chat/type") != Some("room") {
            return None;
        }
        Some(RoomRef {
            id: s("/chat/room_id")?.to_string(),
            name: s("/chat/name").unwrap_or("").to_string(),
            call_uid: s("/message/message_id")?.to_string(),
        })
    }

    pub(super) fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub(super) fn parse(json: Option<&str>) -> Option<Self> {
        json.and_then(|j| serde_json::from_str(j).ok())
    }

    pub(super) fn sheet(&self) -> SheetRoom<'_> {
        SheetRoom { id: &self.id, name: &self.name }
    }

    /// The reply an answer to this call carries: the call's id, its author, its words.
    pub(super) fn reply(&self, by: &str, call_text: &str) -> ReplyRef {
        ReplyRef::new(self.call_uid.clone(), by, "text", Some(call_text))
    }
}

/// Whose conversation an AI turn belongs to: the member's 1:1 chat, or that member in that room.
pub(super) fn context_key(user: &str, room: Option<&RoomRef>) -> String {
    match room {
        Some(r) => format!("{}/{user}", r.id),
        None => user.to_string(),
    }
}

impl UserInbox {
    /// The bot says `text` about something `to` wrote: 1:1, or — when it came from a room call —
    /// into that room as a reply to the call (`call_text` = the call's words, for the quote).
    /// A room post costs nothing now; the tick's room round pays for its key shares.
    pub(super) async fn builtin_reply(
        &self,
        ctx: &BotCtx,
        to: &str,
        room: Option<&RoomRef>,
        call_text: &str,
        text: &str,
        spent: &mut u32,
    ) {
        match room {
            None => self.builtin_say(ctx, to, text, spent).await,
            Some(r) => {
                let text = super::builtin_ai::cut(text.trim(), super::builtin_run::MAX_REPLY_CHARS);
                let now = (now_secs() * 1000) as i64;
                self.bot_queue_room_text(&r.id, &text, Some(&r.reply(to, call_text)), now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_update_names_its_room_and_a_message_does_not() {
        let who = super::super::updates::Who { user_id: "u".into(), display_name: None, server_role: None };
        let room = super::super::updates::CallRoom { id: "g", name: "Hukuk", role: "member" };
        let call = super::super::updates::call_update(1, "u", Some(&who), &room, "loc-7", "hi", None, None);
        let r = RoomRef::of_update(&call).unwrap();
        assert_eq!(r, RoomRef { id: "g".into(), name: "Hukuk".into(), call_uid: "loc-7".into() });
        assert_eq!(RoomRef::parse(Some(&r.to_json())), Some(r.clone()));
        assert_eq!(RoomRef::parse(None), None);
        let msg = super::super::updates::message_update(1, "u", None, Some("m"), "hi", &serde_json::Value::Null);
        assert_eq!(RoomRef::of_update(&msg), None);
        assert_eq!(context_key("u", Some(&r)), "g/u");
        assert_eq!(context_key("u", None), "u");
        let reply = r.reply("u", "hi");
        assert_eq!((reply.uid.as_str(), reply.by.as_str(), reply.text.as_deref()), ("loc-7", "u", Some("hi")));
    }
}
