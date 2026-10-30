//! A room post's last leg: the outbox `room_send` row, handed to the members' inboxes in chunks
//! (`room.rs` encrypts it; `outbox.rs` drains it).
//!
//! Each chunk is behind the same gate as the post: removed (or deleted) → the row is done and
//! goes nowhere; off → it waits ([`RoomSendStep::Hold`], until `/bot/wake`); the room's generation
//! moved during the chunk's D1 reads → it tries again next drain. Only members it was encrypted
//! for who are STILL active members get it: a member who left since is never handed it.

use super::room::RoomGate;
use super::*;
use crate::messages::budget::{SubrequestBudget, COST_MEMBER_CALL};
use crate::messages::group_fanout::{self, DoCalls, GroupMessage, MemberOutcome};

/// An outbox `room_send` row: the post, who it was encrypted for, who already has it.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(in crate::messages::inbox_do::bot) struct RoomSendBody {
    pub(in crate::messages::inbox_do::bot) room_id: String,
    pub(in crate::messages::inbox_do::bot) envelope_b64: String,
    pub(in crate::messages::inbox_do::bot) to: Vec<String>,
    #[serde(default)]
    pub(in crate::messages::inbox_do::bot) done: Vec<String>,
}

/// What one drain did with a `room_send` row.
pub(in crate::messages::inbox_do::bot) enum RoomSendStep {
    /// Everyone it is still owed to has it, or nobody is owed it any more.
    Done,
    /// Some got it; the rest go next, at once.
    Progress(String),
    /// Nobody could be reached this time: back off.
    Retry(String),
    /// The bot is off: wait (no attempt counted) until it is back on.
    Hold,
}

impl UserInbox {
    /// One drain's part of a `room_send` row, within `budget`: the members still owed it who are
    /// still active members, as many as the budget pays, through the group fan-out's own
    /// `notify_members`. (step, spent).
    pub(super) async fn bot_send_room_chunk(&self, ctx: &BotCtx, body: &str, budget: u32) -> (RoomSendStep, u32) {
        let Ok(mut row) = serde_json::from_str::<RoomSendBody>(body) else {
            return (RoomSendStep::Done, 0);
        };
        let gen = self.bot_room_gen(&row.room_id);
        match self.bot_room_gate(&row.room_id, &ctx.bot_id).await {
            // Removed since it was encrypted: the post goes nowhere.
            Ok(RoomGate::Out) => return (RoomSendStep::Done, 1),
            Ok(RoomGate::Off) => return (RoomSendStep::Hold, 1),
            Ok(RoomGate::On) => {}
            Err(_) => return (RoomSendStep::Retry(body.to_string()), 1),
        }
        let (Ok(db), Ok(ns)) = (self.env.d1("DB"), self.env.durable_object("USER_INBOX")) else {
            return (RoomSendStep::Retry(body.to_string()), 1);
        };
        let Ok(members) = group_fanout::group_send_members(&db, &row.room_id, &ctx.bot_id).await else {
            return (RoomSendStep::Retry(body.to_string()), 2);
        };
        if self.bot_room_gen(&row.room_id) != gen {
            // A room event came in meanwhile (a removal also deleted this row): ask again.
            return (RoomSendStep::Retry(body.to_string()), 2);
        }
        // Owed: encrypted for them, not yet given it, and still an active member (a leaver is
        // never handed it, even though the session was shared with them before they left).
        let owed: Vec<group_fanout::Member> =
            members.into_iter().filter(|m| row.to.contains(&m.user_id) && !row.done.contains(&m.user_id)).collect();
        if owed.is_empty() {
            return (RoomSendStep::Done, 2);
        }
        let msg = GroupMessage {
            sender_id: ctx.bot_id.clone(),
            sender_device_id: ctx.device_id.clone(),
            envelope_b64: row.envelope_b64.clone(),
            group_id: row.room_id.clone(),
            silent: false,
            urgent: false,
        };
        let mut purse = SubrequestBudget::new(budget as usize, 2);
        let outcomes = group_fanout::notify_members(&DoCalls { ns: &ns }, &msg, &owed, &mut purse, false).await;
        let mut reached = 0;
        for (m, o) in owed.iter().zip(&outcomes) {
            if matches!(o, MemberOutcome::Delivered { .. }) {
                row.done.push(m.user_id.clone());
                reached += 1;
            }
        }
        let tried = outcomes.iter().filter(|o| **o != MemberOutcome::Deferred).count();
        let cost = 2 + (tried * COST_MEMBER_CALL) as u32;
        let left = owed.len() - reached;
        let next = serde_json::to_string(&row).unwrap_or_default();
        match (left, reached) {
            (0, _) => (RoomSendStep::Done, cost),
            (_, 0) => (RoomSendStep::Retry(next), cost),
            _ => (RoomSendStep::Progress(next), cost),
        }
    }
}
