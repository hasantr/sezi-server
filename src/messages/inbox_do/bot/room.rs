//! The bot in its rooms (docs/BOTS_BUILD.md Phase 3): what it hears from them, and how it posts.
//!
//! **It hears only calls.** A room's Megolm traffic never reaches a bot (it is no member, and the
//! engine holds no one's room key); what does is a member's `BotCall`, copied 1:1. The tick
//! believes one only when the room is one of this bot's (`group_bots`) AND the caller is an active
//! member of it — both read from D1 before the frames are opened ([`CALL_ROOMS_SQL`]). Anything
//! else is acked and dropped: a forged or stale call never becomes an update, and never makes the
//! bot speak in a room. A believed call is an update like a 1:1 message, held like one while the
//! bot is off.
//!
//! **It posts with its own session, after its own check.** The public group send stays closed to
//! it (`group_fanout::send_group` refuses a non-member, a bot always). A post is queued
//! (`bot_room_posts`) and the tick's room round asks D1 whether the bot is still a bot of that
//! room, and on ([`ROOM_GATE_SQL`]): removed (or deleted), its posts, key requests and owed
//! frames for the room are dropped and its session forgotten; off, they wait. Then:
//! 1. `room_prepare` with the room's ACTIVE member devices (rotating if one it was shared with
//!    left);
//! 2. the key shares, DEVICE BY DEVICE, as far as the round's budget pays for the key claims
//!    (`room_plan.rs`; a device it cannot reach is noted as skipped for this post, never waited
//!    on), the rest on the next round;
//! 3. the post encrypted, and an outbox `room_send` row that hands it to the members' inboxes in
//!    chunks the drain's budget pays for (`room_send.rs`), each chunk behind the same gate.
//!
//! **Nothing is written for a room the bot has left.** Every `/bot/room-event` bumps the room's
//! generation in this inbox; after every `await` the post checks it, and if it moved, writes
//! nothing — no session, no share — and the next round starts over. A key share queued for the
//! outbox names its room and session, and is dropped at send time unless that is still the room's
//! session.

use super::outbox::OutKind;
use super::room_plan::{self as plan, CLAIM_COST, READS};
use super::room_store as rs;
use super::store::{Arg, Exec};
use super::*;
use sezi_bot_engine::{
    devices_without_session, room_encrypt, room_forget, room_prepare, room_share, room_text_payload,
    DeviceKeys, Effect,
};
use sezi_protocol::inner::ChatPayload;
use sezi_protocol::reply::ReplyRef;
use std::collections::{BTreeSet, HashMap};

pub(super) use super::room_send::{RoomSendBody, RoomSendStep};

/// The rooms this bot is in, with the role of each sender of this batch who is an active member
/// there (NULL user for a room none of them is in). Bind: bot, JSON array of sender ids.
pub(crate) const CALL_ROOMS_SQL: &str = "SELECT gb.group_id AS room_id, g.name AS name,
       gm.user_id AS user_id, gm.role AS role
  FROM group_bots gb
  JOIN groups g ON g.id = gb.group_id
  JOIN bots b ON b.bot_id = gb.bot_id AND b.deleted_at IS NULL
  LEFT JOIN group_members gm ON gm.group_id = gb.group_id AND gm.status = 'active'
       AND gm.user_id IN (SELECT value FROM json_each(?2))
 WHERE gb.bot_id = ?1";

/// Is the bot a bot of the room (a row), and is it on (`enabled`)? Bind: room, bot.
pub(crate) const ROOM_GATE_SQL: &str = "SELECT b.disabled_at IS NULL AS enabled
  FROM group_bots gb JOIN bots b ON b.bot_id = gb.bot_id
 WHERE gb.group_id = ?1 AND gb.bot_id = ?2 AND b.deleted_at IS NULL LIMIT 1";

/// A room's active member devices with their keys, the bot left out. Bind: room, bot.
pub(crate) const ROOM_DEVICES_SQL: &str = "SELECT gm.user_id AS user_id, d.device_id AS device_id,
       d.ed_pub AS ed_pub, d.x_pub AS x_pub
  FROM group_members gm
  JOIN devices d ON d.user_id = gm.user_id AND d.revoked_at IS NULL
 WHERE gm.group_id = ?1 AND gm.user_id != ?2 AND gm.status = 'active'
 ORDER BY gm.user_id, d.device_id";

/// A post waits for its key shares this long at most.
const POST_TTL_MS: i64 = 24 * 3600 * 1000;
/// A call is remembered (for `reply_to`) this long.
pub(super) const CALL_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
/// The most the room round may spend in one tick, and what it leaves the drain at least.
pub(super) const ROOM_ROUND_MAX: u32 = 24;
pub(super) const DRAIN_FLOOR: u32 = 10;
/// `bot_kv`: until when the room round's work waits (a stall, an error, the bot off).
const KV_ROOM_HOLD: &str = "room_hold_until";

/// What the room round may spend after the built-in round spent `round_spent` of the purse.
pub(super) fn room_budget(round_spent: u32) -> u32 {
    super::builtin_policy::TICK_PURSE
        .saturating_sub(round_spent)
        .saturating_sub(DRAIN_FLOOR)
        .min(ROOM_ROUND_MAX)
}

/// What D1 says of the bot and a room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RoomGate {
    /// A bot of the room, and on.
    On,
    /// A bot of the room, turned off: its room work waits.
    Off,
    /// Not (or no longer) a bot of the room, or deleted: its room work is dropped.
    Out,
}

impl RoomGate {
    /// From [`ROOM_GATE_SQL`]'s `enabled`: no row is `Out`.
    pub(super) fn of(enabled: Option<i64>) -> Self {
        match enabled {
            None => RoomGate::Out,
            Some(0) => RoomGate::Off,
            Some(_) => RoomGate::On,
        }
    }
}

/// The rooms this bot is in, as the prefetch read them: name, and the senders' room roles.
#[derive(Default)]
pub(super) struct BotRooms(pub(super) HashMap<String, (String, HashMap<String, String>)>);

impl BotRooms {
    /// The room's name and `from`'s role there, when `from` may call the bot in it.
    pub(super) fn caller(&self, room_id: &str, from: &str) -> Option<(&str, &str)> {
        let (name, roles) = self.0.get(room_id)?;
        roles.get(from).map(|role| (name.as_str(), role.as_str()))
    }

    pub(super) fn from_rows(rows: Vec<(String, String, Option<String>, Option<String>)>) -> Self {
        let mut out: HashMap<String, (String, HashMap<String, String>)> = HashMap::new();
        for (room, name, user, role) in rows {
            let entry = out.entry(room).or_insert_with(|| (name, HashMap::new()));
            if let (Some(u), Some(r)) = (user, role) {
                entry.1.insert(u, r);
            }
        }
        BotRooms(out)
    }
}

/// What one round did with one post.
enum PostStep {
    /// Finished with for this round: sent on, dropped, or abandoned because its room changed.
    Finished,
    /// Shared as far as the budget paid; `progressed` = at least one device was.
    Partial { progressed: bool },
    /// The bot is off: the post waits.
    Held,
}

#[derive(Deserialize)]
struct PostRow {
    id: i64,
    room_id: String,
    payload_json: String,
    skipped: String,
    created_at: i64,
}

#[derive(Deserialize)]
struct DeviceRow {
    user_id: String,
    device_id: String,
    ed_pub: Vec<u8>,
    x_pub: Vec<u8>,
}

#[derive(Deserialize)]
struct CallRow {
    from_user: String,
    body: String,
}

/// "user/device", as `bot_room_posts.skipped` names a device.
fn device_key(d: &DeviceKeys) -> String {
    format!("{}/{}", d.user_id, d.device_id)
}

fn room_gen_key(room_id: &str) -> String {
    format!("room_gen:{room_id}")
}

impl UserInbox {
    /// The rooms this bot is in and the senders' roles there, for the tick's prefetch.
    pub(super) async fn bot_rooms_of(&self, bot_id: &str, senders_json: &str) -> Result<BotRooms> {
        #[derive(Deserialize)]
        struct Row {
            room_id: String,
            name: String,
            #[serde(default)]
            user_id: Option<String>,
            #[serde(default)]
            role: Option<String>,
        }
        let rows: Vec<Row> = self
            .env
            .d1("DB")?
            .prepare(CALL_ROOMS_SQL)
            .bind(&[crate::d1util::d1_text(bot_id), crate::d1util::d1_text(senders_json)])?
            .all()
            .await?
            .results()?;
        Ok(BotRooms::from_rows(rows.into_iter().map(|r| (r.room_id, r.name, r.user_id, r.role)).collect()))
    }

    /// Remember a call the program is handed, so its `reply_to` can name it. Synchronous.
    pub(super) fn bot_note_call(&self, room_id: &str, msg_uid: &str, from: &str, body: &str, now: i64) {
        self.bot_store().db.run(
            rs::CALL_PUT,
            &[Arg::T(room_id), Arg::T(msg_uid), Arg::T(from), Arg::T(body), Arg::I(now)],
        );
    }

    /// A member's `RoomKeyRequest`, kept to be answered by a room round (`room_asks.rs`).
    /// Synchronous: the tick's frame block writes it.
    pub(super) fn bot_note_key_ask(&self, room_id: &str, from: &str, session_id: Option<&str>, now: i64) {
        let session = session_id.map_or(Arg::Null, Arg::T);
        self.bot_store().db.run(rs::ASK_PUT, &[Arg::T(room_id), Arg::T(from), session, Arg::I(now)]);
    }

    /// The reply to a call this bot was handed in `room_id`, built from the bot's own record of it.
    pub(super) fn bot_call_reply(&self, room_id: &str, msg_uid: &str) -> Option<ReplyRef> {
        let rows: Vec<CallRow> = self
            .state
            .storage()
            .sql()
            .exec_raw(rs::CALL_GET, Some(vec![JsValue::from_str(room_id), JsValue::from_str(msg_uid)]))
            .and_then(|c| c.to_array())
            .ok()?;
        let call = rows.into_iter().next()?;
        Some(ReplyRef::new(msg_uid, call.from_user, "text", Some(&call.body)))
    }

    /// Queue a post into a room; the tick's room round shares the key and sends it.
    pub(super) fn bot_queue_room_post(&self, room_id: &str, payload: &ChatPayload, now: i64) {
        let Ok(json) = serde_json::to_string(payload) else {
            return;
        };
        self.bot_store().db.run(rs::POST_PUSH, &[Arg::T(room_id), Arg::T(&json), Arg::I(now)]);
    }

    /// The bot's text into a room as `msg_uid`, as a reply to `reply` when given.
    pub(super) fn bot_queue_room_text(&self, room_id: &str, text: &str, reply: Option<&ReplyRef>, msg_uid: &str, now: i64) {
        self.bot_queue_room_post(room_id, &room_text_payload(text, msg_uid, reply), now);
    }

    /// `sendMessage` into a room, as `msg_uid`. The Worker has already checked `group_bots`; the
    /// room round checks it again before anything leaves.
    pub(super) async fn bot_send_room_text(
        &self,
        room_id: &str,
        text: &str,
        reply_to: Option<&str>,
        msg_uid: &str,
    ) -> Result<Response> {
        let reply = match reply_to.filter(|r| !r.is_empty()) {
            Some(uid) => match self.bot_call_reply(room_id, uid) {
                Some(r) => Some(r),
                None => return crate::bots::api::bot_err(400, "unknown-reply"),
            },
            None => None,
        };
        let now = (now_secs() * 1000) as i64;
        self.bot_queue_room_text(room_id, text, reply.as_ref(), msg_uid, now);
        // Queued: the room round sends it whatever happens to this request (`send_replay.rs`).
        super::send_replay::mark_sent(&self.bot_store().db, msg_uid);
        self.arm_alarm_within(0).await;
        Response::from_json(&crate::bots::api_answer::sent(msg_uid))
    }

    /// The room's generation in this inbox: moved by every `/bot/room-event`.
    pub(super) fn bot_room_gen(&self, room_id: &str) -> i64 {
        self.bot_store().kv_get(&room_gen_key(room_id)).and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    /// Everything of a room the bot is no longer in: its session and shares, its waiting posts and
    /// key requests, and every frame still owed for it (key shares, the post's chunks).
    /// Synchronous.
    pub(super) fn bot_room_drop(&self, room_id: &str) {
        room_forget(&mut self.bot_store(), room_id);
        let db = self.bot_store().db;
        for q in [rs::POSTS_DROP_ROOM, rs::ASKS_DROP_ROOM, super::outbox::OUTBOX_DROP_ROOM] {
            db.run(q, &[Arg::T(room_id)]);
        }
    }

    /// `/bot/room-event`: an admin added the bot to a room, or removed it. The update for the
    /// program; a removal drops everything of the room. Either moves the room's generation, so a
    /// round that awaited across it writes nothing for the room.
    pub(super) async fn bot_room_event(&self, body: serde_json::Value) -> Result<Response> {
        let s = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let (kind, room_id) = (s("kind"), s("room_id"));
        if !matches!(kind.as_str(), "added" | "removed") || room_id.is_empty() {
            return Response::error("bad room event", 400);
        }
        let now = (now_secs() * 1000) as i64;
        let gen = self.bot_room_gen(&room_id) + 1;
        self.bot_store().kv_put(&room_gen_key(&room_id), &gen.to_string());
        if kind == "removed" {
            self.bot_room_drop(&room_id);
        }
        let update = super::updates::room_event_update(&kind, now, &room_id, &s("name"), body.get("who"));
        self.bot_push_update(&update, now);
        self.arm_alarm_within(0).await;
        Response::empty().map(|r| r.with_status(204))
    }

    pub(super) async fn bot_room_devices(&self, room_id: &str, bot_id: &str) -> Result<Vec<DeviceKeys>> {
        let rows: Vec<DeviceRow> = self
            .env
            .d1("DB")?
            .prepare(ROOM_DEVICES_SQL)
            .bind(&[crate::d1util::d1_text(room_id), crate::d1util::d1_text(bot_id)])?
            .all()
            .await?
            .results()?;
        Ok(rows
            .into_iter()
            .map(|r| DeviceKeys {
                user_id: r.user_id,
                device_id: r.device_id,
                x_pub_b64: crate::utils::b64_encode(&r.x_pub),
                ed_pub_b64: crate::utils::b64_encode(&r.ed_pub),
            })
            .collect())
    }

    /// Is this bot still a bot of the room, and on? A D1 failure answers `Err`: nothing is sent,
    /// nothing forgotten, the work waits.
    pub(super) async fn bot_room_gate(&self, room_id: &str, bot_id: &str) -> Result<RoomGate> {
        #[derive(Deserialize)]
        struct Row {
            enabled: i64,
        }
        let row: Option<Row> = self
            .env
            .d1("DB")?
            .prepare(ROOM_GATE_SQL)
            .bind(&[crate::d1util::d1_text(room_id), crate::d1util::d1_text(bot_id)])?
            .first(None)
            .await?;
        Ok(RoomGate::of(row.map(|r| r.enabled)))
    }

    /// Queue key shares for the outbox, each naming its room and session (checked again when it
    /// is sent). A key share is invisible control: no msg_uid, no wake.
    pub(super) fn bot_queue_room_shares(&self, room_id: &str, session_id: &str, effects: Vec<Effect>, now: i64) {
        for e in effects {
            if let Effect::Deliver { user_id, device_id, envelope_b64, .. } = e {
                let body = serde_json::json!({
                    "user_id": user_id,
                    "device_id": device_id,
                    "envelope_b64": envelope_b64,
                    "msg_uid": null,
                    "room_id": room_id,
                    "session_id": session_id,
                });
                self.bot_outbox_push(OutKind::Notify, &body, now);
            }
        }
    }

    /// The tick's room round: the members' key requests, then the oldest waiting posts, as far as
    /// `budget` pays. What it spent. Never leaves the alarm re-firing at once without progress.
    pub(super) async fn bot_room_round(&self, ctx: &BotCtx, budget: u32) -> u32 {
        let mut spent = 0u32;
        let (mut progressed, mut held) = self.bot_room_asks(ctx, budget, &mut spent).await;
        let mut failed = false;
        while spent + READS < budget {
            let post: Option<PostRow> = self
                .state
                .storage()
                .sql()
                .exec_raw(rs::POST_NEXT, sql_no_args())
                .and_then(|c| c.to_array())
                .ok()
                .and_then(|v: Vec<PostRow>| v.into_iter().next());
            let Some(post) = post else { break };
            match self.bot_room_post(ctx, &post, budget, &mut spent).await {
                Ok(PostStep::Finished) => progressed = true,
                Ok(PostStep::Partial { progressed: p }) => {
                    progressed |= p;
                    break;
                }
                Ok(PostStep::Held) => {
                    held = true;
                    break;
                }
                Err(e) => {
                    console_log!("[bot] room post failed: {e:?}");
                    failed = true;
                    break;
                }
            }
        }
        let now = (now_secs() * 1000) as i64;
        let waiting = self.bot_store().db.int(rs::POSTS_WAITING, &[]).unwrap_or(0) > 0;
        match plan::wait_after_round(waiting, progressed && !failed, held) {
            None | Some(0) => self.bot_store().db.run("DELETE FROM bot_kv WHERE k = ?", &[Arg::T(KV_ROOM_HOLD)]),
            Some(ms) => self.bot_store().kv_put(KV_ROOM_HOLD, &(now + ms).to_string()),
        }
        spent
    }

    /// One post, as far as `budget` pays.
    async fn bot_room_post(&self, ctx: &BotCtx, post: &PostRow, budget: u32, spent: &mut u32) -> Result<PostStep> {
        let now = (now_secs() * 1000) as i64;
        let room = post.room_id.as_str();
        let done = |s: &Self| s.bot_store().db.run(rs::POST_DONE, &[Arg::I(post.id)]);
        if now - post.created_at > POST_TTL_MS {
            done(self);
            return Ok(PostStep::Finished);
        }
        let gen = self.bot_room_gen(room);
        let moved = |s: &Self| s.bot_room_gen(room) != gen;
        *spent += 1;
        match self.bot_room_gate(room, &ctx.bot_id).await? {
            _ if moved(self) => return Ok(PostStep::Finished),
            RoomGate::Out => {
                // Removed (or deleted): this and everything else for the room is impossible now.
                self.bot_room_drop(room);
                return Ok(PostStep::Finished);
            }
            RoomGate::Off => return Ok(PostStep::Held),
            RoomGate::On => {}
        }
        *spent += 1;
        let members = self.bot_room_devices(room, &ctx.bot_id).await?;
        if moved(self) {
            return Ok(PostStep::Finished);
        }
        let prep = room_prepare(&mut self.bot_store(), &ctx.key, room, &members, now)
            .map_err(|e| Error::RustError(format!("bot room: {e}")))?;
        let mut skipped: BTreeSet<String> = serde_json::from_str(&post.skipped).unwrap_or_default();
        let todo: Vec<DeviceKeys> =
            prep.unshared.into_iter().filter(|d| !skipped.contains(&device_key(d))).collect();
        let has_session: Vec<bool> = {
            let store = self.bot_store();
            todo.iter().map(|d| sezi_bot_engine::BotStore::current_session(&store, &d.user_id, &d.device_id).is_some()).collect()
        };
        let (n, all) = plan::plan_shares(&has_session, budget.saturating_sub(*spent));
        let taken = &todo[..n];
        let users: Vec<&str> = {
            let mut seen = Vec::new();
            for d in taken {
                if !seen.contains(&d.user_id.as_str()) {
                    seen.push(d.user_id.as_str());
                }
            }
            seen
        };
        for user in users {
            let devices: Vec<DeviceKeys> = taken.iter().filter(|d| d.user_id == user).cloned().collect();
            let need = devices_without_session(&self.bot_store(), user, &devices);
            *spent += CLAIM_COST * need.len() as u32;
            let claimed = self.bot_claim_keys(user, &need).await?;
            if moved(self) {
                return Ok(PostStep::Finished); // left (or re-added) while claiming: write nothing
            }
            let effects = room_share(&mut self.bot_store(), &ctx.key, room, user, &devices, &claimed)
                .map_err(|e| Error::RustError(format!("bot room share: {e}")))?;
            let reached: BTreeSet<&str> = effects
                .iter()
                .filter_map(|e| match e {
                    Effect::Deliver { device_id, .. } => Some(device_id.as_str()),
                    _ => None,
                })
                .collect();
            for d in devices.iter().filter(|d| !reached.contains(d.device_id.as_str())) {
                skipped.insert(device_key(d));
            }
            self.bot_queue_room_shares(room, &prep.session_id, effects, now);
        }
        if !all {
            let skipped = serde_json::to_string(&skipped).unwrap_or_else(|_| "[]".into());
            self.bot_store().db.run(rs::POST_SKIPPED, &[Arg::T(&skipped), Arg::I(post.id)]);
            return Ok(PostStep::Partial { progressed: n > 0 });
        }
        let payload: ChatPayload = serde_json::from_str(&post.payload_json)
            .map_err(|e| Error::RustError(format!("bot room post unreadable: {e}")))?;
        let Effect::DeliverRoom { envelope_b64, .. } = room_encrypt(&mut self.bot_store(), &ctx.key, room, &payload)
            .map_err(|e| Error::RustError(format!("bot room encrypt: {e}")))?
        else {
            return Err(Error::RustError("bot room encrypt: no envelope".into()));
        };
        let to: Vec<String> = members.iter().map(|m| m.user_id.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        let body = RoomSendBody { room_id: room.to_string(), envelope_b64, to, done: Vec::new() };
        self.bot_outbox_push(OutKind::RoomSend, &serde_json::to_value(&body).unwrap_or_default(), now);
        done(self);
        Ok(PostStep::Finished)
    }

    /// When the room work still waiting needs the alarm: at once, unless a round said to wait.
    pub(super) fn bot_room_next(&self) -> Option<i64> {
        let store = self.bot_store();
        if store.db.int(rs::POSTS_WAITING, &[]).unwrap_or(0) == 0 {
            return None;
        }
        Some(store.kv_get(KV_ROOM_HOLD).and_then(|v| v.parse().ok()).unwrap_or(0))
    }

    /// The bot was turned back on: its room work goes now, chunks of posts held off included.
    /// Synchronous.
    pub(super) fn bot_room_wake(&self, now: i64) {
        let db = self.bot_store().db;
        db.run("DELETE FROM bot_kv WHERE k = ?", &[Arg::T(KV_ROOM_HOLD)]);
        db.run(super::outbox::OUTBOX_WAKE_ROOM_SENDS, &[Arg::I(now)]);
    }

    /// Retention for the room tables. Synchronous.
    pub(super) fn bot_room_housekeeping(&self, now: i64) {
        let db = self.bot_store().db;
        db.run(rs::POSTS_EXPIRE, &[Arg::I(now - POST_TTL_MS)]);
        db.run(rs::CALLS_EXPIRE, &[Arg::I(now - CALL_TTL_MS)]);
    }
}

#[cfg(test)]
#[path = "room_tests.rs"]
mod tests;
