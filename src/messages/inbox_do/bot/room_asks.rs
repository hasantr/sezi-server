//! Members' `RoomKeyRequest`s to the bot, answered inside the room round's budget.
//!
//! The tick's frame block only NOTES a request from an active member of one of the bot's rooms
//! (`bot_room_asks`, one per (room, member), the newest replacing an older one). A round then:
//! 1. judges it with the engine FIRST (`room_key_request_due`: the room has a session, the
//!    request names it or none, not inside the 20 s window) — a moot request is dropped having
//!    cost no D1 call and none of the member's one-time keys;
//! 2. asks D1 in one read whether the bot is still a bot of the room and on, and the asker still an
//!    active member ([`ASK_GATE_SQL`]) — removed or left drops it, off keeps it;
//! 3. reads the asker's devices and claims keys device by device as far as the budget pays
//!    (`room_plan::plan_shares`), then answers. A request the round cannot pay for stays for the
//!    next round; it is never dropped for want of budget.

use super::room::RoomGate;
use super::room_plan::{self as plan, CLAIM_COST};
use super::room_store as rs;
use super::store::{Arg, Exec};
use super::*;
use sezi_bot_engine::{devices_without_session, room_key_request, room_key_request_due, BotStore};

/// Is the bot a bot of the room and on (`enabled`, NULL = not a bot of it), and is the asker an
/// active member of it? Bind: room, bot, asker.
pub(crate) const ASK_GATE_SQL: &str = "SELECT
       (SELECT b.disabled_at IS NULL FROM group_bots gb JOIN bots b ON b.bot_id = gb.bot_id
         WHERE gb.group_id = ?1 AND gb.bot_id = ?2 AND b.deleted_at IS NULL) AS enabled,
       EXISTS(SELECT 1 FROM group_members
               WHERE group_id = ?1 AND user_id = ?3 AND status = 'active') AS member";

/// Requests one round looks at.
const ASK_BATCH: i64 = 5;

#[derive(Deserialize)]
struct AskRow {
    room_id: String,
    user_id: String,
    #[serde(default)]
    session_id: Option<String>,
}

impl UserInbox {
    /// The round's key requests: (progressed, held — one waits because the bot is off).
    pub(super) async fn bot_room_asks(&self, ctx: &BotCtx, budget: u32, spent: &mut u32) -> (bool, bool) {
        let asks: Vec<AskRow> = self
            .state
            .storage()
            .sql()
            .exec_raw(rs::ASKS_DUE, Some(vec![JsValue::from_f64(ASK_BATCH as f64)]))
            .and_then(|c| c.to_array())
            .unwrap_or_default();
        let (mut progressed, mut held) = (false, false);
        for ask in asks {
            match self.bot_room_ask(ctx, &ask, budget, spent).await {
                Ok(Some(true)) => progressed = true,
                Ok(Some(false)) => held = true,
                Ok(None) => break, // the budget is spent: the rest wait for the next round
                Err(e) => {
                    console_log!("[bot] room key request not answered: {e:?}");
                    break;
                }
            }
        }
        (progressed, held)
    }

    /// One request: `Some(true)` = finished with (answered or dropped), `Some(false)` = held
    /// (the bot is off), `None` = no budget left to go on.
    async fn bot_room_ask(&self, ctx: &BotCtx, ask: &AskRow, budget: u32, spent: &mut u32) -> Result<Option<bool>> {
        let (room, from) = (ask.room_id.as_str(), ask.user_id.as_str());
        let session = ask.session_id.as_deref();
        let done = |s: &Self| s.bot_store().db.run(rs::ASK_DONE, &[Arg::T(room), Arg::T(from)]);
        let due = |s: &Self| room_key_request_due(&s.bot_store(), room, from, session, (now_secs() * 1000) as i64);
        if !due(self) {
            done(self);
            return Ok(Some(true));
        }
        if *spent + plan::READS > budget {
            return Ok(None);
        }
        let gen = self.bot_room_gen(room);
        *spent += 1;
        #[derive(Deserialize)]
        struct Gate {
            #[serde(default)]
            enabled: Option<i64>,
            member: i64,
        }
        let gate: Option<Gate> = self
            .env
            .d1("DB")?
            .prepare(ASK_GATE_SQL)
            .bind(&[
                crate::d1util::d1_text(room),
                crate::d1util::d1_text(&ctx.bot_id),
                crate::d1util::d1_text(from),
            ])?
            .first(None)
            .await?;
        let (bot, member) = gate.map_or((RoomGate::Out, false), |g| (RoomGate::of(g.enabled), g.member != 0));
        match bot {
            RoomGate::Off => return Ok(Some(false)),
            RoomGate::Out => {
                self.bot_room_drop(room);
                return Ok(Some(true));
            }
            RoomGate::On if !member => {
                done(self); // left the room since asking
                return Ok(Some(true));
            }
            RoomGate::On => {}
        }
        *spent += 1;
        let devices = self.bot_member_devices(from).await?;
        if self.bot_room_gen(room) != gen || !due(self) {
            return Ok(Some(true)); // the room changed, or another answer went meanwhile
        }
        let has_session: Vec<bool> = {
            let store = self.bot_store();
            devices.iter().map(|d| store.current_session(from, &d.device_id).is_some()).collect()
        };
        let (n, _) = plan::plan_shares(&has_session, budget.saturating_sub(*spent));
        if n == 0 && !devices.is_empty() {
            return Ok(None); // not even one device fits: next round, from its start
        }
        // The devices past what this round pays for wait for the member's next request.
        let devices = &devices[..n];
        let need = devices_without_session(&self.bot_store(), from, devices);
        *spent += CLAIM_COST * need.len() as u32;
        let claimed = self.bot_claim_keys(from, &need).await?;
        if self.bot_room_gen(room) != gen {
            return Ok(Some(true));
        }
        let now = (now_secs() * 1000) as i64;
        let effects = room_key_request(&mut self.bot_store(), &ctx.key, room, from, session, devices, &claimed, now)
            .map_err(|e| Error::RustError(format!("bot room key request: {e}")))?;
        if let Some(s) = sezi_bot_engine::RoomStore::room_session(&self.bot_store(), room) {
            self.bot_queue_room_shares(room, &s.session_id, effects, now);
        }
        done(self);
        Ok(Some(true))
    }
}
