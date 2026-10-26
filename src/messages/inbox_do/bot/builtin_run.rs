//! The built-in runner's round in the alarm's tick: members' updates, then rows owed to the
//! sheet (`builtin_jobs.rs`). It follows the webhook round (`deliver.rs`): oldest first, a failure
//! that is tried again holds the queue behind it on the outbox's ladder, and an update the runner
//! has handled is "taken" — the member's `forward-read`, their blue tick.
//!
//! **What each kind does with a member's message.**
//! - `sheet`: the message becomes a row owed to the sheet (`bot_sheet_jobs`), taken at once —
//!   up to `DAILY_ROWS` a member a day; past that no row is queued and the member hears it once.
//!   Before the sheet's address is set ("not connected"), each message is answered with one line
//!   saying the bot is not set up yet; no row is queued and nothing is retried.
//! - `ai`: one model call with that member's last 10 turns; the answer goes back as the bot's
//!   message. With rows on, a `ROW:` line in the answer becomes a proposal the member is asked
//!   to confirm, shown whole; their "evet"/"yes" queues the row, "hayır"/"no" drops it, any
//!   other message leaves it behind, and after 10 minutes it lapses. A passing failure
//!   (unreachable, overloaded, rate-limited) is tried twice more (5 s, 30 s), then said; any
//!   other failure is said at once.
//!
//! **Budget** (`builtin_policy`): an item starts only when its worst case fits what the round
//! may still spend; the outbox drain after the round gets what the round left of the tick's
//! purse. When work is still due, the alarm re-arms at once (`bot_builtin_next`).
//!
//! **A change of configuration mid-round.** Every owner's set bumps a generation. After every
//! `await` the round checks it and, if it moved, stops where it is — the update it was on is
//! neither answered nor deleted, nothing it computed is written — and the next tick starts over
//! on the new configuration.
//!
//! Nothing a member wrote, nothing the model answered, and no key is logged: codes only.

use super::builtin::KV_HOLD_UNTIL;
use super::builtin_ai::{self, Role, Turn};
use super::builtin_copy::{line, Line};
use super::builtin_policy::{self as policy, ProposalStep};
use super::builtin_room::{context_key, RoomRef};
use super::builtin_store as bs;
use super::outbox::retry_delay_ms;
use super::store::{Arg, Exec};
use super::*;
use crate::bots::builtin_rules::{allow_lan, Config, Kind, Lang};

/// Updates one round looks at.
const UPDATE_BATCH: i64 = 5;
/// A passing model failure is tried this many times in all.
const AI_ATTEMPTS: i64 = 3;
/// The longest message the bot sends (the API's own cap).
pub(super) const MAX_REPLY_CHARS: usize = 4000;

#[derive(Deserialize)]
struct DueUpdate {
    update_id: i64,
    json: String,
    attempts: i64,
    #[serde(default)]
    next_at: Option<i64>,
}

#[derive(Deserialize)]
struct ProposalRow {
    row_json: String,
    text: String,
    at: i64,
    /// The room call it came from, if it did (`builtin_room::RoomRef`).
    #[serde(default)]
    room_json: Option<String>,
}

#[derive(Deserialize)]
struct TurnRow {
    role: String,
    text: String,
}

/// What became of one update.
enum Handled {
    /// Done with: taken, deleted.
    Done,
    /// Try again later; the queue waits behind it.
    Retry,
    /// The configuration changed under it: leave it as it is, and end the round.
    Abandon,
    /// Its worst case does not fit what the round has left: leave it for the next tick.
    NoRoom,
}

/// What a member wrote, and where: 1:1 (`room: None`) or as a call in a room.
struct Ask {
    from: String,
    name: String,
    text: String,
    room: Option<RoomRef>,
}

/// What a round needs at hand.
pub(super) struct Run {
    pub(super) cfg: Config,
    pub(super) lang: Lang,
    pub(super) bot_name: String,
    pub(super) allow_lan: bool,
    /// The configuration's generation when the round began.
    pub(super) gen: i64,
}

impl UserInbox {
    /// The runner's round; what it spent, for the drain after it. Errors are logged by code;
    /// the alarm re-arms from `bot_builtin_next`.
    pub(super) async fn bot_builtin_round(&self, ctx: &BotCtx) -> u32 {
        let Some(cfg) = self.builtin_config() else {
            return 0;
        };
        let now = (now_secs() * 1000) as i64;
        if self.bot_builtin_next().is_none_or(|t| t > now) {
            return 0; // nothing due (or held while the bot is off): no D1 read
        }
        let gen = self.builtin_gen();
        let mut spent = 1u32;
        let store = self.bot_store();
        let hold = |ms: i64| store.kv_put(KV_HOLD_UNTIL, &(now + ms).to_string());
        // Off (or deleted): the round takes nothing, so no held message gets a `forward-read`.
        let bot_name = match policy::round_gate(self.builtin_bot_row().await) {
            policy::Gate::Run(name) => name,
            policy::Gate::Hold(ms) => {
                hold(ms);
                return spent;
            }
        };
        if self.builtin_gen() != gen {
            return spent;
        }
        store.db.run("DELETE FROM bot_kv WHERE k = ?", &[Arg::T(KV_HOLD_UNTIL)]);
        let run = Run { lang: cfg.lang, cfg, bot_name, allow_lan: allow_lan(&self.env), gen };
        if self.builtin_updates(ctx, &run, &mut spent).await {
            self.builtin_jobs(ctx, &run, &mut spent).await;
        }
        spent
    }

    /// Is the round's configuration still the one in force?
    pub(super) fn builtin_current(&self, run: &Run) -> bool {
        self.builtin_gen() == run.gen
    }

    /// The updates' part of the round; `false` when the round must end here.
    async fn builtin_updates(&self, ctx: &BotCtx, run: &Run, spent: &mut u32) -> bool {
        let sql = self.state.storage().sql();
        let due: Vec<DueUpdate> = match sql
            .exec_raw(bs::UPDATES_DUE, Some(vec![JsValue::from_f64(UPDATE_BATCH as f64)]))
            .and_then(|c| c.to_array())
        {
            Ok(r) => r,
            Err(e) => {
                console_log!("[bot] built-in queue read failed: {e:?}");
                return true;
            }
        };
        for row in due {
            let now = (now_secs() * 1000) as i64;
            if !self.builtin_current(run) {
                return false; // the item before awaited, and the owner changed the bot meanwhile
            }
            if row.next_at.is_some_and(|t| t > now) {
                break;
            }
            let update: serde_json::Value = serde_json::from_str(&row.json).unwrap_or_default();
            let handled = match update.get("kind").and_then(|k| k.as_str()) {
                // A room call is a message whose answer goes to the room (`builtin_room.rs`).
                Some("message" | "call") => self.builtin_message(ctx, run, &update, row.attempts, now, spent).await,
                // `added` / `removed`, a `ping` from program mode, or a kind this build does not
                // handle: nothing to answer.
                _ => Handled::Done,
            };
            let id = JsValue::from_f64(row.update_id as f64);
            match handled {
                Handled::Done => {
                    self.bot_updates_taken(ctx, row.update_id, row.update_id, now);
                    let _ = sql.exec_raw(super::deliver::HOOK_DONE, Some(vec![id]));
                }
                Handled::Retry => {
                    let next = JsValue::from_f64((now + retry_delay_ms(row.attempts)) as f64);
                    let _ = sql.exec_raw(super::deliver::HOOK_RETRY, Some(vec![next, id]));
                    break;
                }
                Handled::NoRoom => return false,
                Handled::Abandon => return false,
            }
        }
        true
    }

    async fn builtin_message(
        &self,
        ctx: &BotCtx,
        run: &Run,
        update: &serde_json::Value,
        attempts: i64,
        now: i64,
        spent: &mut u32,
    ) -> Handled {
        let s = |p: &str| update.pointer(p).and_then(|v| v.as_str()).unwrap_or("").to_string();
        // A call's `chat` is the room; who called is `who`, which the relay filled from D1.
        let room = RoomRef::of_update(update);
        let from = if room.is_some() { s("/who/user_id") } else { s("/chat/user_id") };
        let ask = Ask { from, name: s("/who/display_name"), text: s("/message/text"), room };
        let at = update.get("at").and_then(|v| v.as_i64()).unwrap_or(now);
        if ask.from.is_empty() {
            return Handled::Done;
        }
        match run.cfg.kind {
            // Not connected yet: one line, no row queued, nothing retried.
            Kind::Sheet if run.cfg.sheet_not_connected() => {
                if !policy::fits(*spent, policy::SAY_BASE) {
                    return Handled::NoRoom;
                }
                self.builtin_note(Err(super::builtin::NOT_CONNECTED), now);
                self.builtin_answer(ctx, &ask, line(run.lang, Line::NotSetUp), spent).await;
                Handled::Done
            }
            Kind::Sheet => self.builtin_sheet_row(ctx, run, &ask, at, now, spent).await,
            Kind::Ai if !policy::fits(*spent, policy::AI_BASE) => Handled::NoRoom,
            Kind::Ai => self.builtin_ai_turn(ctx, run, &ask, attempts, now, spent).await,
        }
    }

    /// A connected sheet bot's message: a row owed to the sheet while the member is under the
    /// day's cap (`policy::row_admission`), counted either way; past it, nothing is queued and
    /// the member hears so once.
    async fn builtin_sheet_row(&self, ctx: &BotCtx, run: &Run, ask: &Ask, at: i64, now: i64, spent: &mut u32) -> Handled {
        let store = self.bot_store();
        let usage = [Arg::T(&ask.from), Arg::I(bs::day_of(now))];
        let used = store.db.int(bs::SHEET_USAGE_GET, &usage).unwrap_or(0);
        match policy::row_admission(used) {
            policy::RowAdmission::Queue => {
                store.db.run(bs::SHEET_USAGE_BUMP, &usage);
                self.builtin_queue_row(&ask.from, &ask.name, &ask.text, None, at, false, now, ask.room.as_ref());
            }
            // Left for the next tick, uncounted: it is judged again there.
            policy::RowAdmission::Refuse { say: true } if !policy::fits(*spent, policy::SAY_BASE) => {
                return Handled::NoRoom;
            }
            policy::RowAdmission::Refuse { say } => {
                store.db.run(bs::SHEET_USAGE_BUMP, &usage);
                console_log!("[bot] built-in refusal {}", policy::ROW_REFUSED);
                if say {
                    self.builtin_answer(ctx, ask, line(run.lang, Line::SheetDailyLimit), spent).await;
                }
            }
        }
        Handled::Done
    }

    /// Answer what `ask` wrote, where it wrote it: 1:1, or in the room replying to the call.
    async fn builtin_answer(&self, ctx: &BotCtx, ask: &Ask, text: &str, spent: &mut u32) {
        self.builtin_reply(ctx, &ask.from, ask.room.as_ref(), &ask.text, text, spent).await;
    }

    /// A row owed to the sheet; `room` when it came from a call in one.
    #[allow(clippy::too_many_arguments)]
    fn builtin_queue_row(
        &self,
        user: &str,
        name: &str,
        text: &str,
        row: Option<&str>,
        at: i64,
        confirm: bool,
        now: i64,
        room: Option<&RoomRef>,
    ) {
        let text = builtin_ai::cut(text, builtin_ai::MAX_INPUT_CHARS);
        let row_arg = row.map_or(Arg::Null, Arg::T);
        let room_json = room.map(RoomRef::to_json);
        self.bot_store().db.run(
            bs::JOB_PUSH,
            &[
                Arg::T(user),
                Arg::T(name),
                Arg::T(&text),
                row_arg,
                Arg::I(at),
                Arg::I(i64::from(confirm)),
                Arg::I(now),
                Arg::I(now),
                room_json.as_deref().map_or(Arg::Null, Arg::T),
            ],
        );
    }

    /// The bot says `text` to `to`. Best effort: a send that cannot be made is logged by code.
    pub(super) async fn builtin_say(&self, ctx: &BotCtx, to: &str, text: &str, spent: &mut u32) {
        let text = builtin_ai::cut(text.trim(), MAX_REPLY_CHARS);
        match self.bot_send_text_queued(ctx, to, &text).await {
            Ok(cost) => *spent += cost,
            Err(_) => {
                *spent += 1;
                console_log!("[bot] built-in reply could not be queued");
            }
        }
    }

    async fn builtin_ai_turn(
        &self,
        ctx: &BotCtx,
        run: &Run,
        ask: &Ask,
        attempts: i64,
        now: i64,
        spent: &mut u32,
    ) -> Handled {
        let Some(ai) = run.cfg.ai.as_ref() else {
            return Handled::Done;
        };
        let (from, name, text) = (ask.from.as_str(), ask.name.as_str(), ask.text.as_str());
        let room = ask.room.as_ref();
        // Whose conversation this is: the member's 1:1 chat, or that member in that room.
        let context = context_key(from, room);
        let store = self.bot_store();
        let sql = self.state.storage().sql();
        // Forgotten on read, too: nothing older than its keep is ever used.
        store.db.run(bs::TURNS_EXPIRE, &[Arg::I(now - bs::TURN_TTL_MS)]);
        store.db.run(bs::PROPOSAL_EXPIRE, &[Arg::I(now - bs::PROPOSAL_KEEP_MS)]);
        // A row waiting for this member's yes; whatever they say next IN THEIR 1:1 CHAT settles
        // it. A room call never does: the confirmation is the caller's alone (`builtin_room.rs`).
        let proposal: Option<ProposalRow> = if room.is_some() {
            None
        } else {
            sql.exec_raw(bs::PROPOSAL_GET, Some(vec![JsValue::from_str(from)]))
                .and_then(|c| c.to_array())
                .ok()
                .and_then(|v: Vec<ProposalRow>| v.into_iter().next())
        };
        let step = policy::proposal_step(proposal.as_ref().map(|p| p.at), run.cfg.writes_sheet(), text, now);
        if proposal.is_some() {
            store.db.run(bs::PROPOSAL_DROP, &[Arg::T(from)]);
        }
        // The member's answer to a row, and what came of it, go into the context as one exchange
        // (`policy::settled_exchange`): without it the model never learned a row was saved, and on
        // Haiku told members saved rows were still waiting (lab, 2026-10-26).
        if let Some((said, line_out)) = policy::settled_exchange(run.lang, &step) {
            self.builtin_remember(&context, text, line_out, now);
            if let (ProposalStep::Confirm, Some(p)) = (&step, proposal.as_ref()) {
                // A row proposed for a room call keeps that room: its "Kaydedildi." goes there.
                let came_from = RoomRef::parse(p.room_json.as_deref());
                self.builtin_queue_row(from, name, &p.text, Some(&p.row_json), now, true, now, came_from.as_ref());
                return Handled::Done;
            }
            if let Some(l) = said {
                self.builtin_say(ctx, from, line(run.lang, l), spent).await;
            }
            return Handled::Done;
        }
        let day = bs::day_of(now);
        // The cap counts per member, across their 1:1 chat and every room.
        let used = store.db.int(bs::USAGE_GET, &[Arg::T(from), Arg::I(day)]).unwrap_or(0);
        if used >= bs::DAILY_CALLS {
            self.builtin_answer(ctx, ask, line(run.lang, Line::DailyLimit), spent).await;
            return Handled::Done;
        }
        let Some(key) = self.builtin_api_key() else {
            self.builtin_note(Err("ai/no-key"), now);
            self.builtin_answer(ctx, ask, line(run.lang, Line::AiUnavailable), spent).await;
            return Handled::Done;
        };
        let history: Vec<Turn> = sql
            .exec_raw(
                bs::TURNS_RECENT,
                Some(vec![
                    JsValue::from_str(&context),
                    JsValue::from_f64((now - bs::TURN_TTL_MS) as f64),
                    JsValue::from_f64((bs::CONTEXT_TURNS * 2) as f64),
                ]),
            )
            .and_then(|c| c.to_array::<TurnRow>())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| Some(Turn { role: Role::parse(&r.role)?, text: r.text }))
            .collect();
        let history = policy::whole_turns(history);
        let room_name = room.map(|r| r.name.as_str());
        let system = builtin_ai::system_prompt(ai, &run.bot_name, name, room_name, run.cfg.writes_sheet(), now);
        let body = builtin_ai::request_body(ai, &system, &history, text);
        store.db.run(bs::USAGE_BUMP, &[Arg::T(from), Arg::I(day)]);
        *spent += 1;
        let result = builtin_ai::call(ai, &key, &body, run.allow_lan).await;
        if !self.builtin_current(run) {
            return Handled::Abandon; // answered on instructions that are gone: nothing is kept
        }
        let answer = match result {
            Ok(a) => a,
            Err(code) => {
                self.builtin_note(Err(code), now);
                if builtin_ai::transient(code) && attempts + 1 < AI_ATTEMPTS {
                    return Handled::Retry;
                }
                let l = if builtin_ai::transient(code) { Line::TryLater } else { Line::AiUnavailable };
                self.builtin_answer(ctx, ask, line(run.lang, l), spent).await;
                return Handled::Done;
            }
        };
        self.builtin_note(Ok(()), now);
        let user_text = builtin_ai::cut(text, builtin_ai::MAX_INPUT_CHARS);
        self.builtin_remember(&context, &user_text, &answer, now);
        let (shown, row) = builtin_ai::split_row(&answer);
        let row = row.filter(|_| ai.sheet_tool && run.cfg.writes_sheet());
        let room_json = room.map(RoomRef::to_json);
        let propose = |r: &super::builtin_sheet::Row| {
            let room_arg = room_json.as_deref().map_or(Arg::Null, Arg::T);
            store.db.run(
                bs::PROPOSAL_PUT,
                &[Arg::T(from), Arg::T(&r.to_json()), Arg::T(&user_text), Arg::I(now), room_arg],
            );
        };
        if let Some(room) = room {
            // The answer to the room; a row it proposes goes to the caller alone, shown whole
            // with nothing of the prose (the room has that) but the group it is for, and is
            // settled in their 1:1 chat. One proposal waits per member: one still waiting is
            // replaced, and the new one says so, so their next yes or no answers what they see.
            if !shown.trim().is_empty() {
                self.builtin_answer(ctx, ask, &shown, spent).await;
            }
            let waiting: Option<ProposalRow> = sql
                .exec_raw(bs::PROPOSAL_GET, Some(vec![JsValue::from_str(from)]))
                .and_then(|c| c.to_array())
                .ok()
                .and_then(|v: Vec<ProposalRow>| v.into_iter().next());
            let replaced = waiting.is_some_and(|p| !bs::lapsed(p.at, now));
            let header = policy::room_proposal_header(run.lang, &room.name, replaced);
            if let Some((confirm, r)) =
                row.and_then(|r| Some((policy::confirm_text(run.lang, &header, &r, MAX_REPLY_CHARS)?, r)))
            {
                propose(&r);
                self.builtin_say(ctx, from, &confirm, spent).await;
            }
            return Handled::Done;
        }
        let proposal = row.and_then(|r| Some((policy::confirm_text(run.lang, &shown, &r, MAX_REPLY_CHARS)?, r)));
        let reply = match proposal {
            Some((text, r)) => {
                propose(&r);
                text
            }
            // No row, or one too big to show whole: the prose alone.
            None => shown,
        };
        if !reply.trim().is_empty() {
            self.builtin_say(ctx, from, &reply, spent).await;
        }
        Handled::Done
    }

    /// One exchange into a context (`builtin_room::context_key`: a member 1:1, or a member in a
    /// room), keeping its last `CONTEXT_TURNS`.
    fn builtin_remember(&self, from: &str, user: &str, assistant: &str, now: i64) {
        let db = self.bot_store().db;
        let user = builtin_ai::cut(user, builtin_ai::MAX_INPUT_CHARS);
        for (role, t) in [(Role::User, user.as_str()), (Role::Assistant, assistant)] {
            db.run(bs::TURN_PUT, &[Arg::T(from), Arg::T(role.as_str()), Arg::T(t), Arg::I(now)]);
        }
        db.run(bs::TURNS_TRIM, &[Arg::T(from), Arg::T(from), Arg::I(bs::CONTEXT_TURNS * 2)]);
    }

    /// Retention for the built-in tables. Synchronous, no network.
    pub(super) fn builtin_housekeeping(&self, now: i64) {
        let db = self.bot_store().db;
        db.run(bs::TURNS_EXPIRE, &[Arg::I(now - bs::TURN_TTL_MS)]);
        db.run(bs::PROPOSAL_EXPIRE, &[Arg::I(now - bs::PROPOSAL_KEEP_MS)]);
        db.run(bs::USAGE_EXPIRE, &[Arg::I(bs::day_of(now) - 1)]);
        db.run(bs::SHEET_USAGE_EXPIRE, &[Arg::I(bs::day_of(now) - 1)]);
    }
}
