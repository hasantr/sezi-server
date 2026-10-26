//! The rows a built-in bot owes its sheet (`bot_sheet_jobs`): the second part of the round.
//!
//! Rows are written in order; a failed write holds the queue and backs off (5 s … hourly).
//! The head row's author hears once on the first failure; the authors of rows waiting behind a
//! failing head hear once that the sheet is unreachable and their entry will follow. Each of
//! them hears once more when their row finally lands; a row not written in 23 hours is given up
//! on, and said. Every POST carries the row's stable `row_id` (`<bot>-<job>`), so a row sent
//! again after its answer was lost is skipped by the script, not written twice.
//!
//! Like the updates' part (`builtin_run.rs`), an item starts only when its worst case fits the
//! round's budget, and the round ends where it is when the configuration changed under an
//! `await`: a job is then neither marked nor deleted.

use super::builtin_copy::{line, Line};
use super::builtin_policy as policy;
use super::builtin_room::RoomRef;
use super::builtin_run::Run;
use super::builtin_sheet::{self, Row};
use super::builtin_store as bs;
use super::outbox::retry_delay_ms;
use super::store::{Arg, Exec};
use super::*;
use std::collections::HashSet;

/// Rows one round looks at.
const JOB_BATCH: i64 = 5;
/// Authors one round tells their row is waiting.
const TELL_BATCH: i64 = 5;

#[derive(Deserialize)]
struct DueJob {
    id: i64,
    user_id: String,
    name: String,
    text: String,
    #[serde(default)]
    row_json: Option<String>,
    at: i64,
    confirm: i64,
    attempts: i64,
    next_at: i64,
    created_at: i64,
    told: i64,
    /// The room call the row came from (`builtin_room::RoomRef`); its lines go to that room.
    #[serde(default)]
    room_json: Option<String>,
}

#[derive(Deserialize)]
struct Author {
    user_id: String,
    /// Their earliest waiting row's room and words, where that row came from a call.
    #[serde(default)]
    room_json: Option<String>,
    text: String,
}

/// A row's id at the script, the same on every send.
pub(super) fn row_id(bot_id: &str, job_id: i64) -> String {
    format!("{bot_id}-{job_id}")
}

impl UserInbox {
    pub(super) async fn builtin_jobs(&self, ctx: &BotCtx, run: &Run, spent: &mut u32) {
        let (Some(url), Some(secret)) = (run.cfg.sheet_url.as_deref(), self.builtin_sheet_secret()) else {
            return;
        };
        let sql = self.state.storage().sql();
        let jobs: Vec<DueJob> = match sql
            .exec_raw(bs::JOB_DUE, Some(vec![JsValue::from_f64(JOB_BATCH as f64)]))
            .and_then(|c| c.to_array())
        {
            Ok(r) => r,
            Err(e) => {
                console_log!("[bot] sheet queue read failed: {e:?}");
                return;
            }
        };
        let store = self.bot_store();
        let mut landed_said: HashSet<String> = HashSet::new();
        for job in jobs {
            let room = RoomRef::parse(job.room_json.as_deref());
            let now = (now_secs() * 1000) as i64;
            if !self.builtin_current(run) {
                return;
            }
            if job.next_at > now {
                // The head is waiting out a back-off: whoever queued behind it hears why.
                if job.attempts > 0 {
                    self.builtin_tell_queued(ctx, run, job.id, spent).await;
                }
                return;
            }
            if now - job.created_at >= bs::JOB_GIVE_UP_MS {
                if !policy::fits(*spent, policy::SAY_BASE) {
                    return;
                }
                store.db.run(bs::JOB_DONE, &[Arg::I(job.id)]);
                self.builtin_reply(ctx, &job.user_id, room.as_ref(), &job.text, line(run.lang, Line::SheetGaveUp), spent).await;
                continue;
            }
            if !policy::fits(*spent, policy::JOB_BASE) {
                return;
            }
            let row = job.row_json.as_deref().and_then(Row::parse);
            let id = row_id(&ctx.bot_id, job.id);
            let body = builtin_sheet::body_json(
                &secret,
                false,
                Some(&id),
                job.at,
                &job.user_id,
                &job.name,
                room.as_ref().map(RoomRef::sheet),
                &job.text,
                row.as_ref(),
            );
            let (outcome, hops) = builtin_sheet::post(url, &body, run.allow_lan).await;
            *spent += hops;
            if !self.builtin_current(run) {
                return; // sent on a configuration that is gone; `row_id` makes a re-send safe
            }
            self.builtin_note(outcome, now);
            if outcome.is_err() {
                store.db.run(bs::JOB_RETRY, &[Arg::I(now + retry_delay_ms(job.attempts)), Arg::I(job.id)]);
                if job.attempts == 0 && job.told == 0 {
                    store.db.run(bs::JOB_MARK_TOLD, &[Arg::T(&job.user_id)]);
                    self.builtin_reply(ctx, &job.user_id, room.as_ref(), &job.text, line(run.lang, Line::SheetRetrying), spent).await;
                }
                self.builtin_tell_queued(ctx, run, job.id, spent).await;
                return;
            }
            store.db.run(bs::JOB_DONE, &[Arg::I(job.id)]);
            let late = job.attempts > 0 || job.told != 0;
            let said = match (late, job.confirm != 0) {
                // One "written (late)" per author per round, however many of their rows land.
                (true, _) if landed_said.insert(job.user_id.clone()) => Some(Line::SheetLandedLate),
                (true, _) => None,
                (false, true) => Some(Line::RowSaved),
                (false, false) => None,
            };
            if let Some(l) = said {
                self.builtin_reply(ctx, &job.user_id, room.as_ref(), &job.text, line(run.lang, l), spent).await;
            }
        }
    }

    /// Tell the authors of rows waiting behind the failing head (`head`) — once each — that the
    /// sheet is unreachable and their entry will be written when it is.
    async fn builtin_tell_queued(&self, ctx: &BotCtx, run: &Run, head: i64, spent: &mut u32) {
        let authors: Vec<Author> = self
            .state
            .storage()
            .sql()
            .exec_raw(
                bs::JOB_BEHIND_UNTOLD,
                Some(vec![JsValue::from_f64(head as f64), JsValue::from_f64(TELL_BATCH as f64)]),
            )
            .and_then(|c| c.to_array())
            .unwrap_or_default();
        let store = self.bot_store();
        for a in authors {
            if !policy::fits(*spent, policy::SAY_BASE) || !self.builtin_current(run) {
                return;
            }
            store.db.run(bs::JOB_MARK_TOLD, &[Arg::T(&a.user_id)]);
            let room = RoomRef::parse(a.room_json.as_deref());
            self.builtin_reply(ctx, &a.user_id, room.as_ref(), &a.text, line(run.lang, Line::SheetQueued), spent).await;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_rows_id_is_the_bot_and_the_job() {
        assert_eq!(super::row_id("b0000000-0000-4000-8000-000000000002", 17), "b0000000-0000-4000-8000-000000000002-17");
    }
}
