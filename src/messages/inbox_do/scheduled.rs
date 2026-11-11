//! Scheduled messages held in the SENDER's inbox (`docs/SCHEDULED_MESSAGES_PLAN.md`): the
//! `scheduled` table (`scheduled_rules::SCHEDULED_TABLE_SQL`), its internal doors (`/scheduled-put`,
//! `/scheduled-cancel`, reached only from `messages/scheduled.rs` for the caller's own inbox, and
//! `/notify-release`, one member's share of a release), and the release this object's alarm runs.
//!
//! The release re-checks, at the time, who may still receive it (`scheduled_rules::
//! release_targets`): a removed member, a revoked device or a sender who left gets nothing. ONE held
//! message a run, chosen by when it is next to be tried (`SELECT_DUE_SQL`, so a row that keeps
//! failing never stands in front of the others); a row past saving is given up before it is tried.
//! Each other member costs one call, `/notify-release` to their inbox, which stores a row per device
//! and wakes them from ITS invocation (the group fan-out's shape); the sender's own devices go into
//! this queue directly. At most `members_per_release_run` calls a run: what is left waits a second.

use super::{sql_no_args, UserInbox};
use crate::messages::scheduled_rules::{self as rules, Conversation, Target};
use serde::Deserialize;
use std::collections::BTreeMap;
use wasm_bindgen::JsValue;
use worker::*;

#[derive(Deserialize)]
struct PutBody {
    schedule_id: String,
    sender_id: String,
    sender_device_id: String,
    #[serde(default)]
    recipient_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    release_at: i64,
    envelope_b64: String,
    targets_json: String,
}

#[derive(Deserialize)]
struct CancelBody {
    schedule_id: String,
}

#[derive(Deserialize)]
struct HeldRow {
    schedule_id: String,
    sender_id: String,
    sender_device_id: String,
    #[serde(default)]
    recipient_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    release_at: i64,
    envelope_b64: String,
    targets_json: String,
    attempts: i64,
}

/// One member's share of a release: their devices, the envelope, who sent it.
#[derive(serde::Serialize, Deserialize)]
struct ReleaseBody {
    sender_id: String,
    sender_device_id: String,
    recipient_id: String,
    device_ids: Vec<String>,
    envelope_b64: String,
}

fn js(s: &str) -> JsValue {
    JsValue::from_str(s)
}

fn num(n: i64) -> JsValue {
    JsValue::from_f64(n as f64)
}

impl UserInbox {
    pub(super) fn ensure_scheduled_table(&self) -> Result<()> {
        self.state.storage().sql().exec_raw(rules::SCHEDULED_TABLE_SQL, sql_no_args())?;
        Ok(())
    }

    fn scheduled_count(&self) -> i64 {
        #[derive(Deserialize)]
        struct N {
            n: i64,
        }
        self.state
            .storage()
            .sql()
            .exec_raw("SELECT COUNT(*) AS n FROM scheduled", sql_no_args())
            .ok()
            .and_then(|c| c.to_array::<N>().ok())
            .and_then(|r| r.into_iter().next())
            .map(|r| r.n)
            .unwrap_or(rules::MAX_PENDING)
    }

    fn held_envelope(&self, schedule_id: &str) -> Option<String> {
        #[derive(Deserialize)]
        struct E {
            envelope_b64: String,
        }
        self.state
            .storage()
            .sql()
            .exec_raw("SELECT envelope_b64 FROM scheduled WHERE schedule_id = ?", Some(vec![js(schedule_id)]))
            .ok()
            .and_then(|c| c.to_array::<E>().ok())
            .and_then(|r| r.into_iter().next())
            .map(|r| r.envelope_b64)
    }

    /// `/scheduled-put`: hold one. The same id with the same envelope again is a no-op; with
    /// another envelope, a conflict. At most `MAX_PENDING` held.
    pub(super) async fn scheduled_put(&self, mut req: Request) -> Result<Response> {
        let body: PutBody = req.json().await?;
        if let Some(existing) = self.held_envelope(&body.schedule_id) {
            return if existing == body.envelope_b64 {
                Response::empty().map(|r| r.with_status(204))
            } else {
                crate::respond::json_err(409, "scheduled/conflict")
            };
        }
        if self.scheduled_count() >= rules::MAX_PENDING {
            return crate::respond::json_err(409, "scheduled/quota");
        }
        let now = crate::utils::now_ms() as i64;
        self.state.storage().sql().exec_raw(
            "INSERT INTO scheduled (schedule_id, sender_id, sender_device_id, recipient_id, group_id, release_at,
                                    envelope_b64, targets_json, created_at, attempts, next_attempt_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
            Some(vec![
                js(&body.schedule_id),
                js(&body.sender_id),
                js(&body.sender_device_id),
                body.recipient_id.as_deref().map(js).unwrap_or(JsValue::NULL),
                body.group_id.as_deref().map(js).unwrap_or(JsValue::NULL),
                num(body.release_at),
                js(&body.envelope_b64),
                js(&body.targets_json),
                num(now),
                num(body.release_at),
            ]),
        )?;
        self.arm_alarm_within((body.release_at - now).max(0)).await;
        Response::empty().map(|r| r.with_status(204))
    }

    /// `/scheduled-cancel`: let go of one. Answers `{held, released_any}`: whether it was still held,
    /// and whether its release had already begun — a sender who cancels one the relay has released,
    /// to everyone (review finding 6) or to some (re-review 6a), is told so, and a row whose release
    /// began is kept to reach the rest (`scheduled_rules::cancel_answer`).
    pub(super) async fn scheduled_cancel(&self, mut req: Request) -> Result<Response> {
        let body: CancelBody = req.json().await?;
        let (delete, answer) = rules::cancel_answer(self.held_released_any(&body.schedule_id));
        if delete {
            self.forget_scheduled(&body.schedule_id);
        }
        Response::from_json(&answer)
    }

    /// Whether `schedule_id` is held, and if so whether its release has begun.
    fn held_released_any(&self, schedule_id: &str) -> Option<bool> {
        #[derive(Deserialize)]
        struct R {
            released_any: i64,
        }
        self.state
            .storage()
            .sql()
            .exec_raw("SELECT released_any FROM scheduled WHERE schedule_id = ?", Some(vec![js(schedule_id)]))
            .ok()
            .and_then(|c| c.to_array::<R>().ok())
            .and_then(|r| r.into_iter().next())
            .map(|r| r.released_any != 0)
    }

    /// How long until the soonest held row is next to be tried, from now (`None`: nothing held).
    pub(super) fn next_scheduled_in(&self) -> Option<i64> {
        #[derive(Deserialize)]
        struct At {
            at: Option<i64>,
        }
        let at = self
            .state
            .storage()
            .sql()
            .exec_raw("SELECT MIN(next_attempt_at) AS at FROM scheduled", sql_no_args())
            .ok()
            .and_then(|c| c.to_array::<At>().ok())
            .and_then(|r| r.into_iter().next())
            .and_then(|r| r.at)?;
        Some(at - crate::utils::now_ms() as i64)
    }

    /// Release the held message most due now, if any. Answers whether this run released (or tried
    /// to release) anything — the caller then leaves the stale-pending backstop to the next run.
    pub(super) async fn release_due_scheduled(&self) -> bool {
        let now = crate::utils::now_ms() as i64;
        let row: Option<HeldRow> = self
            .state
            .storage()
            .sql()
            .exec_raw(rules::SELECT_DUE_SQL, Some(vec![num(now)]))
            .ok()
            .and_then(|c| c.to_array::<HeldRow>().ok())
            .and_then(|r| r.into_iter().next());
        let Some(row) = row else { return false };
        // Past saving: given up before it is tried again.
        if rules::gives_up(row.release_at, now) {
            console_log!("[sched] {} given up, {} days past its time", row.schedule_id, rules::RELEASE_GIVE_UP_MS / 86_400_000);
            self.forget_scheduled(&row.schedule_id);
            return true;
        }
        let (Ok(db), Ok(namespace)) = (self.env.d1("DB"), self.env.durable_object("USER_INBOX")) else {
            self.retry_scheduled(&row, None, now, false);
            return true;
        };
        let mut budget = rules::members_per_release_run(crate::messages::budget::resolve_budget(&self.env));
        let (left, budget_only) = self.release_one(&db, &namespace, &row, &mut budget).await;
        if left.is_empty() {
            self.forget_scheduled(&row.schedule_id);
        } else {
            self.retry_scheduled(&row, Some(&left), now, budget_only);
        }
        true
    }

    fn forget_scheduled(&self, schedule_id: &str) {
        let _ = self
            .state
            .storage()
            .sql()
            .exec_raw("DELETE FROM scheduled WHERE schedule_id = ?", Some(vec![js(schedule_id)]));
    }

    /// Keep what is left of a row for its next try, on its backoff (a second when only the budget
    /// ran out).
    fn retry_scheduled(&self, row: &HeldRow, left: Option<&[Target]>, now: i64, budget_only: bool) {
        let targets = left.map_or_else(|| row.targets_json.clone(), |l| serde_json::to_string(l).unwrap_or_default());
        let attempts = if budget_only { row.attempts } else { row.attempts + 1 };
        let next = rules::next_attempt_at(now, attempts, budget_only);
        let _ = self.state.storage().sql().exec_raw(
            "UPDATE scheduled SET targets_json = ?, attempts = ?, next_attempt_at = ? WHERE schedule_id = ?",
            Some(vec![js(&targets), num(attempts), num(next), js(&row.schedule_id)]),
        );
    }

    /// Release one held message to whoever may still have it. Answers the targets left, and whether
    /// only the run's budget left them (not a failed call).
    async fn release_one(
        &self,
        db: &D1Database,
        namespace: &ObjectNamespace,
        row: &HeldRow,
        budget: &mut usize,
    ) -> (Vec<Target>, bool) {
        let targets: Vec<Target> = serde_json::from_str(&row.targets_json).unwrap_or_default();
        let conversation = match (row.recipient_id.as_deref(), row.group_id.as_deref()) {
            (Some(r), _) => Conversation::Direct(r),
            (None, Some(g)) => Conversation::Room(g),
            (None, None) => return (Vec::new(), false),
        };
        let Ok(allowed) = crate::messages::scheduled::allowed_users(db, &row.sender_id, &conversation).await else {
            return (targets, false);
        };
        let mut users: Vec<&str> = targets.iter().map(|t| t.user_id.as_str()).collect();
        users.push(row.sender_id.as_str());
        users.sort_unstable();
        users.dedup();
        let Ok(devices) = crate::messages::scheduled::active_devices(db, &users).await else {
            return (targets, false);
        };
        let to = rules::release_targets(&targets, &row.sender_id, &row.sender_device_id, &allowed, &devices);
        let mut per_user: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (user, device) in to {
            per_user.entry(user).or_default().push(device);
        }
        // From here a take-back is too late (re-review 6a): marked before the first delivery. A
        // row no longer there was taken back while the lookups above were awaited: nothing goes.
        if !per_user.is_empty() {
            match self.state.storage().sql().exec_raw(rules::BEGIN_RELEASE_SQL, Some(vec![js(&row.schedule_id)])) {
                Ok(c) if c.rows_written() == 0 => {
                    console_log!("[sched] {} taken back before its release", row.schedule_id);
                    return (Vec::new(), true);
                }
                Ok(_) => {}
                Err(_) => return (targets, false),
            }
        }
        let mut left: Vec<Target> = Vec::new();
        let mut failed = false;
        for (user, device_ids) in per_user {
            if user == row.sender_id {
                // My own devices: into this very queue, no call.
                let mut missed = Vec::new();
                for device in &device_ids {
                    if !self.release_to_own(&row.sender_id, &row.sender_device_id, device, &row.envelope_b64).await {
                        missed.push(device.clone());
                    }
                }
                if !missed.is_empty() {
                    failed = true;
                    left.push(Target { user_id: user, device_ids: missed });
                }
                continue;
            }
            if *budget == 0 {
                left.push(Target { user_id: user, device_ids });
                continue;
            }
            *budget -= 1;
            let body = ReleaseBody {
                sender_id: row.sender_id.clone(),
                sender_device_id: row.sender_device_id.clone(),
                recipient_id: user.clone(),
                device_ids: device_ids.clone(),
                envelope_b64: row.envelope_b64.clone(),
            };
            if !notify_release(namespace, &body).await {
                failed = true;
                left.push(Target { user_id: user, device_ids });
            }
        }
        console_log!(
            "[sched] {} released ({} members left)",
            row.schedule_id,
            left.len()
        );
        (left, !failed)
    }

    /// `/notify-release`: one member's share of a release — a row per device in this inbox, and one
    /// wake for those not connected, from this invocation (the group fan-out's `/notify-member`
    /// shape). Never a group frame: the receiver reads a kind-3 envelope as a release.
    pub(super) async fn notify_release_here(&self, mut req: Request) -> Result<Response> {
        let body: ReleaseBody = req.json().await?;
        if body.device_ids.is_empty() || body.device_ids.len() > crate::devices::handlers::MAX_DEVICES {
            return Response::error("bad_request", 400);
        }
        // A release is the only thing this door carries (`scheduled_rules::is_scheduled_envelope`).
        if !rules::is_scheduled_envelope(&body.envelope_b64) {
            return Response::error("bad_request", 400);
        }
        let covers_ms = crate::utils::now_ms() as i64;
        let mut asleep = Vec::new();
        let mut carried = crate::push::carry::Carried::none();
        for device in &body.device_ids {
            let notified = self
                .notify_inner(
                    &body.sender_id,
                    Some(&body.sender_device_id),
                    Some(device),
                    Some(&body.recipient_id),
                    &body.envelope_b64,
                    None,
                    false,
                    false,
                )
                .await?;
            if !notified.delivered_live && !notified.deduped {
                if let Some(frame) = &notified.frame {
                    carried.add(device, frame, self.push_key(device).as_ref());
                }
                asleep.push(device.clone());
            }
        }
        self.ensure_alarm().await;
        if !asleep.is_empty() {
            // One wake for every device not connected, after the answer and paid by this invocation.
            let env = self.env.clone();
            let user = body.recipient_id.clone();
            let marks = self.wake_marks();
            let ask = crate::push::coalesce::WakeAsk { covers_ms, urgent: false };
            self.state.wait_until(async move {
                if let Ok(db) = env.d1("DB") {
                    crate::push::wake::push_wake_devices(&env, &db, &marks, &user, Some(asleep.as_slice()), ask, &carried).await;
                }
            });
        }
        Response::empty().map(|r| r.with_status(204))
    }

    /// A release to one of the sender's own devices: into this object's own queue, as `/notify`
    /// would put it, with its wake.
    async fn release_to_own(&self, sender_id: &str, sender_device: &str, device: &str, envelope_b64: &str) -> bool {
        let covers_ms = crate::utils::now_ms() as i64;
        let Ok(notified) = self
            .notify_inner(sender_id, Some(sender_device), Some(device), Some(sender_id), envelope_b64, None, false, false)
            .await
        else {
            return false;
        };
        if !notified.delivered_live && !notified.deduped {
            let ask = crate::push::coalesce::WakeAsk { covers_ms, urgent: false };
            let mut carried = crate::push::carry::Carried::none();
            if let Some(frame) = &notified.frame {
                carried.add(device, frame, self.push_key(device).as_ref());
            }
            self.wake_after_notify(Some(sender_id.to_string()), Some(device.to_string()), ask, carried);
        }
        true
    }
}

/// One member call: their inbox's `/notify-release`.
async fn notify_release(namespace: &ObjectNamespace, body: &ReleaseBody) -> bool {
    let call = async {
        let stub = namespace.id_from_name(&body.recipient_id)?.get_stub()?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        init.with_body(Some(serde_json::to_string(body).unwrap_or_default().into()));
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        init.with_headers(headers);
        let req = Request::new_with_init("https://do.sezgi/notify-release", &init)?;
        let resp = stub.fetch_with_request(req).await?;
        Ok::<bool, Error>(resp.status_code() == 204)
    };
    call.await.unwrap_or(false)
}
