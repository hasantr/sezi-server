//! The inbox's two group fan-out routes (D8, 2026-10-13).
//!
//! - `POST /notify-member` — one group message for THIS inbox's owner and all of their devices:
//!   a pending row and a live push per device (`notify_inner`, unchanged), one answer per device,
//!   and then — after answering — ONE wake for every device that was not live, sent from this
//!   invocation. That is the point of the route: the wake's D1 reads and its fetch to FCM or the
//!   relay leave the sender's request, whose free-plan budget of 50 used to pay for 7 asleep
//!   devices, and come out of this invocation's own budget (`budget::MEMBER_WAKE_*`).
//! - `POST /fanout` — a fan-out HOP. The sender's request hands a chunk of members to the sender's
//!   own inbox, which calls them from here, a fresh invocation with its own budget
//!   (`budget::plan_group_fanout`). Reachable only through a DO stub, i.e. only from the worker.

use super::UserInbox;
use crate::messages::budget;
use crate::messages::group_fanout::{run_hop, DeviceResult, DoCalls, HopBody, HopReply, MemberNotifyBody};
use worker::*;

#[cfg(feature = "bench-faults")]
#[path = "bench_faults.rs"]
mod bench_faults;

impl UserInbox {
    pub(crate) async fn notify_member(&self, mut req: Request) -> Result<Response> {
        let body: MemberNotifyBody = req.json().await?;
        #[cfg(feature = "bench-faults")]
        if self.bench_member_fault(&body.recipient_id).await {
            return Response::error("bench_fault", 503);
        }
        let msg = &body.message;
        // Every device named, or one device-blind row. An empty list names nobody and is a bug in
        // the caller, not a request to store a blind row.
        let targets: Vec<Option<String>> = match &body.recipient_device_ids {
            Some(list) if list.is_empty() => return Response::error("no_devices", 400),
            Some(list) => list.iter().cloned().map(Some).collect(),
            None => vec![None],
        };
        // Before anything is stored: what the wake must cover (`push::coalesce`).
        let covers_ms = crate::utils::now_ms() as i64;
        let mut results = Vec::with_capacity(targets.len());
        let mut fresh_asleep: Vec<Option<String>> = Vec::new();
        let mut failure = None;
        for device in targets {
            match self
                .notify_inner(
                    &msg.sender_id,
                    Some(msg.sender_device_id.as_str()),
                    device.as_deref(),
                    Some(body.recipient_id.as_str()),
                    &msg.envelope_b64,
                    Some(msg.group_id.as_str()),
                    msg.silent,
                )
                .await
            {
                Ok((id, delivered_live, deduped)) => {
                    // Only a device whose row THIS call stored is woken here. A dedup hit means an
                    // earlier call stored it and decided its wake — a hop whose answer was lost,
                    // the sender's retry, a drained row — and waking again is how one message
                    // used to wake a phone two or three times (the D8 review's F4).
                    if !delivered_live && !deduped {
                        fresh_asleep.push(device.clone());
                    }
                    results.push(DeviceResult { device_id: device, id, delivered_live });
                }
                // One device failing fails the member: the caller retries it whole, and the dedup
                // makes the devices already stored answer again without a second row or wake.
                Err(e) => failure = Some(e),
            }
        }
        // As on `/notify`: cheap, and revives a broken alarm chain so the backstop wake still runs.
        self.ensure_alarm().await;
        // The wake for what was stored goes out even when a later device failed: the retry will
        // find those rows deduplicated and will not wake them.
        if let Some(devices) = wake_plan(&fresh_asleep) {
            if msg.silent {
                console_log!("[push] skipped (silent) group={} user={}", msg.group_id, body.recipient_id);
            } else {
                console_log!(
                    "[push] waking group={} user={} devices={}",
                    msg.group_id,
                    body.recipient_id,
                    fresh_asleep.len()
                );
                let env = self.env.clone();
                let user = body.recipient_id.clone();
                let marks = self.wake_marks();
                let ask = crate::push::coalesce::WakeAsk { covers_ms, urgent: msg.urgent };
                // AFTER the answer: the caller does not wait for FCM, and this invocation pays.
                self.state.wait_until(async move {
                    if let Ok(db) = env.d1("DB") {
                        crate::push::wake::push_wake_devices(
                            &env,
                            &db,
                            &marks,
                            &user,
                            devices.as_deref(),
                            ask,
                        )
                        .await;
                    }
                });
            }
        }
        if let Some(e) = failure {
            return Err(e);
        }
        Response::from_json(&serde_json::json!({ "results": results }))
    }

    pub(crate) async fn fanout_hop(&self, mut req: Request) -> Result<Response> {
        let body: HopBody = req.json().await?;
        let namespace = self.env.durable_object("USER_INBOX")?;
        let calls = DoCalls { ns: &namespace };
        let budget_total = budget::resolve_budget(&self.env);
        let outcomes = run_hop(&calls, &body.message, &body.members, budget_total).await;
        #[cfg(feature = "bench-faults")]
        if self.bench_hop_fault().await {
            return Response::error("bench_fault_after_delivery", 500);
        }
        Response::from_json(&HopReply { outcomes })
    }
}

/// Which devices to wake, given the asleep devices THIS call stored: `None` = nobody;
/// `Some(None)` = every device the member has (a device-blind row); `Some(Some(list))` = those.
fn wake_plan(fresh_asleep: &[Option<String>]) -> Option<Option<Vec<String>>> {
    if fresh_asleep.is_empty() {
        None
    } else if fresh_asleep.iter().any(Option::is_none) {
        Some(None)
    } else {
        Some(Some(fresh_asleep.iter().flatten().cloned().collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::wake_plan;

    #[test]
    fn a_member_whose_rows_were_all_there_already_is_not_woken_again() {
        assert_eq!(wake_plan(&[]), None);
    }

    #[test]
    fn only_the_freshly_stored_asleep_devices_are_woken() {
        assert_eq!(wake_plan(&[Some("a".into())]), Some(Some(vec!["a".to_string()])));
        assert_eq!(wake_plan(&[None]), Some(None), "a device-blind row wakes every device");
    }
}
