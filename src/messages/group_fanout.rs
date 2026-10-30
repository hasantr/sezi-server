//! A group message's fan-out (D8, 2026-10-13): one call per MEMBER, the wake sent by the
//! member's own inbox, at most six calls in flight, and hops for a room too large for one request.
//!
//! **Why it changed.** It used to be one DO `/notify` per (member, device) plus, for an asleep
//! device, a push from the sender's request — so the free plan's 50 subrequests paid for 7 asleep
//! devices and an 80 × 2 class waited ~35 minutes for the cron (I4.8 in
//! `docs/FIELD_READINESS_PLAN.md`). Now:
//! - a member is ONE `/notify-member` carrying every one of its devices; the inbox stores a pending
//!   row per device and wakes the asleep ones out of its own invocation
//!   (`inbox_do/member_notify.rs`);
//! - calls go `MAX_CONCURRENT_CALLS` at a time instead of one after another;
//! - past what one invocation can safely call (`budget::plan_group_fanout`), the members are handed
//!   in chunks to `/fanout` hops on the sender's own inbox, each a fresh invocation.
//!
//! The same `notify_members` serves the send, a hop and the retry drain, so the three cannot drift.

use crate::d1util::d1_text;
use crate::messages::budget::{
    self, FanoutPlan, SubrequestBudget, COST_MEMBER_CALL, MAX_CONCURRENT_CALLS,
};
use crate::respond::json_err;
use crate::utils::now_secs;
use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use worker::*;

/// A pause before the one in-request retry: long enough for a DO restart or a routing hiccup to
/// settle, short enough not to matter to the sender. Everything beyond is `fanout_retry`'s job.
const RETRY_DELAY_MS: u64 = 50;

/// One recipient of a group message: a user and the devices to store it for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Member {
    pub(crate) user_id: String,
    /// `None` = device-blind: an active member who never published a device list. The inbox
    /// queues one pending row with no device, which the NULL-tolerant flush delivers once that
    /// member publishes and connects.
    #[serde(default)]
    pub(crate) devices: Option<Vec<String>>,
}

/// The message itself — the same for every member, so it travels once per call.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GroupMessage {
    pub(crate) sender_id: String,
    pub(crate) sender_device_id: String,
    pub(crate) envelope_b64: String,
    pub(crate) group_id: String,
    /// No wake for an asleep device (control traffic). The inbox persists it on the pending row.
    pub(crate) silent: bool,
    /// A ring starting or stopping: the member's wake goes past the coalescing gate
    /// (`push::coalesce`). Not kept by the durable retry queue (`fanout_retry`): its first retry
    /// is 30 s after the send, when a 45 s ring has little left to save, and an ordinary wake
    /// still goes out for it. Absent (an older hop body) reads as false.
    #[serde(default)]
    pub(crate) urgent: bool,
}

/// One device's answer from `/notify-member`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DeviceResult {
    pub(crate) device_id: Option<String>,
    pub(crate) id: i64,
    pub(crate) delivered_live: bool,
}

/// What became of one member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum MemberOutcome {
    /// Stored for every device; `first_id` is a pending id the sender may report.
    Delivered { first_id: i64 },
    /// Attempted and failed → the durable retry queue.
    Failed,
    /// Never attempted: the budget could not pay for it → the durable retry queue.
    Deferred,
}

/// The `/notify-member` body. `recipient_id` is the inbox's owner (persisted for its alarm).
#[derive(Serialize, Deserialize)]
pub(crate) struct MemberNotifyBody {
    #[serde(flatten)]
    pub(crate) message: GroupMessage,
    pub(crate) recipient_id: String,
    pub(crate) recipient_device_ids: Option<Vec<String>>,
}

/// The `/fanout` body and answer: a chunk of members for a hop, and one outcome per member in the
/// same order.
#[derive(Serialize, Deserialize)]
pub(crate) struct HopBody {
    pub(crate) message: GroupMessage,
    pub(crate) members: Vec<Member>,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct HopReply {
    pub(crate) outcomes: Vec<MemberOutcome>,
}

/// The member×device query's rows, grouped per member in first-seen order. A NULL device (the
/// LEFT JOIN's member with no devices) makes the member device-blind.
pub(crate) fn members_from_pairs(pairs: Vec<(String, Option<String>)>) -> Vec<Member> {
    let mut out: Vec<Member> = Vec::new();
    for (user_id, device) in pairs {
        let idx = match out.iter().position(|m| m.user_id == user_id) {
            Some(i) => i,
            None => {
                out.push(Member { user_id, devices: Some(Vec::new()) });
                out.len() - 1
            }
        };
        let m = &mut out[idx];
        match (device, m.devices.as_mut()) {
            (Some(d), Some(list)) => list.push(d),
            (None, _) => m.devices = None,
            (Some(_), None) => {}
        }
    }
    out
}

async fn post_json(stub: &Stub, path: &str, body: String) -> Result<Response> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let req = Request::new_with_init(&format!("https://do.sezgi{path}"), &init)?;
    stub.fetch_with_request(req).await
}

/// The subrequests a fan-out makes, behind a seam: production calls Durable Objects
/// (`DoCalls`); `messages/spend_tests.rs` runs this same orchestration against fakes that count
/// every call under a hard ceiling and inject failures.
pub(crate) trait FanoutCalls {
    /// ONE `/notify-member`; the member's first pending id.
    async fn member(&self, msg: &GroupMessage, m: &Member) -> Result<i64>;
    /// ONE `/fanout` to a hop, one outcome per member of `chunk`.
    async fn hop(&self, msg: &GroupMessage, chunk: &[Member]) -> Result<Vec<MemberOutcome>>;
    /// The pause before the one in-request retry.
    async fn pause(&self);
}

/// Where a send's undelivered members are written for the drain.
pub(crate) trait RetryStore {
    async fn enqueue(&self, msg: &GroupMessage, members: &[&Member]) -> Result<()>;
}

/// The real calls: each member's inbox, and the sender's own inbox as the hop.
pub(crate) struct DoCalls<'a> {
    pub(crate) ns: &'a ObjectNamespace,
}

impl FanoutCalls for DoCalls<'_> {
    async fn member(&self, msg: &GroupMessage, m: &Member) -> Result<i64> {
        let stub = self.ns.id_from_name(&m.user_id)?.get_stub()?;
        let body = serde_json::to_string(&MemberNotifyBody {
            message: msg.clone(),
            recipient_id: m.user_id.clone(),
            recipient_device_ids: m.devices.clone(),
        })?;
        let mut resp = post_json(&stub, "/notify-member", body).await?;
        if resp.status_code() != 200 {
            return Err(Error::RustError(format!("notify_member_status_{}", resp.status_code())));
        }
        #[derive(Deserialize)]
        struct Reply {
            results: Vec<DeviceResult>,
        }
        let reply: Reply = resp.json().await?;
        reply
            .results
            .first()
            .map(|r| r.id)
            .ok_or_else(|| Error::RustError("notify_member_empty".into()))
    }

    async fn hop(&self, msg: &GroupMessage, chunk: &[Member]) -> Result<Vec<MemberOutcome>> {
        let stub = self.ns.id_from_name(&msg.sender_id)?.get_stub()?;
        let body = serde_json::to_string(&HopBody { message: msg.clone(), members: chunk.to_vec() })?;
        let mut resp = post_json(&stub, "/fanout", body).await?;
        if resp.status_code() != 200 {
            return Err(Error::RustError(format!("fanout_status_{}", resp.status_code())));
        }
        let reply: HopReply = resp.json().await?;
        if reply.outcomes.len() != chunk.len() {
            return Err(Error::RustError("fanout_bad_reply".into()));
        }
        Ok(reply.outcomes)
    }

    async fn pause(&self) {
        worker::Delay::from(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
    }
}

/// Run `call` for each index in `todo`, at most `MAX_CONCURRENT_CALLS` at a time.
async fn bounded<'a, T, F, Fut>(todo: Vec<usize>, call: F) -> Vec<(usize, Result<T>)>
where
    F: Fn(usize) -> Fut + 'a,
    Fut: std::future::Future<Output = Result<T>> + 'a,
{
    stream::iter(todo)
        .map(|i| {
            let f = call(i);
            async move { (i, f.await) }
        })
        .buffer_unordered(MAX_CONCURRENT_CALLS)
        .collect()
        .await
}

/// Pick the indices the budget can pay for, charging one member call each, in order.
fn affordable(candidates: impl Iterator<Item = usize>, budget: &mut SubrequestBudget) -> Vec<usize> {
    let mut out = Vec::new();
    for i in candidates {
        if !budget.can_afford(COST_MEMBER_CALL) {
            break;
        }
        budget.spend(COST_MEMBER_CALL);
        out.push(i);
    }
    out
}

/// Notify `members` from this invocation, paying `COST_MEMBER_CALL` each. A member the budget
/// cannot pay for is `Deferred` and never attempted. With `retry`, every failed member gets ONE
/// more attempt after a pause, as far as the budget still pays; the inbox's dedup makes a repeat
/// store nothing twice and wake nobody twice. The send and the hops retry; the drain does not
/// (its row backoff IS the retry).
pub(crate) async fn notify_members<C: FanoutCalls>(
    calls: &C,
    msg: &GroupMessage,
    members: &[Member],
    budget: &mut SubrequestBudget,
    retry: bool,
) -> Vec<MemberOutcome> {
    let mut out = vec![MemberOutcome::Deferred; members.len()];
    let mut todo = affordable(0..members.len(), budget);
    for attempt in 0..2 {
        if todo.is_empty() || (attempt > 0 && !retry) {
            break;
        }
        if attempt > 0 {
            calls.pause().await;
        }
        let results = bounded(todo, |i| calls.member(msg, &members[i])).await;
        let mut failed = Vec::new();
        for (i, r) in results {
            match r {
                Ok(first_id) => out[i] = MemberOutcome::Delivered { first_id },
                Err(_) => {
                    out[i] = MemberOutcome::Failed;
                    failed.push(i);
                }
            }
        }
        failed.sort_unstable();
        todo = affordable(failed.into_iter(), budget);
    }
    out
}

/// A hop's whole job, in its own invocation: its chunk, with retries, out of a fresh purse.
pub(crate) async fn run_hop<C: FanoutCalls>(
    calls: &C,
    msg: &GroupMessage,
    members: &[Member],
    budget_total: usize,
) -> Vec<MemberOutcome> {
    let mut budget = SubrequestBudget::new(budget_total, budget::HOP_OVERHEAD);
    notify_members(calls, msg, members, &mut budget, true).await
}

/// The sender's side: direct, or through hops, per `budget::plan_group_fanout`. A hop that fails
/// twice fails its whole chunk, which then goes to the retry queue member by member; a member it
/// did reach is not stored or woken again by that retry (the inbox's dedup).
pub(crate) async fn fan_out<C: FanoutCalls>(
    calls: &C,
    msg: &GroupMessage,
    members: &[Member],
    budget_total: usize,
    reserved: usize,
) -> Vec<MemberOutcome> {
    let mut budget = SubrequestBudget::new(budget_total, reserved);
    let chunk = match budget::plan_group_fanout(budget_total, reserved, members.len()) {
        FanoutPlan::Direct => return notify_members(calls, msg, members, &mut budget, true).await,
        FanoutPlan::Hops { chunk } => chunk,
    };
    let chunks: Vec<&[Member]> = members.chunks(chunk).collect();
    let mut per_chunk: Vec<Option<Vec<MemberOutcome>>> = vec![None; chunks.len()];
    let mut todo = affordable(0..chunks.len(), &mut budget);
    for attempt in 0..2 {
        if todo.is_empty() {
            break;
        }
        if attempt > 0 {
            calls.pause().await;
        }
        let results = bounded(todo, |i| calls.hop(msg, chunks[i])).await;
        let mut failed = Vec::new();
        for (i, r) in results {
            match r {
                Ok(outcomes) => per_chunk[i] = Some(outcomes),
                Err(_) => {
                    per_chunk[i] = Some(vec![MemberOutcome::Failed; chunks[i].len()]);
                    failed.push(i);
                }
            }
        }
        failed.sort_unstable();
        todo = affordable(failed.into_iter(), &mut budget);
    }
    per_chunk
        .into_iter()
        .zip(chunks)
        .flat_map(|(o, c)| o.unwrap_or_else(|| vec![MemberOutcome::Deferred; c.len()]))
        .collect()
}

/// What the group send answers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendVerdict {
    /// Every member was delivered or durably queued. `queued` is the count of the latter.
    Sent { first_id: Option<i64>, queued: usize },
    /// Every attempted member failed: a retryable 502, nothing queued — the sender resends, and
    /// the inbox's dedup makes that safe.
    AllFailed,
    /// Members were neither delivered nor written to the queue (the close failed twice). The send
    /// must NOT be acknowledged: a 502 makes the sender resend, which the dedup absorbs for the
    /// members already reached.
    NotRecorded { queued: usize },
}

/// The fan-out and its close: everything after the prelude, behind the two seams, so the budget
/// tests run exactly this. `reserved` is what the invocation holds back from the fan-out —
/// `budget::send_reserved` — which includes the close, so the close is never the call cut off.
pub(crate) async fn fan_out_and_close<C: FanoutCalls, S: RetryStore>(
    calls: &C,
    store: &S,
    msg: &GroupMessage,
    members: &[Member],
    budget_total: usize,
    reserved: usize,
) -> SendVerdict {
    let outcomes = fan_out(calls, msg, members, budget_total, reserved).await;
    let first_id = outcomes.iter().find_map(|o| match o {
        MemberOutcome::Delivered { first_id } => Some(*first_id),
        _ => None,
    });
    let attempted = outcomes.iter().filter(|o| **o != MemberOutcome::Deferred).count();
    // `attempted` rather than `members.is_empty()`: a DEFERRED member was never tried and is no
    // evidence that delivery is broken.
    if attempted > 0 && first_id.is_none() {
        return SendVerdict::AllFailed;
    }
    let queued: Vec<&Member> = members
        .iter()
        .zip(&outcomes)
        .filter(|(_, o)| !matches!(o, MemberOutcome::Delivered { .. }))
        .map(|(m, _)| m)
        .collect();
    // The close, retried once — both attempts are in `budget::CLOSE`, inside `reserved`.
    if !queued.is_empty()
        && store.enqueue(msg, &queued).await.is_err()
        && store.enqueue(msg, &queued).await.is_err()
    {
        return SendVerdict::NotRecorded { queued: queued.len() };
    }
    SendVerdict::Sent { first_id, queued: queued.len() }
}

/// The group branch of `POST /messages/send`: the PUBLIC gate (an active member, or 403), then
/// [`fan_out_group`]. The gate is unchanged by bots: they post from inside the relay.
pub(crate) async fn send_group(
    env: &Env,
    db: &D1Database,
    ns: &ObjectNamespace,
    msg: GroupMessage,
) -> Result<Response> {
    // The send gate is MEMBERSHIP ALONE, by design: the server never sees the content and
    // distributes purely from the membership table (blocking is not a moderation layer here).
    if crate::groups::group_role(db, &msg.group_id, &msg.sender_id).await?.is_none() {
        return json_err(403, "not_member");
    }
    fan_out_group(env, db, ns, msg).await
}

/// Active members crossed with their active devices (`revoked_at IS NULL`), the sender left out.
/// The join MUST stay LEFT: an INNER JOIN dropped a member with no device rows from the fan-out
/// and lost their group message permanently. Bind: group, sender.
pub(crate) const GROUP_SEND_MEMBERS_SQL: &str = "SELECT gm.user_id AS user_id, d.device_id AS device_id
     FROM group_members gm
     LEFT JOIN devices d
       ON d.user_id = gm.user_id AND d.revoked_at IS NULL
     WHERE gm.group_id = ? AND gm.user_id != ?
       AND gm.status = 'active'";

/// Who a room message goes to: every active member but the sender, with their active devices,
/// grouped per member. One D1 query. The bot's room send (`inbox_do/bot/room.rs`) reads its
/// recipients through this too, so the two cannot drift.
pub(crate) async fn group_send_members(db: &D1Database, group_id: &str, sender_id: &str) -> Result<Vec<Member>> {
    #[derive(Deserialize)]
    struct MemberDevice {
        user_id: String,
        // NULL for an active member who never published a device list — see the LEFT JOIN.
        device_id: Option<String>,
    }
    let pairs: Vec<MemberDevice> = db
        .prepare(GROUP_SEND_MEMBERS_SQL)
        .bind(&[d1_text(group_id), d1_text(sender_id)])?
        .all()
        .await?
        .results()?;
    Ok(members_from_pairs(pairs.into_iter().map(|p| (p.user_id, p.device_id)).collect()))
}

/// How many pending rows a fan-out to `members` stores: one per device, one for a device-blind
/// member.
pub(crate) fn fanout_width(members: &[Member]) -> usize {
    members.iter().map(|m| m.devices.as_ref().map_or(1, Vec::len)).sum()
}

/// Everything after the public gate, for a sender that passed it: the members, the
/// width-weighted rate limit, the fan-out and its close, the response.
///
/// It is NOT the bot's way into a room. A bot is never a member, so it never reaches here
/// through `send_group`; its posts go out from its own inbox after its own `group_bots` check
/// (`inbox_do/bot/room.rs`), in budgeted chunks through [`notify_members`].
pub(crate) async fn fan_out_group(
    env: &Env,
    db: &D1Database,
    ns: &ObjectNamespace,
    msg: GroupMessage,
) -> Result<Response> {
    let members = group_send_members(db, &msg.group_id, &msg.sender_id).await?;
    let width = fanout_width(&members);
    // A second guard, weighted by fan-out WIDTH in devices: one group send stores a pending row
    // per device, which the single-hit `msg:send` bucket counts as one event. 6000 units/60s
    // permits ~23 sends/min into a full 256-member group and far more into small ones.
    if width > 0
        && !crate::ratelimit::check_rate_limit_weighted_env(
            env,
            &format!("msg:grp_fanout:{}", msg.sender_id),
            6000,
            60,
            width,
        )
        .await
    {
        return json_err(429, "rate_limited");
    }

    // What THIS invocation already spent provisioning a cold isolate is charged here, measured
    // where it ran (`self_provision::recent_spend`).
    let provision = crate::self_provision::recent_spend(crate::utils::now_ms());
    let verdict = fan_out_and_close(
        &DoCalls { ns },
        &super::handlers::D1RetryStore { db },
        &msg,
        &members,
        budget::resolve_budget(env),
        budget::send_reserved(provision),
    )
    .await;
    let (first_id, queued) = match verdict {
        SendVerdict::AllFailed => return json_err(502, "fanout_failed"),
        SendVerdict::NotRecorded { queued } => {
            console_error!(
                "[deliv] W4-b enqueue FAILED for {queued} members (group={}) -> 502, the sender resends",
                msg.group_id
            );
            return json_err(502, "fanout_incomplete");
        }
        SendVerdict::Sent { first_id, queued } => (first_id, queued),
    };
    if queued > 0 {
        console_log!(
            "[deliv] W4-b enqueue: {queued} of {} members to durable-retry (group={})",
            members.len(),
            msg.group_id
        );
    }
    let id = first_id.unwrap_or_else(|| now_secs() as i64);
    // The response MUST carry `acks`: the client's `send_group_message` reads `res.acks.first()`.
    // A group has one canonical id, hence a single element. `id` stays for older clients.
    Response::from_json(&serde_json::json!({
        "id": id,
        "ts": now_secs(),
        "acks": [{ "id": id }],
        // MEMBERS (not device pairs, since D8) that fell back to durable retry — failed or over
        // budget. 0 = fully delivered. Telemetry: nothing in the core reads it.
        "failed": queued,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(u: &str, d: Option<&str>) -> (String, Option<String>) {
        (u.to_string(), d.map(str::to_string))
    }

    #[test]
    fn pairs_group_into_members_in_first_seen_order() {
        let m = members_from_pairs(vec![
            pair("a", Some("a1")),
            pair("b", None),
            pair("a", Some("a2")),
            pair("c", Some("c1")),
        ]);
        assert_eq!(
            m,
            vec![
                Member { user_id: "a".into(), devices: Some(vec!["a1".into(), "a2".into()]) },
                Member { user_id: "b".into(), devices: None },
                Member { user_id: "c".into(), devices: Some(vec!["c1".into()]) },
            ]
        );
    }

    /// The wire shape the inbox reads: the message flattened beside the recipient fields, `null`
    /// for a device-blind member.
    #[test]
    fn the_member_notify_body_is_flat() {
        let body = MemberNotifyBody {
            message: GroupMessage {
                sender_id: "s".into(),
                sender_device_id: "sd".into(),
                envelope_b64: "e".into(),
                group_id: "g".into(),
                silent: false,
                urgent: true,
            },
            recipient_id: "r".into(),
            recipient_device_ids: None,
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["sender_id"], "s");
        assert_eq!(v["group_id"], "g");
        assert!(v["recipient_device_ids"].is_null());
        // A ring's flag reaches the member's inbox; a body without it (an older hop) is ordinary.
        assert_eq!(v["urgent"], true);
        let back: MemberNotifyBody = serde_json::from_value(v.clone()).unwrap();
        assert!(back.message.urgent);
        let mut old = v;
        old.as_object_mut().unwrap().remove("urgent");
        assert!(!serde_json::from_value::<MemberNotifyBody>(old).unwrap().message.urgent);
    }

    /// The rate limit's weight: a pending row per device, one for a device-blind member.
    #[test]
    fn the_width_counts_devices_and_a_blind_member_once() {
        let m = members_from_pairs(vec![pair("a", Some("a1")), pair("a", Some("a2")), pair("b", None)]);
        assert_eq!(fanout_width(&m), 3);
        assert_eq!(fanout_width(&[]), 0);
    }

    /// The recipients' query on the real schema: active members only, the sender left out,
    /// revoked devices dropped, a member with no device kept (device-blind).
    #[test]
    fn the_members_query_takes_active_members_and_live_devices() {
        let db = crate::test_schema::full_schema();
        db.execute_batch(
            "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES
               ('s','s@x',x'00',1),('a','a@x',x'00',1),('b','b@x',x'00',1),('p','p@x',x'00',1);
             INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES ('g','G','s',1,1);
             INSERT INTO group_members (group_id, user_id, role, joined_at, status) VALUES
               ('g','s','owner',1,'active'),('g','a','member',1,'active'),
               ('g','b','member',1,'active'),('g','p','member',1,'pending');
             INSERT INTO devices (user_id, device_id, role, ed_pub, x_pub, label, added_at, revoked_at) VALUES
               ('a','a1','primary',x'00',x'00','',1,NULL),('a','a2','linked',x'00',x'00','',1,5),
               ('s','s1','primary',x'00',x'00','',1,NULL);",
        )
        .unwrap();
        let mut st = db.prepare(GROUP_SEND_MEMBERS_SQL).unwrap();
        let mut rows: Vec<(String, Option<String>)> = st
            .query_map(["g", "s"], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        rows.sort();
        assert_eq!(rows, vec![pair("a", Some("a1")), pair("b", None)]);
    }

    #[test]
    fn an_outcome_survives_the_hop_round_trip() {
        let all = vec![
            MemberOutcome::Delivered { first_id: 7 },
            MemberOutcome::Failed,
            MemberOutcome::Deferred,
        ];
        let s = serde_json::to_string(&HopReply { outcomes: all.clone() }).unwrap();
        assert_eq!(serde_json::from_str::<HopReply>(&s).unwrap().outcomes, all);
    }
}
