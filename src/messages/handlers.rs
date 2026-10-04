use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use sha2::{Digest, Sha256};

/// Durable-retry constants for a partially failed group fan-out.
const W4B_INITIAL_BACKOFF_SECS: i64 = 30; // delay from enqueue to the first drain attempt
// The LEASE is the in-flight claim window and is deliberately SEPARATE from the backoff base: it
// must exceed the cron period plus the longest drain, so an overlapping cron cannot re-claim a row
// another drain is still working and double-notify. On failure next_at is overwritten with the
// backoff, so a retry is not delayed; only a CRASHED drain waits out the full lease to self-heal.
const W4B_LEASE_SECS: i64 = 600;
const W4B_BACKOFF_BASE_SECS: i64 = 120; // 120→240→…→cap
const W4B_MAX_BACKOFF_SECS: i64 = 3600; // a long outage retries hourly and is NEVER deleted
const W4B_DRAIN_BATCH: usize = 50; // per cron; bounded by D1 response size + sequential DO fetches
use crate::respond::{json_err, no_content, passthrough};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// HTTP and WebSocket transports must consume the same per-operation buckets.
/// Keeping key construction here prevents a hot-WS path from silently drifting
/// from its HTTP fallback again.
pub(crate) fn send_rate_limit_key(user_id: &str) -> String {
    format!("msg:send:{user_id}")
}

pub(crate) fn read_rate_limit_key(user_id: &str) -> String {
    format!("msg:read:{user_id}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectHttpError {
    status: u16,
    code: &'static str,
}

/// Transport-neutral classification for direct-message authorization. In
/// particular, a D1/query failure is a retryable authorization outage, not an
/// unclassified 500. `not_found_code` preserves each endpoint's wire contract.
fn classify_direct_http(
    decision: std::result::Result<crate::contacts::DirectDecision, ()>,
    not_found_code: &'static str,
) -> std::result::Result<(), DirectHttpError> {
    match decision {
        Ok(crate::contacts::DirectDecision::Allowed) => Ok(()),
        Ok(crate::contacts::DirectDecision::NotFound) => Err(DirectHttpError {
            status: 404,
            code: not_found_code,
        }),
        Ok(crate::contacts::DirectDecision::Denied) => Err(DirectHttpError {
            status: 403,
            code: "contact_not_authorized",
        }),
        Err(()) => Err(DirectHttpError {
            status: 503,
            code: "authorization_unavailable",
        }),
    }
}

/// One item of the envelope batch. For 1:1, `device_id` is the TARGET recipient device (the
/// sender knows it from the bundle → a separate Olm envelope per device). For a GROUP there is
/// NO `device_id`: a single Megolm envelope, whose device fan-out is derived inside the worker.
#[derive(Deserialize)]
struct EnvItem {
    #[serde(default)]
    device_id: Option<String>,
    envelope_b64: String,
}

/// The `/messages/send` body, bit-identical between the HTTP and WS-send paths.
#[derive(Deserialize)]
struct SendBody {
    /// Recipient of a 1:1 direct message. `None` for a group message (`group_id` instead).
    #[serde(default)]
    recipient_id: Option<String>,
    /// Fan out to this group's members. `None` for 1:1.
    #[serde(default)]
    group_id: Option<String>,
    /// The SENDER's device, which lets the recipient pick the right Olm device session; still
    /// carried for a group's single Megolm envelope.
    sender_device_id: String,
    /// One envelope per device. 1:1 has N >= 1; a group has one element with no device_id.
    envelopes: Vec<EnvItem>,
    /// Do NOT send an FCM wake for an offline recipient of this message. The SENDER sets it for
    /// control traffic meaningless to a sleeping device — a capabilities announcement, a
    /// reconnect state digest, a receipt, a typing indicator (the core's `needs_device_wake`).
    ///
    /// It changes nothing about storage or delivery: the envelope is written to the recipient's
    /// pending queue as before and arrives on their next connect. It only declines to spend a
    /// push, a cold start and several seconds of the recipient's radio on it — measured at three
    /// wakes and three full queue drains for one desktop launch, delivering nothing visible.
    #[serde(default)]
    silent: bool,
}

#[derive(Deserialize)]
struct NotifyResult {
    id: i64,
    #[serde(default)]
    delivered_live: bool,
}

/// The recipient DO's `/notify` body. `notify_recipient` and the retry drain both build it here
/// so the shape has one source of truth.
fn build_notify_payload(
    recipient_id: &str,
    sender_id: &str,
    sender_device_id: &str,
    recipient_device_id: Option<&str>,
    envelope_b64: &str,
    group_id: Option<&str>,
    silent: bool,
) -> String {
    serde_json::json!({
        "sender_id": sender_id,
        "sender_device_id": sender_device_id,
        "recipient_device_id": recipient_device_id,
        // notify_inner persists this: an offline DO does not know its own user.
        "recipient_id": recipient_id,
        "envelope_b64": envelope_b64,
        "group_id": group_id,
        // Persisted on the pending row, so the backstop alarm does not wake the device later for
        // a message the immediate path deliberately stayed quiet about.
        "silent": silent,
    })
    .to_string()
}

/// A SINGLE DO `/notify` attempt (store + WS push). Ok → (pending_id, delivered_live); Err on
/// id_from_name/stub failure, a failed fetch, a non-200 status or an unparseable body.
/// `notify_recipient` calls this at most twice; the drain calls it once per row, because that
/// row's own next_at backoff is the retry.
async fn notify_once(
    namespace: &ObjectNamespace,
    recipient_id: &str,
    payload: &str,
) -> Result<(i64, bool)> {
    let stub = namespace.id_from_name(recipient_id)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(payload.to_string().into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let do_req = Request::new_with_init("https://do.sezgi/notify", &init)?;
    let mut resp = stub.fetch_with_request(do_req).await?;
    if resp.status_code() != 200 {
        return Err(Error::RustError(format!("do_notify_status_{}", resp.status_code())));
    }
    resp.json::<NotifyResult>()
        .await
        .map(|r| (r.id, r.delivered_live))
        .map_err(|_| Error::RustError("do_notify_bad_response".into()))
}

/// `/notify` one user's DO inbox (store + WS push). A `group_id` rides along in the recipient's
/// frame so they take the Megolm decrypt path; a `recipient_device` scopes the pending row to
/// that device (per-device queue + ack isolation). The returned `id` is that RECIPIENT's pending
/// sequence id. A per-device failure surfaces as `Err` rather than being silently skipped, which
/// is what makes it visible during fan-out.
#[allow(clippy::too_many_arguments)]
async fn notify_recipient(
    namespace: &ObjectNamespace,
    recipient_id: &str,
    sender_id: &str,
    sender_device_id: &str,
    recipient_device_id: Option<&str>,
    envelope_b64: &str,
    group_id: Option<&str>,
    silent: bool,
) -> Result<(i64, bool)> {
    let payload = build_notify_payload(
        recipient_id,
        sender_id,
        sender_device_id,
        recipient_device_id,
        envelope_b64,
        group_id,
        silent,
    );
    // A bounded in-request retry for a transient DO 5xx / overload / routing error. The DO's own
    // 60s dedup absorbs "it succeeded but the response was lost", so no duplicate pending row
    // appears. Exhausting the attempts returns Err, which the caller counts and enqueues.
    //
    // TWO ATTEMPTS, NOT THREE, AND NOT BACK TO BACK. Three immediate calls to an overloaded
    // Durable Object are an amplifier, not a retry policy — the same question three times inside
    // a few milliseconds, at the moment it is least able to answer — and three subrequests out of
    // a ~50 ceiling (see `messages::budget`), so one struggling member's retries could starve the
    // members behind it. The pause gives the DO time to be re-created, which is the only thing a
    // same-request retry can usefully wait for; everything beyond that is `fanout_retry`'s job.
    const NOTIFY_ATTEMPTS: usize = 2;
    /// Long enough for a DO restart or a routing hiccup to settle, short enough that a group
    /// fan-out of failures does not blow the request's wall clock.
    const NOTIFY_RETRY_DELAY_MS: u64 = 50;
    let mut last_err = Error::RustError("do_notify_failed".into());
    for attempt in 0..NOTIFY_ATTEMPTS {
        if attempt > 0 {
            worker::Delay::from(std::time::Duration::from_millis(NOTIFY_RETRY_DELAY_MS)).await;
        }
        match notify_once(namespace, recipient_id, &payload).await {
            Ok(r) => {
                if attempt > 0 {
                    console_log!(
                        "[deliv] W4 notify retry-recovered: OK on attempt {} (recipient={recipient_id})",
                        attempt + 1
                    );
                }
                return Ok(r);
            }
            Err(e) => last_err = e,
        }
    }
    console_log!("[deliv] W4 notify FAILED after {NOTIFY_ATTEMPTS} attempts (recipient={recipient_id})");
    Err(last_err)
}

// The durable retry queue (cron drain + TTL collector). Declared HERE rather than in
// `messages/mod.rs` so `messages::handlers::drain_fanout_retry` stays the name the scheduler
// already calls — the shape `keys/handlers.rs` uses for `bundle_slot`.
#[path = "fanout_retry.rs"]
mod fanout_retry;
pub(crate) use fanout_retry::{drain_fanout_retry, gc_fanout_retry};

pub async fn send(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (sender_id, token_device) = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => (auth.user_id, auth.device_id),
        Err(resp) => return Ok(resp),
    };
    // Per-user rate limit, so envelopes differing by a byte cannot slip past the 60s dedup and
    // bloat the UserInbox DO's SQLite. 300/60s sits above the busiest legitimate conversation
    // while still cutting automated spam. A group fan-out is ONE hit here however wide it is; the
    // weighted guard further down covers the amplification. The KV binding is optional, and
    // without it check_rate_limit_env fails open.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &send_rate_limit_key(&sender_id),
        300,
        60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let body: SendBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    // Batch validation is ALL-OR-NOTHING: one out-of-range envelope rejects the whole request, so
    // from the client's view either everything was sent or nothing was and its state stays
    // consistent.
    if body.envelopes.is_empty() || body.envelopes.len() > 100 {
        return json_err(400, "bad_request");
    }
    if body.sender_device_id.is_empty() {
        return json_err(400, "bad_request");
    }
    // Token binding — the trust foundation of every self/echo exclusion: `sender_device_id` MUST
    // match the JWT's `device_id` claim, or an HTTP send could be made on another device's behalf
    // (fake self-copy / group echo injection). The WS-send path is already bound through its
    // socket attachment, so this only closes the HTTP forgery surface.
    if token_device != body.sender_device_id {
        return json_err(403, "device_mismatch");
    }
    // A revoked device cannot send, without waiting out the 15 min access-token TTL, so a stolen
    // device is cut off at revocation. One query per send, no polling.
    if crate::auth::middleware::device_revoked(&ctx.env, &sender_id, &body.sender_device_id).await? {
        return json_err(401, "device_revoked");
    }
    for e in &body.envelopes {
        if e.envelope_b64.len() < 20 || e.envelope_b64.len() > 64 * 1024 {
            return json_err(400, "bad_request");
        }
    }

    let db = match ctx.env.d1("DB") {
        Ok(db) => db,
        Err(_) => return json_err(503, "authorization_unavailable"),
    };
    let namespace = ctx.env.durable_object("USER_INBOX")?;

    // ---- GROUP path: /notify every member except the sender ----
    if let Some(group_id) = body.group_id.as_deref() {
        // The send gate is MEMBERSHIP ALONE, by design: the server never sees the content and
        // distributes purely from the membership table (blocking is not a moderation layer here).
        if crate::groups::group_role(&db, group_id, &sender_id)
            .await?
            .is_none()
        {
            return json_err(403, "not_member");
        }
        // A group carries a single Megolm envelope, so exactly one EnvItem with no device_id:
        // the fan-out is derived inside the worker.
        if body.envelopes.len() != 1 || body.envelopes[0].device_id.is_some() {
            return json_err(400, "bad_request");
        }
        let envelope_b64 = body.envelopes[0].envelope_b64.as_str();
        #[derive(Deserialize)]
        struct MemberDevice {
            user_id: String,
            // NULL for an active member who never published a device list — see the LEFT JOIN
            // below.
            device_id: Option<String>,
        }
        // Active members crossed with their active devices (`revoked_at IS NULL`), one (member,
        // device) pair per insert of the single Megolm envelope; the DO's dedup keys on
        // recipient_device, so a second device of the same member is not swallowed.
        //
        // The join MUST stay LEFT. An active member who never published a device list has no row
        // in `devices`, and an INNER JOIN dropped them from the fan-out, losing their group
        // message permanently. LEFT gives `device_id = NULL`, the loop below queues a device-blind
        // pending row, and the NULL-tolerant flush delivers it once that member publishes and
        // connects.
        let pairs: Vec<MemberDevice> = db
            .prepare(
                "SELECT gm.user_id AS user_id, d.device_id AS device_id
                 FROM group_members gm
                 LEFT JOIN devices d
                   ON d.user_id = gm.user_id AND d.revoked_at IS NULL
                 WHERE gm.group_id = ? AND gm.user_id != ?
                   AND gm.status = 'active'",
            )
            .bind(&[d1_text(group_id), d1_text(&sender_id)])?
            .all()
            .await?
            .results()?;
        // A second guard, weighted by fan-out WIDTH: one group send is `pairs.len()` DO writes,
        // which the single-hit `msg:send` bucket counts as one event, so a large group would allow
        // ~300xN writes per minute. 6000 units/60s permits ~23 sends/min into a full 256-member
        // group and far more into small ones, and MAX_GROUP_MEMBERS bounds a single send's cost.
        if !pairs.is_empty()
            && !crate::ratelimit::check_rate_limit_weighted_env(
                &ctx.env,
                &format!("msg:grp_fanout:{sender_id}"),
                6000,
                60,
                pairs.len(),
            )
            .await
        {
            return json_err(429, "rate_limited");
        }
        // Fan out sequentially — the worker's WASM runtime is single-threaded. One device's DO
        // failure skips that device and lets the others through; idempotency lives in the DO's
        // dedup. A group has no single canonical id, so the response reports the first successful
        // pair's id, or a timestamp if none succeeded (the sender's local "Sent" tracking only;
        // group receipts are a separate axis).
        //
        // THE SUBREQUEST BUDGET (full reasoning in `messages::budget`): every pair costs at least
        // one DO call, plus a push worth several more for an offline recipient, against a Workers
        // ceiling of ~50 per request. A room past roughly two dozen used to run out MID-LOOP, so
        // every remaining pair failed for want of subrequests rather than for any delivery reason
        // and fell into `fanout_retry`, whose drain hit the same wall. Pairs this request cannot
        // pay for are now recognised BEFORE they are attempted and go straight to the queue.
        let mut budget = crate::messages::budget::SubrequestBudget::new(
            crate::messages::budget::resolve_budget(&ctx.env),
            // +1 held back for the single `fanout_retry` batch that closes this handler.
            crate::messages::budget::GROUP_SEND_PRELUDE + 1,
        );
        let mut first_id: Option<i64> = None;
        let mut delivered_count: usize = 0;
        let mut attempted: usize = 0;
        let mut failed_pairs = Vec::new();
        let mut deferred_pairs = Vec::new();
        for p in &pairs {
            if !budget.can_afford(crate::messages::budget::COST_PAIR_WORST_CASE) {
                deferred_pairs.push(p);
                continue;
            }
            attempted += 1;
            budget.spend(crate::messages::budget::COST_NOTIFY);
            match notify_recipient(
                &namespace,
                &p.user_id,
                &sender_id,
                &body.sender_device_id,
                p.device_id.as_deref(),
                envelope_b64,
                Some(group_id),
                body.silent,
            )
            .await
            {
                Ok((id, delivered_live)) => {
                    if first_id.is_none() {
                        first_id = Some(id);
                    }
                    delivered_count += 1;
                    // An offline member device gets a content-less FCM wake, unless the sender
                    // marked the message silent. BOTH outcomes are logged: with only the sends
                    // logged, a control message that still wakes a phone looks identical to one
                    // correctly silenced, which is how a waking group path stayed invisible next
                    // to an already-quiet 1:1 path.
                    if !delivered_live && body.silent {
                        console_log!(
                            "[push] skipped (silent) group={group_id} user={} dev={:?}",
                            p.user_id, p.device_id
                        );
                    }
                    if !delivered_live && !body.silent {
                        console_log!(
                            "[push] waking group={group_id} user={}",
                            p.user_id
                        );
                        budget.spend(crate::messages::budget::COST_PUSH_WAKE);
                        crate::push::fcm::maybe_push_wake(
                            &ctx.env, &db, &p.user_id, p.device_id.as_deref(),
                        )
                        .await;
                    }
                }
                Err(_) => {
                    // The in-request retry spent a second DO call before giving up.
                    budget.spend(crate::messages::budget::COST_NOTIFY);
                    failed_pairs.push(p); // every attempt failed → durable retry
                }
            }
        }
        // TOTAL failure → a retryable 502 and NO enqueue: the sender retries the whole thing, and
        // the DO's dedup makes that safe. Returning 200 with a synthetic id here would have the
        // sender believe it succeeded and lose the message permanently. `attempted` rather than
        // `pairs.is_empty()` because a pair the budget DEFERRED was never tried and is no evidence
        // that delivery is broken.
        if attempted > 0 && delivered_count == 0 {
            return json_err(502, "fanout_failed");
        }
        // PARTIAL failure → the failed (member, device) pairs go into the durable queue so the
        // cron drain re-notifies them and that member does not miss the message. The
        // sha256(recipient|device|group|envelope) retry_key with INSERT OR IGNORE makes the
        // enqueue idempotent, so a sender retry cannot write the same row twice. Best-effort: a
        // failed INSERT does not break the send and stays visible as `failed: n` in the response.
        let failed_n = failed_pairs.len();
        let deferred_n = deferred_pairs.len();
        if failed_n + deferred_n > 0 {
            let now = now_secs() as i64;
            // ONE BATCH, not one INSERT per pair: a separate statement is a separate subrequest,
            // so the enqueue for a wide fan-out was paid for out of the same purse the fan-out had
            // just exhausted. A D1 batch is one subrequest whatever its length.
            let mut stmts = Vec::with_capacity(failed_n + deferred_n);
            for p in failed_pairs.iter().chain(deferred_pairs.iter()) {
                let device = p.device_id.as_deref().unwrap_or("");
                let mut hasher = Sha256::new();
                hasher.update(p.user_id.as_bytes());
                hasher.update(b"|");
                hasher.update(device.as_bytes());
                hasher.update(b"|");
                hasher.update(group_id.as_bytes());
                hasher.update(b"|");
                hasher.update(envelope_b64.as_bytes());
                let retry_key: String =
                    hasher.finalize()[..16].iter().map(|b| format!("{:02x}", b)).collect();
                if let Ok(stmt) = db
                    .prepare(
                        "INSERT OR IGNORE INTO fanout_retry
                         (retry_key, recipient_id, recipient_device, sender_id, sender_device,
                          envelope_b64, group_id, attempts, next_at, created_at, silent)
                         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                    )
                    .bind(&[
                        d1_text(&retry_key),
                        d1_text(&p.user_id),
                        d1_opt_text(p.device_id.as_deref()),
                        d1_text(&sender_id),
                        d1_text(&body.sender_device_id),
                        d1_text(envelope_b64),
                        d1_text(group_id),
                        d1_int(now + W4B_INITIAL_BACKOFF_SECS),
                        d1_int(now),
                        d1_int(i64::from(body.silent)),
                    ])
                {
                    stmts.push(stmt);
                }
            }
            if !stmts.is_empty() {
                let _ = db.batch(stmts).await;
            }
            console_log!(
                "[deliv] W4-b enqueue: {failed_n} failed + {deferred_n} over-budget of {} pairs to durable-retry (group={group_id})",
                pairs.len()
            );
        }
        let id = first_id.unwrap_or_else(|| now_secs() as i64);
        // The response MUST carry `acks`: the client's `send_group_message` reads
        // `res.acks.first()`, and an {id, ts} body without it dropped the group message after all
        // its retries. A group has one canonical id, hence a single element. `id` stays for
        // backwards compatibility with older clients.
        return Response::from_json(&serde_json::json!({
            "id": id,
            "ts": now_secs(),
            "acks": [{ "id": id }],
            // Pairs that fell back to durable retry — failed plus budget-deferred, since from the
            // sender's side both mean "queued, not yet delivered". 0 = fully delivered. Telemetry
            // today; the hook for future partial-delivery visibility.
            "failed": failed_n + deferred_n,
        }));
    }

    // ---- 1:1 path (batched device fan-out) ----
    let recipient_id = match body.recipient_id.as_deref() {
        Some(r) => r,
        None => return json_err(400, "bad_request"), // neither a recipient nor a group
    };
    if recipient_id.len() != 36 {
        return json_err(400, "bad_request");
    }
    // A self-send is allowed only to a DIFFERENT device (the OutboundCopy self-copy shape), so
    // every EnvItem's device_id must differ from sender_device_id.
    if recipient_id == sender_id {
        let any_same = body
            .envelopes
            .iter()
            .any(|e| e.device_id.as_deref() == Some(body.sender_device_id.as_str()));
        // A self-send without a device_id (target device unknown) is rejected too.
        let any_missing = body.envelopes.iter().any(|e| e.device_id.is_none());
        if any_same || any_missing {
            return json_err(400, "cannot_send_to_self");
        }
    }
    // Contacts/Directory V2: apply one shared server-side gate before any
    // delivery or key-related side effect. Block reason is deliberately merged
    // with missing-grant policy denial.
    if let Err(err) = classify_direct_http(
        crate::contacts::direct_decision(&db, &sender_id, recipient_id)
            .await
            .map_err(|_| ()),
        "recipient_not_found",
    ) {
        return json_err(err.status, err.code);
    }
    #[derive(Deserialize)]
    struct Idr {
        #[allow(dead_code)] // fetched only as an existence check; the value is never read
        id: String,
    }
    let recipient: Option<Idr> = db
        .prepare("SELECT id FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(recipient_id)])?
        .first(None)
        .await?;
    if recipient.is_none() {
        return json_err(404, "recipient_not_found");
    }
    // On the 1:1 path `device_id` is MANDATORY: the sender knows the recipient's devices from the
    // bundle, so each envelope targets a concrete device. A device-less 1:1 envelope would create
    // an orphan NULL pending row nobody resolves. NULL is legitimate only via the group fallback.
    if body.envelopes.iter().any(|e| e.device_id.is_none()) {
        return json_err(400, "bad_request");
    }
    // The recipient's published devices, resolved ONCE, in place of a per-envelope
    // `device_revoked` call — which answers a different question: it is false for a device that
    // DOES NOT EXIST, so an invented device id was indistinguishable from a live one and every
    // envelope aimed at one became a `pending` row nobody would ever ack. See
    // `messages::recipient_devices` for what that bought an attacker.
    let recipient_devices =
        crate::messages::recipient_devices::load_recipient_devices(&db, recipient_id).await?;
    // All-or-nothing again: one fabricated target rejects the whole batch, so the sender re-fetches
    // the bundle rather than half-succeeding against a device list it got wrong.
    if body.envelopes.iter().any(|e| {
        e.device_id.as_deref().map(|d| {
            recipient_devices.verdict(d)
                == crate::messages::recipient_devices::DeviceVerdict::Unknown
        }) == Some(true)
    }) {
        return json_err(
            400,
            crate::messages::recipient_devices::UNKNOWN_DEVICE_CODE,
        );
    }
    // Batched 1:1 fan-out: each EnvItem gets its own /notify(recipient_device). Per-device
    // outcomes are visible to the client — successful devices join `acks`, failed ones drop out.
    let mut acks: Vec<serde_json::Value> = Vec::with_capacity(body.envelopes.len());
    for e in &body.envelopes {
        // A revoked recipient device is SKIPPED, giving 1:1 the parity the group fan-out gets from
        // its JOIN: the worker is the authoritative gate, so the sender's ~2 min stale device
        // cache cannot open a delivery window to a revoked device. An id that was never published
        // at all already rejected the whole request above.
        if let Some(dev) = e.device_id.as_deref() {
            if recipient_devices.verdict(dev)
                != crate::messages::recipient_devices::DeviceVerdict::Active
            {
                continue; // not added to acks → no pending row and no ack for that device
            }
        }
        match notify_recipient(
            &namespace,
            recipient_id,
            &sender_id,
            &body.sender_device_id,
            e.device_id.as_deref(),
            &e.envelope_b64,
            None,
            body.silent,
        )
        .await
        {
            Ok((id, delivered_live)) => {
                acks.push(serde_json::json!({
                    "device_id": e.device_id,
                    "id": id,
                }));
                // Offline on that device → a content-less FCM wake, unless the message is silent
                // control traffic, which is stored and delivered on the next connect instead.
                if !delivered_live && body.silent {
                    console_log!(
                        "[push] skipped (silent) 1:1 user={recipient_id} dev={:?}",
                        e.device_id
                    );
                }
                if !delivered_live && !body.silent {
                    console_log!("[push] waking 1:1 user={recipient_id} dev={:?}", e.device_id);
                    crate::push::fcm::maybe_push_wake(
                        &ctx.env, &db, recipient_id, e.device_id.as_deref(),
                    )
                    .await;
                }
            }
            Err(_) => { /* per-device failure → drops out of the ack list (visibly) */ }
        }
    }
    // No device succeeded → 502.
    if acks.is_empty() {
        return json_err(502, "do_notify_failed");
    }
    Response::from_json(&serde_json::json!({ "ts": now_secs(), "acks": acks }))
}

#[derive(Deserialize)]
struct ReadBody {
    peer_id: String,
    ids: Vec<i64>,
    /// msg_uids PARALLEL to `ids`, so sibling convergence keeps the uid even when a WS read falls
    /// back to HTTP. An old client or the WS path sends an empty Vec.
    #[serde(default)]
    uids: Vec<String>,
}

pub async fn read(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (recipient_id, reader_device) = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => (auth.user_id, auth.device_id),
        Err(resp) => return Ok(resp),
    };
    // Without this guard the WS read limit could simply be bypassed over HTTP, pushing unlimited
    // forward-reads into the peer DO. Its own bucket, so legitimate read traffic does not eat the
    // send quota; the HTTP path rejects with 429 where the WS path silently drops.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &read_rate_limit_key(&recipient_id),
        300,
        60,
    )
        .await
    {
        return json_err(429, "rate_limited");
    }
    let body: ReadBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.ids.is_empty() || body.ids.len() > 500 {
        return json_err(400, "bad_request");
    }
    if body.peer_id == recipient_id {
        return json_err(400, "cannot_read_self");
    }
    if body.peer_id.len() != 36 {
        return json_err(400, "bad_request");
    }
    let authz_db = match ctx.env.d1("DB") {
        Ok(db) => db,
        Err(_) => return json_err(503, "authorization_unavailable"),
    };
    if let Err(err) = classify_direct_http(
        crate::contacts::direct_decision(&authz_db, &recipient_id, &body.peer_id)
            .await
            .map_err(|_| ()),
        "not_found",
    ) {
        return json_err(err.status, err.code);
    }
    // A revoked device must not be able to FORGE a read receipt — revoke parity with the send
    // path, without waiting out the 15 min token TTL.
    if crate::auth::middleware::device_revoked(&ctx.env, &recipient_id, &reader_device).await? {
        return json_err(401, "device_revoked");
    }

    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&body.peer_id)?.get_stub()?;
    let payload = serde_json::json!({
        "from": recipient_id,
        "ids": body.ids,
        "uids": body.uids,
    })
    .to_string();
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(payload.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let do_req = Request::new_with_init("https://do.sezgi/forward-read", &init)?;
    stub.fetch_with_request(do_req).await?;
    no_content()
}

/// `GET /messages/receipt-sync?since=<seq>` (auth required) → the DO's `{rows, more}`. Cursor-pull
/// the caller's OWN durable `receipt_state`, the HTTP twin of the WS `receipt_sync` frame: a
/// device on the HTTP send fallback converges its outgoing message's stuck tick through here.
/// receipt_state lives in the caller's own inbox, hence `id_from_name(&user_id)`.
pub async fn receipt_sync(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // A safely parsed i64 is the only thing interpolated into the DO URL.
    let mut since: i64 = 0;
    let url = req.url()?;
    for (k, v) in url.query_pairs() {
        if k.as_ref() == "since" {
            since = v.parse().unwrap_or(0);
        }
    }
    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?; // my OWN inbox
    let do_req = Request::new(
        &format!("https://do.sezgi/receipt-sync?since={since}"),
        Method::Get,
    )?;
    passthrough(stub.fetch_with_request(do_req).await?).await
}

/// `POST /messages/self-read` (auth required), body `{uids:[…]}` forwarded opaquely → the DO's
/// 204. A device of U reports the `msg_uid`s of the incoming messages it read to U's OWN inbox DO
/// → `self_read_state` set-once + a delta to U's other devices. The self-read twin of the `read`
/// receipt, but aimed at my own DO instead of the PEER's.
pub async fn self_read(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // Its own bucket, and with the body cap below it bounds how fast `self_read_state` can grow.
    // 300/60s sits far above legitimate use — the client batches mark-read through its dwell
    // controller, so ~30-60/min is the practical ceiling. ⚠ The client's send_self_read_durable
    // drops on error without retrying, so a 429 is a lost read; above legitimate use that only
    // costs an abuser their own fabricated reads, but a client-side retry is the honest fix.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("msg:selfread:{user_id}"), 300, 60).await {
        return json_err(429, "rate_limited");
    }
    let body = req.text().await.unwrap_or_default();
    // 500 uids x ~40B is about 20KB, so 32KB is generous; larger is an anomaly or abuse.
    if body.len() > 32 * 1024 {
        return json_err(400, "payload_too_large");
    }
    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?; // my OWN inbox
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let do_req = Request::new_with_init("https://do.sezgi/self-read", &init)?;
    passthrough(stub.fetch_with_request(do_req).await?).await
}

/// `GET /messages/self-read-sync?since=<seq>` (auth required) → the DO's `{rows, more}`. The
/// sibling-read cursor pull, HTTP twin of the WS `self_read_sync` frame; a new device pulls from
/// since=0 to converge its backlog. Mirrors receipt_sync.
pub async fn self_read_sync(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    let mut since: i64 = 0;
    let url = req.url()?;
    for (k, v) in url.query_pairs() {
        if k.as_ref() == "since" {
            since = v.parse().unwrap_or(0);
        }
    }
    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?; // my OWN inbox
    let do_req = Request::new(
        &format!("https://do.sezgi/self-read-sync?since={since}"),
        Method::Get,
    )?;
    passthrough(stub.fetch_with_request(do_req).await?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_direct_decision_maps_storage_failure_to_retryable_503() {
        assert_eq!(
            classify_direct_http(Err(()), "recipient_not_found"),
            Err(DirectHttpError {
                status: 503,
                code: "authorization_unavailable",
            })
        );
    }

    #[test]
    fn http_direct_decision_maps_policy_outcomes_and_endpoint_not_found_code() {
        assert_eq!(
            classify_direct_http(Ok(crate::contacts::DirectDecision::Allowed), "not_found"),
            Ok(())
        );
        assert_eq!(
            classify_direct_http(Ok(crate::contacts::DirectDecision::Denied), "not_found"),
            Err(DirectHttpError {
                status: 403,
                code: "contact_not_authorized",
            })
        );
        assert_eq!(
            classify_direct_http(
                Ok(crate::contacts::DirectDecision::NotFound),
                "recipient_not_found",
            ),
            Err(DirectHttpError {
                status: 404,
                code: "recipient_not_found",
            })
        );
        assert_eq!(
            classify_direct_http(Ok(crate::contacts::DirectDecision::NotFound), "not_found"),
            Err(DirectHttpError {
                status: 404,
                code: "not_found",
            })
        );
    }

    #[test]
    fn send_and_read_rate_limit_namespaces_are_stable_and_separate() {
        let user = "11111111-2222-3333-4444-555555555555";
        assert_eq!(send_rate_limit_key(user), format!("msg:send:{user}"));
        assert_eq!(read_rate_limit_key(user), format!("msg:read:{user}"));
        assert_ne!(send_rate_limit_key(user), read_rate_limit_key(user));
    }

    /// The in-request notify retry, guarded at source because `notify_recipient` needs a live
    /// Durable Object namespace and its policy is two numbers rather than a behaviour. Both
    /// halves are pinned: the attempt count, and the fact that the second attempt WAITS. Needles
    /// are split with `concat!` so they cannot match themselves in `include_str!`'s copy.
    #[test]
    fn the_in_request_notify_retry_is_bounded_and_paced() {
        const SRC: &str = include_str!("handlers.rs");
        assert!(
            SRC.contains(concat!("NOTIFY_ATTEMPTS: usize", " = 2")),
            "the in-request retry count changed — more than one retry against the same DO belongs \
             in the durable fanout_retry queue, not in the request path"
        );
        assert!(
            SRC.contains(concat!("worker::Delay::", "from(")),
            "the retry lost its pause and is back to hammering the same DO with no delay"
        );
    }
}
