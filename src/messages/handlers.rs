use crate::auth::jwt::device_id_from_token;
use crate::auth::middleware::{extract_bearer, require_active_auth};
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use sha2::{Digest, Sha256};

/// W4-b constants (durable retry for a partially failed group fan-out).
const W4B_INITIAL_BACKOFF_SECS: i64 = 30; // delay from enqueue to the first drain attempt
// MINOR-1 (Fable+Codex): keep the lease SEPARATE from the backoff base. The LEASE is the in-flight
// claim window (10 min): after a drain crash or against a slow DO the row stays "busy" that long, so
// an overlapping cron never re-claims the SAME row (lease >> the 2 min cron period + the maximum
// drain duration → the double-notify window closes). On failure next_at is OVERWRITTEN with the
// backoff (retry is not delayed); only a crashed drain has to wait out the 10 min to self-heal.
const W4B_LEASE_SECS: i64 = 600;
const W4B_BACKOFF_BASE_SECS: i64 = 120; // failure-backoff base (SEPARATE from the lease): 120→240→…→3600 cap
const W4B_MAX_BACKOFF_SECS: i64 = 3600; // backoff ceiling — a long outage retries hourly and is NEVER deleted (no loss)
const W4B_DRAIN_BATCH: usize = 50; // rows drained per cron (bounded by D1 response size + sequential DO fetch time)
use crate::respond::{json_err, no_content};
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

/// M2-S2.3 (WIRE-CUT): one item of the envelope batch. For 1:1, `device_id` is the TARGET
/// recipient device (the sender knows it from the bundle → a separate Olm envelope per
/// device). For a GROUP there is NO `device_id` (a single Megolm envelope; the device
/// fan-out is derived INSIDE the worker).
#[derive(Deserialize)]
struct EnvItem {
    #[serde(default)]
    device_id: Option<String>,
    envelope_b64: String,
}

/// M2-S2.3: the single `envelope_b64` was REMOVED in favour of an `envelopes: Vec<EnvItem>`
/// batch. HTTP and WS-send now take a bit-identical body. With N=1 a single-element
/// `envelopes` reproduces today's single-envelope flow exactly.
#[derive(Deserialize)]
struct SendBody {
    /// Recipient of a 1:1 direct message. `None` for a group message (`group_id` instead).
    #[serde(default)]
    recipient_id: Option<String>,
    /// GROUP message (phase 2): fan out to this group's members. `None` for 1:1.
    #[serde(default)]
    group_id: Option<String>,
    /// M2-S2.3: the SENDER's device (lets the recipient pick the right Olm device session;
    /// still carried for a group's single Megolm envelope). Together with bundle v2 and the
    /// device claim this gives end-to-end device addressing. The old single-envelope form did
    /// not carry `sender_device_id`.
    sender_device_id: String,
    /// M2-S2.3: one envelope per device. 1:1 has N >= 1; a group has one element with no device_id.
    envelopes: Vec<EnvItem>,
    /// Do NOT send an FCM wake for an offline recipient of this message. The SENDER sets it for
    /// control traffic that is meaningless to a sleeping device — a capabilities announcement, a
    /// reconnect state digest, a receipt, a typing indicator (see the core's `needs_device_wake`).
    ///
    /// It changes NOTHING about storage or delivery: the envelope is written to the recipient's
    /// pending queue exactly as before and arrives on their next connect. It only declines to spend
    /// a push, a cold start and several seconds of the recipient's radio on it.
    ///
    /// Measured 2026-07-28: launching the desktop client sent one contact four such messages, which
    /// became three FCM wakes and three full queue drains that delivered nothing a person could see.
    ///
    /// `#[serde(default)]` → an older client that does not send the field gets today's behaviour.
    #[serde(default)]
    silent: bool,
}

#[derive(Deserialize)]
struct NotifyResult {
    id: i64,
    #[serde(default)]
    delivered_live: bool,
}

/// Builds the `/notify` payload (the recipient DO's request body for notify_inner).
/// `notify_recipient` and the W4-b drain both build it here so the shape has a single source
/// of truth.
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
        // W1 backstop: the RECIPIENT user_id, which notify_inner persists (an offline DO does not
        // know its own user).
        "recipient_id": recipient_id,
        "envelope_b64": envelope_b64,
        "group_id": group_id,
        // Persisted on the pending row so the W1 backstop ALARM does not wake the device later for
        // a message the immediate path deliberately stayed quiet about. Without this the fix only
        // delays the pointless wake instead of removing it.
        "silent": silent,
    })
    .to_string()
}

/// A SINGLE DO `/notify` attempt (store + WS push). Ok → (pending_id, delivered_live); Err on
/// id_from_name/stub failure, a failed fetch, a non-200 status or an unparseable body.
/// `notify_recipient` loops this 3x for transient retries; the W4-b drain calls it ONCE per row
/// because the row's own next_at backoff is the retry.
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

/// `/notify` one user's DO inbox (store + WS push). When `group_id` is Some the recipient's frame
/// carries it, so the recipient takes the Megolm (group) decrypt path. When `recipient_device` is
/// Some the pending row is scoped to that device (per-device queue + ack isolation; see S2.2
/// notify_inner). The returned `id` is that RECIPIENT's pending sequence id. An error surfaces as
/// `Err`, which makes a per-device failure VISIBLE during fan-out — the old silent skip is gone
/// (red-team #18).
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
    // W4 BOUNDED in-request retry (3 attempts, catching transient DO 5xx / overload / routing
    // errors). notify_inner's dedup (60s on a warm DO) absorbs the "it succeeded but the response
    // was lost" case, so no duplicate pending row appears. All 3 failing returns Err → the caller
    // counts it visibly → on a partial failure it is enqueued into the W4-b durable retry queue.
    const NOTIFY_ATTEMPTS: usize = 3;
    let mut last_err = Error::RustError("do_notify_failed".into());
    for attempt in 0..NOTIFY_ATTEMPTS {
        match notify_once(namespace, recipient_id, &payload).await {
            Ok(r) => {
                if attempt > 0 {
                    console_log!(
                        "[deliv] W4 notify retry-recovered: {}. denemede OK (recipient={recipient_id})",
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

/// W4-b durable-retry drain (cron; runs on EVERY scheduled invocation). Atomically claims rows
/// (`UPDATE ... next_at = LEASE-ahead ... RETURNING`, so an overlapping cron cannot re-notify the
/// SAME row), then re-notifies each ONCE: on success DELETE the row and keep FCM-wake parity, on
/// failure UPDATE with an exponential backoff (NEVER delete — Codex#4 loss prevention: a long
/// outage keeps retrying and the TTL GC collects anything truly ancient). Bounded batch,
/// best-effort: a D1/DO error leaves the row for the next round, and a missing table (migration not
/// applied) is a silent no-op. Deliberately calls `notify_once` rather than notify_recipient's
/// 3-retry body, because the row-level backoff IS the retry (Fable#2).
pub(crate) async fn drain_fanout_retry(env: &Env) {
    let Ok(db) = env.d1("DB") else { return };
    let Ok(namespace) = env.durable_object("USER_INBOX") else { return };
    let now = now_secs() as i64;
    #[derive(serde::Deserialize)]
    struct RetryRow {
        id: i64,
        recipient_id: String,
        #[serde(default)]
        recipient_device: Option<String>,
        sender_id: String,
        #[serde(default)]
        sender_device: Option<String>,
        envelope_b64: String,
        group_id: String,
        attempts: i64,
        /// Whether the sender asked for no FCM wake. `#[serde(default)]` → a row written before this
        /// column existed reads as 0 (wake), i.e. the old behaviour.
        #[serde(default)]
        silent: i64,
    }
    // Atomic claim: push the due rows' next_at a LEASE ahead (the in-flight marker) and return them.
    let claimed: Vec<RetryRow> = match db
        .prepare(
            "UPDATE fanout_retry SET next_at = ?
             WHERE id IN (SELECT id FROM fanout_retry WHERE next_at <= ? ORDER BY next_at LIMIT ?)
             RETURNING id, recipient_id, recipient_device, sender_id, sender_device, envelope_b64, group_id, attempts, silent",
        )
        .bind(&[
            d1_int(now + W4B_LEASE_SECS),
            d1_int(now),
            d1_int(W4B_DRAIN_BATCH as i64),
        ]) {
        Ok(stmt) => match stmt.all().await {
            Ok(res) => res.results::<RetryRow>().unwrap_or_default(),
            Err(_) => return,
        },
        Err(_) => return,
    };
    if claimed.is_empty() {
        return;
    }
    let total = claimed.len();
    let mut ok = 0usize;
    for r in &claimed {
        let payload = build_notify_payload(
            &r.recipient_id,
            &r.sender_id,
            r.sender_device.as_deref().unwrap_or(""),
            r.recipient_device.as_deref(),
            &r.envelope_b64,
            Some(&r.group_id),
            r.silent != 0,
        );
        match notify_once(&namespace, &r.recipient_id, &payload).await {
            Ok((_, delivered_live)) => {
                if let Ok(stmt) = db
                    .prepare("DELETE FROM fanout_retry WHERE id = ?")
                    .bind(&[d1_int(r.id)])
                {
                    let _ = stmt.run().await;
                }
                // FCM-wake parity with the handlers' offline branch (Codex#6): stored OK but
                // offline → wake. A `silent` row skips it: the retry queue must not resurrect a wake
                // the immediate path deliberately declined (a group receipt would otherwise wake the
                // device minutes later, which is worse than the original bug because it looks random).
                if !delivered_live && r.silent == 0 {
                    crate::push::fcm::maybe_push_wake(
                        env, &db, &r.recipient_id, r.recipient_device.as_deref(),
                    )
                    .await;
                }
                ok += 1;
            }
            Err(_) => {
                // Exponential backoff, NEVER delete (Codex#4): attempts++ and push next_at ahead.
                // `attempts` counts only DO errors (offline is not an error — the notify succeeded),
                // so a high attempts value means "the DO has been broken for days", which is rare.
                let shift = r.attempts.clamp(0, 5) as u32;
                let backoff = (W4B_BACKOFF_BASE_SECS << shift).min(W4B_MAX_BACKOFF_SECS);
                if let Ok(stmt) = db
                    .prepare("UPDATE fanout_retry SET attempts = attempts + 1, next_at = ? WHERE id = ?")
                    .bind(&[d1_int(now + backoff), d1_int(r.id)])
                {
                    let _ = stmt.run().await;
                }
            }
        }
    }
    console_log!("[deliv] W4-b drain: {ok}/{total} re-notify OK");
}

/// W4-b TTL GC (daily cron): collect very old fanout_retry rows. Since we never delete on max
/// attempts, THIS is the only upper bound that keeps the table bounded. RETENTION PARITY
/// (server-lean audit 2026-07-03): fanout_retry holds E2E ciphertext, making it a delivery buffer
/// just like `pending` → it is kept for the owner-configured `message_retention_days` window, NOT a
/// fixed TTL. Per the "the server forgets and does not grow" policy, fanout_retry lives exactly as
/// long as the owner's retention says (an exact mirror of the pending cleanup at
/// the alarm handler's pending cleanup in `inbox_do/mod.rs`).
pub(crate) async fn gc_fanout_retry(env: &Env) {
    let Ok(db) = env.d1("DB") else { return };
    let days = crate::server::handlers::fetch_message_retention_days(env).await;
    let cutoff = now_secs() as i64 - days * 24 * 3600;
    if let Ok(stmt) = db
        .prepare("DELETE FROM fanout_retry WHERE created_at < ?")
        .bind(&[d1_int(cutoff)])
    {
        let _ = stmt.run().await;
    }
}

pub async fn send(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let sender_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // S2 (Fable HIGH — quota/DoS): per-user message rate limit, so envelopes that differ by a byte
    // cannot slip past the 60s dedup and bloat the UserInbox DO's SQLite. 300 messages / 60s sits
    // above the busiest legitimate conversation (a human manages well under 2/s) while still cutting
    // automated spam. Implemented as a KV sliding window (the SAME infrastructure as auth
    // redeem/verify and media upload). A group fan-out counts INSIDE this limit (one send = N DO
    // writes but a single hit), so legitimate group traffic is unrestricted here.
    // The KV binding is OPTIONAL (template diet): without it we continue unlimited — see
    // ratelimit::check_rate_limit_env.
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
    // M2-S2.3 (WIRE-CUT): the envelope batch. An empty batch is a 400. The per-envelope length
    // check is ALL-OR-NOTHING: one out-of-range envelope rejects the whole request with 400 (no
    // partial acceptance → from the client's view either everything was sent or nothing was, which
    // keeps its state consistent).
    if body.envelopes.is_empty() || body.envelopes.len() > 100 {
        return json_err(400, "bad_request");
    }
    if body.sender_device_id.is_empty() {
        return json_err(400, "bad_request");
    }
    // M2-S3.1 B1 (token binding) — the TRUST FOUNDATION of every S3 self/echo exclusion: stop an
    // HTTP send on ANOTHER device's behalf via a forged `sender_device_id` (fake self-copy / group
    // echo injection). body.sender_device_id MUST MATCH the JWT's `device_id` claim. require_auth is
    // left UNCHANGED (6 callers, too wide a blast radius), so the bearer and device are extracted
    // separately here. token_device == None (an old token without the claim) → 403: S3 devices get
    // tokens carrying a device claim, and an old token is forced to re-login. The WS-send path
    // (inbox_do/ws.rs) is ALREADY token-bound through its attachment device, so this gate only
    // closes the HTTP send forgery surface.
    let token_device =
        extract_bearer(&req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    if token_device.as_deref() != Some(body.sender_device_id.as_str()) {
        return json_err(403, "device_mismatch");
    }
    // REVOCATION CHECK (security audit — checkpoint 3): if the token-bound device has been REMOVED
    // (revoked) from the device list, REJECT the send without waiting for the 15 min access-token
    // TTL to expire → a stolen device CANNOT send messages after revocation. Event-driven: one
    // query per send, no polling.
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

    // ---- GROUP path (phase 2 fan-out): group_id → /notify every member except the sender ----
    if let Some(group_id) = body.group_id.as_deref() {
        // The sender must be a member of this group (E2E: the server never sees the content, it
        // only distributes based on the membership table).
        if crate::groups::group_role(&db, group_id, &sender_id)
            .await?
            .is_none()
        {
            return json_err(403, "not_member");
        }
        // M2-S2.3 (red-team BLOCKER #9): a group carries a single Megolm envelope, so there must
        // be exactly one EnvItem and it must have no device_id (the fan-out is derived inside the
        // worker). A group body with several envelopes, or one carrying a device_id, is invalid.
        if body.envelopes.len() != 1 || body.envelopes[0].device_id.is_some() {
            return json_err(400, "bad_request");
        }
        let envelope_b64 = body.envelopes[0].envelope_b64.as_str();
        #[derive(Deserialize)]
        struct MemberDevice {
            user_id: String,
            // FIX-1 (BLOCKER): with a LEFT JOIN, `device_id` comes back NULL for an active member
            // who never PUBLISHED a device list. Hence `Option<String>` — the old `String` with an
            // INNER JOIN DROPPED device-less members and lost their group messages permanently.
            device_id: Option<String>,
        }
        // M2-S2.3 group recipient_device derivation (red-team BLOCKER #9 + FIX-1): ACTIVE members
        // (phase 6 #3 consent) crossed with each member's ACTIVE devices. `group_members LEFT JOIN
        // devices` gives one (member, device) pair per INSERT of the SINGLE Megolm envelope, tagged
        // with `recipient_device` — the DO's dedup keys on recipient_device, so a second device is
        // not swallowed.
        //
        // FIX-1 (BLOCKER — dropped group members): INNER JOIN became LEFT JOIN. An active member
        // who never PUBLISHED a device list has no row in `devices`, so the INNER JOIN DROPPED them
        // from the fan-out and lost their group message PERMANENTLY. The LEFT JOIN returns
        // `device_id = NULL` for a device-less member → the loop below queues them with
        // `recipient_device = None` (a device-blind pending row) → once that member publishes a
        // device list and connects, the NULL-tolerant flush delivers it (FIX-2). With N=1 every
        // member yields its single primary, i.e. rows bit-identical to the INNER JOIN.
        // `revoked_at IS NULL` means an active device. The sender's own devices are excluded
        // (user_id != sender).
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
        // M12 (fan-out amplification — DoS): one group send produces `pairs.len()` DO writes
        // (members x devices). The single-hit `msg:send` guard above counts that as ONE event, so a
        // large group allowed 300 sends/60s = ~300xN DO writes. Hence a SECOND guard weighted by the
        // fan-out WIDTH: a separate `msg:grp_fanout:{sender}` bucket charged `pairs.len()` units.
        // 6000 units/60s permits ~23 sends/min into a full 256-member group and far more into small
        // ones — legitimate use is unrestricted while amplification spam is cut off. The member
        // ceiling (MAX_GROUP_MEMBERS=256) bounds the cost of a single send, so together the total
        // stays bounded.
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
        // Fan out to every (member, device) pair, sequentially — the worker's WASM runtime is
        // single-threaded. If one device's DO fails, skip it and let the others through;
        // idempotency lives in the DO's dedup. A group has NO single canonical id, so we report the
        // first successful pair's id, or a timestamp if none succeeded (used only for the sender's
        // local "Sent" tracking; group receipts are a separate axis). FIX-1: `device_id` Some means
        // a concrete device target, None (a member who published no devices) means a
        // `recipient_device = None` device-blind pending row, so the member is not dropped.
        let mut first_id: Option<i64> = None;
        let mut delivered_count: usize = 0;
        let mut failed_pairs = Vec::new();
        for p in &pairs {
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
                    // This member device is OFFLINE → content-less FCM wake (per-device group
                    // fan-out). Skipped for `silent` control traffic such as a group receipt.
                    if !delivered_live && body.silent {
                        // The instrument for the wake policy: without it the log shows only
                        // what was SENT, so a control message that still wakes a phone looks
                        // identical to one correctly silenced. That is how this very door
                        // shipped unnoticed on 2026-07-28 — the 1:1 path was quiet and the
                        // group path was not, and the push log could not tell them apart.
                        console_log!(
                            "[push] skipped (silent) group={group_id} user={} dev={:?}",
                            p.user_id, p.device_id
                        );
                    }
                    if !delivered_live && !body.silent {
                        // Name the door on the WAKING push as well, not only on the skip. Logging one
                        // side is how the group path stayed invisible for a round: "a wake happened"
                        // and "which surface asked for it" are different questions.
                        console_log!(
                            "[push] uyandiriyor grup={group_id} user={}",
                            p.user_id
                        );
                        crate::push::fcm::maybe_push_wake(
                            &ctx.env, &db, &p.user_id, p.device_id.as_deref(),
                        )
                        .await;
                    }
                }
                Err(_) => failed_pairs.push(p), // W4-b: all 3 attempts failed → durable retry
            }
        }
        // TOTAL failure (nothing delivered) → a retryable 502 and NO enqueue: the sender retries the
        // whole thing, so there is no partial-duplicate risk. Hardening #4: previously even a total
        // failure returned 200 with a synthetic id, so the sender believed it had succeeded and lost
        // the message PERMANENTLY; a 502 lets the client retry safely (the DO's dedup makes that safe).
        if !pairs.is_empty() && delivered_count == 0 {
            return json_err(502, "fanout_failed");
        }
        // W4-b: PARTIAL failure (delivered_count > 0 but some pairs Err) → write the failed
        // (member, device) pairs into the DURABLE fanout_retry queue so the cron drain re-notifies
        // them and that member does NOT miss the group message.
        // retry_key = sha256(recipient|device|group|envelope)[..16] with INSERT OR IGNORE, which
        // makes it idempotent: a sender retry or a double enqueue cannot write the SAME row twice,
        // avoiding duplicate pending rows and wasted W2 cap.
        // BEST-EFFORT: a failed INSERT (D1 down / migration missing) does NOT break the send and
        // stays visible as `failed: n` in the response — no false guarantee, and STRICTLY BETTER
        // than the silent loss it replaces. A total failure never reaches this point.
        let failed_n = failed_pairs.len();
        if failed_n > 0 {
            let now = now_secs() as i64;
            for p in &failed_pairs {
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
                    let _ = stmt.run().await;
                }
            }
            console_log!(
                "[deliv] W4-b enqueue: {failed_n}/{} kismi-fail durable-retry'e (group={group_id})",
                pairs.len()
            );
        }
        let id = first_id.unwrap_or_else(|| now_secs() as i64);
        // SAHA-FIX (group send returned an "empty batch ack"): the client's `send_group_message`
        // expects `SendBatchRes { ts, acks }` (the M2-S2.4 batch wire cut), but the old {id, ts}
        // response carried no `acks`, so `res.acks.first()` was None and the group message was
        // DROPPED after 8/8 retries. Now `acks` is included (a group has one canonical id → a single
        // element with device_id = None) while `id` is kept for backwards compatibility with older
        // clients. Not an M4 issue — groups were simply overlooked in the move to the 1:1 batch.
        return Response::from_json(&serde_json::json!({
            "id": id,
            "ts": now_secs(),
            "acks": [{ "id": id }],
            // W4-b: how many (member, device) pairs fell back to durable retry (0 = fully
            // delivered). The client ignores it today, but it is telemetry now and the hook for
            // future "partial delivery" visibility or a nudge.
            "failed": failed_n,
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
    // M2-S2.3 device-aware self-send: when recipient == sender, ONLY a different device is
    // allowed (the wire shape for an OutboundCopy self-copy is ready; the behaviour lands in S3).
    // A self-send to the same device is still a 400. Every EnvItem's device_id must differ from
    // sender_device_id.
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
    // FIX-2(a) (HIGH — orphan NULLs): on the 1:1 path every EnvItem.device_id is MANDATORY. A 1:1
    // sender knows the recipient's devices from bundle v2, so each envelope targets a CONCRETE
    // device (a separate Olm session per device). A 1:1 body carrying device_id = None is a
    // buggy/old client and would create orphan NULL pending rows (multi-device ambiguity), so it is
    // rejected here with an early 400. (A NULL pending row is legitimate ONLY via the group fallback
    // [a member who published no devices, FIX-1] or the device-blind S1-token path — NEVER from 1:1.)
    if body.envelopes.iter().any(|e| e.device_id.is_none()) {
        return json_err(400, "bad_request");
    }
    // M2-S2.3 batched 1:1 fan-out: each EnvItem gets its own /notify(recipient_device). Per-device
    // success and failure are VISIBLE — the old `if let Ok(Some)` silent skip is gone (red-team
    // #18): successful devices join `acks`, failed ones DROP OUT, so a missing device_id is visible
    // to the client. With N=1 the single element yields a single ack, i.e. today's single-envelope
    // flow.
    let mut acks: Vec<serde_json::Value> = Vec::with_capacity(body.envelopes.len());
    for e in &body.envelopes {
        // D-M12: do NOT deliver 1:1 to a revoked RECIPIENT device. The group fan-out already
        // excludes revoked devices in its JOIN, so this establishes parity for 1:1. The sender's
        // ~2 min stale device cache can no longer open a delivery window to a revoked recipient
        // device — the worker is the authoritative gate. Fail-closed: a D1 error propagates via `?`
        // (parity with the sender revoke check in `send`). device_id is MANDATORY for 1:1 (400
        // above), so the None branch is unreachable in practice.
        if let Some(dev) = e.device_id.as_deref() {
            if crate::auth::middleware::device_revoked(&ctx.env, recipient_id, dev).await? {
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
                // Recipient is OFFLINE on that device → content-less FCM wake (1:1 HTTP path).
                // `silent` control traffic (caps announcement, state digest, typing, receipt) is
                // stored and delivered on the next connect WITHOUT a wake — this is the path the
                // 2026-07-28 measurement found burning three cold starts per desktop launch.
                if !delivered_live && body.silent {
                    console_log!(
                        "[push] skipped (silent) 1:1 user={recipient_id} dev={:?}",
                        e.device_id
                    );
                }
                if !delivered_live && !body.silent {
                    console_log!("[push] uyandiriyor 1:1 user={recipient_id} dev={:?}", e.device_id);
                    crate::push::fcm::maybe_push_wake(
                        &ctx.env, &db, recipient_id, e.device_id.as_deref(),
                    )
                    .await;
                }
            }
            Err(_) => { /* per-device failure → drops out of the ack list (visibly) */ }
        }
    }
    // No device succeeded → 502 (parity with the old single-envelope "do_notify_failed").
    if acks.is_empty() {
        return json_err(502, "do_notify_failed");
    }
    Response::from_json(&serde_json::json!({ "ts": now_secs(), "acks": acks }))
}

#[derive(Deserialize)]
struct ReadBody {
    peer_id: String,
    ids: Vec<i64>,
    /// #11 Layer-4b (Codex Q7): msg_uids PARALLEL to `ids`, so sibling convergence keeps the uid
    /// even when a WS read falls back to HTTP. An old client or the WS path sends an empty Vec.
    #[serde(default)]
    uids: Vec<String>,
}

pub async fn read(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let recipient_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // FIX-3 (CONCERN H2 — WS-read DoS bypass): WS read got a rate limit but HTTP
    // `/messages/read` had no guard, so the WS limit could be bypassed over HTTP and unlimited
    // forward-reads pushed into the peer DO (DoS). The guard here mirrors send() (line ~94): a
    // per-user `msg:read:{recipient_id}` bucket of 300/60s, answering 429 when exceeded (the HTTP
    // path rejects instead of silently dropping like the WS path; the limiter itself stays fail-open
    // when the KV binding is missing). Using a separate bucket keeps legitimate read traffic from
    // eating the send quota, and each read still costs one hit.
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
    // Hardening #9: a revoked device must not be able to FORGE a read receipt (revoke parity with
    // the send path — present in `inbox_do::ws`'s send arm but missing from the read path). If the
    // token-bound device has been removed (revoked) from the device list, REJECT the read forward
    // without waiting for the 15 min TTL. (A legacy token with no device claim is not checked.)
    {
        let token_device = crate::auth::middleware::extract_bearer(&req)
            .and_then(|t| crate::auth::jwt::device_id_from_token(&ctx.env, &t).ok().flatten());
        if let Some(dev) = token_device.as_deref() {
            if crate::auth::middleware::device_revoked(&ctx.env, &recipient_id, dev).await? {
                return json_err(401, "device_revoked");
            }
        }
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

/// `GET /messages/receipt-sync?since=` — shared-root #1: cursor-pull the caller's OWN durable
/// `receipt_state` from its UserInbox DO (the HTTP twin of the WS `receipt_sync` frame). A device
/// that is NOT WS-connected (i.e. on the HTTP send fallback) converges the stuck tick of its own
/// outgoing message through here. receipt_state lives in the caller's own inbox, hence
/// `id_from_name(&user_id)`.
pub async fn receipt_sync(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // `since` comes from the client query (the plugin_log::sync pattern — a safely parsed i64 is
    // the only thing interpolated into the DO URL).
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
    stub.fetch_with_request(do_req).await
}

/// `POST /messages/self-read` (the 2026-06-28 sibling-read epic): a device of U reports the
/// `msg_uid`s of the incoming messages it read to U's OWN inbox DO → `self_read_state` set-once +
/// self_read_update/delta to U's other devices. It is the self-read twin of the `read` receipt, but
/// it goes to my own DO instead of the PEER's (sibling convergence). The {uids:[...]} body is parsed
/// in the DO; this handler forwards it opaquely.
pub async fn self_read(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // W3 (self-read DoS hardening, 2026-07-02): rate limit following the send/read pattern — a
    // separate bucket, 300/60s, fail-open on a KV error. Together with the body cap below it bounds
    // how fast `self_read_state` can grow. 300/60s sits FAR above the legitimate ceiling: the client
    // BATCHES mark-read through its dwell controller (a request is not a message; the practical
    // ceiling is ~30-60/min), so a real user NEVER reaches this limit and it only cuts runaway or
    // abusive traffic. NOTE (Codex flag): the client's send_self_read_durable DROPS on error without
    // retrying (pre-existing), so a 429 is theoretically a lost read — but since the limit is above
    // legitimate use, only an abuser's OWN fabricated reads are dropped. A client-side retry is a
    // separate robustness follow-up; this change is lossless for the legitimate path.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("msg:selfread:{user_id}"), 300, 60).await {
        return json_err(429, "rate_limited");
    }
    let body = req.text().await.unwrap_or_default();
    // W3: body size cap — 500 uids x ~40B is about 20KB, so 32KB is generous. Anything larger is an
    // anomaly or abuse → 400.
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
    stub.fetch_with_request(do_req).await
}

/// `GET /messages/self-read-sync?since=` — sibling-read cursor pull (the HTTP twin of the WS
/// `self_read_sync` frame). A new device pulls the entire read state from cursor=0 so its backlog
/// converges. Mirrors receipt_sync.
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
    stub.fetch_with_request(do_req).await
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
}
