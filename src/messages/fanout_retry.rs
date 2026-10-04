//! The W4-b durable retry queue: the cron drain and its TTL collector.
//!
//! A pure move out of `handlers.rs` under the file-size ceiling, and declared THERE rather than in
//! `messages/mod.rs` so `messages::handlers::drain_fanout_retry` remains the name every caller
//! already uses — the shape `keys/handlers.rs` uses for `bundle_slot`.

use super::{
    build_notify_payload, notify_once, W4B_BACKOFF_BASE_SECS, W4B_DRAIN_BATCH, W4B_LEASE_SECS,
    W4B_MAX_BACKOFF_SECS,
};
use crate::d1util::d1_int;
use crate::utils::now_secs;
use worker::*;

/// W4-b durable-retry drain (cron; runs on EVERY scheduled invocation). Atomically claims rows
/// (`UPDATE ... next_at = LEASE-ahead ... RETURNING`, so an overlapping cron cannot re-notify the
/// SAME row), then re-notifies each ONCE: on success DELETE the row and keep FCM-wake parity, on
/// failure UPDATE with an exponential backoff (NEVER delete — Codex#4 loss prevention: a long
/// outage keeps retrying and the TTL GC collects anything truly ancient). Bounded batch,
/// best-effort: a D1/DO error leaves the row for the next round, and a missing table (migration not
/// applied) is a silent no-op. Deliberately calls `notify_once` rather than notify_recipient's
/// in-request retry, because the row-level backoff IS the retry (Fable#2).
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
    // The drain lives under the SAME subrequest ceiling as the send path that fills the queue — a
    // detail that made the original design circular: a fan-out too wide for one request produced
    // retry rows, and a drain of 50 rows was itself too wide for one request, so the tail failed
    // again and was re-queued with a longer backoff each time. The claim is now sized to what this
    // invocation can actually pay for.
    let budget_total = crate::messages::budget::resolve_budget(env);
    let claim_n = crate::messages::budget::drain_claim_size(
        budget_total,
        crate::messages::budget::DRAIN_OVERHEAD,
        W4B_DRAIN_BATCH,
    );
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
            d1_int(claim_n as i64),
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
    let mut released = 0usize;
    let mut budget = crate::messages::budget::SubrequestBudget::new(
        budget_total,
        crate::messages::budget::DRAIN_OVERHEAD,
    );
    // Every terminal write — DELETE on success, backoff UPDATE on failure, lease release on a row
    // we could not afford — is collected and applied as ONE batch below. Per-row writes were a
    // subrequest each, i.e. the bookkeeping cost as much as the work.
    let mut writes = Vec::with_capacity(total);
    for r in &claimed {
        if !budget.can_afford(crate::messages::budget::COST_PAIR_WORST_CASE) {
            // Out of budget. Hand the row straight back instead of holding it for the full
            // ten-minute lease: it was claimed and never touched, so the next cron (two minutes
            // out) should be free to take it.
            if let Ok(stmt) = db
                .prepare("UPDATE fanout_retry SET next_at = ? WHERE id = ?")
                .bind(&[d1_int(now), d1_int(r.id)])
            {
                writes.push(stmt);
            }
            released += 1;
            continue;
        }
        budget.spend(crate::messages::budget::COST_NOTIFY);
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
                    writes.push(stmt);
                }
                // FCM-wake parity with the handlers' offline branch (Codex#6): stored OK but
                // offline → wake. A `silent` row skips it: the retry queue must not resurrect a wake
                // the immediate path deliberately declined (a group receipt would otherwise wake the
                // device minutes later, which is worse than the original bug because it looks random).
                if !delivered_live && r.silent == 0 {
                    budget.spend(crate::messages::budget::COST_PUSH_WAKE);
                    crate::push::fcm::maybe_push_wake(
                        env, &db, &r.recipient_id, r.recipient_device.as_deref(),
                    )
                    .await;
                }
                ok += 1;
            }
            Err(_) => {
                // No extra charge here: the drain deliberately calls `notify_once`, so a failure
                // costs the one call already spent above (the row-level backoff IS its retry).
                // Exponential backoff, NEVER delete (Codex#4): attempts++ and push next_at ahead.
                // `attempts` counts only DO errors (offline is not an error — the notify succeeded),
                // so a high attempts value means "the DO has been broken for days", which is rare.
                let shift = r.attempts.clamp(0, 5) as u32;
                let backoff = (W4B_BACKOFF_BASE_SECS << shift).min(W4B_MAX_BACKOFF_SECS);
                if let Ok(stmt) = db
                    .prepare("UPDATE fanout_retry SET attempts = attempts + 1, next_at = ? WHERE id = ?")
                    .bind(&[d1_int(now + backoff), d1_int(r.id)])
                {
                    writes.push(stmt);
                }
            }
        }
    }
    // BEST-EFFORT, and the failure mode is deliberately the safe one: if this batch does not land,
    // the successful rows keep their (leased) place in the queue and are re-notified later, which
    // the DO's durable dedup absorbs. Losing a delete costs a duplicate attempt; losing a row
    // would cost a message.
    if !writes.is_empty() {
        let _ = db.batch(writes).await;
    }
    console_log!("[deliv] W4-b drain: {ok}/{total} re-notify OK ({released} left for the next run, over budget)");
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
