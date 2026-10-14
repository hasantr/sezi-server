//! The W4-b durable retry queue: the enqueue, the drain and its TTL collector.
//!
//! Declared in `handlers.rs` rather than `messages/mod.rs` so `messages::handlers::drain_fanout_retry`
//! remains the name every caller already uses — the shape `keys/handlers.rs` uses for `bundle_slot`.
//!
//! **One row per MEMBER (D8, 2026-10-13).** A row carries a member and all of their devices
//! (`recipient_devices`, a JSON array), and the drain re-notifies it with the same
//! `/notify-member` the send uses — so the member's inbox stores a row per device and sends the
//! wake itself, and a drained row costs this invocation one subrequest. A row written before the
//! column existed has only `recipient_device` and drains as a one-device member.
//!
//! **The close is never the call cut off (the D8 review).** The drain is sized from the purse its
//! caller grants it (`budget::drain_rows`), which reserves the claim and the close with one retry;
//! the caller's own work after the drain is outside that purse. A close that fails twice leaves the
//! rows leased: they come back after `W4B_LEASE_SECS` and are notified again, which the inbox's
//! dedup absorbs while the message is still pending — the residual is a D1 outage twice in a row.

use super::{W4B_BACKOFF_BASE_SECS, W4B_INITIAL_BACKOFF_SECS, W4B_LEASE_SECS, W4B_MAX_BACKOFF_SECS};
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::messages::budget::{self, SubrequestBudget};
use crate::messages::group_fanout::{
    notify_members, DoCalls, FanoutCalls, GroupMessage, Member, MemberOutcome, RetryStore,
};
use crate::utils::now_secs;
use sha2::{Digest, Sha256};
use worker::*;

/// The idempotency key of a member's row: sha256(recipient|devices|group|envelope)[..16] in hex.
/// With `INSERT OR IGNORE` a sender's retry of the same send cannot queue a member twice.
fn retry_key(m: &Member, msg: &GroupMessage) -> String {
    let mut hasher = Sha256::new();
    hasher.update(m.user_id.as_bytes());
    hasher.update(b"|");
    if let Some(devices) = &m.devices {
        hasher.update(devices.join(",").as_bytes());
    }
    hasher.update(b"|");
    hasher.update(msg.group_id.as_bytes());
    hasher.update(b"|");
    hasher.update(msg.envelope_b64.as_bytes());
    hasher.finalize()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// The queue in D1, as the send writes it: ONE batch whatever its length (a statement per row
/// would be a subrequest per row), one row per member. An error means the members are NOT
/// queued, and the send must not be acknowledged.
pub(crate) struct D1RetryStore<'a> {
    pub(crate) db: &'a D1Database,
}

impl RetryStore for D1RetryStore<'_> {
    async fn enqueue(&self, msg: &GroupMessage, members: &[&Member]) -> Result<()> {
        let now = now_secs() as i64;
        let mut stmts = Vec::with_capacity(members.len());
        for m in members {
            let devices = m.devices.as_ref().and_then(|d| serde_json::to_string(d).ok());
            stmts.push(
                self.db
                    .prepare(
                        "INSERT OR IGNORE INTO fanout_retry
                         (retry_key, recipient_id, recipient_device, recipient_devices, sender_id,
                          sender_device, envelope_b64, group_id, attempts, next_at, created_at, silent)
                         VALUES (?, ?, NULL, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                    )
                    .bind(&[
                        d1_text(&retry_key(m, msg)),
                        d1_text(&m.user_id),
                        d1_opt_text(devices.as_deref()),
                        d1_text(&msg.sender_id),
                        d1_text(&msg.sender_device_id),
                        d1_text(&msg.envelope_b64),
                        d1_text(&msg.group_id),
                        d1_int(now + W4B_INITIAL_BACKOFF_SECS),
                        d1_int(now),
                        d1_int(i64::from(msg.silent)),
                    ])?,
            );
        }
        // ONE attempt; `fan_out_and_close` retries it once (both are in `budget::CLOSE`).
        self.db.batch(stmts).await.map(|_| ())
    }
}

/// One claimed row of `fanout_retry`.
#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct RetryRow {
    pub(crate) id: i64,
    pub(crate) recipient_id: String,
    /// Pre-D8 rows: the single device.
    #[serde(default)]
    pub(crate) recipient_device: Option<String>,
    /// D8 rows: the member's devices as a JSON array.
    #[serde(default)]
    pub(crate) recipient_devices: Option<String>,
    pub(crate) sender_id: String,
    #[serde(default)]
    pub(crate) sender_device: Option<String>,
    pub(crate) envelope_b64: String,
    pub(crate) group_id: String,
    pub(crate) attempts: i64,
    /// Whether the sender asked for no wake. `#[serde(default)]` → a row written before this
    /// column existed reads as 0 (wake), i.e. the old behaviour.
    #[serde(default)]
    pub(crate) silent: i64,
}

impl RetryRow {
    /// The member this row stands for: the JSON device list, else the pre-D8 single device, else
    /// device-blind.
    fn member(&self) -> Member {
        let devices = match (&self.recipient_devices, &self.recipient_device) {
            (Some(json), _) => serde_json::from_str::<Vec<String>>(json).ok(),
            (None, Some(d)) => Some(vec![d.clone()]),
            (None, None) => None,
        };
        Member { user_id: self.recipient_id.clone(), devices }
    }

    fn message(&self) -> GroupMessage {
        GroupMessage {
            sender_id: self.sender_id.clone(),
            sender_device_id: self.sender_device.clone().unwrap_or_default(),
            envelope_b64: self.envelope_b64.clone(),
            group_id: self.group_id.clone(),
            silent: self.silent != 0,
        }
    }
}

/// What the drain decides for one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowWrite {
    /// Delivered: the member's inbox stored it and sent the wake.
    Delete(i64),
    /// Failed: back off, NEVER delete (Codex#4) — a long outage keeps retrying and the TTL GC
    /// collects anything truly ancient.
    Backoff { id: i64, next_at: i64 },
    /// Claimed but not afforded: hand it straight back instead of holding it for the lease.
    Release { id: i64, next_at: i64 },
}

/// The queue the drain works, behind a seam (`messages/spend_tests.rs` runs the drain against a
/// counted fake).
pub(crate) trait RetryQueue {
    /// Claim up to `n` due rows, pushing their `next_at` a lease ahead (the in-flight marker).
    async fn claim(&self, n: usize, now: i64) -> Result<Vec<RetryRow>>;
    /// Apply every terminal write in ONE batch.
    async fn close(&self, writes: &[RowWrite]) -> Result<()>;
}

pub(crate) struct D1RetryQueue<'a> {
    pub(crate) db: &'a D1Database,
}

impl RetryQueue for D1RetryQueue<'_> {
    async fn claim(&self, n: usize, now: i64) -> Result<Vec<RetryRow>> {
        self.db
            .prepare(
                "UPDATE fanout_retry SET next_at = ?
                 WHERE id IN (SELECT id FROM fanout_retry WHERE next_at <= ? ORDER BY next_at LIMIT ?)
                 RETURNING id, recipient_id, recipient_device, recipient_devices, sender_id, sender_device,
                           envelope_b64, group_id, attempts, silent",
            )
            .bind(&[d1_int(now + W4B_LEASE_SECS), d1_int(now), d1_int(n as i64)])?
            .all()
            .await?
            .results::<RetryRow>()
    }

    async fn close(&self, writes: &[RowWrite]) -> Result<()> {
        let mut stmts = Vec::with_capacity(writes.len());
        for w in writes {
            stmts.push(match *w {
                RowWrite::Delete(id) => {
                    self.db.prepare("DELETE FROM fanout_retry WHERE id = ?").bind(&[d1_int(id)])?
                }
                RowWrite::Backoff { id, next_at } => self
                    .db
                    .prepare("UPDATE fanout_retry SET attempts = attempts + 1, next_at = ? WHERE id = ?")
                    .bind(&[d1_int(next_at), d1_int(id)])?,
                RowWrite::Release { id, next_at } => self
                    .db
                    .prepare("UPDATE fanout_retry SET next_at = ? WHERE id = ?")
                    .bind(&[d1_int(next_at), d1_int(id)])?,
            });
        }
        self.db.batch(stmts).await.map(|_| ())
    }
}

/// What one drain did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DrainReport {
    pub(crate) claimed: usize,
    pub(crate) delivered: usize,
    pub(crate) failed: usize,
    pub(crate) released: usize,
    /// Whether the closing batch landed (within its one retry).
    pub(crate) closed: bool,
}

/// The drain itself, behind its two seams. `purse` is every subrequest this drain may spend,
/// claim and close included; a purse that cannot pay for the close claims nothing.
pub(crate) async fn drain_with<Q: RetryQueue, C: FanoutCalls>(
    queue: &Q,
    calls: &C,
    purse: usize,
    now: i64,
) -> DrainReport {
    let rows = budget::drain_rows(purse);
    if rows == 0 {
        return DrainReport::default();
    }
    let Ok(claimed) = queue.claim(rows, now).await else {
        return DrainReport::default();
    };
    let mut report = DrainReport { claimed: claimed.len(), ..DrainReport::default() };
    if claimed.is_empty() {
        report.closed = true;
        return report;
    }
    let mut budget = SubrequestBudget::new(purse, budget::DRAIN_OVERHEAD);
    // A run of consecutive rows of the SAME message (one send queues its members together, so they
    // share a `next_at` and sit side by side) goes out as one `notify_members`, concurrently; rows
    // of different messages are separate runs. One subrequest per row either way.
    let mut outcomes = Vec::with_capacity(claimed.len());
    let mut i = 0;
    while i < claimed.len() {
        let msg = claimed[i].message();
        let mut j = i + 1;
        while j < claimed.len()
            && claimed[j].sender_id == claimed[i].sender_id
            && claimed[j].group_id == claimed[i].group_id
            && claimed[j].envelope_b64 == claimed[i].envelope_b64
            && claimed[j].silent == claimed[i].silent
        {
            j += 1;
        }
        let members: Vec<Member> = claimed[i..j].iter().map(RetryRow::member).collect();
        // No in-request retry: the row-level backoff IS the retry (Fable#2).
        outcomes.extend(notify_members(calls, &msg, &members, &mut budget, false).await);
        i = j;
    }
    let writes: Vec<RowWrite> = claimed
        .iter()
        .zip(&outcomes)
        .map(|(r, o)| match o {
            MemberOutcome::Delivered { .. } => {
                report.delivered += 1;
                RowWrite::Delete(r.id)
            }
            MemberOutcome::Failed => {
                report.failed += 1;
                // `attempts` counts only DO errors — an asleep member is not one.
                let shift = r.attempts.clamp(0, 5) as u32;
                let backoff = (W4B_BACKOFF_BASE_SECS << shift).min(W4B_MAX_BACKOFF_SECS);
                RowWrite::Backoff { id: r.id, next_at: now + backoff }
            }
            MemberOutcome::Deferred => {
                report.released += 1;
                RowWrite::Release { id: r.id, next_at: now }
            }
        })
        .collect();
    // Reserved twice in `budget::DRAIN_OVERHEAD`.
    report.closed = queue.close(&writes).await.is_ok() || queue.close(&writes).await.is_ok();
    report
}

/// The drain in production, with the purse its caller grants it (`budget::cron_drain_purse`,
/// `budget::upkeep_drain_purse`). Best-effort: a D1/DO error leaves the rows for the next round,
/// and a missing table (migration not applied) is a silent no-op.
pub(crate) async fn drain_fanout_retry(env: &Env, purse: usize) {
    let Ok(db) = env.d1("DB") else { return };
    let Ok(namespace) = env.durable_object("USER_INBOX") else { return };
    let r = drain_with(&D1RetryQueue { db: &db }, &DoCalls { ns: &namespace }, purse, now_secs() as i64).await;
    if r.claimed > 0 {
        console_log!(
            "[deliv] W4-b drain: {}/{} re-notify OK, {} failed, {} left for the next run{}",
            r.delivered,
            r.claimed,
            r.failed,
            r.released,
            if r.closed { "" } else { " — CLOSE FAILED, rows return after the lease" }
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn row(device: Option<&str>, devices: Option<&str>) -> RetryRow {
        RetryRow {
            id: 1,
            recipient_id: "u".into(),
            recipient_device: device.map(str::to_string),
            recipient_devices: devices.map(str::to_string),
            sender_id: "s".into(),
            sender_device: Some("sd".into()),
            envelope_b64: "e".into(),
            group_id: "g".into(),
            attempts: 0,
            silent: 0,
        }
    }

    /// A row queued before the D8 column still drains — as the one device it named.
    #[test]
    fn a_pre_d8_row_drains_as_a_one_device_member() {
        assert_eq!(row(Some("d1"), None).member().devices, Some(vec!["d1".to_string()]));
    }

    #[test]
    fn a_d8_row_drains_every_device_it_lists() {
        let m = row(None, Some(r#"["a","b"]"#)).member();
        assert_eq!(m.devices, Some(vec!["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn a_row_with_neither_is_device_blind() {
        assert_eq!(row(None, None).member().devices, None);
    }

    /// The key separates members and messages, and repeats for a repeated send.
    #[test]
    fn the_retry_key_is_per_member_and_message() {
        let msg = row(None, None).message();
        let a = Member { user_id: "a".into(), devices: Some(vec!["1".into()]) };
        let b = Member { user_id: "b".into(), devices: Some(vec!["1".into()]) };
        assert_eq!(retry_key(&a, &msg), retry_key(&a, &msg));
        assert_ne!(retry_key(&a, &msg), retry_key(&b, &msg));
    }
}
