//! Scheduled messages, the relay's rules — pure, so the host tests reach them
//! (`docs/SCHEDULED_MESSAGES_PLAN.md`; the routes are `scheduled.rs`, the hold and the release
//! `inbox_do/scheduled.rs`).
//!
//! The relay holds a scheduled message as the sender sealed it: a kind-3 envelope it cannot open
//! (the one-time key travelled to the targets over Olm), the release time, and the exact devices
//! to release it to. What it decides is only WHO still gets it at the time: a target user must
//! still be an active member of the room (or, for a 1:1, the two must still be allowed to write to
//! each other), a target device must still be an active device, and the sender's own device must
//! still be one — a device revoked before the time releases nothing.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

/// The most messages one account may have held at once.
pub(crate) const MAX_PENDING: i64 = 100;
/// How far ahead a message may be held: a year and a day.
pub(crate) const MAX_AHEAD_MS: i64 = 366 * 24 * 3600 * 1000;
/// How far in the past a release time may be when it is handed over (a device that was offline at
/// the time, a clock a little off). Further, and it would be an unthrottled send dated in the past
/// (review findings 3 and 9); the core gives up on such a hand-over itself
/// (`sezi_protocol::scheduled::LATE_SKEW_MS`, the same ten minutes).
pub(crate) const MAX_LATE_MS: i64 = 10 * 60 * 1000;
/// The most devices one schedule may be released to.
pub(crate) const MAX_TARGET_DEVICES: usize = 200;
/// An envelope's size bounds, as for any envelope (`messages/handlers.rs`).
pub(crate) const MIN_ENVELOPE: usize = 20;
pub(crate) const MAX_ENVELOPE: usize = 64 * 1024;
/// How soon the next alarm runs after a release that did not finish for want of budget.
pub(crate) const RELEASE_RETRY_MS: i64 = 1_000;
/// A release that could not reach a member is given up this long after its time.
pub(crate) const RELEASE_GIVE_UP_MS: i64 = 7 * 24 * 3600 * 1000;

/// What one alarm run spends on the held message it releases besides its member calls (review
/// finding 5; `messages::budget` holds the platform's figures): the two D1 reads (who may still have
/// it, their active devices — one statement per hundred users, so at most two for the 200 devices a
/// schedule may name) and the close (the row's update or delete, with one retry). The run releases
/// ONE held message, and only when it releases anything does it skip the stale-pending backstop
/// (`alarm_ops.rs`), which may spend a wake per device. Every other member's devices are stored and
/// woken from that member's own inbox (`/notify-release`, one call per member).
pub(crate) const RELEASE_RESERVED: usize = 3 + crate::messages::budget::CLOSE + ALARM_TAIL + OWN_WAKE;
/// The sender's OWN devices are released into this very inbox, and their wake (those not
/// connected) is sent from this invocation: the worst case of one member's wake (`budget::MEMBER_WAKE_*`).
pub(crate) const OWN_WAKE: usize = crate::messages::budget::MEMBER_WAKE_FIXED
    + crate::devices::handlers::MAX_DEVICES * crate::messages::budget::MEMBER_WAKE_PER_DEVICE;
/// What the rest of the same alarm run may spend: the daily retention read and the revoked-device
/// reconcile (`alarm_ops.rs`), one D1 read each at most.
pub(crate) const ALARM_TAIL: usize = 2;

/// How many member calls one alarm run makes for a release, out of the invocation's budget: what
/// the reserve leaves, less a fifth held back so a failing call can be tried once more — the
/// group fan-out's own arithmetic (`budget::members_per_invocation`).
pub(crate) fn members_per_release_run(budget: usize) -> usize {
    crate::messages::budget::members_per_invocation(budget, RELEASE_RESERVED)
}

/// When a row is tried again after `attempts` runs that left something undelivered: one second
/// while it is only the budget that ran out, else 10 s, 30 s, 1 min, then every 5 min.
pub(crate) fn next_attempt_at(now_ms: i64, attempts: i64, budget_only: bool) -> i64 {
    let wait = if budget_only {
        RELEASE_RETRY_MS
    } else {
        match attempts {
            0 | 1 => 10_000,
            2 => 30_000,
            3 => 60_000,
            _ => 300_000,
        }
    };
    now_ms.saturating_add(wait)
}

/// Is a held row past saving: its time long gone and still undelivered?
pub(crate) fn gives_up(release_at_ms: i64, now_ms: i64) -> bool {
    now_ms > release_at_ms.saturating_add(RELEASE_GIVE_UP_MS)
}

/// The weighted fan-out bucket a room send pays into (`group_fanout.rs`); a schedule pays into the
/// same one, by the devices its release will reach.
pub(crate) fn fanout_bucket(sender_id: &str) -> String {
    format!("msg:grp_fanout:{sender_id}")
}

/// A kind-3 envelope is the relay's own to hand over, at its time: refused on the ordinary send
/// path (`/messages/send`, the socket's `send`), so a member or contact cannot inject one as if it
/// had been released (review finding 2). The receiver's digest check stands either way.
///
/// A twelve-character prefix test, no decode (re-review N5): the receiver reads nothing as a release
/// that does not start the same way (`WireEnvelope::scheduled_parts`), so this cannot be evaded by
/// writing the JSON differently, and an ordinary send of 100 envelopes of 64 KiB pays nothing for it.
pub(crate) fn is_scheduled_envelope(envelope_b64: &str) -> bool {
    sezi_protocol::envelope::WireEnvelope::is_scheduled_b64(envelope_b64)
}

/// The due rows of the held table, by when each is next to be tried — never by release time alone,
/// so a row that keeps failing does not stand in front of the ones after it (review finding 4).
pub(crate) const SELECT_DUE_SQL: &str = "SELECT schedule_id, sender_id, sender_device_id, recipient_id, group_id,
       release_at, envelope_b64, targets_json, attempts
  FROM scheduled WHERE next_attempt_at <= ? ORDER BY next_attempt_at, release_at LIMIT 1";

/// The devices of one user a release goes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Target {
    pub user_id: String,
    pub device_ids: Vec<String>,
}

/// `POST /messages/scheduled`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PutBody {
    pub schedule_id: String,
    pub release_at_ms: i64,
    #[serde(default)]
    pub recipient_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    pub sender_device_id: String,
    pub envelope_b64: String,
    pub targets: Vec<Target>,
}

/// Where a schedule goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Conversation<'a> {
    Direct(&'a str),
    Room(&'a str),
}

/// A refusal: its status and the code the app words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub status: u16,
    pub code: &'static str,
}

const fn refuse(status: u16, code: &'static str) -> Refusal {
    Refusal { status, code }
}

/// Is `id` a schedule id as the core makes them: a lowercase hex UUID (it names a DO row and a URL
/// segment, so nothing else is taken).
pub(crate) fn valid_schedule_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// What can be judged of a hand-over without the database: its shape, its time, its size, and that
/// it names exactly one conversation whose people are the only target users.
pub(crate) fn check_put<'a>(body: &'a PutBody, sender_id: &str, now_ms: i64) -> Result<Conversation<'a>, Refusal> {
    if !valid_schedule_id(&body.schedule_id) || body.sender_device_id.is_empty() {
        return Err(refuse(400, "bad_request"));
    }
    if body.release_at_ms > now_ms.saturating_add(MAX_AHEAD_MS) || body.release_at_ms < now_ms.saturating_sub(MAX_LATE_MS) {
        return Err(refuse(400, "scheduled/too-far"));
    }
    if body.envelope_b64.len() < MIN_ENVELOPE || body.envelope_b64.len() > MAX_ENVELOPE {
        return Err(refuse(400, "bad_request"));
    }
    // Only a release, and one naming the id it is held under (re-review N4): what the relay hands out
    // at the time is what a receiver reads as this schedule's release, nothing else.
    match sezi_protocol::envelope::WireEnvelope::scheduled_parts(&body.envelope_b64) {
        Some((id, _)) if id == body.schedule_id => {}
        _ => return Err(refuse(400, "bad_request")),
    }
    let conversation = match (body.recipient_id.as_deref(), body.group_id.as_deref()) {
        (Some(r), None) if r.len() == 36 && r != sender_id => Conversation::Direct(r),
        (None, Some(g)) if !g.is_empty() && g.len() <= 64 => Conversation::Room(g),
        _ => return Err(refuse(400, "bad_request")),
    };
    let devices: usize = body.targets.iter().map(|t| t.device_ids.len()).sum();
    if body.targets.is_empty() || devices == 0 || devices > MAX_TARGET_DEVICES {
        return Err(refuse(400, "scheduled/bad-target"));
    }
    let mut users = HashSet::new();
    for t in &body.targets {
        if t.device_ids.is_empty() || !users.insert(t.user_id.as_str()) {
            return Err(refuse(400, "scheduled/bad-target"));
        }
        let mut seen = HashSet::new();
        if t.device_ids.iter().any(|d| d.is_empty() || d.len() > 64 || !seen.insert(d.as_str())) {
            return Err(refuse(400, "scheduled/bad-target"));
        }
        if let Conversation::Direct(r) = conversation {
            if t.user_id != r && t.user_id != sender_id {
                return Err(refuse(400, "scheduled/bad-target"));
            }
        }
    }
    // The sender's own devices are targets too, the scheduling one included: each makes the
    // sender's own copy of the message from the release.
    Ok(conversation)
}

/// Who still gets a held message at its time.
///
/// - `still_allowed`: for a room, the users who are ACTIVE members now; for a 1:1, the two when they
///   may still write to each other, else nobody.
/// - `active_devices`: the `(user, device)`s not revoked now.
///
/// The sender's own device must be among the active ones, and for a room the sender among the
/// active members: otherwise nothing is released.
pub(crate) fn release_targets(
    targets: &[Target],
    sender_id: &str,
    sender_device: &str,
    still_allowed: &HashSet<String>,
    active_devices: &HashSet<(String, String)>,
) -> Vec<(String, String)> {
    if !still_allowed.contains(sender_id) || !active_devices.contains(&(sender_id.to_string(), sender_device.to_string())) {
        return Vec::new();
    }
    let mut out = BTreeSet::new();
    for t in targets {
        if !still_allowed.contains(&t.user_id) {
            continue;
        }
        for d in &t.device_ids {
            let pair = (t.user_id.clone(), d.clone());
            if active_devices.contains(&pair) {
                out.insert(pair);
            }
        }
    }
    out.into_iter().collect()
}

/// The next alarm, given the inbox's own and the soonest held release (both delays from now).
pub(crate) fn with_release(own: Option<i64>, next_release_in: Option<i64>) -> Option<i64> {
    match (own, next_release_in.map(|d| d.max(0))) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The relay's held row, as stored in the sender's inbox Durable Object. It is ROUTING and an
/// envelope the relay cannot open — nothing else (`a_held_row_is_ciphertext_and_routing_only`).
pub(crate) const SCHEDULED_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS scheduled (
    schedule_id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    recipient_id TEXT,
    group_id TEXT,
    release_at INTEGER NOT NULL,
    envelope_b64 TEXT NOT NULL,
    targets_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    released_any INTEGER NOT NULL DEFAULT 0
)";

/// Mark a row as being released, BEFORE its first delivery is tried (re-review 6a). Before, not
/// after: a take-back can reach this object while a member call is in flight (an awaited fetch does
/// not hold the object's input gate), and it must then read "too late" — a delivery that then
/// fails leaves the row to be tried again, so the worst case is a sender told "too late" for a
/// message nobody has yet, never "cancelled" for one somebody has.
pub(crate) const BEGIN_RELEASE_SQL: &str = "UPDATE scheduled SET released_any = 1 WHERE schedule_id = ?";

/// A take-back (`/scheduled-cancel`), from the held row's `released_any` (`None`: not held): whether
/// to delete the row, and the answer. A row already released to anyone is too late — it stays and
/// keeps releasing the rest, and the sender is told (re-review 6a); "cancelled" while some have it
/// would be a lie.
pub(crate) fn cancel_answer(held: Option<bool>) -> (bool, serde_json::Value) {
    let released_any = held == Some(true);
    let delete = held == Some(false);
    (delete, serde_json::json!({ "held": held.is_some(), "released_any": released_any }))
}

#[cfg(test)]
#[path = "scheduled_rules_tests.rs"]
mod tests;
