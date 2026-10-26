//! Idempotent sending: `sendMessage {…, client_id}` (docs/BOTS_BUILD.md §2.5, added 2026-10-26).
//!
//! A program that timed out waiting for `sendMessage` cannot know whether the message went. With
//! a `client_id` of its own choosing, it sends the same call again: the inbox answers the first
//! send's `message_id` with `duplicate: true`, and nothing is posted twice. Without one, every
//! call is a new message, as before.
//!
//! - Remembered per bot for [`CLIENT_ID_TTL_MS`] (24 h, the updates' own window).
//! - A `client_id` is bound to what it sent (the chat, the text, `reply_to`): the same id with
//!   different content is `bot/client-id-reused` (409) — a program bug, not a retry.
//! - A retry that arrives while the first is still being sent waits for it, up to
//!   [`WAIT_FOR_FIRST_MS`]; still unsettled, it is `bot/in-progress` (409): call again.
//! - A send is "sent" the moment its envelopes are queued (`mark_sent`), before the network: from
//!   then on the outbox delivers it whatever happens to this request. One that never got that far
//!   frees its id (`release`), and one left half-way by an inbox that died is taken as never sent
//!   after [`ABANDONED_AFTER_MS`].
//! - A duplicate takes no slot of the send limits (`send_guard.rs`).

use super::store::{Arg, Exec};
use super::*;

pub(super) const CLIENT_ID_TTL_MS: i64 = 24 * 3600 * 1000;
/// How long a retry waits for the first send of its `client_id` to settle.
pub(super) const WAIT_FOR_FIRST_MS: i64 = 10_000;
const WAIT_STEP_MS: u64 = 250;
/// A send still unsettled after this was cut off with its request (an evicted inbox).
pub(super) const ABANDONED_AFTER_MS: i64 = 60_000;

pub(super) const TABLES: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS bot_client_ids (
        client_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, message_id TEXT NOT NULL,
        sent INTEGER NOT NULL DEFAULT 0, at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_bot_client_ids_at ON bot_client_ids(at)",
];

/// Bind: client_id.
pub(super) const CLIENT_GET: &str = "SELECT json_object('fp', fingerprint, 'id', message_id,
      'sent', sent, 'at', at) FROM bot_client_ids WHERE client_id = ?";
/// Bind: client_id, fingerprint, message_id, at. Replaces only an abandoned reservation
/// (`replay` decided so in the same synchronous block).
pub(super) const CLIENT_RESERVE: &str = "INSERT OR REPLACE INTO bot_client_ids
      (client_id, fingerprint, message_id, sent, at) VALUES (?, ?, ?, 0, ?)";
/// Bind: message_id.
pub(super) const CLIENT_SENT: &str = "UPDATE bot_client_ids SET sent = 1 WHERE message_id = ?";
/// Bind: client_id.
pub(super) const CLIENT_RELEASE: &str = "DELETE FROM bot_client_ids WHERE client_id = ? AND sent = 0";
/// Bind: cutoff.
pub(super) const CLIENT_EXPIRE: &str = "DELETE FROM bot_client_ids WHERE at < ?";

/// A remembered `client_id`.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(super) struct ClientRow {
    pub(super) fp: String,
    pub(super) id: String,
    pub(super) sent: i64,
    pub(super) at: i64,
}

/// What a `client_id` seen before means for this call.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Replay {
    /// Never seen (or abandoned): send, under this id.
    New,
    /// Sent: answer its `message_id` again.
    Sent(String),
    /// The same id, other content.
    Conflict,
    /// The first is still being sent.
    InFlight,
}

pub(super) fn replay(row: Option<&ClientRow>, fp: &str, now_ms: i64) -> Replay {
    match row {
        None => Replay::New,
        Some(r) if r.fp != fp => Replay::Conflict,
        Some(r) if r.sent == 1 => Replay::Sent(r.id.clone()),
        Some(r) if now_ms - r.at >= ABANDONED_AFTER_MS => Replay::New,
        Some(_) => Replay::InFlight,
    }
}

/// What a `client_id` is bound to: the chat (`send_guard::chat_key`), the text, the reply.
pub(super) fn fingerprint(chat: &str, text: &str, reply_to: Option<&str>) -> String {
    let canonical = serde_json::json!([chat, text, reply_to.unwrap_or("")]).to_string();
    crate::auth::hashing::sha256_hex(&canonical)
}

pub(super) fn lookup<E: Exec>(db: &E, client_id: &str) -> Option<ClientRow> {
    let json = db.texts(CLIENT_GET, &[Arg::T(client_id)]).into_iter().next()?;
    serde_json::from_str(&json).ok()
}

pub(super) fn reserve<E: Exec>(db: &E, client_id: &str, fp: &str, message_id: &str, now_ms: i64) {
    db.run(CLIENT_RESERVE, &[Arg::T(client_id), Arg::T(fp), Arg::T(message_id), Arg::I(now_ms)]);
}

/// The send's envelopes are queued: it is sent, whatever this request does next.
pub(super) fn mark_sent<E: Exec>(db: &E, message_id: &str) {
    db.run(CLIENT_SENT, &[Arg::T(message_id)]);
}

/// The send did not happen: the id is free for the next try.
pub(super) fn release<E: Exec>(db: &E, client_id: &str) {
    db.run(CLIENT_RELEASE, &[Arg::T(client_id)]);
}

/// The answer to a send repeated under its `client_id`.
pub(super) fn duplicate(message_id: &str) -> Result<Response> {
    Response::from_json(&crate::bots::api_answer::duplicate(message_id))
}

impl UserInbox {
    /// What a `client_id` means now, waiting while its first send is in flight. `New` is answered
    /// from a read with no `await` after it: the caller reserves in the same synchronous block.
    pub(super) async fn bot_client_replay(&self, client_id: &str, fp: &str) -> Replay {
        let mut waited = 0;
        loop {
            let now = crate::utils::now_ms() as i64;
            let r = replay(lookup(&self.bot_store().db, client_id).as_ref(), fp, now);
            if r != Replay::InFlight || waited >= WAIT_FOR_FIRST_MS {
                return r;
            }
            worker::Delay::from(std::time::Duration::from_millis(WAIT_STEP_MS)).await;
            waited += WAIT_STEP_MS as i64;
        }
    }
}

#[cfg(test)]
#[path = "send_replay_tests.rs"]
mod tests;
