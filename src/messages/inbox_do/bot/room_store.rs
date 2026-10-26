//! The bot inbox's room tables (docs/BOTS_BUILD.md §2.3, Phase 3) and the engine's `RoomStore`
//! over them. Created with the other bot tables, only in bot mode. As in `store.rs`, every
//! statement is a `const` the tests run on rusqlite, binds positional in the order each doc says.
//!
//! | Table | Holds | Kept |
//! |---|---|---|
//! | `bot_megolm` | the bot's OWN outbound session per room | until rotated, or the bot leaves the room |
//! | `bot_megolm_shared` | which member device got that session, and the key snapshot it got | with its session |
//! | `bot_megolm_requests` | when a member's `RoomKeyRequest` was last answered | with the room |
//! | `bot_room_posts` | posts waiting for their key shares, then encrypted | until encrypted, 24 h at most |
//! | `bot_calls` | the calls the program was handed, so `reply_to` can name one | 7 days |
//! | `bot_room_asks` | members' `RoomKeyRequest`s still to answer, one per (room, member) | until answered or judged moot |
//!
//! There is no table for a key somebody else shared: the bot never holds one.

use super::store::{Arg, Exec, SqlBotStore};
use sezi_bot_engine::{RoomSession, RoomShare, RoomStore};

pub(super) const TABLES: [&str; 6] = [
    "CREATE TABLE IF NOT EXISTS bot_room_asks (
        room_id TEXT NOT NULL, user_id TEXT NOT NULL, session_id TEXT, at INTEGER NOT NULL,
        PRIMARY KEY (room_id, user_id))",
    "CREATE TABLE IF NOT EXISTS bot_megolm (
        room_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, pickle TEXT NOT NULL,
        created_at INTEGER NOT NULL, sent INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS bot_megolm_shared (
        room_id TEXT NOT NULL, session_id TEXT NOT NULL, user_id TEXT NOT NULL,
        device_id TEXT NOT NULL, key_b64 TEXT NOT NULL,
        PRIMARY KEY (room_id, session_id, user_id, device_id))",
    "CREATE TABLE IF NOT EXISTS bot_megolm_requests (
        room_id TEXT NOT NULL, user_id TEXT NOT NULL, at INTEGER NOT NULL,
        PRIMARY KEY (room_id, user_id))",
    // `skipped` = the member devices this post could not reach (no session, no key to claim): a
    // JSON array of "user/device", so the post is not held for them forever.
    "CREATE TABLE IF NOT EXISTS bot_room_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT NOT NULL, payload_json TEXT NOT NULL,
        skipped TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS bot_calls (
        room_id TEXT NOT NULL, msg_uid TEXT NOT NULL, from_user TEXT NOT NULL,
        body TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (room_id, msg_uid))",
];

// The store's `Exec` reads one column; a row of several comes back as one JSON object.

/// Bind: room.
pub(super) const SESSION_GET: &str = "SELECT json_object('session_id', session_id, 'pickle', pickle,
      'created_at', created_at, 'sent', sent) AS v FROM bot_megolm WHERE room_id = ?";
/// Bind: room, session_id, pickle, created_at, sent.
pub(super) const SESSION_PUT: &str = "INSERT INTO bot_megolm (room_id, session_id, pickle, created_at, sent)
      VALUES (?, ?, ?, ?, ?) ON CONFLICT(room_id) DO UPDATE SET session_id = excluded.session_id,
      pickle = excluded.pickle, created_at = excluded.created_at, sent = excluded.sent";
/// Bind: room, session_id.
pub(super) const SHARES_GET: &str = "SELECT json_object('user_id', user_id, 'device_id', device_id,
      'key_b64', key_b64) AS v FROM bot_megolm_shared
      WHERE room_id = ? AND session_id = ? ORDER BY user_id, device_id";
/// Bind: room, session_id, user, device, key.
pub(super) const SHARE_PUT: &str = "INSERT OR REPLACE INTO bot_megolm_shared
      (room_id, session_id, user_id, device_id, key_b64) VALUES (?, ?, ?, ?, ?)";
/// Bind: room (each).
pub(super) const FORGET: [&str; 3] = [
    "DELETE FROM bot_megolm WHERE room_id = ?",
    "DELETE FROM bot_megolm_shared WHERE room_id = ?",
    "DELETE FROM bot_megolm_requests WHERE room_id = ?",
];
/// Bind: room, user.
pub(super) const REQUEST_GET: &str = "SELECT at FROM bot_megolm_requests WHERE room_id = ? AND user_id = ?";
/// Bind: room, user, at.
pub(super) const REQUEST_PUT: &str = "INSERT INTO bot_megolm_requests (room_id, user_id, at) VALUES (?, ?, ?)
      ON CONFLICT(room_id, user_id) DO UPDATE SET at = excluded.at";

/// Bind: room, payload_json, created_at.
pub(super) const POST_PUSH: &str =
    "INSERT INTO bot_room_posts (room_id, payload_json, skipped, created_at) VALUES (?, ?, '[]', ?)";
/// The oldest waiting post. Bind: none.
pub(super) const POST_NEXT: &str =
    "SELECT id, room_id, payload_json, skipped, created_at FROM bot_room_posts ORDER BY id LIMIT 1";
/// Bind: skipped, id.
pub(super) const POST_SKIPPED: &str = "UPDATE bot_room_posts SET skipped = ? WHERE id = ?";
/// Bind: id.
pub(super) const POST_DONE: &str = "DELETE FROM bot_room_posts WHERE id = ?";
/// Every post for a room the bot is no longer in. Bind: room.
pub(super) const POSTS_DROP_ROOM: &str = "DELETE FROM bot_room_posts WHERE room_id = ?";
/// Bind: cutoff.
pub(super) const POSTS_EXPIRE: &str = "DELETE FROM bot_room_posts WHERE created_at < ?";
/// Room work waiting: posts and unanswered key requests.
pub(super) const POSTS_WAITING: &str =
    "SELECT (SELECT COUNT(*) FROM bot_room_posts) + (SELECT COUNT(*) FROM bot_room_asks) AS n";

/// A member asked again (the newest ask replaces an older one). Bind: room, user, session_id, at.
pub(super) const ASK_PUT: &str = "INSERT OR REPLACE INTO bot_room_asks (room_id, user_id, session_id, at)
      VALUES (?, ?, ?, ?)";
/// The oldest asks. Bind: limit.
pub(super) const ASKS_DUE: &str = "SELECT room_id, user_id, session_id FROM bot_room_asks ORDER BY at, room_id, user_id LIMIT ?";
/// Bind: room, user.
pub(super) const ASK_DONE: &str = "DELETE FROM bot_room_asks WHERE room_id = ? AND user_id = ?";
/// Bind: room.
pub(super) const ASKS_DROP_ROOM: &str = "DELETE FROM bot_room_asks WHERE room_id = ?";

/// Bind: room, msg_uid, from, body, at.
pub(super) const CALL_PUT: &str =
    "INSERT OR IGNORE INTO bot_calls (room_id, msg_uid, from_user, body, at) VALUES (?, ?, ?, ?, ?)";
/// Bind: room, msg_uid.
pub(super) const CALL_GET: &str = "SELECT from_user, body FROM bot_calls WHERE room_id = ? AND msg_uid = ?";
/// Bind: cutoff.
pub(super) const CALLS_EXPIRE: &str = "DELETE FROM bot_calls WHERE at < ?";

#[derive(serde::Deserialize)]
struct SessionRow {
    session_id: String,
    pickle: String,
    created_at: i64,
    sent: i64,
}

#[derive(serde::Deserialize)]
struct ShareRow {
    user_id: String,
    device_id: String,
    key_b64: String,
}

impl<E: Exec> RoomStore for SqlBotStore<E> {
    fn room_session(&self, room_id: &str) -> Option<RoomSession> {
        let json = self.db.texts(SESSION_GET, &[Arg::T(room_id)]).into_iter().next()?;
        let r: SessionRow = serde_json::from_str(&json).ok()?;
        Some(RoomSession {
            session_id: r.session_id,
            pickle: r.pickle,
            created_at_ms: r.created_at,
            sent: u32::try_from(r.sent.max(0)).unwrap_or(u32::MAX),
        })
    }

    fn put_room_session(&mut self, room_id: &str, s: RoomSession) {
        self.db.run(
            SESSION_PUT,
            &[
                Arg::T(room_id),
                Arg::T(&s.session_id),
                Arg::T(&s.pickle),
                Arg::I(s.created_at_ms),
                Arg::I(i64::from(s.sent)),
            ],
        );
    }

    fn room_shares(&self, room_id: &str, session_id: &str) -> Vec<RoomShare> {
        self.db
            .texts(SHARES_GET, &[Arg::T(room_id), Arg::T(session_id)])
            .into_iter()
            .filter_map(|j| serde_json::from_str::<ShareRow>(&j).ok())
            .map(|r| RoomShare { user_id: r.user_id, device_id: r.device_id, key_b64: r.key_b64 })
            .collect()
    }

    fn put_room_share(&mut self, room_id: &str, session_id: &str, share: RoomShare) {
        self.db.run(
            SHARE_PUT,
            &[
                Arg::T(room_id),
                Arg::T(session_id),
                Arg::T(&share.user_id),
                Arg::T(&share.device_id),
                Arg::T(&share.key_b64),
            ],
        );
    }

    fn forget_room(&mut self, room_id: &str) {
        for q in FORGET {
            self.db.run(q, &[Arg::T(room_id)]);
        }
    }

    fn room_request_at(&self, room_id: &str, user_id: &str) -> Option<i64> {
        self.db.int(REQUEST_GET, &[Arg::T(room_id), Arg::T(user_id)])
    }

    fn set_room_request_at(&mut self, room_id: &str, user_id: &str, at_ms: i64) {
        self.db.run(REQUEST_PUT, &[Arg::T(room_id), Arg::T(user_id), Arg::I(at_ms)]);
    }
}

#[cfg(test)]
#[path = "room_store_tests.rs"]
mod tests;
