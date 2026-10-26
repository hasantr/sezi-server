//! The bot's state as the engine sees it: one trait the host implements, and the few helpers the
//! engine builds on it (load the account, read the current session).
//!
//! The trait is synchronous on purpose. The relay's host is a Durable Object whose SQLite is
//! synchronous, and everything one inbound frame changes — the ratchet, the account, the update,
//! the ack — has to land in one block with no `await` in it, so that it commits as one.

use sezi_crypto::messaging::unpickle_session;
use sezi_error::{Error, Result};
use vodozemac::olm::{Account, AccountPickle, Session};

/// The bot's state, owned by the host. Synchronous on purpose: the Durable Object's SQLite is.
///
/// Sessions are kept per (user, device) in slots: at most one CURRENT session, and an archive of
/// up to three behind it. The current one is what a send uses; the archive exists because a
/// displaced session may still be the only one able to read a frame already in flight (INV-11),
/// so a failure retires the current session into the archive instead of deleting it.
pub trait BotStore {
    /// The account pickle, encrypted with the pickle key.
    fn account(&self) -> Option<String>;
    fn put_account(&mut self, pickle: String);
    /// Every pickled session with this device, the current one first (when there is one), then
    /// the archive, newest first. This is the order a decrypt tries them in, and the index
    /// [`BotStore::promote`] takes.
    fn sessions(&self, user_id: &str, device_id: &str) -> Vec<String>;
    /// Make `pickle` the current session; the old current moves to the archive (cap 3).
    fn put_current_session(&mut self, user_id: &str, device_id: &str, pickle: String);
    /// `sessions()[index]` decrypted (or encrypted) and advanced: replace it with `pickle` and make
    /// it current. When it was archived, the session that was current moves to the archive.
    fn promote(&mut self, user_id: &str, device_id: &str, index: usize, pickle: String);
    /// Forget every session (current and archived) with every device of this user.
    fn wipe_user(&mut self, user_id: &str);
    fn last_repair_at(&self, user_id: &str) -> Option<i64>;
    fn set_last_repair_at(&mut self, user_id: &str, at_ms: i64);
    /// The current session with this device, if one is current. `None` after
    /// [`BotStore::retire_current`] even while the archive still holds sessions.
    fn current_session(&self, user_id: &str, device_id: &str) -> Option<String>;
    /// INV-11: move the current session to the archive and leave none current, so the next send
    /// to this device opens a fresh session while a frame still in flight on the old one can be
    /// read. A no-op when nothing is current.
    fn retire_current(&mut self, user_id: &str, device_id: &str);
}

/// The bot's Olm account, unpickled. Only the paths that need it call this: creating the identity,
/// topping up keys, a PreKey that no stored session reads, and a send that opens a session.
pub(crate) fn load_account(store: &impl BotStore, pickle_key: &[u8; 32]) -> Result<Account> {
    let blob = store.account().ok_or_else(|| Error::Crypto("bot/no-account".into()))?;
    let pickle = AccountPickle::from_encrypted(&blob, pickle_key)
        .map_err(|e| Error::Crypto(format!("bot/account-unreadable: {e}")))?;
    Ok(Account::from(pickle))
}

/// The current session with this device, unpickled. `Ok(None)` when none is current.
pub(crate) fn current(
    store: &impl BotStore,
    pickle_key: &[u8; 32],
    user_id: &str,
    device_id: &str,
) -> Result<Option<Session>> {
    match store.current_session(user_id, device_id) {
        Some(blob) => unpickle_session(&blob, pickle_key)
            .map(Some)
            .map_err(|e| Error::Crypto(format!("bot/session-unreadable: {e}"))),
        None => Ok(None),
    }
}

/// The bot's own outbound Megolm session in one room (Phase 3, `room.rs`), pickled with the pickle
/// key. `sent` counts the messages encrypted on it, for rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSession {
    pub session_id: String,
    pub pickle: String,
    pub created_at_ms: i64,
    pub sent: u32,
}

/// One member device the current session was shared with, and the key it was given: a SNAPSHOT
/// exported at that first share, so a re-share (the member's `RoomKeyRequest`) opens exactly what
/// the first one did — never an earlier message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomShare {
    pub user_id: String,
    pub device_id: String,
    pub key_b64: String,
}

/// What the room half of the engine keeps beside the 1:1 state. A trait of its own, so a host that
/// runs 1:1 only is not made to implement it. Synchronous, like [`BotStore`].
///
/// There is deliberately no method that stores a key somebody ELSE shared: a bot never imports a
/// room key, so it cannot read a room message it was not sent.
pub trait RoomStore: BotStore {
    fn room_session(&self, room_id: &str) -> Option<RoomSession>;
    fn put_room_session(&mut self, room_id: &str, session: RoomSession);
    /// The shares of session `session_id` in this room.
    fn room_shares(&self, room_id: &str, session_id: &str) -> Vec<RoomShare>;
    fn put_room_share(&mut self, room_id: &str, session_id: &str, share: RoomShare);
    /// Forget the room: its session, every share of it, every request mark.
    fn forget_room(&mut self, room_id: &str);
    /// When `user_id` last had a `RoomKeyRequest` answered in this room.
    fn room_request_at(&self, room_id: &str, user_id: &str) -> Option<i64>;
    fn set_room_request_at(&mut self, room_id: &str, user_id: &str, at_ms: i64);
}
