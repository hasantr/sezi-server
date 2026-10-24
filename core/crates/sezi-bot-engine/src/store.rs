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
