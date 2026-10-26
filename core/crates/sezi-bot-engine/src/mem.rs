//! An in-memory [`BotStore`] for tests and the wire scenarios.

use std::collections::HashMap;

use crate::store::{RoomSession, RoomShare, RoomStore};
use crate::BotStore;

/// How many sessions per device are kept behind the current one.
pub const ARCHIVE: usize = 3;

/// The sessions with one device: at most one current, then the archive, newest first.
#[derive(Debug, Default, Clone)]
pub struct Slots {
    pub current: Option<String>,
    pub archive: Vec<String>,
}

impl Slots {
    fn ordered(&self) -> Vec<String> {
        self.current.iter().chain(self.archive.iter()).cloned().collect()
    }

    fn shift_current_to_archive(&mut self) {
        if let Some(old) = self.current.take() {
            self.archive.insert(0, old);
            self.archive.truncate(ARCHIVE);
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemStore {
    pub account: Option<String>,
    /// (user, device) → that device's session slots.
    pub sessions: HashMap<(String, String), Slots>,
    pub repairs: HashMap<String, i64>,
    /// room → the bot's outbound Megolm session there.
    pub rooms: HashMap<String, RoomSession>,
    /// (room, session id) → the devices it was shared with.
    pub room_shares: HashMap<(String, String), Vec<RoomShare>>,
    /// (room, user) → when their last `RoomKeyRequest` was answered.
    pub room_requests: HashMap<(String, String), i64>,
}

impl RoomStore for MemStore {
    fn room_session(&self, room_id: &str) -> Option<RoomSession> {
        self.rooms.get(room_id).cloned()
    }

    fn put_room_session(&mut self, room_id: &str, session: RoomSession) {
        self.rooms.insert(room_id.to_owned(), session);
    }

    fn room_shares(&self, room_id: &str, session_id: &str) -> Vec<RoomShare> {
        self.room_shares.get(&key(room_id, session_id)).cloned().unwrap_or_default()
    }

    fn put_room_share(&mut self, room_id: &str, session_id: &str, share: RoomShare) {
        let shares = self.room_shares.entry(key(room_id, session_id)).or_default();
        shares.retain(|s| !(s.user_id == share.user_id && s.device_id == share.device_id));
        shares.push(share);
    }

    fn forget_room(&mut self, room_id: &str) {
        self.rooms.remove(room_id);
        self.room_shares.retain(|(r, _), _| r != room_id);
        self.room_requests.retain(|(r, _), _| r != room_id);
    }

    fn room_request_at(&self, room_id: &str, user_id: &str) -> Option<i64> {
        self.room_requests.get(&key(room_id, user_id)).copied()
    }

    fn set_room_request_at(&mut self, room_id: &str, user_id: &str, at_ms: i64) {
        self.room_requests.insert(key(room_id, user_id), at_ms);
    }
}

fn key(user_id: &str, device_id: &str) -> (String, String) {
    (user_id.to_owned(), device_id.to_owned())
}

impl BotStore for MemStore {
    fn account(&self) -> Option<String> {
        self.account.clone()
    }

    fn put_account(&mut self, pickle: String) {
        self.account = Some(pickle);
    }

    fn sessions(&self, user_id: &str, device_id: &str) -> Vec<String> {
        self.sessions.get(&key(user_id, device_id)).map(Slots::ordered).unwrap_or_default()
    }

    fn put_current_session(&mut self, user_id: &str, device_id: &str, pickle: String) {
        let slots = self.sessions.entry(key(user_id, device_id)).or_default();
        slots.shift_current_to_archive();
        slots.current = Some(pickle);
    }

    fn promote(&mut self, user_id: &str, device_id: &str, index: usize, pickle: String) {
        let slots = self.sessions.entry(key(user_id, device_id)).or_default();
        let archived = if slots.current.is_some() { index.checked_sub(1) } else { Some(index) };
        match archived {
            // The current one advanced: replace it in place.
            None => slots.current = Some(pickle),
            Some(i) => {
                if i < slots.archive.len() {
                    slots.archive.remove(i);
                }
                slots.shift_current_to_archive();
                slots.current = Some(pickle);
            }
        }
    }

    fn wipe_user(&mut self, user_id: &str) {
        self.sessions.retain(|(u, _), _| u != user_id);
    }

    fn last_repair_at(&self, user_id: &str) -> Option<i64> {
        self.repairs.get(user_id).copied()
    }

    fn set_last_repair_at(&mut self, user_id: &str, at_ms: i64) {
        self.repairs.insert(user_id.to_owned(), at_ms);
    }

    fn current_session(&self, user_id: &str, device_id: &str) -> Option<String> {
        self.sessions.get(&key(user_id, device_id)).and_then(|s| s.current.clone())
    }

    fn retire_current(&mut self, user_id: &str, device_id: &str) {
        if let Some(slots) = self.sessions.get_mut(&key(user_id, device_id)) {
            slots.shift_current_to_archive();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(s: &MemStore) -> (Option<String>, Vec<String>) {
        (s.current_session("u", "d"), s.sessions("u", "d"))
    }

    #[test]
    fn the_archive_keeps_three_behind_the_current() {
        let mut s = MemStore::default();
        for p in ["a", "b", "c", "d", "e"] {
            s.put_current_session("u", "d", p.into());
        }
        assert_eq!(order(&s), (Some("e".into()), vec!["e".into(), "d".into(), "c".into(), "b".into()]));
    }

    #[test]
    fn promoting_an_archived_session_shifts_the_current_one_back() {
        let mut s = MemStore::default();
        s.put_current_session("u", "d", "old".into());
        s.put_current_session("u", "d", "new".into());
        s.promote("u", "d", 1, "old+1".into());
        assert_eq!(order(&s), (Some("old+1".into()), vec!["old+1".into(), "new".into()]));
        s.promote("u", "d", 0, "old+2".into());
        assert_eq!(order(&s), (Some("old+2".into()), vec!["old+2".into(), "new".into()]));
    }

    #[test]
    fn a_retired_session_is_listed_but_not_current_until_promoted() {
        let mut s = MemStore::default();
        s.put_current_session("u", "d", "s".into());
        s.retire_current("u", "d");
        assert_eq!(order(&s), (None, vec!["s".into()]));
        s.promote("u", "d", 0, "s+1".into());
        assert_eq!(order(&s), (Some("s+1".into()), vec!["s+1".into()]));
    }
}
