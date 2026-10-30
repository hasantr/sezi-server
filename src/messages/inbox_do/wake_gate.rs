//! The wake coalescing gate's state (`push::coalesce`), in this inbox's own SQLite.
//!
//! The inbox is where both halves of the rule are seen: every wake to its owner's devices is sent
//! from here (`/notify` below, `/notify-member`, the backstop alarm), and every connection of
//! those devices is accepted here (`ws_upgrade` → [`UserInbox::note_device_seen`]) — `/sync` is
//! the only way a device fetches `pending`. One row per device (plus `coalesce::BLIND_KEY`), so
//! the table is as small as the device list; `delete_all` on a purge takes it with the rest. No
//! subrequest is spent on any of it, and a lost table (a fresh object) only means a wake that
//! would have been coalesced is sent.

use super::{UserInbox, RECIPIENT_UID_KEY};
use crate::push::coalesce::{WakeAsk, WakeMark, WakeMarks, BLIND_KEY};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

pub(super) const WAKE_GATE_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS wake_gate (
    device_id TEXT PRIMARY KEY,
    woke_for_ms INTEGER,
    seen_ms INTEGER
)";
pub(crate) const READ_SQL: &str = "SELECT woke_for_ms, seen_ms FROM wake_gate WHERE device_id = ?1";
/// Written after a push went out. Never backwards: of two wakes finishing out of order, the
/// later moment stands.
pub(crate) const MARK_SQL: &str = "INSERT INTO wake_gate (device_id, woke_for_ms) VALUES (?1, ?2)
     ON CONFLICT(device_id) DO UPDATE SET
       woke_for_ms = MAX(COALESCE(wake_gate.woke_for_ms, excluded.woke_for_ms), excluded.woke_for_ms)";
pub(crate) const SEEN_SQL: &str = "INSERT INTO wake_gate (device_id, seen_ms) VALUES (?1, ?2)
     ON CONFLICT(device_id) DO UPDATE SET seen_ms = excluded.seen_ms";
/// A socket whose device is unknown is a target for every device's rows (`ws_targets_device`),
/// so it counts as seen for all of them.
pub(crate) const SEEN_ALL_SQL: &str = "UPDATE wake_gate SET seen_ms = ?1";

/// The marks over this inbox's storage. Owned, so a wake sent after the answer
/// (`State::wait_until`) can carry it.
pub(crate) struct DoWakeMarks {
    storage: Storage,
}

impl DoWakeMarks {
    pub(crate) fn new(storage: Storage) -> Self {
        Self { storage }
    }

    fn exec(&self, sql: &str, args: Vec<JsValue>) {
        // Best effort: a failed write only means one wake more, never one less — an unwritten
        // mark coalesces nothing.
        let _ = self.storage.sql().exec_raw(sql, Some(args));
    }
}

#[derive(Deserialize)]
struct MarkRow {
    #[serde(default)]
    woke_for_ms: Option<i64>,
    #[serde(default)]
    seen_ms: Option<i64>,
}

impl WakeMarks for DoWakeMarks {
    fn read(&self, keys: &[String]) -> Vec<WakeMark> {
        keys.iter()
            .map(|k| {
                self.storage
                    .sql()
                    .exec_raw(READ_SQL, Some(vec![JsValue::from_str(k)]))
                    .ok()
                    .and_then(|c| c.to_array::<MarkRow>().ok())
                    .and_then(|rows| rows.into_iter().next())
                    .map(|r| WakeMark { woke_for_ms: r.woke_for_ms, seen_ms: r.seen_ms })
                    .unwrap_or_default()
            })
            .collect()
    }

    fn mark(&self, keys: &[String], covers_ms: i64) {
        for k in keys {
            self.exec(MARK_SQL, vec![JsValue::from_str(k), JsValue::from_f64(covers_ms as f64)]);
        }
    }
}

impl UserInbox {
    pub(crate) fn wake_marks(&self) -> DoWakeMarks {
        DoWakeMarks::new(self.state.storage())
    }

    /// A device connected: whatever wake it had outstanding has been fetched, so the next envelope
    /// wakes it again at once (`coalesce::gate`). Its own key and the blind key; every key when
    /// the socket's device is unknown. Synchronous, and called right after the socket is
    /// accepted, before its queue is flushed.
    pub(super) fn note_device_seen(&self, device: Option<&str>, now_ms: i64) {
        let marks = self.wake_marks();
        let at = JsValue::from_f64(now_ms as f64);
        match device {
            Some(d) => marks.exec(SEEN_SQL, vec![JsValue::from_str(d), at.clone()]),
            None => marks.exec(SEEN_ALL_SQL, vec![at.clone()]),
        }
        marks.exec(SEEN_SQL, vec![JsValue::from_str(BLIND_KEY), at]);
    }

    /// `/notify`'s wake for an envelope no socket took. Sent from here, after the answer and out
    /// of this invocation's own budget, like `/notify-member`'s — so the sender's request no
    /// longer pays for it, and every wake goes through this inbox's gate. `ask.covers_ms` was
    /// taken before the envelope was stored.
    pub(super) fn wake_after_notify(
        &self,
        recipient_id: Option<String>,
        device: Option<String>,
        ask: WakeAsk,
    ) {
        let env = self.env.clone();
        let storage = self.state.storage();
        self.state.wait_until(async move {
            let user = match recipient_id {
                Some(u) => Some(u),
                None => storage.get::<String>(RECIPIENT_UID_KEY).await.ok().flatten(),
            };
            let Some(user) = user else {
                return; // an older body, and the owner not known yet: nobody to wake
            };
            let Ok(db) = env.d1("DB") else { return };
            let marks = DoWakeMarks::new(storage);
            crate::push::wake::maybe_push_wake(&env, &db, &marks, &user, device.as_deref(), ask)
                .await;
        });
    }
}

#[cfg(test)]
#[path = "wake_gate_tests.rs"]
mod tests;
