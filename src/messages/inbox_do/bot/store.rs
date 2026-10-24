//! The bot inbox's own tables, and the engine's `BotStore` over them (docs/BOTS_BUILD.md §2.3).
//!
//! Created lazily, only in bot mode, so a human's inbox pays nothing. The DO's SQLite is
//! synchronous, which is what lets the engine's trait be: a whole frame — decrypt, ratchet,
//! update row, ack — is written with no `await` in between and commits as one.
//!
//! Every statement is a `const` so `store_tests.rs` can run the same text on rusqlite. The DO's
//! SQL binds positional `?` only, in the order each const's doc gives.

use sezi_bot_engine::BotStore;
use wasm_bindgen::JsValue;
use worker::SqlStorage;

pub(super) const TABLES: [&str; 7] = [
    "CREATE TABLE IF NOT EXISTS bot_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    // slot 0 = the current session with that device, 1..=ARCHIVE_SLOTS = older ones, newest first.
    "CREATE TABLE IF NOT EXISTS bot_olm (
        user_id TEXT NOT NULL, device_id TEXT NOT NULL, slot INTEGER NOT NULL,
        pickle TEXT NOT NULL, updated_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, device_id, slot))",
    // What the program has not confirmed yet; kept 24 h (R9 decision 3). `json` has no
    // `update_id` — the row id is it, added when read.
    "CREATE TABLE IF NOT EXISTS bot_updates (
        update_id INTEGER PRIMARY KEY AUTOINCREMENT, json TEXT NOT NULL,
        created_at INTEGER NOT NULL, delivered_at INTEGER,
        attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER)",
    // Work the tick owes the network: `notify`, `forward_delivered`, `forward_failed` (Phase 1).
    "CREATE TABLE IF NOT EXISTS bot_outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, body TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, created_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_bot_outbox_next ON bot_outbox(next_at)",
    // What the bot sent, per device, so a `delivery_failed` can be answered with a resend.
    "CREATE TABLE IF NOT EXISTS bot_sent (
        msg_uid TEXT NOT NULL, user_id TEXT NOT NULL, device_id TEXT NOT NULL,
        pending_id INTEGER, payload_json TEXT NOT NULL, created_at INTEGER NOT NULL,
        failed INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (msg_uid, device_id))",
    // Which member texts the program has been handed, by (sender, msg_uid): a member's kernel
    // resends after a re-pair when its `delivered` came late, and the engine keeps no record of
    // what it read. Kept 7 days, beyond the updates' own 24 h, so a resend after the program
    // confirmed the first one is still recognised.
    "CREATE TABLE IF NOT EXISTS bot_seen (
        from_user TEXT NOT NULL, msg_uid TEXT NOT NULL, at INTEGER NOT NULL,
        PRIMARY KEY (from_user, msg_uid))",
];

/// Bind: from, msg_uid.
pub(super) const SEEN_GET: &str = "SELECT msg_uid FROM bot_seen WHERE from_user = ? AND msg_uid = ?";
/// Bind: from, msg_uid, at.
pub(super) const SEEN_PUT: &str =
    "INSERT OR IGNORE INTO bot_seen (from_user, msg_uid, at) VALUES (?, ?, ?)";
/// Bind: cutoff.
pub(super) const SEEN_EXPIRE: &str = "DELETE FROM bot_seen WHERE at < ?";

/// Older sessions kept per device behind the current one (INV-11: a failure retires the current
/// session into the archive, it never deletes it). The engine's `mem::ARCHIVE`.
pub(super) const ARCHIVE_SLOTS: usize = sezi_bot_engine::mem::ARCHIVE;

/// Bind: k.
pub(super) const KV_GET: &str = "SELECT v FROM bot_kv WHERE k = ?";
/// Bind: k, v.
pub(super) const KV_PUT: &str =
    "INSERT INTO bot_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v";

/// The current session: slot 0, which may be ABSENT while the archive is not (a retired one).
/// Bind: user, device.
pub(super) const CURRENT: &str =
    "SELECT pickle FROM bot_olm WHERE user_id = ? AND device_id = ? AND slot = 0";
/// The archive, newest first. Bind: user, device.
pub(super) const ARCHIVE: &str =
    "SELECT pickle FROM bot_olm WHERE user_id = ? AND device_id = ? AND slot > 0 ORDER BY slot";
/// A device's sessions are rewritten whole (at most four rows), so the slots are always 0 for
/// the current one and 1..=n for the archive, with no gaps. Bind: user, device.
pub(super) const CLEAR_DEVICE: &str = "DELETE FROM bot_olm WHERE user_id = ? AND device_id = ?";
/// Bind: user, device, slot, pickle.
pub(super) const INSERT_SLOT: &str = "INSERT INTO bot_olm (user_id, device_id, slot, pickle, updated_at)
      VALUES (?, ?, ?, ?, CAST(strftime('%s', 'now') AS INTEGER) * 1000)";
/// Bind: user.
pub(super) const WIPE_USER: &str = "DELETE FROM bot_olm WHERE user_id = ?";

/// One device's sessions, as the engine's `mem::Slots` models them.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Slots {
    pub(super) current: Option<String>,
    pub(super) archive: Vec<String>,
}

impl Slots {
    fn retire_current(&mut self) {
        if let Some(old) = self.current.take() {
            self.archive.insert(0, old);
            self.archive.truncate(ARCHIVE_SLOTS);
        }
    }
}

pub(super) fn repair_key(user_id: &str) -> String {
    format!("repair_at:{user_id}")
}

/// One bind value. The DO binds `JsValue`s, the tests rusqlite values; both come from this.
#[derive(Clone, Copy)]
pub(super) enum Arg<'a> {
    T(&'a str),
    I(i64),
}

/// The three things the store asks of a SQLite connection. The DO's `SqlStorage` is one; a
/// rusqlite connection is the other (`store_tests.rs`), so the tests run the real sequences.
pub(super) trait Exec {
    fn run(&self, query: &str, args: &[Arg<'_>]);
    fn texts(&self, query: &str, args: &[Arg<'_>]) -> Vec<String>;
    fn int(&self, query: &str, args: &[Arg<'_>]) -> Option<i64>;
}

/// The engine's state, in this inbox's SQLite.
///
/// The trait is infallible on purpose (the engine has no use for a storage error mid-frame), so a
/// failed statement is logged by the `Exec` and the frame goes on. A DO SQLite write fails only
/// when the object is out of storage, and then nothing the engine could do would help.
pub(super) struct SqlBotStore<E: Exec> {
    pub(super) db: E,
}

impl<E: Exec> SqlBotStore<E> {
    pub(super) fn kv_get(&self, k: &str) -> Option<String> {
        self.db.texts(KV_GET, &[Arg::T(k)]).into_iter().next()
    }

    pub(super) fn kv_put(&self, k: &str, v: &str) {
        self.db.run(KV_PUT, &[Arg::T(k), Arg::T(v)]);
    }

    /// True the first time (`from`, `msg_uid`) is seen, and remembers it; false for a repeat,
    /// which the host drops before it becomes a second update.
    pub(super) fn first_sight(&self, from: &str, msg_uid: &str, now_ms: i64) -> bool {
        if !self.db.texts(SEEN_GET, &[Arg::T(from), Arg::T(msg_uid)]).is_empty() {
            return false;
        }
        self.db.run(SEEN_PUT, &[Arg::T(from), Arg::T(msg_uid), Arg::I(now_ms)]);
        true
    }

    pub(super) fn slots(&self, user: &str, device: &str) -> Slots {
        let at = [Arg::T(user), Arg::T(device)];
        Slots {
            current: self.db.texts(CURRENT, &at).into_iter().next(),
            archive: self.db.texts(ARCHIVE, &at),
        }
    }

    /// Rewrite one device's sessions whole: the current at slot 0 (when there is one), the
    /// archive at 1..=n.
    fn write_slots(&self, user: &str, device: &str, slots: &Slots) {
        self.db.run(CLEAR_DEVICE, &[Arg::T(user), Arg::T(device)]);
        let rows = slots
            .current
            .iter()
            .map(|p| (0, p))
            .chain(slots.archive.iter().enumerate().map(|(i, p)| (i as i64 + 1, p)));
        for (slot, pickle) in rows {
            self.db.run(INSERT_SLOT, &[Arg::T(user), Arg::T(device), Arg::I(slot), Arg::T(pickle)]);
        }
    }
}

impl<E: Exec> BotStore for SqlBotStore<E> {
    fn account(&self) -> Option<String> {
        self.kv_get("account_pickle")
    }

    fn put_account(&mut self, pickle: String) {
        self.kv_put("account_pickle", &pickle);
    }

    fn sessions(&self, user_id: &str, device_id: &str) -> Vec<String> {
        let s = self.slots(user_id, device_id);
        s.current.into_iter().chain(s.archive).collect()
    }

    fn put_current_session(&mut self, user_id: &str, device_id: &str, pickle: String) {
        let mut s = self.slots(user_id, device_id);
        s.retire_current();
        s.current = Some(pickle);
        self.write_slots(user_id, device_id, &s);
    }

    /// `index` is into `sessions()`: 0 is the current one when there is one; otherwise the
    /// archive starts at 0 (the engine's `mem::MemStore` rule).
    fn promote(&mut self, user_id: &str, device_id: &str, index: usize, pickle: String) {
        let mut s = self.slots(user_id, device_id);
        let archived = if s.current.is_some() { index.checked_sub(1) } else { Some(index) };
        match archived {
            None => s.current = Some(pickle),
            Some(i) => {
                if i < s.archive.len() {
                    s.archive.remove(i);
                }
                s.retire_current();
                s.current = Some(pickle);
            }
        }
        self.write_slots(user_id, device_id, &s);
    }

    fn current_session(&self, user_id: &str, device_id: &str) -> Option<String> {
        self.db.texts(CURRENT, &[Arg::T(user_id), Arg::T(device_id)]).into_iter().next()
    }

    fn retire_current(&mut self, user_id: &str, device_id: &str) {
        let mut s = self.slots(user_id, device_id);
        if s.current.is_some() {
            s.retire_current();
            self.write_slots(user_id, device_id, &s);
        }
    }

    fn wipe_user(&mut self, user_id: &str) {
        self.db.run(WIPE_USER, &[Arg::T(user_id)]);
    }

    fn last_repair_at(&self, user_id: &str) -> Option<i64> {
        self.kv_get(&repair_key(user_id)).and_then(|v| v.parse().ok())
    }

    fn set_last_repair_at(&mut self, user_id: &str, at_ms: i64) {
        self.kv_put(&repair_key(user_id), &at_ms.to_string());
    }
}

/// The Durable Object's own SQLite.
pub(super) struct DoSql(pub(super) SqlStorage);

fn js_args(args: &[Arg<'_>]) -> Vec<JsValue> {
    args.iter()
        .map(|a| match a {
            Arg::T(s) => JsValue::from_str(s),
            Arg::I(n) => JsValue::from_f64(*n as f64),
        })
        .collect()
}

impl DoSql {
    /// Rows as JSON objects; the store's reads are all single-column.
    fn first_column(&self, query: &str, args: &[Arg<'_>]) -> Vec<serde_json::Value> {
        let rows: Vec<serde_json::Map<String, serde_json::Value>> = self
            .0
            .exec_raw(query, Some(js_args(args)))
            .ok()
            .and_then(|c| c.to_array().ok())
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| r.into_iter().next().map(|(_, v)| v))
            .collect()
    }
}

impl Exec for DoSql {
    fn run(&self, query: &str, args: &[Arg<'_>]) {
        if let Err(e) = self.0.exec_raw(query, Some(js_args(args))) {
            worker::console_log!("[bot] store write failed: {e:?}");
        }
    }

    fn texts(&self, query: &str, args: &[Arg<'_>]) -> Vec<String> {
        self.first_column(query, args)
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    }

    fn int(&self, query: &str, args: &[Arg<'_>]) -> Option<i64> {
        // A JS number may arrive as an f64 even when it holds an integer.
        let v = self.first_column(query, args).into_iter().next()?;
        v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
    }
}

/// The store over this DO's SQLite.
pub(super) fn do_store(sql: SqlStorage) -> SqlBotStore<DoSql> {
    SqlBotStore { db: DoSql(sql) }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

