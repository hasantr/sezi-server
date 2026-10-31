//! Each device's push key: what seals the frame a wake carries to it (`push::carry`).
//!
//! A device asks for its key over its own `/sync` socket (`push_key_get`, sent on every connect):
//! the socket is authenticated as that device, so the key reaches nobody else. The inbox mints one
//! the first time — 32 random bytes and a random id — keeps it in its own SQLite, one row per
//! device, and answers `{"type":"push_keys","keys":[{"id","key"}]}`. A key older than
//! [`ROTATE_AFTER_MS`] is replaced on the next ask; the phone keeps the one it had for a grace
//! (`sezi-store` `push_key_store`), so a push sealed before the rotation and delivered late still
//! opens. The relay seals only under the current key, and only for a device that has asked: a
//! client that predates this never asks and is woken content-free, as before. A purged inbox
//! (`delete_all`) takes the table with it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use super::UserInbox;
use crate::push::carry::PushKey;

pub(super) const PUSH_KEYS_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS push_keys (
    device_id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    key_b64 TEXT NOT NULL,
    created_ms INTEGER NOT NULL
)";
pub(crate) const READ_SQL: &str =
    "SELECT key_id, key_b64, created_ms FROM push_keys WHERE device_id = ?1";
pub(crate) const PUT_SQL: &str = "INSERT INTO push_keys (device_id, key_id, key_b64, created_ms)
     VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(device_id) DO UPDATE SET
       key_id = excluded.key_id, key_b64 = excluded.key_b64, created_ms = excluded.created_ms";

/// How long one key seals a device's pushes before the next ask replaces it.
pub(crate) const ROTATE_AFTER_MS: i64 = 7 * 24 * 3600 * 1000;

/// Is a key minted at `created_ms` due for replacement? A clock that went backwards replaces it
/// too: a key must never outlive its window, whatever the clock does.
pub(crate) fn rotation_due(created_ms: i64, now_ms: i64) -> bool {
    !(0..ROTATE_AFTER_MS).contains(&(now_ms - created_ms))
}

#[derive(Deserialize)]
struct KeyRow {
    key_id: String,
    key_b64: String,
    created_ms: i64,
}

fn decode(row: &KeyRow) -> Option<PushKey> {
    let key: [u8; 32] = STANDARD.decode(&row.key_b64).ok()?.try_into().ok()?;
    Some(PushKey { id: row.key_id.clone(), key })
}

/// A fresh key: 32 random bytes, and a random 8-byte id in hex.
fn mint() -> Option<PushKey> {
    let mut key = [0u8; 32];
    let mut id = [0u8; 8];
    getrandom::getrandom(&mut key).ok()?;
    getrandom::getrandom(&mut id).ok()?;
    Some(PushKey { id: hex::encode(id), key })
}

impl UserInbox {
    fn push_key_row(&self, device: &str) -> Option<KeyRow> {
        self.state
            .storage()
            .sql()
            .exec_raw(READ_SQL, Some(vec![JsValue::from_str(device)]))
            .ok()
            .and_then(|c| c.to_array::<KeyRow>().ok())
            .and_then(|rows| rows.into_iter().next())
    }

    /// The key this device's pushes are sealed under, if it has ever asked for one. Synchronous:
    /// the inbox's own SQLite.
    pub(crate) fn push_key(&self, device: &str) -> Option<PushKey> {
        self.push_key_row(device).as_ref().and_then(decode)
    }

    /// `push_key_get` from a socket: its device's current key — minted on the first ask, replaced
    /// once due — sent back on that socket alone. A socket whose device is unknown gets nothing.
    pub(super) fn answer_push_key_get(&self, ws: &WebSocket) {
        let Some(device) = super::message::ws_attachment_device(ws) else {
            return;
        };
        let now = crate::utils::now_ms() as i64;
        let current = self
            .push_key_row(&device)
            .filter(|r| !rotation_due(r.created_ms, now))
            .as_ref()
            .and_then(decode);
        let key = match current {
            Some(k) => k,
            None => {
                let Some(k) = mint() else { return };
                let args = vec![
                    JsValue::from_str(&device),
                    JsValue::from_str(&k.id),
                    JsValue::from_str(&STANDARD.encode(k.key)),
                    JsValue::from_f64(now as f64),
                ];
                if self.state.storage().sql().exec_raw(PUT_SQL, Some(args)).is_err() {
                    return; // unwritten: nothing is sealed under it, so it is not handed out
                }
                k
            }
        };
        let frame = serde_json::json!({
            "type": "push_keys",
            "keys": [{ "id": key.id, "key": STANDARD.encode(key.key) }],
        });
        let _ = ws.send_with_str(frame.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    #[test]
    fn a_key_is_replaced_after_its_window_and_on_a_clock_gone_back() {
        assert!(!rotation_due(1_000, 1_000));
        assert!(!rotation_due(1_000, 1_000 + ROTATE_AFTER_MS - 1));
        assert!(rotation_due(1_000, 1_000 + ROTATE_AFTER_MS));
        assert!(rotation_due(1_000, 999), "a clock gone backwards replaces it");
    }

    /// The SQL as the inbox runs it, against SQLite: one row per device, the rotation overwrites.
    #[test]
    fn one_key_per_device_and_a_rotation_replaces_it() {
        let c = Connection::open_in_memory().unwrap();
        c.execute(PUSH_KEYS_TABLE_SQL, []).unwrap();
        c.execute(PUT_SQL, params!["d1", "k1", "a2V5MQ==", 1]).unwrap();
        c.execute(PUT_SQL, params!["d2", "k2", "a2V5Mg==", 1]).unwrap();
        c.execute(PUT_SQL, params!["d1", "k3", "a2V5Mw==", 9]).unwrap();
        let read = |d: &str| -> (String, i64) {
            c.query_row(READ_SQL, [d], |r| Ok((r.get(0)?, r.get(2)?))).unwrap()
        };
        assert_eq!(read("d1"), ("k3".to_string(), 9));
        assert_eq!(read("d2"), ("k2".to_string(), 1));
    }

    #[test]
    fn a_stored_key_decodes_and_a_damaged_one_does_not() {
        let row = |b64: &str| KeyRow { key_id: "k".into(), key_b64: b64.into(), created_ms: 0 };
        assert_eq!(decode(&row(&STANDARD.encode([5u8; 32]))).unwrap().key, [5u8; 32]);
        assert!(decode(&row("c2hvcnQ=")).is_none(), "a key of the wrong length");
        assert!(decode(&row("not base64!")).is_none());
    }
}
