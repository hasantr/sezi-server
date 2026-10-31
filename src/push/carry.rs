//! The envelope a wake carries (2026-10-30, `docs/PUSH_CARRIED_ENVELOPE.md`).
//!
//! A content-free wake makes the phone start, take its writer lease, connect `/sync` and fetch —
//! seconds of work that Honor's and Xiaomi's battery managers cut short in the field, leaving a
//! generic "New message" behind. So a wake now carries the frame it is for, when that frame fits:
//! the SAME `msg` frame `/sync` would deliver (`inbox_do::message::pending_frame` — row id,
//! sender, sender device, the end-to-end encrypted envelope, group, the relay's timestamp), plus
//! `rd`, the device it was stored for, and — for a 1:1 frame — `older`: how many older rows from
//! the same sender device still wait for that device (`inbox_do/message.rs`). The phone reads a
//! 1:1 frame from the push only when that is 0: read ahead of its queue, it would make Olm keep
//! skipped keys for the frames behind, and past vodozemac's 40 per chain the oldest would no longer
//! decrypt when `/sync` brings them — ack false, `delivery_failed`, a re-pair.
//!
//! **Sealed to the device, by its own server.** Nothing in a push is authenticated by FCM, and the
//! shared push relay serves every server — any of which holds the phone's token. A frame the phone
//! believed on its word could plant a row under a relay id still to come (and so drop the genuine
//! message that id later names), pose as an unpinned sender, or move a timestamp. So the frame
//! travels SEALED: XChaCha20-Poly1305 under a random key this inbox minted for the device and
//! handed to it over its authenticated `/sync` socket (`inbox_do/push_keys.rs`), with the device
//! id as associated data. The phone reads only what opens under a key its own server gave it
//! (`kernel/carried.rs`). Google sees `v1.<key id>.<blob>` and its size — not the row id, the
//! sender or the recipient.
//!
//! **What carries nothing** — and wakes exactly as before: a device that never fetched a key (an
//! older client); a frame whose sealed form is over [`MAX_CARRIED_FRAME_BYTES`]; a device-blind row
//! (no device to name); a visible wake (the OS draws it without starting the app, so a payload
//! would reach nobody — `style.rs`); the backstop alarm's wake (it covers several rows, and the
//! drain fetches them all); a takeover nudge. A coalesced wake is not sent at all.
//!
//! **The gate.** A carrying wake passes the coalescing gate (`coalesce.rs`) and marks it like any
//! other. The phone still runs its drain after reading the carried frame, and that drain's
//! connection is what clears the mark; an unmarked carrying wake would instead send one push per
//! envelope of a burst — the storm the gate exists to stop, and a hit on the shared relay's limit
//! of six a minute per token. The frames a coalesced wake would have carried are fetched by that
//! drain, as they always were.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::Value;

/// The key the frame travels under in the FCM `data` map (`fcm_service.dart` reads it).
pub(crate) const DATA_KEY: &str = "msg";

/// The largest SEALED frame a wake carries. FCM refuses a `data` payload over 4096 bytes, keys
/// and values counted; `type`/`wake` and this key take 11 of them, and the rest is margin for what
/// Google counts that we cannot see. The core's mock relay keeps the same number
/// (`testkit/mock_fcm.rs`, `CARRIED_FRAME_MAX`).
pub(crate) const MAX_CARRIED_FRAME_BYTES: usize = 3_584;

/// The sealed form's version prefix.
const SEALED_V1: &str = "v1";

/// One device's push key, as this inbox keeps it (`inbox_do/push_keys.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushKey {
    /// Random, names the key on the wire so the phone knows which of its keys opens a push.
    pub(crate) id: String,
    pub(crate) key: [u8; 32],
}

/// The frames one wake may carry, per device: each device's own row, never another's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Carried(Vec<(String, String)>);

impl Carried {
    /// Nothing to carry: the wake every server sent before.
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// Carry `frame` (a stored row's `msg` frame) to `device`, sealed under its `key`. Answers
    /// whether it was taken: not without a key (the device never fetched one), nor when its sealed
    /// form does not fit.
    pub(crate) fn add(&mut self, device: &str, frame: &Value, key: Option<&PushKey>) -> bool {
        let Some(key) = key else { return false };
        let mut nonce = [0u8; 24];
        if getrandom::getrandom(&mut nonce).is_err() {
            return false;
        }
        match frame_for(frame, device, key, &nonce) {
            Some(f) => {
                self.0.retain(|(d, _)| d != device);
                self.0.push((device.to_string(), f));
                true
            }
            None => false,
        }
    }

    /// The sealed frame for this device's token, if any.
    pub(crate) fn for_device(&self, device: &str) -> Option<&str> {
        self.0.iter().find(|(d, _)| d == device).map(|(_, f)| f.as_str())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

/// The carried copy of a stored row's `msg` frame, sealed: the frame as `/sync` sends it, null
/// fields left out, plus `rd`, under [`seal`]. None when the sealed form does not fit.
pub(crate) fn frame_for(frame: &Value, device: &str, key: &PushKey, nonce: &[u8; 24]) -> Option<String> {
    let mut out = serde_json::Map::new();
    for (k, v) in frame.as_object()? {
        if !v.is_null() {
            out.insert(k.clone(), v.clone());
        }
    }
    out.insert("rd".into(), Value::String(device.to_string()));
    let sealed = seal(key, device, nonce, Value::Object(out).to_string().as_bytes())?;
    (sealed.len() <= MAX_CARRIED_FRAME_BYTES).then_some(sealed)
}

/// `v1.<key id>.<base64url(nonce ‖ XChaCha20-Poly1305(key, plaintext, aad = device))>` — the one
/// sealed form, opened by the core's `kernel/carried.rs` (`open_frame`); `carry_tests.rs` and the
/// core's `carried_tests.rs` hold the same test vector.
pub(crate) fn seal(key: &PushKey, device: &str, nonce: &[u8; 24], plaintext: &[u8]) -> Option<String> {
    let cipher = XChaCha20Poly1305::new((&key.key).into());
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad: device.as_bytes() })
        .ok()?;
    let mut blob = Vec::with_capacity(nonce.len() + ct.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    Some(format!("{SEALED_V1}.{}.{}", key.id, URL_SAFE_NO_PAD.encode(blob)))
}

#[cfg(test)]
#[path = "carry_tests.rs"]
mod tests;
