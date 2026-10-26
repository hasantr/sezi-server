//! A bot account's end of the encryption (docs/BOTS_BUILD.md §2.4).
//!
//! Pure and synchronous: the host passes the clock in and owns every byte of storage through
//! [`BotStore`]. The relay runs it inside the bot's own `UserInbox` Durable Object; the wire
//! scenarios run it against the mock relay with [`mem::MemStore`]. Nothing here may grow an
//! `async fn`, a socket or a `SystemTime` — that is what keeps both hosts possible.
//!
//! The rule it exists to keep: a bot reads only what is addressed to it. It never holds a human's
//! room key (no API here accepts one), and it writes to a room only with its own Megolm session.
//!
//! Where things are: `identity.rs` (made once, keys topped up), `inbound.rs` (reading a frame),
//! `classify.rs` (what it means to a program), `heal.rs` (who re-pairs, and when), `direct.rs`
//! (sealing a frame to a member's devices), `room.rs` (the bot's own Megolm session per room:
//! share, rotate, post, answer a key request), `store.rs` (the host's storage traits), `mem.rs` (a
//! HashMap store for tests).
//!
//! ## Phase 3 (rooms, 2026-10-26) — for the relay track
//!
//! [`RoomStore`] (a supertrait of [`BotStore`]) holds the room state; a 1:1-only host needs none of
//! it. [`Inbound::RoomKeyRequest`] gained `session_id`, and a `BotCall` now classifies as
//! [`Inbound::Call`]. Anything carrying a room secret that reaches the bot is
//! `Inbound::Ignored("room_secret")`: acked, never imported.
//!
//! ## CONTRACT CHANGES (engine track, 2026-10-23) — for the relay track
//!
//! The skeleton's names and signatures all stand. What the relay must adapt to:
//!
//! 1. **`BotStore` has two more required methods**, `current_session(user, device)` and
//!    `retire_current(user, device)`. A failure retires the current session into the archive
//!    instead of deleting it (INV-11), so "the archive holds sessions but none is current" is a
//!    state the store must be able to say: in the DO's `bot_olm`, slot 0 absent while 1..3 exist.
//!    `sessions()` then lists the archive alone, and `promote(index)` indexes into that list.
//!    The trait now lives in `store.rs`; `sezi_bot_engine::BotStore` is unchanged as a path.
//! 2. **`on_envelope` answers a PreKey pair-ack itself**: its effects carry the Normal pair-ack
//!    back as an `Effect::Deliver` (`msg_uid: None`) before `Update(Inbound::PairAck)`. On
//!    `PairAck` the host only resends that user's failed `bot_sent` rows — it must NOT call
//!    `send_pair_ack` too, which would be a second frame for one handshake.
//! 3. **Additions:** `signed_device_list` (re-sign the one-device list under a user id),
//!    `text_payload(body, msg_uid)`, the constants `PAIR_ACK_MARKER` and `REPAIR_WINDOW_MS`.
//! 4. **`mem::MemStore::sessions` is now `HashMap<(user, device), mem::Slots>`** (current +
//!    archive) rather than a `Vec` per device.
//! 5. **`expected_x_pub: None` refuses a new session** (ack `false`, no repair): a PreKey from a
//!    device the relay has no `x_pub` for opens nothing. A PreKey an existing session reads needs
//!    no lookup.
//!
//! Host rules the signatures cannot say: apply the effects of one call in ONE synchronous block
//! with the store writes (the ack deletes the pending row, so the same frame is never read twice —
//! a replayed frame fails its decrypt and would retire a healthy session); after
//! `Effect::Repair`, claim keys for `devices_without_session`, call `send_pair_ack`, then resend
//! the user's failed `bot_sent` rows; and drop an `Inbound::Text` whose (`from`, `msg_uid`) is
//! already in `bot_updates`. A member's kernel resends a message after a re-pair whenever its
//! `delivered` was not credited in time, so the same text can reach the bot twice (seen in the
//! wire scenarios under load); a kernel recipient dedups that by `msg_uid`, and the engine keeps
//! no record of what it has read.

mod classify;
mod direct;
mod heal;
mod identity;
mod inbound;
pub mod mem;
mod room;
mod store;
#[cfg(test)]
mod testutil;

pub use classify::{PAIR_ACK_MARKER, SYSTEM_MARKER_PREFIX};
pub use direct::text_payload;
pub use heal::REPAIR_WINDOW_MS;
pub use identity::{DEVICE_LABEL, SPK_PREKEY_ID};
pub use room::{
    room_encrypt, room_forget, room_key_request, room_key_request_due, room_prepare, room_share, room_text_payload, RoomPrep,
    Rotation, ROOM_REQUEST_WINDOW_MS, ROTATE_AFTER_MESSAGES, ROTATE_AFTER_MS,
};
pub use store::{BotStore, RoomSession, RoomShare, RoomStore};

use sezi_error::Result;
use sezi_protocol::inner::ChatPayload;

/// One device of a user, as the relay's `devices` table and signed list give it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeys {
    pub user_id: String,
    pub device_id: String,
    pub x_pub_b64: String,
    pub ed_pub_b64: String,
}

/// A one-time key (or the signed fallback) claimed from a device's bundle slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedKey {
    pub device_id: String,
    pub key_b64: String,
}

/// An inbound frame as the relay stored it for the bot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub remote_id: i64,
    pub sender_id: String,
    pub sender_device_id: String,
    pub envelope_b64: String,
    pub group_id: Option<String>,
}

/// What the host must do after the engine has run. Applied in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Acknowledge a stored frame (`ack_rows`): success → `delivered` to the sender, else
    /// `delivery_failed`.
    Ack { remote_id: i64, success: bool, uid: Option<String> },
    /// Seal-and-deliver one Olm envelope to one device of a user.
    Deliver { user_id: String, device_id: String, envelope_b64: String, msg_uid: Option<String> },
    /// One Megolm envelope into a room the bot belongs to (Phase 3).
    DeliverRoom { room_id: String, envelope_b64: String },
    /// Claim keys for this user's devices and call [`send_pair_ack`].
    Repair { user_id: String },
    /// Hand this to the bot's program (the host adds `who`).
    Update(Inbound),
}

/// An inbound frame, classified. The host fills in who sent it from its own tables.
#[derive(Debug, Clone, PartialEq)]
pub enum Inbound {
    Text { from: String, device: String, msg_uid: Option<String>, body: String, ext: serde_json::Value },
    /// A pair-ack opened a fresh session: the host resends this user's failed `bot_sent` rows.
    PairAck { from: String },
    /// A group message that called the bot, copied to it 1:1 (Phase 3).
    Call {
        from: String,
        room_id: String,
        msg_uid: String,
        body: String,
        lang: Option<String>,
        utc_offset_min: Option<i32>,
    },
    /// A button tap (Phase 4).
    Tap { from: String, room_id: Option<String>, msg_uid: String, action_id: String },
    /// A member asking for the bot's room key again (Phase 3): answer with [`room_key_request`]
    /// once the host has checked `from` is an active member of a room the bot is in.
    RoomKeyRequest { from: String, room_id: String, session_id: Option<String> },
    /// Read, acked and dropped: caps, digest, avatar, typing, receipts.
    Ignored(&'static str),
}

/// What [`create_identity`] makes, for the relay to write as the bot's `users`/`devices`/key rows.
#[derive(Debug, Clone)]
pub struct Registration {
    pub account_pickle: String,
    pub device_id: String,
    pub ed_pub_b64: String,
    pub x_pub_b64: String,
    /// The signed device list document and its signature.
    pub doc_json: String,
    pub sig_b64: String,
    /// (prekey_id, public key, signature) of the signed fallback key.
    pub spk: (u64, String, String),
    /// (prekey_id, public key) of each one-time key.
    pub otks: Vec<(u64, String)>,
}

/// Make the bot's identity: its account, its one `primary` device and the list that signs it,
/// the signed prekey (id 1) and `otks` one-time keys, all marked published — the host writes them
/// to the relay in the same transaction that stores `account_pickle`. Made ONCE per bot.
pub fn create_identity(user_id: &str, pickle_key: &[u8; 32], otks: usize, now_ms: i64) -> Result<Registration> {
    identity::create_identity(user_id, pickle_key, otks, now_ms)
}

/// `n` more one-time keys, marked published, the account stored. The host uploads the returned
/// `(prekey_id, public key)` pairs; the pool target is 200, topped up below 100 (§2.1).
pub fn top_up_otks(store: &mut impl BotStore, pickle_key: &[u8; 32], n: usize) -> Result<Vec<(u64, String)>> {
    identity::top_up_otks(store, pickle_key, n)
}

/// The bot's one-device list signed again under `user_id` at `rev` — for a host that learns the
/// user id after the identity exists, or re-publishes the list.
pub fn signed_device_list(
    store: &impl BotStore,
    pickle_key: &[u8; 32],
    user_id: &str,
    rev: u64,
    added_at_ms: i64,
) -> Result<(String, String)> {
    identity::signed_device_list(store, pickle_key, user_id, rev, added_at_ms)
}

/// Read one stored 1:1 frame. `expected_x_pub` is the relay's `devices.x_pub` for
/// (`env.sender_id`, `env.sender_device_id`): a PreKey from any other identity key opens no
/// session, and `None` (the relay does not know the device) is treated the same way.
///
/// The effects, in order: one [`Effect::Ack`]; for a PreKey pair-ack, the Normal pair-ack back to
/// that device as an [`Effect::Deliver`] (the engine answers it — the host must not send another);
/// an [`Effect::Repair`] when the frame did not decrypt and the bot is the lower id; and the
/// [`Effect::Update`] for the program.
pub fn on_envelope(
    store: &mut impl BotStore,
    pickle_key: &[u8; 32],
    me: &str,
    env: &Envelope,
    expected_x_pub: Option<&str>,
    now_ms: i64,
) -> Vec<Effect> {
    inbound::on_envelope(store, pickle_key, me, env, expected_x_pub, now_ms)
}

/// The relay forwarded `delivery_failed` from `from`: wipe every session with that user (the host
/// marks their `bot_sent` rows failed), and re-pair when the bot is the lower id.
pub fn on_delivery_failed(store: &mut impl BotStore, me: &str, from: &str, now_ms: i64) -> Vec<Effect> {
    heal::on_delivery_failed(store, me, from, now_ms)
}

/// The devices of `user_id` with no current session: the only ones the host claims keys for.
pub fn devices_without_session(store: &impl BotStore, user_id: &str, devices: &[DeviceKeys]) -> Vec<String> {
    direct::devices_without_session(store, user_id, devices)
}

/// Seal `payload` to every device of `to`: through the current session where there is one, as a
/// PreKey from `claimed` where there is none. A device with neither is skipped; if no device at
/// all could be reached the send is refused (`bot/no-device-reachable`).
pub fn send_direct(
    store: &mut impl BotStore,
    pickle_key: &[u8; 32],
    to: &str,
    devices: &[DeviceKeys],
    claimed: &[ClaimedKey],
    payload: &ChatPayload,
) -> Result<Vec<Effect>> {
    direct::send_direct(store, pickle_key, to, devices, claimed, payload)
}

/// The pair-ack to every reachable device of `to`, for an [`Effect::Repair`]: the host claims keys
/// for [`devices_without_session`] first. After it, the host resends `to`'s failed `bot_sent` rows.
pub fn send_pair_ack(
    store: &mut impl BotStore,
    pickle_key: &[u8; 32],
    to: &str,
    devices: &[DeviceKeys],
    claimed: &[ClaimedKey],
) -> Result<Vec<Effect>> {
    direct::send_direct(store, pickle_key, to, devices, claimed, &direct::pair_ack_payload())
}

