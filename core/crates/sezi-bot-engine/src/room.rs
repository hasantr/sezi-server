//! The bot in a room (docs/BOTS_BUILD.md Phase 3): it WRITES there with its own Megolm session
//! and reads nothing there.
//!
//! **What a bot holds of a room is only its own outbound session.** Megolm gives every sender a
//! session of their own; the bot shares ITS session's key with every member device (an Olm
//! `RoomKeyShare`, 1:1), so they read what it posts, and nobody shares theirs with it — there is
//! no function here, or in [`RoomStore`], that takes another sender's key. A room message the bot
//! was not sent is unreadable to it by construction; what reaches it from a room is a member's
//! `BotCall` copy, 1:1.
//!
//! **Who gets the key is the host's word.** The host passes the room's ACTIVE member devices, as
//! the relay's `group_members` × `devices` tables say at that moment, after checking the bot is
//! still a bot of that room (`group_bots`). The engine shares with those devices and no others,
//! and [`room_prepare`] rotates the session before anything new is encrypted when:
//! - a device it was shared with is no longer among them — a member who left, or a device removed
//!   (a member who left must never read the bot's next post);
//! - it is 7 days old ([`ROTATE_AFTER_MS`]) or has carried 1,000 messages ([`ROTATE_AFTER_MESSAGES`]).
//!
//! **The order the host keeps:** [`room_prepare`] → [`room_share`] for every unshared device it
//! can reach (in budgeted chunks, across ticks) → [`room_encrypt`]. A key is exported at the
//! session's current index when a device is first shared with, and that snapshot is what every
//! re-share sends ([`room_key_request`]), so sharing everything before encrypting is what lets
//! every member read the post — and a device shared with later reads forward only.

use sezi_crypto::megolm::{create_group_session, encrypt_to_room, group_session_key};
use sezi_error::{Error, Result};
use sezi_protocol::inner::{ChatPayload, InnerMessage};
use sezi_protocol::reply::{self, ReplyRef};

use crate::direct::send_direct;
use crate::store::{RoomSession, RoomShare, RoomStore};
use crate::{ClaimedKey, DeviceKeys, Effect};

/// A session older than this is replaced before the next post.
pub const ROTATE_AFTER_MS: i64 = 7 * 24 * 3600 * 1000;
/// A session that has carried this many messages is replaced before the next post.
pub const ROTATE_AFTER_MESSAGES: u32 = 1000;
/// A member's `RoomKeyRequest` is answered at most once in this window per room (the kernel's
/// per-(room, sender) debounce).
pub const ROOM_REQUEST_WINDOW_MS: i64 = 20_000;

/// Why [`room_prepare`] made a new session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// There was none.
    New,
    /// A device it was shared with is no longer an active member's.
    Departed,
    /// Older than [`ROTATE_AFTER_MS`].
    Age,
    /// Past [`ROTATE_AFTER_MESSAGES`].
    Count,
}

/// What a room send needs next.
#[derive(Debug, Clone, PartialEq)]
pub struct RoomPrep {
    pub session_id: String,
    /// `Some` when this call replaced (or first made) the session.
    pub rotated: Option<Rotation>,
    /// The member devices the current session has not been shared with yet, in the host's order.
    pub unshared: Vec<DeviceKeys>,
}

fn key_vec(pickle_key: &[u8; 32]) -> Vec<u8> {
    pickle_key.to_vec()
}

fn crypto(e: String) -> Error {
    Error::Crypto(format!("bot/room: {e}"))
}

fn rotation(session: Option<&RoomSession>, shares: &[RoomShare], members: &[DeviceKeys], now_ms: i64) -> Option<Rotation> {
    let Some(s) = session else {
        return Some(Rotation::New);
    };
    let still_here =
        |sh: &RoomShare| members.iter().any(|m| m.user_id == sh.user_id && m.device_id == sh.device_id);
    if !shares.iter().all(still_here) {
        Some(Rotation::Departed)
    } else if now_ms.saturating_sub(s.created_at_ms) >= ROTATE_AFTER_MS {
        Some(Rotation::Age)
    } else if s.sent >= ROTATE_AFTER_MESSAGES {
        Some(Rotation::Count)
    } else {
        None
    }
}

/// Make sure the room has a session fit to post on for exactly these `members` (every active
/// member device but the bot's own), and say which of them still need its key.
pub fn room_prepare(
    store: &mut impl RoomStore,
    pickle_key: &[u8; 32],
    room_id: &str,
    members: &[DeviceKeys],
    now_ms: i64,
) -> Result<RoomPrep> {
    let current = store.room_session(room_id);
    let shares = current.as_ref().map(|s| store.room_shares(room_id, &s.session_id)).unwrap_or_default();
    let rotated = rotation(current.as_ref(), &shares, members, now_ms);
    let (session_id, shares) = match (rotated, current) {
        (None, Some(s)) => (s.session_id, shares),
        _ => {
            let created = create_group_session(key_vec(pickle_key)).map_err(crypto)?;
            // Forgetting first drops the old session's shares and request marks with it.
            store.forget_room(room_id);
            store.put_room_session(
                room_id,
                RoomSession {
                    session_id: created.session_id.clone(),
                    pickle: created.session_pickle,
                    created_at_ms: now_ms,
                    sent: 0,
                },
            );
            (created.session_id, Vec::new())
        }
    };
    let unshared = members
        .iter()
        .filter(|m| !shares.iter().any(|s| s.user_id == m.user_id && s.device_id == m.device_id))
        .cloned()
        .collect();
    Ok(RoomPrep { session_id, rotated, unshared })
}

/// Share the room's current session with `devices` of `user_id`: one Olm `RoomKeyShare` per
/// device reached, through its current session or a PreKey from `claimed` (the 1:1 rules). A
/// device shared with before gets its first snapshot again; a new one gets the key at the
/// session's index now, recorded as its snapshot. A device that cannot be reached is skipped
/// (the answer then holds no `Deliver` for it). Refused when the room has no session.
pub fn room_share(
    store: &mut impl RoomStore,
    pickle_key: &[u8; 32],
    room_id: &str,
    user_id: &str,
    devices: &[DeviceKeys],
    claimed: &[ClaimedKey],
) -> Result<Vec<Effect>> {
    let session = store.room_session(room_id).ok_or_else(|| Error::Crypto("bot/no-room-session".into()))?;
    let shares = store.room_shares(room_id, &session.session_id);
    let mut effects = Vec::new();
    for device in devices.iter().filter(|d| d.user_id == user_id) {
        let earlier = shares.iter().find(|s| s.user_id == user_id && s.device_id == device.device_id);
        let key_b64 = match earlier {
            Some(s) => s.key_b64.clone(),
            None => group_session_key(session.pickle.clone(), key_vec(pickle_key)).map_err(crypto)?,
        };
        let payload = ChatPayload::new(
            None,
            None,
            InnerMessage::RoomKeyShare {
                room_id: room_id.to_owned(),
                session_id: session.session_id.clone(),
                session_key_b64: key_b64.clone(),
            },
        );
        let Ok(sealed) =
            send_direct(&mut *store, pickle_key, user_id, std::slice::from_ref(device), claimed, &payload)
        else {
            continue; // no session and no key to open one: reached on a later share or request
        };
        if earlier.is_none() {
            let share = RoomShare { user_id: user_id.to_owned(), device_id: device.device_id.clone(), key_b64 };
            store.put_room_share(room_id, &session.session_id, share);
        }
        effects.extend(sealed);
    }
    Ok(effects)
}

/// Encrypt one message into the room on the current session: the envelope every member device
/// gets, identical for all. Refused when the room has no session.
pub fn room_encrypt(
    store: &mut impl RoomStore,
    pickle_key: &[u8; 32],
    room_id: &str,
    payload: &ChatPayload,
) -> Result<Effect> {
    let mut session =
        store.room_session(room_id).ok_or_else(|| Error::Crypto("bot/no-room-session".into()))?;
    let enc = encrypt_to_room(
        session.pickle.clone(),
        key_vec(pickle_key),
        payload.inner.clone(),
        payload.thread_id.clone(),
        payload.thread_title.clone(),
        payload.msg_uid.clone(),
        payload.ext.clone(),
    )
    .map_err(crypto)?;
    session.pickle = enc.new_session_pickle;
    session.sent = session.sent.saturating_add(1);
    store.put_room_session(room_id, session);
    Ok(Effect::DeliverRoom { room_id: room_id.to_owned(), envelope_b64: enc.envelope_b64 })
}

/// A member asked for the bot's room key again. The HOST has checked that `from` is an active
/// member of the room and that the bot is still one of its bots; `devices` are `from`'s active
/// devices. Answered at most once per [`ROOM_REQUEST_WINDOW_MS`] per (room, member), only for the
/// current session (a rotated-away one is gone), with each device's snapshot — or, for a device
/// never shared with, the key from now on.
#[allow(clippy::too_many_arguments)]
pub fn room_key_request(
    store: &mut impl RoomStore,
    pickle_key: &[u8; 32],
    room_id: &str,
    from: &str,
    session_id: Option<&str>,
    devices: &[DeviceKeys],
    claimed: &[ClaimedKey],
    now_ms: i64,
) -> Result<Vec<Effect>> {
    if !room_key_request_due(store, room_id, from, session_id, now_ms) {
        return Ok(Vec::new());
    }
    store.set_room_request_at(room_id, from, now_ms);
    room_share(store, pickle_key, room_id, from, devices, claimed)
}

/// Would [`room_key_request`] answer this request now? The host asks BEFORE it claims any key, so
/// a request for a session that is gone, or one inside the window, spends none of the member's
/// one-time keys and none of the tick's budget.
pub fn room_key_request_due(
    store: &impl RoomStore,
    room_id: &str,
    from: &str,
    session_id: Option<&str>,
    now_ms: i64,
) -> bool {
    let Some(session) = store.room_session(room_id) else {
        return false;
    };
    if session_id.is_some_and(|id| id != session.session_id) {
        return false;
    }
    store.room_request_at(room_id, from).is_none_or(|at| now_ms.saturating_sub(at) >= ROOM_REQUEST_WINDOW_MS)
}

/// The bot is no longer in the room: forget its session there and everyone it was shared with.
pub fn room_forget(store: &mut impl RoomStore, room_id: &str) {
    store.forget_room(room_id);
}

/// A text from the bot into a room, with its own `msg_uid` (`b-<uuid>`) and, when it answers a
/// call, `ext.reply` naming that call (`sezi_protocol::reply`).
pub fn room_text_payload(body: &str, msg_uid: &str, reply_to: Option<&ReplyRef>) -> ChatPayload {
    let mut payload = ChatPayload::new(None, None, InnerMessage::Text { body: body.to_owned() });
    payload.msg_uid = Some(msg_uid.to_owned());
    payload.ext = reply::write(serde_json::Value::Null, reply_to);
    payload
}

#[cfg(test)]
#[path = "room_tests.rs"]
mod tests;
