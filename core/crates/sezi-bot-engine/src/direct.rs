//! Sealing 1:1 frames from the bot to a member's devices.
//!
//! One Olm envelope per device, through that device's current session — and a PreKey (a new
//! outbound session from a claimed key) ONLY for a device that has no current session. Never
//! initiating a PreKey to a device the bot already shares a session with is the rule that keeps
//! two ends from opening sessions at each other (glare); it is also why the host asks
//! [`devices_without_session`] first and claims keys for those devices alone.
//!
//! The payload is byte-for-byte what a kernel sends: a `ChatPayload` (schema version, optional
//! `msg_uid`, `ext`, the flattened `InnerMessage`), sealed by `Session::encrypt`, wrapped as a
//! `WireEnvelope` and base64'd — `sezi_crypto::messaging::encrypt_inner_to_peer_uid`'s shape.

use sezi_crypto::messaging::pickle_session;
use sezi_error::{Error, Result};
use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::{ChatPayload, InnerMessage};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::classify::PAIR_ACK_MARKER;
use crate::store::{current, load_account, BotStore};
use crate::{ClaimedKey, DeviceKeys, Effect};

pub(crate) fn devices_without_session(
    store: &impl BotStore,
    user_id: &str,
    devices: &[DeviceKeys],
) -> Vec<String> {
    devices
        .iter()
        .filter(|d| store.current_session(user_id, &d.device_id).is_none())
        .map(|d| d.device_id.clone())
        .collect()
}

/// Seal `payload` to every device of `to` the bot can reach: those with a current session, and
/// those without one for which `claimed` holds a key. A device with neither is skipped; when that
/// leaves nothing at all the send is refused (`bot/no-device-reachable`).
pub(crate) fn send_direct(
    store: &mut impl BotStore,
    pickle_key: &[u8; 32],
    to: &str,
    devices: &[DeviceKeys],
    claimed: &[ClaimedKey],
    payload: &ChatPayload,
) -> Result<Vec<Effect>> {
    let bytes = payload.encode();
    let mut account: Option<Account> = None;
    let mut effects = Vec::new();
    for device in devices {
        let (mut session, had_current) = match current(store, pickle_key, to, &device.device_id)? {
            Some(session) => (session, true),
            None => {
                let Some(key) = claimed.iter().find(|c| c.device_id == device.device_id) else {
                    continue;
                };
                let account = match account {
                    Some(ref a) => a,
                    None => account.insert(load_account(store, pickle_key)?),
                };
                (open_outbound(account, device, key)?, false)
            }
        };
        let envelope_b64 = seal(&mut session, &bytes)?;
        let pickle = pickle_session(&session, pickle_key);
        if had_current {
            store.promote(to, &device.device_id, 0, pickle);
        } else {
            store.put_current_session(to, &device.device_id, pickle);
        }
        effects.push(Effect::Deliver {
            user_id: to.to_owned(),
            device_id: device.device_id.clone(),
            envelope_b64,
            msg_uid: payload.msg_uid.clone(),
        });
    }
    if effects.is_empty() {
        return Err(Error::Crypto("bot/no-device-reachable".into()));
    }
    Ok(effects)
}

/// The pair-ack: the invisible marker a kernel sends to (re-)establish a session
/// (`kernel::runners::run_pair_ack` — no thread, no `msg_uid`, no `ext`).
pub(crate) fn pair_ack_payload() -> ChatPayload {
    ChatPayload::new(None, None, InnerMessage::Text { body: PAIR_ACK_MARKER.into() })
}

/// A plain 1:1 text from the bot, carrying the bot's own `msg_uid` (`b-<uuid>`) so every device of
/// the member stores the same id and receipts can name it.
pub fn text_payload(body: &str, msg_uid: &str) -> ChatPayload {
    let mut payload = ChatPayload::new(None, None, InnerMessage::Text { body: body.to_owned() });
    payload.msg_uid = Some(msg_uid.to_owned());
    payload
}

/// Encrypt one plaintext on `session` into the wire's envelope string.
pub(crate) fn seal(session: &mut Session, plaintext: &[u8]) -> Result<String> {
    let message = session
        .encrypt(plaintext)
        .map_err(|e| Error::Crypto(format!("bot/encrypt: {e}")))?;
    envelope_b64(&message)
}

fn envelope_b64(message: &OlmMessage) -> Result<String> {
    let json = serde_json::to_vec(&WireEnvelope::from_olm(message))
        .map_err(|e| Error::Crypto(format!("bot/envelope-serialize: {e}")))?;
    Ok(vodozemac::base64_encode(json))
}

fn open_outbound(account: &Account, device: &DeviceKeys, key: &ClaimedKey) -> Result<Session> {
    let identity = Curve25519PublicKey::from_base64(&device.x_pub_b64)
        .map_err(|e| Error::Crypto(format!("bot/peer-x-pub-unreadable: {e}")))?;
    let one_time = Curve25519PublicKey::from_base64(&key.key_b64)
        .map_err(|e| Error::Crypto(format!("bot/claimed-key-unreadable: {e}")))?;
    account
        .create_outbound_session(SessionConfig::version_1(), identity, one_time)
        .map_err(|e| Error::Crypto(format!("bot/outbound-session: {e}")))
}

#[cfg(test)]
#[path = "direct_tests.rs"]
mod tests;
