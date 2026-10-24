//! Reading one 1:1 frame a member sent the bot.
//!
//! Every stored session with the sender's device is tried first — the current one, then the
//! archive — and the Olm account is unpickled ONLY for a PreKey that none of them reads. That is
//! the difference from `sezi_crypto::messaging::decrypt_payload_from_peer_sessions`, which
//! unpickles the account on every frame: a cost the relay's Durable Object would pay per message,
//! and the account pickle grows with every one-time key it holds.
//!
//! The ack is the kernel's: a frame that decrypts is acked `success: true` with its `msg_uid`
//! (the member's second tick), whatever its kind; one that does not is acked `success: false`, so
//! the relay forwards `delivery_failed` and the member resends once the pair is mended
//! (`heal.rs`).

use sezi_crypto::messaging::{pickle_session, unpickle_session};
use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::ChatPayload;
use vodozemac::olm::{DecryptionError, OlmMessage, PreKeyMessage, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::classify::classify;
use crate::direct::{pair_ack_payload, seal};
use crate::heal::{undecryptable, Failure};
use crate::store::{current, load_account, BotStore};
use crate::{Effect, Envelope, Inbound};

pub(crate) fn on_envelope(
    store: &mut impl BotStore,
    pickle_key: &[u8; 32],
    me: &str,
    env: &Envelope,
    expected_x_pub: Option<&str>,
    now_ms: i64,
) -> Vec<Effect> {
    // A bot holds no room key (Phase 3 sends its room answers under its own session and never
    // receives one), so a room envelope addressed to it is unreadable by design. Acked as read so
    // the relay does not answer it with `delivery_failed` and a re-pair that cannot help.
    if env.group_id.is_some() {
        return vec![
            Effect::Ack { remote_id: env.remote_id, success: true, uid: None },
            Effect::Update(Inbound::Ignored("room_envelope")),
        ];
    }
    let Some(olm) = parse(&env.envelope_b64) else {
        return undecryptable(store, me, env, Failure::Broken, now_ms);
    };
    let (user, device) = (env.sender_id.as_str(), env.sender_device_id.as_str());
    let was_prekey = matches!(olm, OlmMessage::PreKey(_));

    // 1. Every session already held, current first.
    let has_current = store.current_session(user, device).is_some();
    let mut gap = false;
    for (index, blob) in store.sessions(user, device).iter().enumerate() {
        let Ok(mut session) = unpickle_session(blob, pickle_key) else {
            continue; // a corrupt archive entry must not sink the whole decrypt
        };
        match session.decrypt(&olm) {
            Ok(plain) => {
                store.promote(user, device, index, pickle_session(&session, pickle_key));
                return read(store, pickle_key, env, &plain, was_prekey);
            }
            Err(DecryptionError::MissingMessageKey(_)) if index == 0 && has_current => gap = true,
            Err(_) => {}
        }
    }

    // 2. A PreKey nobody reads opens a new session — from the device the relay says sent it.
    let OlmMessage::PreKey(pre) = olm else {
        let failure = if gap { Failure::Gap } else { Failure::Broken };
        return undecryptable(store, me, env, failure, now_ms);
    };
    if !identity_matches(&pre, expected_x_pub) {
        // A forged envelope, or a key that changed under the same device: no session, no re-pair
        // (the kernel's `IdentityMismatch` answer). Unknown to the relay counts as a mismatch.
        return vec![Effect::Ack { remote_id: env.remote_id, success: false, uid: None }];
    }
    let Ok(mut account) = load_account(store, pickle_key) else {
        return vec![Effect::Ack { remote_id: env.remote_id, success: false, uid: None }];
    };
    match account.create_inbound_session(SessionConfig::version_1(), pre.identity_key(), &pre) {
        Ok(created) => {
            // The one-time key it used is gone from the account now; persist that, or it would be
            // accepted a second time.
            store.put_account(account.pickle().encrypt(pickle_key));
            store.put_current_session(user, device, pickle_session(&created.session, pickle_key));
            read(store, pickle_key, env, &created.plaintext, was_prekey)
        }
        Err(_) => undecryptable(store, me, env, Failure::Broken, now_ms),
    }
}

/// A frame that decrypted: ack it, answer a pair-ack, and hand the program what it is.
fn read(
    store: &mut impl BotStore,
    pickle_key: &[u8; 32],
    env: &Envelope,
    plain: &[u8],
    was_prekey: bool,
) -> Vec<Effect> {
    let Ok(payload) = ChatPayload::decode(plain) else {
        // The session is fine and has advanced; the body is just not something this build reads.
        return vec![
            Effect::Ack { remote_id: env.remote_id, success: true, uid: None },
            Effect::Update(Inbound::Ignored("unparseable")),
        ];
    };
    let inbound = classify(&payload, &env.sender_id, &env.sender_device_id, was_prekey);
    let mut effects =
        vec![Effect::Ack { remote_id: env.remote_id, success: true, uid: payload.msg_uid.clone() }];
    if matches!(inbound, Inbound::PairAck { .. }) {
        // The member opened a session and waits to hear on it: one Normal pair-ack back, to this
        // device, over the session that just read theirs — what makes the pairing `mutual` there.
        effects.extend(answer_pair_ack(store, pickle_key, env));
    }
    effects.push(Effect::Update(inbound));
    effects
}

fn answer_pair_ack(store: &mut impl BotStore, pickle_key: &[u8; 32], env: &Envelope) -> Option<Effect> {
    let (user, device) = (env.sender_id.as_str(), env.sender_device_id.as_str());
    let mut session = current(store, pickle_key, user, device).ok()??;
    let envelope_b64 = seal(&mut session, &pair_ack_payload().encode()).ok()?;
    store.promote(user, device, 0, pickle_session(&session, pickle_key));
    Some(Effect::Deliver {
        user_id: user.to_owned(),
        device_id: device.to_owned(),
        envelope_b64,
        msg_uid: None,
    })
}

fn identity_matches(pre: &PreKeyMessage, expected_x_pub: Option<&str>) -> bool {
    expected_x_pub
        .and_then(|b64| Curve25519PublicKey::from_base64(b64).ok())
        .is_some_and(|expected| expected == pre.identity_key())
}

fn parse(envelope_b64: &str) -> Option<OlmMessage> {
    let bytes = vodozemac::base64_decode(envelope_b64).ok()?;
    let envelope: WireEnvelope = serde_json::from_slice(&bytes).ok()?;
    envelope.to_olm().ok()
}

#[cfg(test)]
#[path = "inbound_tests.rs"]
mod tests;
