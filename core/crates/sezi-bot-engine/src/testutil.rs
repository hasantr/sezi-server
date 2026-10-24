//! Shared unit-test fixtures: a bot over a [`MemStore`], and a member device that speaks Olm the
//! way a kernel does (one outbound session to the bot, PreKey until it has heard back).

use sezi_crypto::identity::Identity;
use sezi_crypto::session;
use sezi_protocol::devices::device_id_from_ed25519_b64;
use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::ChatPayload;
use vodozemac::olm::{OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::mem::MemStore;
use crate::{create_identity, ClaimedKey, DeviceKeys, Effect, Envelope, Registration};

pub(crate) const KEY: [u8; 32] = [9; 32];

pub(crate) struct Bot {
    pub id: String,
    pub store: MemStore,
    pub reg: Registration,
    /// The bot's one-time keys not yet claimed by a member.
    pub unclaimed: Vec<String>,
}

pub(crate) fn bot(user_id: &str) -> Bot {
    let reg = create_identity(user_id, &KEY, 8, 1).expect("identity");
    let store = MemStore { account: Some(reg.account_pickle.clone()), ..MemStore::default() };
    let unclaimed = reg.otks.iter().map(|(_, k)| k.clone()).collect();
    Bot { id: user_id.into(), store, reg, unclaimed }
}

pub(crate) struct Member {
    pub user: String,
    pub device: String,
    pub identity: Identity,
    /// The one session this device holds with the bot.
    pub session: Option<Session>,
    unclaimed: Vec<String>,
    next_remote_id: i64,
}

impl Member {
    pub fn new(user: &str) -> Self {
        let mut identity = Identity::generate();
        identity.generate_otks(4);
        let unclaimed =
            identity.unpublished_otks().values().map(|k| k.to_base64()).collect::<Vec<_>>();
        identity.mark_otks_published();
        let ed = vodozemac::base64_encode(identity.signing_pubkey_bytes());
        let device = device_id_from_ed25519_b64(&ed).expect("device id");
        Self { user: user.into(), device, identity, session: None, unclaimed, next_remote_id: 1 }
    }

    pub fn x_pub(&self) -> String {
        self.identity.diffie_pubkey().to_base64()
    }

    pub fn keys(&self) -> DeviceKeys {
        DeviceKeys {
            user_id: self.user.clone(),
            device_id: self.device.clone(),
            x_pub_b64: self.x_pub(),
            ed_pub_b64: vodozemac::base64_encode(self.identity.signing_pubkey_bytes()),
        }
    }

    /// One of this device's one-time keys, as the relay's bundle slot would hand it to the bot.
    pub fn claim(&mut self) -> ClaimedKey {
        ClaimedKey { device_id: self.device.clone(), key_b64: self.unclaimed.pop().expect("an OTK") }
    }

    /// Open this device's outbound session to the bot with one of its one-time keys.
    pub fn open_to(&mut self, bot: &mut Bot) {
        let bot_x = Curve25519PublicKey::from_base64(&bot.reg.x_pub_b64).expect("bot x");
        let otk = Curve25519PublicKey::from_base64(&bot.unclaimed.pop().expect("bot OTK")).expect("otk");
        let s = self
            .identity
            .account()
            .create_outbound_session(SessionConfig::version_1(), bot_x, otk)
            .expect("outbound");
        self.session = Some(s);
    }

    /// Seal raw bytes on the member's session into an [`Envelope`] as the relay stores it.
    pub fn send_raw(&mut self, plaintext: &[u8]) -> Envelope {
        let msg = self.session.as_mut().expect("session").encrypt(plaintext).expect("encrypt");
        self.envelope(&msg)
    }

    pub fn send(&mut self, payload: &ChatPayload) -> Envelope {
        self.send_raw(&payload.encode())
    }

    pub fn envelope(&mut self, msg: &OlmMessage) -> Envelope {
        let json = serde_json::to_vec(&WireEnvelope::from_olm(msg)).expect("json");
        let remote_id = self.next_remote_id;
        self.next_remote_id += 1;
        Envelope {
            remote_id,
            sender_id: self.user.clone(),
            sender_device_id: self.device.clone(),
            envelope_b64: vodozemac::base64_encode(json),
            group_id: None,
        }
    }

    /// Read a frame the bot delivered: on the held session, or — a PreKey nothing reads — on a
    /// new inbound session, which then becomes the one this device holds. Returns the payload and
    /// whether the frame was a PreKey.
    pub fn receive(&mut self, envelope_b64: &str) -> (ChatPayload, bool) {
        let bytes = vodozemac::base64_decode(envelope_b64).expect("b64");
        let env: WireEnvelope = serde_json::from_slice(&bytes).expect("env");
        let msg = env.to_olm().expect("olm");
        let prekey = matches!(msg, OlmMessage::PreKey(_));
        if let Some(s) = self.session.as_mut() {
            if let Ok(plain) = s.decrypt(&msg) {
                return (ChatPayload::decode(&plain).expect("payload"), prekey);
            }
        }
        let OlmMessage::PreKey(pre) = msg else { panic!("a Normal frame no session reads") };
        let created = session::inbound(&mut self.identity, pre.identity_key(), &pre).expect("inbound");
        self.session = Some(created.session);
        (ChatPayload::decode(&created.plaintext).expect("payload"), prekey)
    }
}

/// The envelopes of every `Deliver` among `effects`, in order.
pub(crate) fn delivered(effects: &[Effect]) -> Vec<String> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Deliver { envelope_b64, .. } => Some(envelope_b64.clone()),
            _ => None,
        })
        .collect()
}

/// Pair a member with the bot the way a kernel does: its PreKey pair-ack in, the bot's Normal
/// answer back. Afterwards both ends hold the same session and the member sends Normal frames.
pub(crate) fn pair(bot: &mut Bot, member: &mut Member, now_ms: i64) {
    member.open_to(bot);
    let env = member.send(&crate::direct::pair_ack_payload());
    let x = member.x_pub();
    let effects = crate::on_envelope(&mut bot.store, &KEY, &bot.id, &env, Some(&x), now_ms);
    let answer = delivered(&effects);
    assert_eq!(answer.len(), 1, "one Normal pair-ack back: {effects:?}");
    member.receive(&answer[0]);
}
