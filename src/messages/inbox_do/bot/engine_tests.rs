//! The real engine through the relay's own code: a bot made by `create_identity`, written to D1
//! with the provisioning SQL, its state in the DO tables through `SqlBotStore`, and a member
//! device that speaks Olm the way a kernel does, with keys and identities read back from D1 the
//! way the inbox reads them (`bundle_slot`'s claim, the tick's `devices.x_pub`).

use super::super::{SqlBotStore, TABLES};
use super::Lite;
use crate::bots::provision::*;
use crate::utils::{b64_decode, b64_encode};
use rusqlite::{params, Connection};
use sezi_bot_engine::{
    create_identity, devices_without_session, on_envelope, send_direct, text_payload, BotStore, DeviceKeys,
    Effect, Envelope, Inbound, PAIR_ACK_MARKER,
};
use sezi_crypto::identity::Identity;
use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::{ChatPayload, InnerMessage};
use vodozemac::olm::{OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

const BOT: &str = "b0000000-0000-4000-8000-000000000001";
const ALICE: &str = "a0000000-0000-4000-8000-000000000001";
const KEY: [u8; 32] = [7; 32];
const NOW: i64 = 1_761_200_000;

/// D1 with alice and the bot provisioned from a real registration.
fn d1(reg: &sezi_bot_engine::Registration) -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES (?1, 'a@example.test', X'01', ?2)",
        params![ALICE, NOW],
    )
    .unwrap();
    let doc: crate::devices::handlers::DeviceListDoc = serde_json::from_str(&reg.doc_json).unwrap();
    let x = b64_decode(&reg.x_pub_b64).unwrap();
    let ed = b64_decode(&reg.ed_pub_b64).unwrap();
    db.execute(INSERT_BOT_USER_SQL, params![BOT, bot_email(BOT), x, ed, "Echo", doc.rev, NOW]).unwrap();
    db.execute(INSERT_BOT_SQL, params![BOT, "Echo", None::<String>, ALICE, NOW]).unwrap();
    db.execute(INSERT_DEVICE_LIST_SQL, params![BOT, doc.rev, reg.doc_json, reg.sig_b64, NOW]).unwrap();
    let entry = doc.devices.iter().find(|d| d.device_id == reg.device_id).expect("the bot's device is listed");
    db.execute(INSERT_DEVICE_SQL, params![BOT, reg.device_id, ed, x, entry.label, entry.added_at_ms]).unwrap();
    let (spk_id, spk, sig) = &reg.spk;
    db.execute(
        INSERT_SPK_SQL,
        params![BOT, *spk_id as i64, b64_decode(spk).unwrap(), b64_decode(sig).unwrap(), NOW, reg.device_id],
    )
    .unwrap();
    for (id, otk) in &reg.otks {
        db.execute(&otk_insert_sql(1), params![BOT, *id as i64, b64_decode(otk).unwrap(), reg.device_id]).unwrap();
    }
    db.execute(GRANT_ALL_HUMANS_SQL, params![BOT, NOW]).unwrap();
    db
}

/// The bot inbox's own SQLite, initialized the way `/bot/init` does.
fn inbox(reg: &sezi_bot_engine::Registration) -> SqlBotStore<Lite> {
    let c = Connection::open_in_memory().unwrap();
    for t in TABLES {
        c.execute_batch(t).unwrap();
    }
    let store = SqlBotStore { db: Lite(c) };
    store.kv_put("account_pickle", &reg.account_pickle);
    store
}

struct Member {
    identity: Identity,
    device: String,
    session: Option<Session>,
    next_id: i64,
}

impl Member {
    fn new(d1: &Connection) -> Self {
        let mut identity = Identity::generate();
        identity.generate_otks(2);
        identity.mark_otks_published();
        let ed = vodozemac::base64_encode(identity.signing_pubkey_bytes());
        let device = sezi_protocol::devices::device_id_from_ed25519_b64(&ed).unwrap();
        d1.execute(
            "INSERT INTO devices (user_id, device_id, role, ed_pub, x_pub, added_at) VALUES (?1, ?2, 'primary', ?3, ?4, ?5)",
            params![ALICE, device, identity.signing_pubkey_bytes().to_vec(), identity.diffie_pubkey_bytes().to_vec(), NOW],
        )
        .unwrap();
        Self { identity, device, session: None, next_id: 1 }
    }

    /// The kernel's first contact: the bot's bundle from D1 (its x_pub, one claimed OTK).
    fn open_to_bot(&mut self, d1: &Connection, bot_device: &str) {
        let x: Vec<u8> = d1
            .query_row(crate::keys::handlers::DEVICE_X_PUB_SQL, params![BOT, bot_device], |r| r.get(0))
            .unwrap();
        let otk: Vec<u8> = d1
            .query_row(crate::keys::handlers::CLAIM_DEVICE_OTK_SQL, params![BOT, bot_device], |r| r.get(2))
            .unwrap();
        let x = Curve25519PublicKey::from_slice(&x).unwrap();
        let otk = Curve25519PublicKey::from_slice(&otk).unwrap();
        let s = self.identity.account().create_outbound_session(SessionConfig::version_1(), x, otk).unwrap();
        self.session = Some(s);
    }

    fn send(&mut self, payload: &ChatPayload) -> Envelope {
        let msg = self.session.as_mut().unwrap().encrypt(payload.encode()).unwrap();
        let json = serde_json::to_vec(&WireEnvelope::from_olm(&msg)).unwrap();
        let remote_id = self.next_id;
        self.next_id += 1;
        Envelope {
            remote_id,
            sender_id: ALICE.into(),
            sender_device_id: self.device.clone(),
            envelope_b64: vodozemac::base64_encode(json),
            group_id: None,
        }
    }

    fn receive(&mut self, envelope_b64: &str) -> ChatPayload {
        let env: WireEnvelope = serde_json::from_slice(&vodozemac::base64_decode(envelope_b64).unwrap()).unwrap();
        let msg: OlmMessage = env.to_olm().unwrap();
        let plain = self.session.as_mut().expect("a session").decrypt(&msg).expect("the member reads it");
        ChatPayload::decode(&plain).unwrap()
    }
}

/// What the tick's prefetch hands the engine: D1's `devices.x_pub`, b64 as the relay encodes it.
fn x_pub_from_d1(d1: &Connection, device: &str) -> String {
    let x: Vec<u8> = d1
        .query_row("SELECT x_pub FROM devices WHERE user_id = ?1 AND device_id = ?2", params![ALICE, device], |r| {
            r.get(0)
        })
        .unwrap();
    b64_encode(&x)
}

fn delivered(effects: &[Effect]) -> Vec<(String, String, Option<String>)> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Deliver { device_id, envelope_b64, msg_uid, .. } => {
                Some((device_id.clone(), envelope_b64.clone(), msg_uid.clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn a_member_pairs_writes_and_reads_the_answer_through_the_relays_store() {
    let reg = create_identity(BOT, &KEY, 4, NOW * 1000).expect("identity");
    let d1 = d1(&reg);
    let mut store = inbox(&reg);
    let mut alice = Member::new(&d1);

    // 1. The member's PreKey pair-ack. The engine answers it itself; the host only queues that.
    alice.open_to_bot(&d1, &reg.device_id);
    let pair_ack = ChatPayload::new(None, None, InnerMessage::Text { body: PAIR_ACK_MARKER.into() });
    let x = x_pub_from_d1(&d1, &alice.device);
    let effects = on_envelope(&mut store, &KEY, BOT, &alice.send(&pair_ack), Some(&x), NOW * 1000);
    assert!(matches!(effects[0], Effect::Ack { success: true, .. }), "{effects:?}");
    assert!(effects.contains(&Effect::Update(Inbound::PairAck { from: ALICE.into() })));
    let answer = delivered(&effects);
    assert_eq!(answer.len(), 1, "one Normal pair-ack back, from the engine");
    assert_eq!(answer[0].2, None, "no msg_uid: the outbox sends it silent");
    let back = alice.receive(&answer[0].1);
    assert!(matches!(back.inner, InnerMessage::Text { ref body } if body == PAIR_ACK_MARKER));
    assert!(store.current_session(ALICE, &alice.device).is_some(), "slot 0 holds the session");

    // 2. A text: acked with its msg_uid, one update for the program.
    let hello = text_payload("merhaba", "m-1");
    let effects = on_envelope(&mut store, &KEY, BOT, &alice.send(&hello), Some(&x), NOW * 1000 + 5);
    assert_eq!(effects[0], Effect::Ack { remote_id: 2, success: true, uid: Some("m-1".into()) });
    let text = effects.iter().find_map(|e| match e {
        Effect::Update(Inbound::Text { from, msg_uid, body, .. }) => Some((from.clone(), msg_uid.clone(), body.clone())),
        _ => None,
    });
    assert_eq!(text, Some((ALICE.into(), Some("m-1".into()), "merhaba".into())));
    assert!(store.first_sight(ALICE, "m-1", NOW), "the first copy becomes an update");
    assert!(!store.first_sight(ALICE, "m-1", NOW + 1), "a kernel's resend does not");

    // 3. The program's answer: no claim needed (the session is current), one frame she reads.
    let devices = vec![DeviceKeys {
        user_id: ALICE.into(),
        device_id: alice.device.clone(),
        x_pub_b64: x.clone(),
        ed_pub_b64: b64_encode(&alice.identity.signing_pubkey_bytes()),
    }];
    assert!(devices_without_session(&store, ALICE, &devices).is_empty());
    let reply = text_payload("↩ merhaba", "b-1");
    let effects = send_direct(&mut store, &KEY, ALICE, &devices, &[], &reply).expect("sealed");
    let out = delivered(&effects);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].2.as_deref(), Some("b-1"));
    let got = alice.receive(&out[0].1);
    assert!(matches!(got.inner, InnerMessage::Text { ref body } if body == "↩ merhaba"));
    assert_eq!(got.msg_uid.as_deref(), Some("b-1"));

    // The bundle the member fetched came from the provisioned pool: one OTK is spent.
    let left: i64 = d1.query_row(OTK_POOL_SQL, params![BOT, reg.device_id], |r| r.get(0)).unwrap();
    assert_eq!(left, 3);
}

#[test]
fn a_prekey_from_a_device_d1_does_not_know_opens_nothing() {
    let reg = create_identity(BOT, &KEY, 2, NOW * 1000).expect("identity");
    let d1 = d1(&reg);
    let mut store = inbox(&reg);
    let mut alice = Member::new(&d1);
    alice.open_to_bot(&d1, &reg.device_id);
    let frame = alice.send(&text_payload("hi", "m-1"));
    let effects = on_envelope(&mut store, &KEY, BOT, &frame, None, NOW * 1000);
    assert!(matches!(effects[0], Effect::Ack { success: false, .. }), "{effects:?}");
    assert!(store.sessions(ALICE, &alice.device).is_empty(), "no session was stored");
}
