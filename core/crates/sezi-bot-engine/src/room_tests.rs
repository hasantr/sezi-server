//! The bot's own room session: who gets its key, when it is replaced, and that nothing else of a
//! room ever reaches the bot.

use sezi_crypto::megolm::{decrypt_from_room, import_inbound_group_session};
use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::{ChatPayload, InnerMessage};
use sezi_protocol::reply::{self, ReplyRef};

use super::*;
use crate::testutil::{bot, pair, Bot, Member, KEY};
use crate::{DeviceKeys, Effect};

const ROOM: &str = "room-1";
const T0: i64 = 1_000_000;
const MEMBER_KEY: [u8; 32] = [3; 32];

/// What one member device holds of the bot's room: the inbound session from its key share.
struct Seat {
    member: Member,
    inbound: Option<(String, String)>, // (session id, inbound pickle)
}

impl Seat {
    fn new(user: &str) -> Self {
        Self { member: Member::new(user), inbound: None }
    }

    /// Read every key share the bot sent this device; returns how many there were.
    fn take_shares(&mut self, effects: &[Effect]) -> usize {
        let mut n = 0;
        for e in effects {
            let Effect::Deliver { user_id, device_id, envelope_b64, msg_uid } = e else { continue };
            if *user_id != self.member.user || *device_id != self.member.device {
                continue;
            }
            assert_eq!(*msg_uid, None, "a key share is invisible control, no msg_uid");
            let (payload, _) = self.member.receive(envelope_b64);
            let InnerMessage::RoomKeyShare { room_id, session_id, session_key_b64 } = payload.inner else {
                panic!("not a key share: {:?}", payload.inner);
            };
            assert_eq!(room_id, ROOM);
            let imported = import_inbound_group_session(session_key_b64, MEMBER_KEY.to_vec()).unwrap();
            assert_eq!(imported.session_id, session_id);
            self.inbound = Some((session_id, imported.inbound_pickle));
            n += 1;
        }
        n
    }

    fn read(&self, post: &Effect) -> std::result::Result<ChatPayload, String> {
        let Effect::DeliverRoom { envelope_b64, .. } = post else { panic!("not a room post") };
        let (_, pickle) = self.inbound.as_ref().ok_or_else(|| "no key".to_string())?;
        decrypt_from_room(pickle.clone(), MEMBER_KEY.to_vec(), envelope_b64.clone()).map(|d| d.payload)
    }
}

fn session_of(post: &Effect) -> String {
    let Effect::DeliverRoom { envelope_b64, .. } = post else { panic!("not a room post") };
    WireEnvelope::megolm_session_id(envelope_b64).expect("a megolm envelope")
}

fn keys(seats: &[&Seat]) -> Vec<DeviceKeys> {
    seats.iter().map(|s| s.member.keys()).collect()
}

/// Share with every unshared device of the room, claiming a key where the bot has no session.
fn share_all(b: &mut Bot, seats: &mut [&mut Seat], now: i64) -> crate::RoomPrep {
    let members: Vec<DeviceKeys> = seats.iter().map(|s| s.member.keys()).collect();
    let prep = room_prepare(&mut b.store, &KEY, ROOM, &members, now).unwrap();
    for seat in seats.iter_mut() {
        let k = seat.member.keys();
        if !prep.unshared.contains(&k) {
            continue;
        }
        let claimed = if crate::devices_without_session(&b.store, &k.user_id, std::slice::from_ref(&k)).is_empty() {
            Vec::new()
        } else {
            vec![seat.member.claim()]
        };
        let effects = room_share(&mut b.store, &KEY, ROOM, &k.user_id, std::slice::from_ref(&k), &claimed).unwrap();
        assert_eq!(seat.take_shares(&effects), 1, "one share for {}", k.user_id);
    }
    prep
}

fn post(b: &mut Bot, body: &str, uid: &str, reply_to: Option<&ReplyRef>) -> Effect {
    room_encrypt(&mut b.store, &KEY, ROOM, &room_text_payload(body, uid, reply_to)).unwrap()
}

#[test]
fn every_member_device_reads_the_bots_answer_with_its_reply() {
    let mut b = bot("b-bot");
    let (mut ayse, mut mert) = (Seat::new("u-ayse"), Seat::new("u-mert"));
    // Ayşe has paired with the bot 1:1 (her share goes on that session); Mert never wrote to it
    // (his is a PreKey from one of his claimed keys).
    pair(&mut b, &mut ayse.member, T0);
    let prep = share_all(&mut b, &mut [&mut ayse, &mut mert], T0);
    assert_eq!(prep.rotated, Some(Rotation::New));
    assert_eq!(prep.unshared.len(), 2);

    let call = ReplyRef::new("loc-7", "u-ayse", "text", Some("@bot yarın kaçta?"));
    let answer = post(&mut b, "10:00", "b-1", Some(&call));
    for seat in [&ayse, &mert] {
        let got = seat.read(&answer).expect("a member reads the bot's post");
        assert_eq!(got.msg_uid.as_deref(), Some("b-1"));
        assert_eq!(reply::read(&got.ext), Some(call.clone()), "the answer names the call");
        assert!(matches!(got.inner, InnerMessage::Text { ref body } if body == "10:00"));
    }
    // Nothing more to share: the next post needs no key share, and keeps the session.
    let again = room_prepare(&mut b.store, &KEY, ROOM, &keys(&[&ayse, &mert]), T0 + 1).unwrap();
    assert_eq!((again.rotated, again.unshared.len()), (None, 0));
    assert_eq!(again.session_id, prep.session_id);
}

#[test]
fn a_member_who_left_never_gets_the_next_session() {
    let mut b = bot("b-bot");
    let (mut ayse, mut mert) = (Seat::new("u-ayse"), Seat::new("u-mert"));
    let first = share_all(&mut b, &mut [&mut ayse, &mut mert], T0);
    let before = post(&mut b, "before", "b-1", None);
    assert!(mert.read(&before).is_ok());

    // Mert leaves: the host's member list no longer has him.
    let prep = share_all(&mut b, &mut [&mut ayse], T0 + 10);
    assert_eq!(prep.rotated, Some(Rotation::Departed));
    assert_ne!(prep.session_id, first.session_id);
    assert_eq!(prep.unshared, keys(&[&ayse]), "only those still here get the new key");
    let after = post(&mut b, "after", "b-2", None);
    assert_eq!(session_of(&after), prep.session_id);
    assert!(ayse.read(&after).is_ok());
    assert!(mert.read(&after).is_err(), "the leaver holds only the old session");
}

#[test]
fn a_device_removed_from_a_member_also_rotates() {
    let mut b = bot("b-bot");
    let (mut phone, mut laptop) = (Seat::new("u-ayse"), Seat::new("u-ayse"));
    let first = share_all(&mut b, &mut [&mut phone, &mut laptop], T0);
    let prep = room_prepare(&mut b.store, &KEY, ROOM, &keys(&[&phone]), T0 + 1).unwrap();
    assert_eq!(prep.rotated, Some(Rotation::Departed));
    assert_ne!(prep.session_id, first.session_id);
}

#[test]
fn a_session_is_replaced_after_a_week_or_a_thousand_messages() {
    let mut b = bot("b-bot");
    let mut ayse = Seat::new("u-ayse");
    let first = share_all(&mut b, &mut [&mut ayse], T0);
    let just_before = room_prepare(&mut b.store, &KEY, ROOM, &keys(&[&ayse]), T0 + ROTATE_AFTER_MS - 1).unwrap();
    assert_eq!(just_before.rotated, None);
    let aged = room_prepare(&mut b.store, &KEY, ROOM, &keys(&[&ayse]), T0 + ROTATE_AFTER_MS).unwrap();
    assert_eq!(aged.rotated, Some(Rotation::Age));
    assert_ne!(aged.session_id, first.session_id);
    assert_eq!(aged.unshared.len(), 1, "a new session is shared again");

    let mut s = b.store.rooms.get(ROOM).unwrap().clone();
    s.sent = ROTATE_AFTER_MESSAGES;
    b.store.rooms.insert(ROOM.into(), s);
    let counted = room_prepare(&mut b.store, &KEY, ROOM, &keys(&[&ayse]), T0 + ROTATE_AFTER_MS + 1).unwrap();
    assert_eq!(counted.rotated, Some(Rotation::Count));
}

#[test]
fn a_key_request_resends_the_first_snapshot_once_per_window() {
    let mut b = bot("b-bot");
    let mut ayse = Seat::new("u-ayse");
    let prep = share_all(&mut b, &mut [&mut ayse], T0);
    let missed = post(&mut b, "the one she missed", "b-1", None);
    let _later = post(&mut b, "a later one", "b-2", None);
    ayse.inbound = None; // her key is lost

    let k = keys(&[&ayse]);
    let resent = room_key_request(&mut b.store, &KEY, ROOM, "u-ayse", Some(&prep.session_id), &k, &[], T0 + 5).unwrap();
    assert_eq!(ayse.take_shares(&resent), 1);
    assert!(ayse.read(&missed).is_ok(), "the snapshot from the first share opens the missed post");

    let again = room_key_request(&mut b.store, &KEY, ROOM, "u-ayse", None, &k, &[], T0 + 5 + ROOM_REQUEST_WINDOW_MS - 1);
    assert!(again.unwrap().is_empty(), "debounced");
    let later = room_key_request(&mut b.store, &KEY, ROOM, "u-ayse", None, &k, &[], T0 + 5 + ROOM_REQUEST_WINDOW_MS);
    assert_eq!(later.unwrap().len(), 1);
    let stale = room_key_request(&mut b.store, &KEY, ROOM, "u-ayse", Some("old"), &k, &[], T0 + 10 * ROOM_REQUEST_WINDOW_MS);
    assert!(stale.unwrap().is_empty(), "a rotated-away session is gone");
}

/// The host asks this before it claims a key: a request nothing would answer costs nothing.
#[test]
fn a_request_is_judged_before_any_key_is_claimed() {
    let mut b = bot("b-bot");
    let mut ayse = Seat::new("u-ayse");
    assert!(!room_key_request_due(&b.store, ROOM, "u-ayse", None, T0), "no session yet");
    let prep = share_all(&mut b, &mut [&mut ayse], T0);
    assert!(room_key_request_due(&b.store, ROOM, "u-ayse", None, T0));
    assert!(room_key_request_due(&b.store, ROOM, "u-ayse", Some(&prep.session_id), T0));
    assert!(!room_key_request_due(&b.store, ROOM, "u-ayse", Some("rotated-away"), T0));
    let k = keys(&[&ayse]);
    room_key_request(&mut b.store, &KEY, ROOM, "u-ayse", None, &k, &[], T0).unwrap();
    assert!(!room_key_request_due(&b.store, ROOM, "u-ayse", None, T0 + 1), "inside the window");
    assert!(room_key_request_due(&b.store, ROOM, "u-ayse", None, T0 + ROOM_REQUEST_WINDOW_MS));
}

#[test]
fn a_device_shared_with_later_reads_forward_only() {
    let mut b = bot("b-bot");
    let (mut ayse, mut mert) = (Seat::new("u-ayse"), Seat::new("u-mert"));
    share_all(&mut b, &mut [&mut ayse], T0);
    let early = post(&mut b, "before Mert", "b-1", None);
    // Mert joins: the same session goes on (nobody left), and his key starts from now.
    let prep = share_all(&mut b, &mut [&mut ayse, &mut mert], T0 + 1);
    assert_eq!(prep.rotated, None);
    assert_eq!(prep.unshared, keys(&[&mert]));
    let late = post(&mut b, "after Mert", "b-2", None);
    assert!(mert.read(&early).is_err(), "no earlier post");
    assert!(mert.read(&late).is_ok());
}

#[test]
fn an_unreachable_device_is_skipped_and_not_counted_as_shared() {
    let mut b = bot("b-bot");
    let mert = Seat::new("u-mert");
    let k = keys(&[&mert]);
    room_prepare(&mut b.store, &KEY, ROOM, &k, T0).unwrap();
    // No session with Mert and no key claimed for him.
    let effects = room_share(&mut b.store, &KEY, ROOM, "u-mert", &k, &[]).unwrap();
    assert!(effects.is_empty());
    let prep = room_prepare(&mut b.store, &KEY, ROOM, &k, T0 + 1).unwrap();
    assert_eq!(prep.unshared, k, "still owed his key");
}

#[test]
fn nothing_is_shared_or_posted_without_a_session() {
    let mut b = bot("b-bot");
    let mert = Seat::new("u-mert");
    let k = keys(&[&mert]);
    assert!(room_share(&mut b.store, &KEY, ROOM, "u-mert", &k, &[]).is_err());
    assert!(room_encrypt(&mut b.store, &KEY, ROOM, &room_text_payload("x", "b-1", None)).is_err());
    let asked = room_key_request(&mut b.store, &KEY, ROOM, "u-mert", None, &k, &[], T0);
    assert!(asked.unwrap().is_empty());
    room_prepare(&mut b.store, &KEY, ROOM, &k, T0).unwrap();
    room_forget(&mut b.store, ROOM);
    assert!(b.store.rooms.is_empty() && b.store.room_shares.is_empty());
}

#[test]
fn a_call_reaches_the_program_and_a_room_secret_is_never_taken() {
    let mut b = bot("b-bot");
    let mut ayse = Member::new("u-ayse");
    pair(&mut b, &mut ayse, T0);
    let call = ChatPayload::new(
        None,
        None,
        InnerMessage::BotCall {
            room_id: ROOM.into(),
            msg_uid: "loc-7".into(),
            body: "yarın kaçta?".into(),
            lang: Some("tr".into()),
            utc_offset_min: Some(180),
        },
    );
    let env = ayse.send(&call);
    let effects = crate::on_envelope(&mut b.store, &KEY, &b.id, &env, Some(&ayse.x_pub()), T0 + 1);
    assert!(effects.contains(&Effect::Update(crate::Inbound::Call {
        from: "u-ayse".into(),
        room_id: ROOM.into(),
        msg_uid: "loc-7".into(),
        body: "yarın kaçta?".into(),
        lang: Some("tr".into()),
        utc_offset_min: Some(180),
    })));

    let share = ChatPayload::new(
        None,
        None,
        InnerMessage::RoomKeyShare { room_id: ROOM.into(), session_id: "s".into(), session_key_b64: "k".into() },
    );
    let env = ayse.send(&share);
    let effects = crate::on_envelope(&mut b.store, &KEY, &b.id, &env, Some(&ayse.x_pub()), T0 + 2);
    assert!(matches!(effects[0], Effect::Ack { success: true, .. }), "acked, so it is not retried");
    assert!(effects.contains(&Effect::Update(crate::Inbound::Ignored("room_secret"))));
    assert!(b.store.rooms.is_empty() && b.store.room_shares.is_empty(), "and nothing was kept of it");
}
