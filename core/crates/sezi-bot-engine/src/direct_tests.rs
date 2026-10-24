//! Sealing to a member's devices: a PreKey only where no session is current.

use sezi_protocol::inner::InnerMessage;

use crate::testutil::{bot, delivered, pair, Member, KEY};
use crate::{devices_without_session, send_direct, send_pair_ack, text_payload, BotStore, Effect, PAIR_ACK_MARKER};

#[test]
fn a_device_with_a_session_gets_a_normal_frame_even_when_a_key_is_offered() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 0);
    let otks_before = b.store.account.clone();
    let offered = m.claim();
    let effects =
        send_direct(&mut b.store, &KEY, "user-m", &[m.keys()], &[offered], &text_payload("hi", "b-1"))
            .expect("send");
    let (payload, was_prekey) = m.receive(&delivered(&effects)[0]);
    assert!(!was_prekey, "never initiate a PreKey to a device that has a session");
    assert_eq!(payload.msg_uid.as_deref(), Some("b-1"));
    assert!(matches!(payload.inner, InnerMessage::Text { ref body } if body == "hi"));
    assert_eq!(b.store.account, otks_before);
}

#[test]
fn a_new_device_gets_a_prekey_from_its_claimed_key_and_reads_it() {
    let mut b = bot("user-b");
    let mut m = Member::new("user-m");
    let devices = [m.keys()];
    assert_eq!(devices_without_session(&b.store, "user-m", &devices), vec![m.device.clone()]);
    let claimed = [m.claim()];
    let effects =
        send_direct(&mut b.store, &KEY, "user-m", &devices, &claimed, &text_payload("hello", "b-2"))
            .expect("send");
    assert!(matches!(
        &effects[..],
        [Effect::Deliver { user_id, msg_uid: Some(uid), .. }] if user_id == "user-m" && uid == "b-2"
    ));
    let (payload, was_prekey) = m.receive(&delivered(&effects)[0]);
    assert!(was_prekey);
    assert!(matches!(payload.inner, InnerMessage::Text { ref body } if body == "hello"));
    assert!(devices_without_session(&b.store, "user-m", &devices).is_empty());

    // The member answers on that session; the bot reads it with the session it opened.
    let env = m.send(&text_payload("answer", "loc-1"));
    let effects = crate::on_envelope(&mut b.store, &KEY, &b.id, &env, None, 5);
    assert!(matches!(effects[0], Effect::Ack { success: true, .. }), "{effects:?}");
}

#[test]
fn every_device_is_reached_and_one_without_a_key_is_skipped() {
    let mut b = bot("user-b");
    let mut phone = Member::new("user-m");
    let mut laptop = Member::new("user-m");
    let tablet = Member::new("user-m");
    pair(&mut b, &mut phone, 0);
    let devices = [phone.keys(), laptop.keys(), tablet.keys()];
    assert_eq!(
        devices_without_session(&b.store, "user-m", &devices),
        vec![laptop.device.clone(), tablet.device.clone()]
    );
    let claimed = [laptop.claim()];
    let effects =
        send_direct(&mut b.store, &KEY, "user-m", &devices, &claimed, &text_payload("all", "b-3"))
            .expect("send");
    let to: Vec<_> = effects
        .iter()
        .map(|e| match e {
            Effect::Deliver { device_id, .. } => device_id.clone(),
            other => panic!("only deliveries: {other:?}"),
        })
        .collect();
    assert_eq!(to, vec![phone.device.clone(), laptop.device.clone()]);
    let env = delivered(&effects);
    assert!(!phone.receive(&env[0]).1);
    assert!(laptop.receive(&env[1]).1);
}

#[test]
fn nothing_reachable_is_refused() {
    let mut b = bot("user-b");
    let m = Member::new("user-m");
    let err = send_direct(&mut b.store, &KEY, "user-m", &[m.keys()], &[], &text_payload("x", "b-4"))
        .expect_err("no session and no key");
    assert!(err.to_string().contains("bot/no-device-reachable"), "{err}");
}

#[test]
fn the_pair_ack_is_the_kernel_marker_with_no_uid() {
    let mut b = bot("user-a");
    let mut m = Member::new("user-m");
    let claimed = [m.claim()];
    let effects = send_pair_ack(&mut b.store, &KEY, "user-m", &[m.keys()], &claimed).expect("send");
    assert!(matches!(&effects[..], [Effect::Deliver { msg_uid: None, .. }]));
    let (payload, was_prekey) = m.receive(&delivered(&effects)[0]);
    assert!(was_prekey, "a repair opens a fresh session");
    assert!(payload.msg_uid.is_none() && payload.thread_id.is_none() && payload.ext.is_null());
    assert!(matches!(payload.inner, InnerMessage::Text { ref body } if body == PAIR_ACK_MARKER));
    assert!(b.store.current_session("user-m", &m.device).is_some());
}
