//! Who re-pairs, and how often: the lower id, once per 20 s per member.

use sezi_protocol::inner::{ChatPayload, InnerMessage};

use crate::testutil::{bot, pair, Member, KEY};
use crate::{on_delivery_failed, on_envelope, BotStore, Effect, REPAIR_WINDOW_MS};

fn text(body: &str) -> ChatPayload {
    ChatPayload::new(None, None, InnerMessage::Text { body: body.into() })
}

fn nack(remote_id: i64) -> Effect {
    Effect::Ack { remote_id, success: false, uid: None }
}

fn repair(user: &str) -> Effect {
    Effect::Repair { user_id: user.into() }
}

#[test]
fn a_lower_bot_repairs_a_lost_session_once_per_window() {
    let mut b = bot("user-a"); // "user-a" < "user-m": the bot is the lower id
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 0);
    b.store.sessions.clear();

    let t0 = 1_000_000;
    let e1 = m.send(&text("one"));
    assert_eq!(on_envelope(&mut b.store, &KEY, &b.id, &e1, None, t0), vec![nack(e1.remote_id), repair("user-m")]);
    let e2 = m.send(&text("two"));
    assert_eq!(
        on_envelope(&mut b.store, &KEY, &b.id, &e2, None, t0 + REPAIR_WINDOW_MS - 1),
        vec![nack(e2.remote_id)],
        "a second failure inside the window re-pairs nothing"
    );
    let e3 = m.send(&text("three"));
    assert_eq!(
        on_envelope(&mut b.store, &KEY, &b.id, &e3, None, t0 + REPAIR_WINDOW_MS),
        vec![nack(e3.remote_id), repair("user-m")]
    );
}

#[test]
fn a_higher_bot_waits_for_the_member_to_repair() {
    let mut b = bot("user-z");
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 0);
    b.store.sessions.clear();
    let e = m.send(&text("one"));
    assert_eq!(on_envelope(&mut b.store, &KEY, &b.id, &e, None, 5), vec![nack(e.remote_id)]);
}

/// A message key already used: on the higher side the session is healthy and stays current; on
/// the lower side it is retired and re-paired, as the kernel does.
#[test]
fn a_gap_keeps_the_session_on_the_higher_side_only() {
    for (bot_id, lower) in [("user-z", false), ("user-a", true)] {
        let mut b = bot(bot_id);
        let mut m = Member::new("user-m");
        pair(&mut b, &mut m, 0);
        let first = m.send(&text("one"));
        on_envelope(&mut b.store, &KEY, &b.id, &first, None, 10);

        let effects = on_envelope(&mut b.store, &KEY, &b.id, &first, None, 50_000);
        let current = b.store.current_session("user-m", &m.device).is_some();
        if lower {
            assert_eq!(effects, vec![nack(first.remote_id), repair("user-m")]);
            assert!(!current, "the lower side retires it");
        } else {
            assert_eq!(effects, vec![nack(first.remote_id)]);
            assert!(current, "the higher side keeps a healthy session");
            let next = m.send(&text("two"));
            let effects = on_envelope(&mut b.store, &KEY, &b.id, &next, None, 50_001);
            assert!(matches!(effects[0], Effect::Ack { success: true, .. }), "{effects:?}");
        }
    }
}

#[test]
fn delivery_failed_wipes_the_user_and_the_lower_bot_repairs() {
    let mut b = bot("user-a");
    let mut m = Member::new("user-m");
    pair(&mut b, &mut m, 0);
    assert_eq!(on_delivery_failed(&mut b.store, &b.id, "user-m", 100_000), vec![repair("user-m")]);
    assert!(b.store.sessions("user-m", &m.device).is_empty(), "archive included");
    assert!(
        on_delivery_failed(&mut b.store, &b.id, "user-m", 100_001).is_empty(),
        "inside the window"
    );

    let mut high = bot("user-z");
    let mut m2 = Member::new("user-m");
    pair(&mut high, &mut m2, 0);
    assert!(on_delivery_failed(&mut high.store, &high.id, "user-m", 100_000).is_empty());
    assert!(high.store.sessions("user-m", &m2.device).is_empty());
}
