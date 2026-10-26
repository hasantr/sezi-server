//! The bot's room half: whose calls it believes, whom it shares with, and what a round may spend.
//! The D1 statements run on the real schema (`test_schema::full_schema`, foreign keys ON).

use super::*;
use rusqlite::{params, Connection};

const NOW: i64 = 1_761_200_000;

fn user(db: &Connection, id: &str, kind: &str) {
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, display_name, created_at, kind)
         VALUES (?1, ?1 || '@example.test', X'01', ?1, ?2, ?3)",
        params![id, NOW, kind],
    )
    .unwrap();
}

fn member(db: &Connection, room: &str, id: &str, role: &str, status: &str) {
    db.execute(
        "INSERT INTO group_members (group_id, user_id, role, joined_at, status) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![room, id, role, NOW, status],
    )
    .unwrap();
}

fn device(db: &Connection, user: &str, device: &str, revoked: Option<i64>) {
    db.execute(
        "INSERT INTO devices (user_id, device_id, role, ed_pub, x_pub, label, added_at, revoked_at)
         VALUES (?1, ?2, 'primary', X'0A', X'0B', NULL, ?3, ?4)",
        params![user, device, NOW, revoked],
    )
    .unwrap();
}

/// Two rooms; the bot is in "g-law" only. Ayşe is its admin, Mert a member, Pınar only invited,
/// Can left long ago (no row). Elif is a member of "g-other", where the bot is not.
fn setup() -> Connection {
    let db = crate::test_schema::full_schema();
    for (id, kind) in [("ayse", "human"), ("mert", "human"), ("pinar", "human"), ("elif", "human"), ("bot", "bot"), ("gone", "bot")] {
        user(&db, id, kind);
    }
    for (bot, name, deleted) in [("bot", "Kâtip", None), ("gone", "Eski", Some(NOW))] {
        db.execute(
            "INSERT INTO bots (bot_id, name, created_by, created_at, deleted_at) VALUES (?1, ?2, 'ayse', ?3, ?4)",
            params![bot, name, NOW, deleted],
        )
        .unwrap();
    }
    for (room, name) in [("g-law", "Hukuk"), ("g-other", "Arşiv")] {
        db.execute(
            "INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES (?1, ?2, 'ayse', ?3, ?3)",
            params![room, name, NOW],
        )
        .unwrap();
    }
    member(&db, "g-law", "ayse", "owner", "active");
    member(&db, "g-law", "mert", "member", "active");
    member(&db, "g-law", "pinar", "member", "pending");
    member(&db, "g-other", "elif", "owner", "active");
    for (room, bot) in [("g-law", "bot"), ("g-other", "gone")] {
        db.execute(
            "INSERT INTO group_bots (group_id, bot_id, added_by, added_at) VALUES (?1, ?2, 'ayse', ?3)",
            params![room, bot, NOW],
        )
        .unwrap();
    }
    device(&db, "ayse", "a1", None);
    device(&db, "ayse", "a2", Some(NOW)); // removed
    device(&db, "mert", "m1", None);
    device(&db, "pinar", "p1", None);
    db
}

fn rooms_for(db: &Connection, bot: &str, senders: &[&str]) -> BotRooms {
    let list = serde_json::to_string(senders).unwrap();
    let mut st = db.prepare(CALL_ROOMS_SQL).unwrap();
    let rows = st
        .query_map(params![bot, list], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    BotRooms::from_rows(rows)
}

#[test]
fn a_call_is_believed_only_from_an_active_member_of_one_of_the_bots_rooms() {
    let db = setup();
    let rooms = rooms_for(&db, "bot", &["ayse", "mert", "pinar", "elif", "can"]);
    assert_eq!(rooms.caller("g-law", "ayse"), Some(("Hukuk", "owner")));
    assert_eq!(rooms.caller("g-law", "mert"), Some(("Hukuk", "member")));
    assert_eq!(rooms.caller("g-law", "pinar"), None, "an invitee is not a member yet");
    assert_eq!(rooms.caller("g-law", "can"), None, "nobody in the room");
    assert_eq!(rooms.caller("g-other", "elif"), None, "a room the bot is not in");
    // The room is known even when no sender of this batch is in it.
    let quiet = rooms_for(&db, "bot", &["elif"]);
    assert!(quiet.0.contains_key("g-law") && quiet.caller("g-law", "elif").is_none());
    // A deleted bot is in no room, whatever rows are left.
    assert!(rooms_for(&db, "gone", &["elif"]).0.is_empty());
}

#[test]
fn the_key_goes_to_active_members_live_devices_only() {
    let db = setup();
    let mut st = db.prepare(ROOM_DEVICES_SQL).unwrap();
    let rows: Vec<(String, String)> = st
        .query_map(params!["g-law", "bot"], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows, vec![("ayse".into(), "a1".into()), ("mert".into(), "m1".into())]);
}

#[test]
fn the_room_round_leaves_the_drain_its_floor() {
    use super::super::builtin_policy::{drain_budget, TICK_PURSE};
    for round in 0..=TICK_PURSE + 5 {
        let room = room_budget(round);
        assert!(room <= ROOM_ROUND_MAX, "round {round}");
        if round + DRAIN_FLOOR <= TICK_PURSE {
            assert!(drain_budget(round + room) >= DRAIN_FLOOR, "round {round}");
        } else {
            assert_eq!(room, 0, "round {round}: nothing left for rooms");
        }
    }
    assert_eq!(room_budget(0), ROOM_ROUND_MAX);
    assert_eq!(room_budget(TICK_PURSE), 0);
}

#[test]
fn a_room_send_row_round_trips_and_an_old_one_reads_as_nobody_done() {
    let row = RoomSendBody { room_id: "g".into(), envelope_b64: "e".into(), to: vec!["a".into()], done: vec![] };
    let json = serde_json::to_string(&row).unwrap();
    assert_eq!(serde_json::from_str::<RoomSendBody>(&json).unwrap(), row);
    let bare: RoomSendBody = serde_json::from_str(r#"{"room_id":"g","envelope_b64":"e","to":["a"]}"#).unwrap();
    assert!(bare.done.is_empty());
}

/// The body of `fn name(` in `src`, to the end of its block.
fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src.find(&format!("fn {name}(")).expect(name);
    &src[start..start + src[start..].find("\n    }\n").expect("end")]
}

/// What makes "a removed bot's next post is impossible" true at source level: every step that
/// sends into a room asks the gate (`group_bots`, the bot on) first.
#[test]
fn every_send_into_a_room_asks_the_gate_first() {
    let room = include_str!("room.rs");
    let send = include_str!("room_send.rs");
    let asks = include_str!("room_asks.rs");
    for (src, f, gate_call) in [
        (room, "bot_room_post", "bot_room_gate("),
        (send, "bot_send_room_chunk", "bot_room_gate("),
        (asks, "bot_room_ask", "ASK_GATE_SQL"),
    ] {
        let b = fn_body(src, f);
        let gate = b.find(gate_call).unwrap_or_else(|| panic!("{f} never asks the gate"));
        for step in ["room_share(", "room_encrypt(", "notify_members(", "room_key_request(", "bot_claim_keys("] {
            if let Some(at) = b.find(step) {
                assert!(gate < at, "{f}: {step} before the gate");
            }
        }
    }
    let api = include_str!("../../../bots/api.rs");
    let send = &api[api.find("if let Some(room_id) = room").expect("the room branch")..];
    assert!(send.find("is_room_bot(").unwrap() < send.find("/bot/api").unwrap());
}

/// A room event during a post's awaits: after EVERY await, the post checks the room's generation
/// before it writes a session or a share (review, 2026-10-26: a removal mid-claim re-created the
/// session and queued key shares into a room the bot had left).
#[test]
fn a_post_writes_nothing_after_an_await_its_room_changed_across() {
    let b = fn_body(include_str!("room.rs"), "bot_room_post");
    let mut rest = b;
    let mut awaits = 0;
    while let Some(at) = rest.find(".await?") {
        awaits += 1;
        let after = &rest[at..];
        let check = after.find("moved(self)").unwrap_or(usize::MAX);
        for write in ["room_prepare(", "room_share(", "room_encrypt(", "bot_queue_room_shares("] {
            if let Some(w) = after.find(write) {
                assert!(check < w, "a write ({write}) follows await #{awaits} with no generation check");
            }
        }
        rest = &after[".await?".len()..];
    }
    assert_eq!(awaits, 3, "the gate, the devices and the claims");
    let event = fn_body(include_str!("room.rs"), "bot_room_event");
    assert!(event.find("room_gen_key").unwrap() < event.find("bot_room_drop").unwrap());
}

#[test]
fn the_gate_tells_on_off_and_out_apart() {
    let db = setup();
    let gate = |room: &str, bot: &str| -> RoomGate {
        let enabled: Option<i64> = db.query_row(ROOM_GATE_SQL, params![room, bot], |r| r.get(0)).ok();
        RoomGate::of(enabled)
    };
    assert_eq!(gate("g-law", "bot"), RoomGate::On);
    assert_eq!(gate("g-other", "bot"), RoomGate::Out, "not a bot of that room");
    assert_eq!(gate("g-other", "gone"), RoomGate::Out, "deleted");
    db.execute("UPDATE bots SET disabled_at = ?1 WHERE bot_id = 'bot'", [NOW]).unwrap();
    assert_eq!(gate("g-law", "bot"), RoomGate::Off, "off keeps its rooms, and waits");

    let ask = |user: &str| -> (Option<i64>, i64) {
        db.query_row(super::super::room_asks::ASK_GATE_SQL, params!["g-law", "bot", user], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    };
    assert_eq!(ask("mert"), (Some(0), 1), "off; Mert is a member");
    db.execute("UPDATE bots SET disabled_at = NULL WHERE bot_id = 'bot'", []).unwrap();
    assert_eq!(ask("mert"), (Some(1), 1));
    assert_eq!(ask("pinar"), (Some(1), 0), "an invitee is no member");
    let other: (Option<i64>, i64) = db
        .query_row(super::super::room_asks::ASK_GATE_SQL, params!["g-other", "bot", "elif"], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!(other, (None, 1), "a room the bot is not in");
}

/// Everything owed for a room the bot left goes with it; other rooms' and 1:1 frames stay.
#[test]
fn leaving_a_room_drops_its_owed_frames_only() {
    use super::super::outbox::{share_still_current, OUTBOX_DROP_ROOM, OUTBOX_PUSH, OUTBOX_WAKE_ROOM_SENDS};
    let c = Connection::open_in_memory().unwrap();
    for t in super::super::store::TABLES {
        c.execute_batch(t).unwrap();
    }
    for (kind, body) in [
        ("notify", r#"{"user_id":"u","room_id":"g","session_id":"s"}"#),
        ("room_send", r#"{"room_id":"g","envelope_b64":"e","to":[]}"#),
        ("notify", r#"{"user_id":"u","room_id":"h"}"#),
        ("notify", r#"{"user_id":"u","msg_uid":"b-1"}"#),
        ("forward_read", r#"{"to":"u","payload":{}}"#),
    ] {
        c.execute(OUTBOX_PUSH, params![kind, body, 1, 1]).unwrap();
    }
    c.execute(OUTBOX_DROP_ROOM, ["g"]).unwrap();
    let left: i64 = c.query_row("SELECT COUNT(*) FROM bot_outbox", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 3);
    c.execute(OUTBOX_PUSH, params!["room_send", r#"{"room_id":"h"}"#, 99, 1]).unwrap();
    c.execute(OUTBOX_WAKE_ROOM_SENDS, [5]).unwrap();
    let next: i64 = c.query_row("SELECT next_at FROM bot_outbox WHERE kind = 'room_send'", [], |r| r.get(0)).unwrap();
    assert_eq!(next, 5, "a held post goes when the bot is back on");

    assert!(share_still_current(None, |_| None), "a 1:1 frame always goes");
    assert!(share_still_current(Some("g"), |_| Some("s2".into())), "a rotated session's share still goes");
    assert!(!share_still_current(Some("g"), |_| None), "a room left: dropped at send time");
}

/// A bot's deletion removes every room session it held: the delete purges its inbox, and the
/// purge deletes the whole DO storage (review item 5, closed by evidence).
#[test]
fn a_deleted_bot_keeps_no_room_session() {
    let admin = include_str!("../../../bots/admin.rs");
    let delete = &admin[admin.find("pub async fn delete(").unwrap()..];
    assert!(delete.contains("purge_account_inbox("), "the delete purges the bot's inbox");
    let inbox = include_str!("../mod.rs");
    let purge = &inbox[inbox.find("path == \"/purge-account\"").unwrap()..];
    assert!(purge[..purge.find("return").unwrap()].contains("delete_all()"), "and the purge deletes everything");
}
