//! The update's shape and `getUpdates`' SQL (rusqlite, the `dedup_sql_tests` style).

use super::*;
use rusqlite::{params, Connection};

#[test]
fn a_command_is_a_slash_name_at_the_very_start() {
    assert_eq!(parse_command("/durusma yarın 10:00"), Some(("durusma".into(), "yarın 10:00".into())));
    assert_eq!(parse_command("/Start"), Some(("start".into(), String::new())));
    assert_eq!(parse_command("/hatirlat@Hatirlatici  her gün"), Some(("hatirlat".into(), "her gün".into())));
    assert_eq!(parse_command("/gün_özeti"), Some(("gün_özeti".into(), String::new())));
    assert_eq!(parse_command("hello /start"), None, "not at the start");
    assert_eq!(parse_command("/"), None);
    assert_eq!(parse_command("/ start"), None);
    assert_eq!(parse_command("/a-b"), None, "a dash is not part of a name");
    assert_eq!(parse_command(&format!("/{}", "x".repeat(33))), None, "at most 32");
}

#[test]
fn a_message_update_carries_the_relays_who_and_never_the_senders() {
    let who = Who {
        user_id: "alice".into(),
        display_name: Some("Alice".into()),
        server_role: Some("member".into()),
    };
    let ext = serde_json::json!({ "reply": { "msg_uid": "b-1", "author": "bot" } });
    let u = message_update(1_761_200_000_000, "alice", Some(&who), Some("m-9"), "/ara kitap", &ext);
    assert_eq!(
        u,
        serde_json::json!({
            "kind": "message",
            "at": 1_761_200_000_000_i64,
            "chat": { "type": "direct", "user_id": "alice" },
            "message": { "message_id": "m-9", "text": "/ara kitap", "reply_to": "b-1" },
            "command": { "name": "ara", "args": "kitap" },
            "who": { "user_id": "alice", "display_name": "Alice", "server_role": "member" },
        })
    );
    let bare = message_update(1, "bob", None, None, "hi", &serde_json::Value::Null);
    assert_eq!(bare["who"], serde_json::json!({ "user_id": "bob" }));
    assert!(bare.get("command").is_none());
    assert_eq!(bare["message"]["reply_to"], serde_json::Value::Null);
}

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    for t in super::super::store::TABLES {
        c.execute_batch(t).unwrap();
    }
    c
}

fn read(c: &Connection, offset: i64, limit: i64) -> Vec<i64> {
    let mut s = c.prepare(UPDATE_READ).unwrap();
    s.query_map(params![offset, limit], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn an_offset_confirms_and_deletes_everything_below_it() {
    let c = db();
    for i in 0..5 {
        c.query_row(UPDATE_PUSH, params![format!("{{\"n\":{i}}}"), 1_000 + i], |r| r.get::<_, i64>(0)).unwrap();
    }
    assert_eq!(read(&c, 0, 100), vec![1, 2, 3, 4, 5]);
    assert_eq!(read(&c, 0, 2), vec![1, 2], "the limit holds");
    c.execute(UPDATE_MARK, params![9_999, 0, 2]).unwrap();
    let marked: i64 = c
        .query_row("SELECT COUNT(*) FROM bot_updates WHERE delivered_at = 9999", [], |r| r.get(0))
        .unwrap();
    assert_eq!(marked, 2);
    c.execute(UPDATE_CONFIRM, [3]).unwrap();
    assert_eq!(read(&c, 3, 100), vec![3, 4, 5], "1 and 2 are confirmed and gone");
    assert_eq!(read(&c, 0, 100), vec![3, 4, 5]);
    // A new update after a confirm keeps counting up: ids are never reused.
    c.query_row(UPDATE_PUSH, params!["{}", 2_000], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(read(&c, 3, 100), vec![3, 4, 5, 6]);
}

#[test]
fn updates_older_than_the_window_expire() {
    let c = db();
    c.query_row(UPDATE_PUSH, params!["{}", 1_000], |r| r.get::<_, i64>(0)).unwrap();
    c.query_row(UPDATE_PUSH, params!["{}", 1_000 + UPDATE_TTL_MS], |r| r.get::<_, i64>(0)).unwrap();
    c.execute(UPDATE_EXPIRE, [1_000 + UPDATE_TTL_MS - 1]).unwrap();
    assert_eq!(read(&c, 0, 100), vec![2]);
}
