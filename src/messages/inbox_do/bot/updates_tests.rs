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

/// H3: a file is its own kind, so a program that switches on `kind` and reads `message.text`
/// never takes a file's empty text for a message; what it reads names the file by `file_id` and
/// never carries the key or the `media_id`.
#[test]
fn a_file_update_names_each_file_and_carries_no_key() {
    let m = sezi_protocol::inner::FileManifest {
        v: 1,
        media_id: "media-secret-id".into(),
        key_b64: "KEY-MUST-NOT-LEAK".into(),
        nonce_b64: "NONCE-MUST-NOT-LEAK".into(),
        chunk_size: 65_536,
        size: 12_345,
        content_type: "application/pdf".into(),
        filename: format!("{}.pdf", "z".repeat(300)),
    };
    let files = [("f-1".to_string(), &m)];
    let u = file_update(7, "alice", None, Some("m-9"), Some("the minutes"), &serde_json::Value::Null, &files);
    let name: String = format!("{}.pdf", "z".repeat(300)).chars().take(MAX_FILE_NAME_CHARS).collect();
    assert_eq!(
        u,
        serde_json::json!({
            "kind": "file",
            "at": 7,
            "chat": { "type": "direct", "user_id": "alice" },
            "message": { "message_id": "m-9", "caption": "the minutes", "reply_to": null },
            "files": [{ "file_id": "f-1", "name": name, "mime": "application/pdf", "size": 12_345 }],
            "who": { "user_id": "alice" },
        })
    );
    let text = u.to_string();
    for secret in ["KEY-MUST-NOT-LEAK", "NONCE-MUST-NOT-LEAK", "media-secret-id"] {
        assert!(!text.contains(secret), "the update carries {secret}");
    }
    // A caption starting with a slash is not a command: a file is not a text.
    let u = file_update(7, "alice", None, None, Some("/durusma"), &serde_json::Value::Null, &files);
    assert!(u.get("command").is_none());
}

#[test]
fn a_message_update_carries_the_relays_who_and_never_the_senders() {
    let who = Who {
        user_id: "alice".into(),
        display_name: Some("Alice".into()),
        server_role: Some("member".into()),
    };
    let ext = serde_json::json!({ "reply": { "uid": "b-1", "by": "bot", "kind": "text", "text": "earlier" } });
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
    read_at(c, offset, i64::MIN, limit)
}

/// What a poll at `cutoff` (= now − the window) answers.
fn read_at(c: &Connection, offset: i64, cutoff: i64, limit: i64) -> Vec<i64> {
    let mut s = c.prepare(UPDATE_READ).unwrap();
    s.query_map(params![offset, cutoff, limit], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// H7: an idle bot's housekeeping runs only on a tick, so a row past its 24 h may still be in
/// the table when a poll comes. A poll never hands it out, below the offset or above it.
#[test]
fn a_poll_never_hands_out_an_update_past_its_window() {
    let c = db();
    c.query_row(UPDATE_PUSH, params!["{}", 1_000], |r| r.get::<_, i64>(0)).unwrap();
    c.query_row(UPDATE_PUSH, params!["{}", 5_000], |r| r.get::<_, i64>(0)).unwrap();
    let now = 1_000 + UPDATE_TTL_MS + 1;
    assert_eq!(read_at(&c, 0, now - UPDATE_TTL_MS, 100), vec![2], "1 is past 24 h");
    assert_eq!(read_at(&c, 5, now - UPDATE_TTL_MS, 100), vec![2], "nor below a wrong offset");
    assert_eq!(read_at(&c, 0, 1_000, 100), vec![1, 2], "at exactly 24 h it is still served");
}

/// H7: the alarm comes back when the oldest update or member's file is due to go, so retention
/// holds for a bot nobody polls and nobody writes to. NULL when nothing is kept.
#[test]
fn the_alarm_comes_back_when_the_oldest_update_or_file_is_due_to_go() {
    let c = db();
    for t in super::super::files::TABLES {
        c.execute_batch(t).unwrap();
    }
    let next = |c: &Connection| -> Option<i64> {
        c.query_row(RETENTION_NEXT, params![UPDATE_TTL_MS, UPDATE_TTL_MS], |r| r.get(0)).unwrap()
    };
    assert_eq!(next(&c), None, "nothing kept, no alarm");
    c.query_row(UPDATE_PUSH, params!["{}", 9_000], |r| r.get::<_, i64>(0)).unwrap();
    // One past the window: `UPDATE_EXPIRE` deletes rows strictly older than the cutoff.
    assert_eq!(next(&c), Some(9_000 + UPDATE_TTL_MS + 1));
    c.execute(super::super::files::FILE_PUT, params!["f-1", 1, "alice", "{}", 4_000]).unwrap();
    assert_eq!(next(&c), Some(4_000 + UPDATE_TTL_MS + 1), "a file's key goes on time too");
    // At that moment the housekeeping's own cutoff takes the file.
    c.execute(super::super::files::FILE_EXPIRE, [4_000 + UPDATE_TTL_MS + 1 - UPDATE_TTL_MS]).unwrap();
    assert_eq!(next(&c), Some(9_000 + UPDATE_TTL_MS + 1));
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

/// A program that sends an offset past anything it was handed (a clock as the offset, another
/// bot's counter, an off-by-a-thousand) must not destroy members' messages it never saw. Until
/// 2026-10-26 `offset` deleted every row below it, handed out or not.
#[test]
fn a_far_future_offset_deletes_nothing_the_program_was_never_handed() {
    let c = db();
    for i in 0..4 {
        c.query_row(UPDATE_PUSH, params![format!("{{\"n\":{i}}}"), 1_000 + i], |r| r.get::<_, i64>(0)).unwrap();
    }
    // The program was handed 1 and 2 (a poll's answer marks them), never 3 and 4.
    c.execute(UPDATE_MARK, params![9_999, 1, 2]).unwrap();
    c.execute(UPDATE_CONFIRM, [1_761_200_000_000_i64]).unwrap();
    let left: Vec<i64> = {
        let mut s = c.prepare("SELECT update_id FROM bot_updates ORDER BY update_id").unwrap();
        s.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(left, vec![3, 4], "only what the program was handed is confirmed");
    // What it was never handed is still served, though it sits below that offset.
    assert_eq!(read(&c, 1_761_200_000_000, 100), vec![3, 4]);
    // Once handed, the next offset past it confirms it as usual.
    c.execute(UPDATE_MARK, params![10_000, 3, 4]).unwrap();
    c.execute(UPDATE_CONFIRM, [5]).unwrap();
    assert!(read(&c, 5, 100).is_empty());
}

#[test]
fn a_call_names_its_room_and_the_callers_room_role_from_the_relay() {
    let who = Who { user_id: "alice".into(), display_name: Some("Alice".into()), server_role: Some("member".into()) };
    let room = CallRoom { id: "g-1", name: "Hukuk", role: "admin" };
    let u = call_update(5, "alice", Some(&who), &room, "loc-7", "yarın kaçta?", Some("tr"), Some(180));
    assert_eq!(
        u,
        serde_json::json!({
            "kind": "call",
            "at": 5,
            "chat": { "type": "room", "room_id": "g-1", "name": "Hukuk" },
            "message": { "message_id": "loc-7", "text": "yarın kaçta?", "reply_to": null,
                         "lang": "tr", "utc_offset_min": 180 },
            "who": { "user_id": "alice", "display_name": "Alice", "server_role": "member", "room_role": "admin" },
        })
    );
    let added = room_event_update("added", 6, "g-1", "Hukuk", Some(&serde_json::json!({"user_id": "bob"})));
    assert_eq!(added["kind"], "added");
    assert_eq!(added["chat"], serde_json::json!({ "type": "room", "room_id": "g-1", "name": "Hukuk" }));
    assert_eq!(added["who"]["user_id"], "bob");
}
