//! What a program may send, judged by the very functions `api.rs` calls.

use super::*;
use serde_json::json;

const ALICE: &str = "a0000000-0000-4000-8000-00000000000a";

fn body(v: Value) -> Vec<u8> {
    v.to_string().into_bytes()
}

#[test]
fn a_body_is_a_json_object_of_at_most_64_kib() {
    assert_eq!(parse_body(b""), Ok(json!({})), "no body reads as {{}}");
    assert_eq!(parse_body(b" \n"), Ok(json!({})));
    assert_eq!(parse_body(&body(json!({"a": 1}))), Ok(json!({"a": 1})));
    for bad in [&b"offset=5"[..], b"{", b"[1,2]", b"\"text\"", b"5", b"null"] {
        assert_eq!(parse_body(bad), Err((400, "bad-request")), "{}", String::from_utf8_lossy(bad));
    }
    let big = format!("{{\"text\":\"{}\"}}", "a".repeat(MAX_BODY_BYTES));
    assert_eq!(parse_body(big.as_bytes()), Err((413, "too-large")), "by what was read");
    assert!(body_too_large(Some(MAX_BODY_BYTES as u64 + 1)), "by what was announced, unread");
    assert!(!body_too_large(Some(MAX_BODY_BYTES as u64)));
    assert!(!body_too_large(None));
}

#[test]
fn the_longest_text_fits_even_when_every_character_is_escaped() {
    // 4,000 characters outside the BMP, each written as a JSON surrogate pair (12 bytes).
    let escaped = format!("{{\"chat\":{{\"user_id\":\"{ALICE}\"}},\"text\":\"{}\"}}", "\\ud83d\\ude00".repeat(4000));
    let v = parse_body(escaped.as_bytes()).expect("fits the cap");
    assert_eq!(parse_send(&v).map(|s| s.text.chars().count()), Ok(4000));
}

/// Until 2026-10-26 a field of the wrong type read as absent: `{"offset": "43"}` was offset 0, so
/// a program that sent its offset as a string never confirmed anything and read the same
/// updates for a day.
#[test]
fn a_field_of_the_wrong_type_is_refused_not_read_as_absent() {
    let q = |v: Value| parse_updates(&v);
    assert_eq!(q(json!({})), Ok(UpdatesQuery { offset: 0, timeout: 0, limit: 100 }));
    assert_eq!(q(json!({"offset": null, "timeout": null, "limit": null})), Ok(UpdatesQuery { offset: 0, timeout: 0, limit: 100 }));
    assert_eq!(q(json!({"offset": 43, "timeout": 25, "limit": 1})), Ok(UpdatesQuery { offset: 43, timeout: 25, limit: 1 }));
    for bad in [
        json!({"offset": "43"}),
        json!({"offset": 4.5}),
        json!({"offset": true}),
        json!({"timeout": "25"}),
        json!({"limit": [1]}),
        json!({"offset": -1}),
        json!({"timeout": 26}),
        json!({"timeout": -1}),
        json!({"limit": 0}),
        json!({"limit": 101}),
    ] {
        assert_eq!(q(bad.clone()), Err((400, "bad-request")), "{bad}");
    }
    // `setWebhook {"url": 5}` used to CLEAR the webhook.
    assert_eq!(parse_webhook(&json!({"url": 5})), Err((400, "bad-request")));
    assert_eq!(parse_webhook(&json!({"url": "https://x.example/h"})), Ok(Some("https://x.example/h")));
    for clears in [json!({}), json!({"url": null}), json!({"url": ""}), json!({"url": "  "})] {
        assert_eq!(parse_webhook(&clears), Ok(None), "{clears}");
    }
}

#[test]
fn a_send_is_judged_shape_then_buttons_then_text_then_a_direct_reply() {
    let send = |v: Value| parse_send(&v);
    let ok = send(json!({"chat": {"user_id": ALICE}, "text": "Merhaba  \n"})).unwrap();
    assert_eq!(
        ok,
        SendReq { chat: Chat::User(ALICE.into()), text: "Merhaba".into(), reply_to: None, client_id: None }
    );
    let room = send(json!({"chat": {"room_id": "g-1"}, "text": "x", "reply_to": "m-1"})).unwrap();
    assert_eq!((room.chat, room.reply_to.as_deref()), (Chat::Room("g-1".into()), Some("m-1")));
    let shape = (400, "bad-request");
    for (v, want) in [
        (json!({"text": "x"}), shape),
        (json!({"chat": ALICE, "text": "x"}), shape),
        (json!({"chat": {"user_id": ALICE}}), shape),
        (json!({"chat": {"user_id": ALICE}, "text": 5}), shape),
        (json!({"chat": {"user_id": 5}, "text": "x"}), shape),
        (json!({"chat": {}, "text": "x"}), shape),
        (json!({"chat": {"user_id": ALICE, "room_id": "g-1"}, "text": "x"}), shape),
        (json!({"chat": {"user_id": "short"}, "text": "x"}), shape),
        (json!({"chat": {"room_id": ""}, "text": "x"}), shape),
        (json!({"chat": {"room_id": "r".repeat(65)}, "text": "x"}), shape),
        (json!({"chat": {"room_id": "g-1"}, "text": "x", "reply_to": 7}), shape),
        (json!({"chat": {"room_id": "g-1"}, "text": "x", "reply_to": "m".repeat(129)}), shape),
        // Types first; which chat it names is judged after buttons and text (as before 2.1).
        (json!({"chat": {"user_id": 5}, "text": "x", "buttons": []}), shape),
        (json!({"chat": {}, "text": "x", "buttons": [[{"id": "a", "label": "A"}]]}), (400, "unsupported")),
        (json!({"chat": {"user_id": ALICE}, "text": "x", "buttons": []}), (400, "unsupported")),
        (json!({"chat": {"user_id": ALICE}, "text": "", "buttons": []}), (400, "unsupported")),
        (json!({"chat": {"user_id": ALICE}, "text": " \n\t"}), (400, "bad-text")),
        (json!({"chat": {"user_id": ALICE}, "text": "x".repeat(4001)}), (400, "bad-text")),
        (json!({"chat": {"user_id": ALICE}, "text": "", "reply_to": "m-1"}), (400, "bad-text")),
        (json!({"chat": {"user_id": ALICE}, "text": "x", "reply_to": "m-1"}), (400, "unsupported")),
        (json!({"chat": {"user_id": "short"}, "text": "x", "reply_to": "m-1"}), (400, "unsupported")),
    ] {
        assert_eq!(send(v.clone()), Err(want), "{v}");
    }
    assert!(send(json!({"chat": {"user_id": ALICE}, "text": "é".repeat(4000)})).is_ok(), "characters, not bytes");
    assert!(send(json!({"chat": {"user_id": ALICE}, "text": "x", "buttons": null, "reply_to": null})).is_ok());
}

#[test]
fn a_client_id_is_optional_and_a_short_plain_string() {
    let with = |id: Value| parse_send(&json!({"chat": {"user_id": ALICE}, "text": "x", "client_id": id}));
    assert_eq!(with(Value::Null).unwrap().client_id, None, "absent is fine: sending as before");
    for good in ["1", "hearing-2026-10-26:esas.42", &"a".repeat(64), "A_b.c:d-e"] {
        assert_eq!(with(json!(good)).unwrap().client_id.as_deref(), Some(good), "{good}");
    }
    for bad in [json!(""), json!("a".repeat(65)), json!("with space"), json!("ü"), json!("a/b"), json!(42)] {
        assert_eq!(with(bad.clone()), Err((400, "bad-request")), "{bad}");
    }
}

#[test]
fn only_an_ok_shaped_answer_of_the_inbox_reaches_the_program() {
    assert!(is_program_answer(200, br#"{"ok":true,"message_id":"b-1"}"#));
    assert!(is_program_answer(429, br#"{"ok":false,"error":"bot/rate-limited","retry_after":3}"#));
    assert!(is_program_answer(409, br#"{"ok":false,"error":"bot/webhook-active"}"#));
    for (status, body) in [
        (404, &b"not found"[..]),                           // an inbox no longer in bot mode
        (500, b"Error: bot inbox not initialized"),
        (500, br#"{"ok":false,"error":"bot/x"}"#),        // a 5xx is never the program's answer
        (200, b""),
        (200, br#"{"id":4,"delivered_live":true}"#),
        (200, br#"{"ok":"yes"}"#),
        (200, b"[]"),
    ] {
        assert!(!is_program_answer(status, body), "{status} {}", String::from_utf8_lossy(body));
    }
}

/// Every call into the bot's inbox reaches the program through `inbox_answer`, never verbatim.
#[test]
fn the_api_hands_the_program_no_raw_inbox_answer() {
    let api = include_str!("api.rs");
    assert!(!api.contains("passthrough("), "a raw inbox answer can reach the program");
    let calls = api.matches("super::bot_inbox(").count();
    assert_eq!(calls, 6, "the call budget, getUpdates, setWebhook, the two sends, and getFile");
    assert!(api.matches("inbox_answer(").count() >= calls, "each one is judged");
}

/// Every body `api.rs` reads goes through this module: nothing parses it a second, laxer way.
#[test]
fn the_api_reads_its_body_only_through_this_module() {
    let api = include_str!("api.rs");
    for lax in [".json().await", "unwrap_or(serde_json::json!({}))", "v.as_i64()", "v.as_str()"] {
        assert!(!api.contains(lax), "api.rs reads a field past api_input: {lax}");
    }
    let doors = ["input::parse_body(", "input::parse_updates(", "input::parse_send(", "input::parse_webhook(", "input::parse_get_file("];
    for door in doors {
        assert!(api.contains(door), "api.rs no longer calls {door}");
    }
}

/// `getFile {file_id}`: the id an update named, of the inbox's spelling; a missing, wrong-typed,
/// empty, over-long or oddly spelled one is refused before the inbox is asked.
#[test]
fn get_file_takes_one_file_id() {
    let id = "f-3f0a1c2e-0000-4000-8000-000000000001";
    assert_eq!(parse_get_file(&json!({ "file_id": id })), Ok(id));
    for bad in [
        json!({}),
        json!({ "file_id": null }),
        json!({ "file_id": 5 }),
        json!({ "file_id": "" }),
        json!({ "file_id": "x".repeat(MAX_FILE_ID_LEN + 1) }),
        json!({ "file_id": "media/abc" }),
        json!({ "file_id": "f 1" }),
    ] {
        assert_eq!(parse_get_file(&bad), Err((400, "bad-request")), "{bad}");
    }
}
