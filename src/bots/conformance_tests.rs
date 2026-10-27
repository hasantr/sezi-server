//! The bot API's conformance suite (docs/WORK_PLAN.md 2.2): `docs/BOTS_BUILD.md` §2.5 is what the
//! code does, and `tools/bots/README.md` — the program's reference — says the same.
//!
//! What a host test can reach of a Worker handler is its pure parts and its source, so the suite
//! holds three things together:
//! - **the tables**: every documented method has its arm in `api.rs` and nothing else does; every
//!   error code the program can be answered — each `(status, "code")` the program's path writes —
//!   is a row of §2.5's error table and of the README's, with the same status, and vice versa;
//! - **the answers**: each method's answer body, built by `api_answer.rs`, has the documented shape;
//! - **the order of the doors**: the key before everything, `bot/disabled` before any method.
//!
//! Each method's request validation is `api_input_tests.rs`; the SQL behind `getUpdates`, the send
//! limits, idempotent sending and who a bot may write to are `updates_tests.rs`,
//! `send_guard_tests.rs` and `send_replay_tests.rs` (in `inbox_do/bot/`) and
//! `provision_tests.rs::a_bot_writes_only_to_unblocked_humans`.

use super::api_answer;
use super::api_input::*;
use serde_json::json;
use std::collections::BTreeSet;

const BUILD_DOC: &str = include_str!("../../../docs/BOTS_BUILD.md");
const README: &str = include_str!("../../../tools/bots/README.md");

/// The methods a program can call today (Phases 1–3; Phase 4's are documented as not built).
const METHODS: [&str; 6] = ["getMe", "getUpdates", "sendMessage", "setWebhook", "deleteWebhook", "getFile"];

/// Every source file on the program's path: the Worker's door and the bot inbox's answers to it.
/// Not the owner's surface (`admin.rs`, `builtin.rs`: `not-builtin` is the owner page's own code).
const PROGRAM_PATH: [(&str, &str); 11] = [
    ("bots/api.rs", include_str!("api.rs")),
    ("bots/api_input.rs", include_str!("api_input.rs")),
    ("bots/key_brake.rs", include_str!("key_brake.rs")),
    ("inbox_do/bot/api_budget.rs", include_str!("../messages/inbox_do/bot/api_budget.rs")),
    ("inbox_do/bot/mod.rs", include_str!("../messages/inbox_do/bot/mod.rs")),
    ("inbox_do/bot/send.rs", include_str!("../messages/inbox_do/bot/send.rs")),
    ("inbox_do/bot/deliver.rs", include_str!("../messages/inbox_do/bot/deliver.rs")),
    ("inbox_do/bot/updates.rs", include_str!("../messages/inbox_do/bot/updates.rs")),
    ("inbox_do/bot/room.rs", include_str!("../messages/inbox_do/bot/room.rs")),
    ("inbox_do/bot/send_guard.rs", include_str!("../messages/inbox_do/bot/send_guard.rs")),
    ("inbox_do/bot/files.rs", include_str!("../messages/inbox_do/bot/files.rs")),
];

/// Every `(DDD, "code")` in `src`: `bot_err(403, "disabled")`, `Err((400, "bad-text"))`.
fn code_pairs(src: &str) -> Vec<(u16, String)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(at) = src[i..].find(", \"") {
        let at = i + at;
        i = at + 3;
        if at < 4 || b[at - 4] != b'(' || !b[at - 3..at].iter().all(u8::is_ascii_digit) {
            continue;
        }
        let Some(end) = src[i..].find('"') else { break };
        let code = &src[i..i + end];
        if code.bytes().all(|c| c.is_ascii_lowercase() || c == b'-') {
            out.push((src[at - 3..at].parse().unwrap(), code.to_string()));
        }
    }
    out
}

/// The rows `| \`bot/<code>\` | <status> | … |` of a Markdown table.
fn doc_codes(doc: &str) -> BTreeSet<(u16, String)> {
    doc.lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("| `bot/")?;
            let (code, rest) = rest.split_once("` | ")?;
            let status = rest.split(' ').next()?.parse().ok()?;
            Some((status, code.to_string()))
        })
        .collect()
}

/// §2.5 of the build doc, up to §2.6.
fn section_2_5() -> &'static str {
    let start = BUILD_DOC.find("### 2.5 ").expect("§2.5");
    let end = BUILD_DOC[start..].find("### 2.6 ").expect("§2.6");
    &BUILD_DOC[start..start + end]
}

fn source_codes() -> BTreeSet<(u16, String)> {
    let mut codes: BTreeSet<_> = PROGRAM_PATH.iter().flat_map(|(_, src)| code_pairs(src)).collect();
    // `rate-limited` is built with its `retry_after` (`api_answer::rate_limited`), not by
    // `bot_err`: the status sits beside it in `api.rs`'s one builder, which the send limits
    // (`send_guard.rs`), the call budget and the wrong-key brake all answer with.
    let api = PROGRAM_PATH.iter().find(|(f, _)| f.ends_with("bots/api.rs")).unwrap().1;
    assert!(api.contains("api_answer::rate_limited(retry_after_s))?.with_status(429)"));
    let guard = PROGRAM_PATH.iter().find(|(f, _)| f.ends_with("send_guard.rs")).unwrap().1;
    assert!(guard.contains("crate::bots::api::rate_limited(retry_after_s)"));
    codes.insert((429, "rate-limited".into()));
    codes
}

#[test]
fn the_scanner_finds_what_it_should() {
    let src = r#"bot_err(403, "disabled"); Err((400, "bad-text")); json_err(400, "bad_request"); f(1, "x")"#;
    assert_eq!(code_pairs(src), vec![(403, "disabled".into()), (400, "bad-text".into())]);
    assert_eq!(doc_codes("| `bot/x` | 409 | y |\n| `bot/z-w` | 400 | v |\n"), [(400, "z-w".into()), (409, "x".into())].into());
}

/// Every code the program can be answered is in §2.5's table, with its status, and the table
/// holds no code the program can never see.
#[test]
fn every_error_code_is_documented_with_its_status_and_nothing_else_is() {
    let code = source_codes();
    let doc = doc_codes(section_2_5());
    assert_eq!(code, doc, "§2.5's error table and the code disagree");
    // One status per code: a program may switch on either.
    let names: BTreeSet<_> = code.iter().map(|(_, c)| c).collect();
    assert_eq!(names.len(), code.len(), "a code answered with two statuses: {code:?}");
}

#[test]
fn the_programs_readme_lists_the_same_codes() {
    assert_eq!(doc_codes(README), doc_codes(section_2_5()), "tools/bots/README.md and §2.5 disagree");
}

/// The method table, the dispatch and the README name the same methods.
#[test]
fn every_documented_method_is_dispatched_and_nothing_else_is() {
    let api = include_str!("api.rs");
    let dispatch = &api[api.find("pub async fn dispatch(").expect("dispatch")..];
    let dispatch = &dispatch[..dispatch.find("\n}\n").expect("end")];
    let arms: BTreeSet<&str> = dispatch
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.split_once("\" =>").map(|(m, _)| m))
        .collect();
    assert_eq!(arms, METHODS.into_iter().collect(), "api.rs dispatches other methods than §2.5 lists");
    let doc = section_2_5();
    for m in METHODS {
        assert!(doc.contains(&format!("| `{m}` |")), "§2.5 has no row for {m}");
        assert!(README.contains(&format!("### `{m}`")), "the README does not document {m}");
    }
}

/// The key is checked before anything, and a turned-off bot answers `bot/disabled` to every
/// method — before its body is even read.
#[test]
fn the_key_then_disabled_then_the_body_then_the_method() {
    let api = include_str!("api.rs");
    let d = &api[api.find("pub async fn dispatch(").unwrap()..];
    let at = |s: &str| d.find(s).unwrap_or_else(|| panic!("{s}"));
    assert!(at("token::authenticate(") < at("\"unauthorized\""));
    assert!(at("\"unauthorized\"") < at("\"disabled\""));
    assert!(at("\"disabled\"") < at("read_body("));
    assert!(at("read_body(") < at("match method.as_str()"));
    // The wrong-key brake before the lookup; the call budget after `disabled`, before the body.
    assert!(at("key_brake::check(") < at("token::authenticate("));
    assert!(at("\"disabled\"") < at("take_call(") && at("take_call(") < at("read_body("));
}

#[test]
fn every_answer_has_its_documented_shape() {
    assert_eq!(api_answer::error("disabled"), json!({"ok": false, "error": "bot/disabled"}));
    assert_eq!(
        api_answer::rate_limited(7),
        json!({"ok": false, "error": "bot/rate-limited", "retry_after": 7})
    );
    // getMe → {ok, bot:{bot_id, name, about}}
    assert_eq!(
        api_answer::me("b-id", "Duruşma", None),
        json!({"ok": true, "bot": {"bot_id": "b-id", "name": "Duruşma", "about": null}})
    );
    // getUpdates → {ok, updates:[Update]}, each with its update_id.
    let stored = [(41, r#"{"kind":"message","at":1}"#.to_string()), (42, "not json".into()), (43, "[1]".into())];
    assert_eq!(
        api_answer::updates(stored),
        json!({"ok": true, "updates": [{"update_id": 41, "kind": "message", "at": 1}]})
    );
    assert_eq!(api_answer::updates([]), json!({"ok": true, "updates": []}));
    // sendMessage → {ok, message_id}; a repeat under its client_id → {ok, message_id, duplicate}.
    assert_eq!(api_answer::sent("b-1"), json!({"ok": true, "message_id": "b-1"}));
    assert_eq!(api_answer::duplicate("b-1"), json!({"ok": true, "message_id": "b-1", "duplicate": true}));
    // setWebhook → {ok, webhook_secret}; deleteWebhook (or a clearing setWebhook) → {ok}.
    assert_eq!(api_answer::webhook(Some("ab")), json!({"ok": true, "webhook_secret": "ab"}));
    assert_eq!(api_answer::webhook(None), json!({"ok": true}));
    // Every answer the program can read is built here, never inline. `deliver.rs` has the one
    // exception, the owner's "Dene" (`bot_ping`, answered to the owner's page, not a program).
    for (file, src) in PROGRAM_PATH {
        let inline = src.matches("\"ok\": true").count() + src.matches("\"ok\": false").count();
        let allowed = usize::from(file.ends_with("deliver.rs"));
        assert_eq!(inline, allowed, "{file} builds an answer past api_answer.rs");
    }
    let deliver = include_str!("../messages/inbox_do/bot/deliver.rs");
    let ping = &deliver[deliver.find("async fn bot_ping(").unwrap()..];
    assert!(ping[..ping.find("\n    }\n").unwrap()].contains("\"ok\": true, \"update_id\""));
}

/// The numbers §2.5 and the README promise are the code's.
#[test]
fn the_documented_limits_are_the_codes() {
    assert_eq!(MAX_BODY_BYTES, 64 * 1024);
    assert_eq!(MAX_TEXT_CHARS, 4000);
    assert_eq!((MAX_POLL_SECS, MAX_LIMIT), (25, 100));
    assert_eq!((MAX_REPLY_TO_LEN, MAX_CLIENT_ID_LEN, MAX_ROOM_ID_LEN), (128, 64, 64));
    let guard = include_str!("../messages/inbox_do/bot/send_guard.rs");
    assert!(guard.contains("SENDS_PER_MINUTE: i64 = 60;"));
    assert!(guard.contains("SENDS_PER_CHAT_PER_MINUTE: i64 = 30;"));
    let replay = include_str!("../messages/inbox_do/bot/send_replay.rs");
    assert!(replay.contains("CLIENT_ID_TTL_MS: i64 = 24 * 3600 * 1000;"));
    assert!(replay.contains("WAIT_FOR_FIRST_MS: i64 = 10_000;"));
    // Every call's budget, and the wrong-key brake.
    let budget = include_str!("../messages/inbox_do/bot/api_budget.rs");
    assert!(budget.contains("BURST: i64 = 60;") && budget.contains("PER_SECOND: i64 = 5;"));
    let brake = include_str!("key_brake.rs");
    assert!(brake.contains("MISSES_PER_MINUTE: u32 = 20;") && brake.contains("WINDOW_S: i64 = 60;"));
    for doc in [section_2_5(), README] {
        for promise in ["300 calls a minute", "burst of 60", "20 refused keys a minute"] {
            assert!(doc.contains(promise), "the call budget {promise:?} is not stated");
        }
    }
    // What one member, and everybody, may leave waiting in a program bot's queue.
    let backlog = include_str!("../messages/inbox_do/bot/backlog.rs");
    assert!(backlog.contains("PER_SENDER: i64 = 100;") && backlog.contains("PER_BOT: i64 = 2_000;"));
    assert!(backlog.contains("NOTICE_EVERY_MS: i64 = 10 * 60_000;"));
    for doc in [section_2_5(), README] {
        for promise in ["100", "2,000", "10 minutes"] {
            assert!(doc.contains(promise), "the queue cap {promise:?} is not stated");
        }
    }
    // A poison update is set aside at its fifth failure, and the docs say so.
    let order = include_str!("../messages/inbox_do/bot/deliver_order.rs");
    assert!(order.contains("ASIDE_AFTER: i64 = 5;"));
    for doc in [section_2_5(), README] {
        assert!(doc.contains("failed 5 times") && doc.contains("arrive late"), "the set-aside rule is not stated");
    }
    // A member's file (H3): what a bot reads, for how long, and how often.
    assert_eq!(crate::media::bot_access::MAX_BOT_FILE_BYTES, 10 * 1024 * 1024);
    let files = include_str!("../messages/inbox_do/bot/files.rs");
    assert!(files.contains("READS_PER_MINUTE: i64 = 20;"));
    assert!(files.contains("FILE_EXPIRE") && files.contains("UPDATE_TTL_MS"));
    assert_eq!(MAX_FILE_ID_LEN, 64);
    for doc in [section_2_5(), README] {
        for promise in ["10 MiB", "20 `getFile`s a minute", "24 h"] {
            assert!(doc.contains(promise), "the file rule {promise:?} is not stated");
        }
    }
    for doc in [section_2_5(), README] {
        for promise in ["64 KiB", "4,000", "0..25", "1..100", "128 bytes", "60 `sendMessage`s a minute", "30"] {
            assert!(doc.contains(promise), "{promise:?} is not stated");
        }
    }
}

/// The README's Apps Script reproduces the relay's fixed signing vector, compares the signature
/// in constant time, and refuses a stale `ts`.
#[test]
fn the_readme_verifies_the_webhook_the_way_the_relay_signs_it() {
    let vector = include_str!("webhook_tests.rs");
    for line in ["const SECRET: &str = \"", "const SIG: &str = \""] {
        let at = vector.find(line).unwrap() + line.len();
        let hex = &vector[at..at + 64];
        assert!(README.contains(hex), "the README's selfTest lacks {hex}");
    }
    assert!(README.contains("function safeEqual_("), "a constant-time comparison");
    assert!(!README.contains("!== env.sig") && !README.contains("=== env.sig"), "never a plain compare");
    assert!(README.contains("5 * 60 * 1000"), "the 5-minute replay window");
}

/// `getFile` answers the file itself, never wrapped, and only from the inbox's 200: every other
/// answer of the inbox goes through `inbox_answer`, so a refusal is the documented JSON.
#[test]
fn get_file_answers_bytes_only_on_success() {
    let api = include_str!("api.rs");
    let f = &api[api.find("async fn get_file(").expect("get_file")..];
    let f = &f[..f.find("\n}\n").expect("end")];
    assert!(f.contains("r.status_code() == 200 => r"));
    assert!(f.contains("other => return inbox_answer(other).await"));
    assert!(f.contains("\"application/octet-stream\"") && f.contains("no-store") && f.contains("nosniff"));
    // The inbox's door: the built-in check, then the rate, then the one verified way in.
    let files = include_str!("../messages/inbox_do/bot/files.rs");
    let door = &files[files.find("async fn bot_get_file(").expect("bot_get_file")..];
    let at = |s: &str| door.find(s).unwrap_or_else(|| panic!("{s}"));
    assert!(at("\"builtin-active\"") < at("take_read(") && at("take_read(") < at("bot_file_bytes("));
    // And that way checks the relay's record before it reads the store.
    let open = &files[files.find("async fn bot_file_bytes(").expect("bot_file_bytes")..];
    let at = |s: &str| open.find(s).unwrap_or_else(|| panic!("{s}"));
    assert!(at("bot_access::check(") < at("router.get("));
    assert!(at("router.get(") < at("decrypt_in_memory("));
}
