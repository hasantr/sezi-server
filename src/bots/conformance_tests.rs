//! The bot API's conformance suite (docs/WORK_PLAN.md 2.2): `docs/BOTS_BUILD.md` §2.5 is what the
//! code does, and `tools/bots/README.md` — the program's reference — says the same.
//!
//! What a host test can reach of a Worker handler is its pure parts and its source, so the suite
//! holds three things together:
//! - **the tables**: every documented method has its arm in `api.rs` and nothing else does; every
//!   error code the program can be answered — each `(status, "code")` the program's path writes —
//!   is a row of §2.5's error table and of the README's, with the same status, and vice versa;
//! - **the answers**: each method's answer body, built by `api_answer.rs`, has the documented shape;
//! - **the order of the doors**: the key before everything, `bot/disabled` before any method;
//! - **the v1 contract** (B2, 2026-11-06): `tools/bots/api_v1.json` names the version, features,
//!   methods with every request and answer field and its type, update kinds, error codes and
//!   limits — each held to the code here (the update shapes in `inbox_do/bot/updates_tests.rs`),
//!   `tools/bots/API_V1.md` held to it, and `tools/bots/CHANGELOG.md` required to carry an entry
//!   for each item under the revision its `since` names. A change inside v1 is additive; one
//!   that is not is v2.
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
    // getMe → {ok, bot:{bot_id, name, about}, api_version, features} (the last two since 1.1).
    assert_eq!(
        api_answer::me("b-id", "Duruşma", None),
        json!({"ok": true, "bot": {"bot_id": "b-id", "name": "Duruşma", "about": null},
               "api_version": 1, "features": api_answer::FEATURES})
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

// ---------------------------------------------------------------------------------------------
// The v1 contract: `tools/bots/api_v1.json` against the code, `API_V1.md` and `CHANGELOG.md`
// against it (B2, 2026-11-06). The update shapes are held in `inbox_do/bot/updates_tests.rs`.

use super::api_spec::{self, check_shape, fields, list, spec};
use serde_json::Value;

const API_V1: &str = include_str!("../../../tools/bots/API_V1.md");
const CHANGELOG: &str = include_str!("../../../tools/bots/CHANGELOG.md");

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

/// `65536` → `65,536`, as the reference writes a number.
fn with_commas(n: i64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `src` declares `name` as `v` (`2000` or `2_000`).
fn declares(src: &str, decl: &str, v: i64) -> bool {
    src.contains(&format!("{decl} = {v};")) || src.contains(&format!("{decl} = {};", with_commas(v).replace(',', "_")))
}

/// A method's section of `API_V1.md`, up to the next heading.
fn reference_section(method: &str) -> &'static str {
    let head = format!("### `{method}`");
    let start = API_V1.find(&head).unwrap_or_else(|| panic!("API_V1.md has no {head}"));
    let rest = &API_V1[start + head.len()..];
    &rest[..rest.find("\n#").unwrap_or(rest.len())]
}

/// A changelog revision's section, by its heading `## <rev> — <date>`.
fn changelog_section(rev: &str) -> &'static str {
    let head = format!("\n## {rev} — ");
    let start = CHANGELOG.find(&head).unwrap_or_else(|| panic!("CHANGELOG.md has no revision {rev}"));
    let rest = &CHANGELOG[start + head.len()..];
    &rest[..rest.find("\n## ").unwrap_or(rest.len())]
}

/// The version, path and features the relay announces are the spec's, and the route is its path.
#[test]
fn the_relay_announces_the_specs_version_and_features() {
    let spec = spec();
    assert_eq!(spec["api_version"], json!(api_answer::API_VERSION));
    let features = list("features");
    let names: Vec<&str> = features.iter().map(|f| s(&f["name"])).collect();
    assert_eq!(names, api_answer::FEATURES, "api_v1.json's features and api_answer::FEATURES differ");
    let path = s(&spec["path"]);
    assert_eq!(path, format!("/bot/v{}/", api_answer::API_VERSION));
    assert_eq!(api_answer::discovery(), json!({"version": 1, "path": path, "features": names}));
    let lib = include_str!("../lib.rs");
    assert!(lib.contains(&format!(".post_async(\"{path}:method\", bots::api::dispatch)")), "the route is not {path}");
    let caps = include_str!("../server/handlers.rs");
    assert!(caps.contains("body[\"bot_api\"] = crate::bots::api_answer::discovery();"), "/capabilities lost bot_api");
    for doc in [API_V1, README] {
        assert!(doc.contains("bot_api"), "the discovery block is not documented");
    }
}

/// The spec's methods are the dispatched ones, and its error codes are the ones the program's
/// path answers, with the same status.
#[test]
fn the_specs_methods_and_errors_are_the_codes() {
    let methods = list("methods");
    let methods: BTreeSet<&str> = methods.iter().map(|m| s(&m["name"])).collect();
    assert_eq!(methods, METHODS.into_iter().collect(), "api_v1.json and the dispatch name other methods");
    let errors: BTreeSet<(u16, String)> = list("errors")
        .iter()
        .map(|e| {
            let code = s(&e["code"]).strip_prefix("bot/").expect("a bot/ code");
            (e["status"].as_u64().unwrap() as u16, code.to_string())
        })
        .collect();
    assert_eq!(errors, source_codes(), "api_v1.json's errors and the code disagree");
    // Every error answer has the documented shape.
    for (_, code) in &errors {
        check_shape(code, &api_answer::error(code), &spec()["error_answer"]).unwrap();
    }
    check_shape("rate-limited", &api_answer::rate_limited(3), &spec()["error_answer"]).unwrap();
}

/// What the parser of each method accepts.
fn parse(method: &str, body: &Value) -> Result<(), Refusal> {
    match method {
        "getMe" | "deleteWebhook" => Ok(()),
        "getUpdates" => parse_updates(body).map(drop),
        "sendMessage" => parse_send(body).map(drop),
        "setWebhook" => parse_webhook(body).map(drop),
        "getFile" => parse_get_file(body).map(drop),
        other => panic!("no parser named for {other}: add it here when it is dispatched"),
    }
}

/// Every documented request field is read with its documented type — the example passes, the
/// field given a wrong type is refused, an optional one may be left out or `null` — and the
/// parser reads no field the spec does not document.
#[test]
fn every_request_field_is_documented_and_read_with_its_type() {
    let mut documented = BTreeSet::new();
    for m in list("methods") {
        let name = s(&m["name"]);
        let example = &m["example"];
        assert_eq!(parse(name, example), Ok(()), "{name}'s example in api_v1.json is refused");
        for (path, (optional, ty)) in fields(&m["request"]) {
            documented.insert(path.clone());
            let mut wrong = example.clone();
            match path.split_once('.') {
                Some((outer, inner)) => {
                    let mut only = serde_json::Map::new();
                    only.insert(inner.to_string(), json!(true));
                    wrong[outer] = Value::Object(only);
                }
                None => wrong[&path] = json!(true),
            }
            assert!(!api_spec::has_type(&json!(true), &ty));
            assert_eq!(parse(name, &wrong), Err((400, "bad-request")), "{name}.{path} of the wrong type");
            if optional && !path.contains('.') {
                let mut absent = example.clone();
                absent.as_object_mut().unwrap().remove(&path);
                assert_eq!(parse(name, &absent), Ok(()), "{name}: optional {path} left out");
                let mut null = example.clone();
                null[&path] = Value::Null;
                assert_eq!(parse(name, &null), Ok(()), "{name}: optional {path} as null");
            }
        }
        if let Some(reserved) = m["reserved"].as_object() {
            for (field, code) in reserved {
                documented.insert(field.clone());
                let mut body = example.clone();
                body[field] = json!([[{"id": "a", "label": "A"}]]);
                let code = s(code).strip_prefix("bot/").unwrap();
                assert_eq!(parse(name, &body).map_err(|e| e.1), Err(code), "{name}.{field} is reserved");
            }
        }
    }
    // What `api_input.rs` reads: `(body, "x")`, `body.get("x")`, and a chat's `(chat, "x")`.
    let src = include_str!("api_input.rs");
    let mut read = BTreeSet::new();
    for (needle, prefix) in [("(body, \"", ""), ("body.get(\"", ""), ("(chat, \"", "chat.")] {
        for (at, _) in src.match_indices(needle) {
            let rest = &src[at + needle.len()..];
            let name = &rest[..rest.find('"').unwrap()];
            if name != "key" {
                read.insert(format!("{prefix}{name}"));
            }
        }
    }
    assert_eq!(read, documented, "api_input.rs reads other fields than api_v1.json documents");
}

/// Each method's answer, as `api_answer.rs` builds it, holds to the spec's answer fields.
#[test]
fn every_answer_holds_to_the_spec() {
    for m in list("methods") {
        let name = s(&m["name"]);
        let answers = match name {
            "getMe" => vec![api_answer::me("b", "n", Some("a")), api_answer::me("b", "n", None)],
            "getUpdates" => vec![api_answer::updates([(1, r#"{"kind":"message"}"#.to_string())])],
            "sendMessage" => vec![api_answer::sent("b-1"), api_answer::duplicate("b-1")],
            "setWebhook" => vec![api_answer::webhook(Some("ab")), api_answer::webhook(None)],
            "deleteWebhook" => vec![api_answer::webhook(None)],
            // The file itself (`get_file_answers_bytes_only_on_success`).
            "getFile" => {
                assert_eq!(m["answer"].as_object().unwrap().keys().collect::<Vec<_>>(), ["bytes"]);
                continue;
            }
            other => panic!("no answer named for {other}"),
        };
        for a in answers {
            check_shape(name, &a, &m["answer"]).unwrap();
        }
    }
}

/// Every limit in the spec is the code's number, and the reference states it.
#[test]
fn every_limit_in_the_spec_is_the_codes() {
    let guard = include_str!("../messages/inbox_do/bot/send_guard.rs");
    let budget = include_str!("../messages/inbox_do/bot/api_budget.rs");
    let brake = include_str!("key_brake.rs");
    let updates = include_str!("../messages/inbox_do/bot/updates.rs");
    let replay = include_str!("../messages/inbox_do/bot/send_replay.rs");
    let files = include_str!("../messages/inbox_do/bot/files.rs");
    let backlog = include_str!("../messages/inbox_do/bot/backlog.rs");
    let order = include_str!("../messages/inbox_do/bot/deliver_order.rs");
    let hook = include_str!("webhook.rs");
    let spec = spec();
    let limits = spec["limits"].as_object().unwrap();
    for (key, v) in limits {
        let v = v.as_i64().unwrap();
        let ok = match key.as_str() {
            "body_bytes" => v == MAX_BODY_BYTES as i64,
            "text_chars" => v == MAX_TEXT_CHARS as i64,
            "reply_to_bytes" => v == MAX_REPLY_TO_LEN as i64,
            "client_id_chars" => v == MAX_CLIENT_ID_LEN as i64,
            "room_id_chars" => v == MAX_ROOM_ID_LEN as i64,
            "file_id_chars" => v == MAX_FILE_ID_LEN as i64,
            "poll_timeout_s" => v == MAX_POLL_SECS,
            "poll_limit" => v == MAX_LIMIT,
            "sends_per_minute" => declares(guard, "SENDS_PER_MINUTE: i64", v),
            "sends_per_chat_per_minute" => declares(guard, "SENDS_PER_CHAT_PER_MINUTE: i64", v),
            "calls_per_minute" => v.rem_euclid(60) == 0 && declares(budget, "PER_SECOND: i64", v / 60),
            "call_burst" => declares(budget, "BURST: i64", v),
            "wrong_keys_per_minute" => declares(brake, "MISSES_PER_MINUTE: u32", v),
            "update_retention_h" => updates.contains(&format!("UPDATE_TTL_MS: i64 = {v} * 3600 * 1000;")),
            "client_id_retention_h" => replay.contains(&format!("CLIENT_ID_TTL_MS: i64 = {v} * 3600 * 1000;")),
            // A member's file goes with the updates' window (`files.rs` expires by it).
            "file_retention_h" => {
                files.contains("UPDATE_TTL_MS") && v == limits["update_retention_h"].as_i64().unwrap()
            }
            "waiting_per_member" => declares(backlog, "PER_SENDER: i64", v),
            "stored_per_bot" => declares(backlog, "PER_BOT: i64", v),
            "file_bytes" => v as u64 == crate::media::bot_access::MAX_BOT_FILE_BYTES,
            "file_reads_per_minute" => declares(files, "READS_PER_MINUTE: i64", v),
            "webhook_url_bytes" => declares(hook, "MAX_URL_LEN: usize", v),
            "webhook_aside_after_failures" => declares(order, "ASIDE_AFTER: i64", v),
            other => panic!("api_v1.json's limit {other} has no check here: add one"),
        };
        assert!(ok, "the limit {key} = {v} is not the code's");
        let row = format!("| `{key}` | {} |", with_commas(v));
        assert!(API_V1.contains(&row), "API_V1.md has no row {row}");
    }
    // The owner sets these (Wave A, `plugin_limits.rs`): the spec's figures are the relay's.
    for l in list("owner_limits") {
        let key = s(&l["key"]);
        let def = crate::plugin_limits::ALL.into_iter().find(|d| d.key == key).unwrap_or_else(|| panic!("{key}"));
        assert_eq!((l["default"].as_i64(), l["min"].as_i64(), l["max"].as_i64()), (Some(def.default), Some(def.min), Some(def.max)));
        let row = format!("| `{key}` | {} | {}..{} |", with_commas(def.default), with_commas(def.min), with_commas(def.max));
        assert!(API_V1.contains(&row), "API_V1.md has no row {row}");
    }
    assert_eq!(crate::plugin_limits::AI_DAILY_CALLS.key, "ai_daily_calls");
    let store = include_str!("../messages/inbox_do/bot/builtin_store.rs");
    for (key, v) in spec["builtin_limits"].as_object().unwrap() {
        let v = v.as_i64().unwrap();
        let ok = match key.as_str() {
            "ai_calls_per_member_per_day" => declares(store, "DAILY_CALLS: i64", v),
            "hearings_calls_per_day" => v == i64::from(super::builtin_hearings_rules::DEFAULT_DAILY_CALLS),
            other => panic!("api_v1.json's built-in limit {other} has no check here: add one"),
        };
        assert!(ok, "the built-in limit {key} = {v} is not the code's");
        assert!(API_V1.contains(&format!("| `{key}` | {} |", with_commas(v))), "API_V1.md lacks {key}");
    }
}

/// `API_V1.md` states every method with its fields, every update kind with its fields, every
/// feature and every error code with its status — no more and no fewer codes.
#[test]
fn the_reference_states_the_whole_spec() {
    let spec = spec();
    assert!(API_V1.contains(&format!("Revision: **{}**", s(&spec["revision"]))));
    for m in list("methods") {
        let name = s(&m["name"]);
        let section = reference_section(name);
        for map in [&m["request"], &m["answer"]] {
            for path in fields(map).keys().filter(|p| p.as_str() != "bytes") {
                assert!(section.contains(&format!("`{path}`")), "API_V1.md's {name} does not state `{path}`");
            }
        }
        for (field, code) in m["reserved"].as_object().into_iter().flatten() {
            assert!(section.contains(&format!("`{field}`")) && section.contains(s(code)), "{name}.{field}");
        }
    }
    for u in list("updates") {
        let kind = s(&u["kind"]);
        let row_head = format!("| `{kind}` | {} |", s(&u["since"]));
        let row = API_V1.lines().find(|l| l.starts_with(&row_head)).unwrap_or_else(|| panic!("no row {row_head}"));
        for path in fields(&u["fields"]).keys() {
            assert!(row.contains(&format!("`{path}`")), "API_V1.md's {kind} update does not state `{path}`");
        }
    }
    for f in list("features") {
        let row = format!("| `{}` | {} |", s(&f["name"]), s(&f["since"]));
        assert!(API_V1.contains(&row), "API_V1.md has no row {row}");
    }
    let codes: BTreeSet<(u16, String)> =
        list("errors").iter().map(|e| (e["status"].as_u64().unwrap() as u16, s(&e["code"])[4..].to_string())).collect();
    assert_eq!(doc_codes(API_V1), codes, "API_V1.md's error table and api_v1.json disagree");
    assert!(API_V1.contains("kept 24 hours"), "the 24 h retention is not stated");
    for doc in [README, section_2_5()] {
        assert!(doc.contains("API_V1.md") && doc.contains("CHANGELOG.md"), "the reference and changelog are not linked");
    }
}

/// Every method, answer field, update kind, error code and feature has its entry in the
/// changelog under the revision its `since` names; the newest revision is the spec's, and no
/// `since` names a revision past it.
#[test]
fn every_change_has_its_changelog_entry() {
    let spec = spec();
    let rev = s(&spec["revision"]);
    let newest = CHANGELOG.split("\n## ").nth(1).expect("a revision").split(" — ").next().unwrap();
    assert_eq!(newest, rev, "CHANGELOG.md's newest revision is not api_v1.json's");
    let rev_num = |r: &str| -> (u32, u32) {
        let (a, b) = r.split_once('.').expect("major.minor");
        (a.parse().unwrap(), b.parse().unwrap())
    };
    assert_eq!(rev_num(rev).0, api_answer::API_VERSION, "a v1 revision is 1.x");
    let mut entries: Vec<(String, String)> = Vec::new();
    for f in list("features") {
        entries.push((s(&f["since"]).into(), s(&f["name"]).into()));
    }
    for m in list("methods") {
        entries.push((s(&m["since"]).into(), s(&m["name"]).into()));
        for (field, since) in m["answer_since"].as_object().into_iter().flatten() {
            entries.push((s(since).into(), field.trim_end_matches('?').into()));
        }
    }
    for u in list("updates") {
        entries.push((s(&u["since"]).into(), s(&u["kind"]).into()));
    }
    for e in list("errors") {
        entries.push((s(&e["since"]).into(), s(&e["code"]).into()));
    }
    for (since, name) in entries {
        assert!(rev_num(&since) <= rev_num(rev), "{name} is since {since}, past the revision {rev}");
        assert!(changelog_section(&since).contains(&format!("`{name}`")), "CHANGELOG.md {since} has no entry for `{name}`");
    }
}
