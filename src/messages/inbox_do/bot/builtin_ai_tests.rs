use super::*;

/// 2026-10-26 12:00 UTC, a Monday.
const NOW: i64 = 1_793_016_000_000;

fn ai(provider: Provider, sheet_tool: bool) -> AiConfig {
    AiConfig {
        provider,
        base_url: None,
        model: "the-model".into(),
        instructions: "Answer questions about hearings.".into(),
        sheet_tool,
    }
}

fn history() -> Vec<Turn> {
    vec![
        Turn { role: Role::User, text: "Merhaba".into() },
        Turn { role: Role::Assistant, text: "Merhaba, buyrun.".into() },
    ]
}

#[test]
fn anthropic_gets_a_top_level_system_and_its_endpoint() {
    let a = ai(Provider::Anthropic, false);
    assert_eq!(endpoint(&a), "https://api.anthropic.com/v1/messages");
    assert_eq!(
        auth_headers(Provider::Anthropic, "sk-ant-x"),
        vec![("x-api-key", "sk-ant-x".to_string()), ("anthropic-version", "2023-06-01".to_string())]
    );
    assert_eq!(
        request_body(&a, "SYS", &history(), "Yarın duruşma var mı?"),
        serde_json::json!({
            "model": "the-model",
            "max_tokens": 2048,
            "system": "SYS",
            "messages": [
                { "role": "user", "content": "Merhaba" },
                { "role": "assistant", "content": "Merhaba, buyrun." },
                { "role": "user", "content": "Yarın duruşma var mı?" },
            ],
        })
    );
}

#[test]
fn openai_gets_the_system_as_its_first_message_and_a_bearer() {
    let mut a = ai(Provider::Openai, false);
    assert_eq!(endpoint(&a), "https://openrouter.ai/api/v1/chat/completions");
    a.base_url = Some("https://api.openai.com/v1".into());
    assert_eq!(endpoint(&a), "https://api.openai.com/v1/chat/completions");
    assert_eq!(auth_headers(Provider::Openai, "sk-1"), vec![("authorization", "Bearer sk-1".to_string())]);
    assert_eq!(
        request_body(&a, "SYS", &[], "hi"),
        serde_json::json!({
            "model": "the-model",
            "max_tokens": 2048,
            "messages": [
                { "role": "system", "content": "SYS" },
                { "role": "user", "content": "hi" },
            ],
        })
    );
}

#[test]
fn a_members_message_is_cut_at_four_thousand_characters() {
    let long = "ğ".repeat(MAX_INPUT_CHARS + 50);
    let body = request_body(&ai(Provider::Anthropic, false), "S", &[], &long);
    let sent = body["messages"][0]["content"].as_str().unwrap();
    assert_eq!(sent.chars().count(), MAX_INPUT_CHARS);
}

#[test]
fn the_system_prompt_carries_the_instructions_and_the_row_protocol_only_when_asked() {
    let plain = system_prompt(&ai(Provider::Anthropic, false), "Kâtip", "Ayşe", None, false, NOW);
    assert!(plain.contains("\"Kâtip\"") && plain.contains("\"Ayşe\""));
    assert!(plain.contains("<instructions>\nAnswer questions about hearings.\n</instructions>"));
    assert!(!plain.contains("ROW:"));
    let unconnected = system_prompt(&ai(Provider::Anthropic, true), "Kâtip", "Ayşe", None, false, NOW);
    assert!(!unconnected.contains("ROW:"), "rows on but no sheet yet: no row is asked for");
    let rows = system_prompt(&ai(Provider::Anthropic, true), "Kâtip", "Ayşe", None, true, NOW);
    assert!(plain.contains("Today is Monday, 26 October 2026 (UTC)."), "every prompt knows the date");
    assert!(rows.contains("NO row is waiting"), "a settled row is never listed as pending");
    assert!(rows.contains("cannot see the spreadsheet"), "nothing claimed beyond what it remembers");
    assert!(rows.contains("\"Kaydedildi.\""), "the saved marker the model reads back");
    assert!(rows.contains("ROW: {\"Column\": \"value\", ...}"));
    assert!(plain.contains("one to one"));
    let room = system_prompt(&ai(Provider::Anthropic, false), "Kâtip", "Ayşe", Some("Hukuk"), false, NOW);
    assert!(room.contains("in the group \"Hukuk\"") && room.contains("everyone in the group sees"));
    assert!(!room.contains("one to one"));
}

#[test]
fn anthropic_answers_are_read_like_the_cores() {
    let p = Provider::Anthropic;
    let ok = r#"{"content":[{"type":"text","text":"Evet, "},{"type":"tool_use"},{"type":"text","text":"yarın 10:00."}],"stop_reason":"end_turn"}"#;
    assert_eq!(parse_response(p, 200, ok), Ok("Evet, yarın 10:00.".into()));
    let cut = r#"{"content":[{"type":"text","text":"Uzun bir"}],"stop_reason":"max_tokens"}"#;
    assert_eq!(parse_response(p, 200, cut), Ok("Uzun bir…".into()), "a cut-off answer is kept, marked");
    assert_eq!(parse_response(p, 200, r#"{"content":[],"stop_reason":"refusal"}"#), Err("ai/refused"));
    assert_eq!(parse_response(p, 200, r#"{"content":[{"type":"text","text":"  "}]}"#), Err("ai/bad-response"));
    assert_eq!(parse_response(p, 200, "<html>"), Err("ai/bad-response"));
    assert_eq!(parse_response(p, 401, "{}"), Err("ai/bad-key"));
    assert_eq!(parse_response(p, 403, "{}"), Err("ai/bad-key"));
    assert_eq!(parse_response(p, 404, "{}"), Err("ai/bad-model"));
    assert_eq!(parse_response(p, 429, "{}"), Err("ai/rate-limited"));
    assert_eq!(parse_response(p, 529, "{}"), Err("ai/overloaded"));
    assert_eq!(parse_response(p, 302, ""), Err("ai/bad-response"), "a redirect is not followed");
    assert_eq!(parse_response(p, 0, ""), Err("ai/unreachable"));
}

#[test]
fn openai_answers_are_read_like_the_cores() {
    let p = Provider::Openai;
    let ok = r#"{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":" Tamam. "}}]}"#;
    assert_eq!(parse_response(p, 200, ok), Ok("Tamam.".into()));
    let cut = r#"{"choices":[{"finish_reason":"length","message":{"content":"Yarım"}}]}"#;
    assert_eq!(parse_response(p, 200, cut), Ok("Yarım…".into()));
    let filtered = r#"{"choices":[{"finish_reason":"content_filter","message":{"content":"x"}}]}"#;
    assert_eq!(parse_response(p, 200, filtered), Err("ai/refused"));
    assert_eq!(parse_response(p, 200, r#"{"error":{"message":"upstream"}}"#), Err("ai/bad-response"));
    assert_eq!(parse_response(p, 200, r#"{"choices":[]}"#), Err("ai/bad-response"));
    assert_eq!(parse_response(p, 503, ""), Err("ai/overloaded"));
}

#[test]
fn only_passing_failures_are_tried_again() {
    for c in ["ai/unreachable", "ai/overloaded", "ai/rate-limited"] {
        assert!(transient(c), "{c}");
    }
    for c in ["ai/bad-key", "ai/bad-model", "ai/refused", "ai/bad-response", "ai/no-key"] {
        assert!(!transient(c), "{c}");
    }
}

#[test]
fn a_row_line_is_cut_from_the_answer_and_its_last_good_one_proposed() {
    let (shown, row) = split_row("Not aldım.\nROW: {\"Tarih\": \"2026-10-27\", \"Saat\": \"10:00\"}");
    assert_eq!(shown, "Not aldım.");
    assert_eq!(row.unwrap().to_json(), r#"{"Tarih":"2026-10-27","Saat":"10:00"}"#);
    let (shown, row) = split_row("Tamam.\n  ROW: not json\nBaşka?");
    assert_eq!((shown.as_str(), row), ("Tamam.\nBaşka?", None), "a bad row line is cut, never shown");
    let (shown, row) = split_row("Satır yok.");
    assert_eq!((shown.as_str(), row), ("Satır yok.", None));
    let (shown, row) = split_row("ROW: {\"a\":\"1\"}\nROW: {\"b\":\"2\"}");
    assert_eq!(shown, "");
    assert_eq!(row.unwrap().0, vec![("b".to_string(), "2".to_string())], "the last one");
}

#[test]
fn yes_and_no_in_either_language() {
    for y in [
        "evet", "Evet.", " EVET! ", "yes", "Yes", "tamam kaydet", "Evet, kaydet.", "Kaydet",
        "Onaylıyorum", "tamam", "OK",
    ] {
        assert_eq!(yes_or_no(y), Some(true), "{y}");
    }
    for n in ["hayır", "Hayır.", "HAYIR", "hayir", "no", "No!", "vazgeç", "Vazgeç!", "iptal", "kaydetme"] {
        assert_eq!(yes_or_no(n), Some(false), "{n}");
    }
    for other in ["evet ama tarihi düzelt", "e", "nope", "", "Kaydet: yarın 10:00 Ankara", "tamam ama 11:00 olsun"] {
        assert_eq!(yes_or_no(other), None, "{other}");
    }
}

#[test]
fn the_date_line_is_the_civil_date_in_utc() {
    assert_eq!(today_line(0), "Today is Thursday, 1 January 1970 (UTC).");
    assert_eq!(today_line(NOW), "Today is Monday, 26 October 2026 (UTC).");
    assert_eq!(today_line(951_782_400_000), "Today is Tuesday, 29 February 2000 (UTC).", "a leap day");
    assert_eq!(today_line(1_798_761_599_000), "Today is Thursday, 31 December 2026 (UTC).", "one second before the year turns");
}
