use super::*;

fn put(v: serde_json::Value) -> Result<Checked, &'static str> {
    validate(serde_json::from_value(v).unwrap(), false)
}

#[test]
fn only_a_public_https_host_is_reachable() {
    for ok in [
        "https://script.google.com/macros/s/AKfy/exec",
        "https://api.anthropic.com",
        "https://openrouter.ai/api/v1",
        "https://a.b.example.com:8443/x?y=1",
    ] {
        assert!(outbound_url(ok, false).is_some(), "{ok}");
    }
    for bad in [
        "http://script.google.com/macros/s/AKfy/exec",
        "https://127.0.0.1/x",
        "https://0x7f.1/x",
        "https://2130706433/x",
        "https://[::1]/x",
        "https://[fd00::1]/x",
        "https://10.0.0.5/x",
        "https://localhost/x",
        "https://LOCALHOST./x",
        "https://relay.localhost/x",
        "https://nas.local/x",
        "https://db.internal/x",
        "https://printer.lan/x",
        "https://nas.home.arpa/x",
        "https://router.localdomain/x",
        "https://fritz.box/x",
        "https://wiki.corp/x",
        "https://pi.home/x",
        "https://intranet/x",
        "https://user:pw@example.com/x",
        "https://example.com/x#frag",
        "ftp://example.com/x",
        "not a url",
        "",
    ] {
        assert!(outbound_url(bad, false).is_none(), "{bad}");
    }
    let long = format!("https://example.com/{}", "a".repeat(600));
    assert!(outbound_url(&long, false).is_none(), "longer than 512");
}

#[test]
fn a_stored_key_follows_only_the_service_it_was_given_for() {
    let ai = |provider, base: Option<&str>| AiConfig {
        provider,
        base_url: base.map(str::to_string),
        model: "m".into(),
        instructions: "x".into(),
        sheet_tool: false,
    };
    let old = ai(Provider::Openai, Some("https://api.openai.com/v1"));
    let mut new = old.clone();
    new.model = "other".into();
    new.instructions = "changed".into();
    assert!(key_follows(Some(&old), &new), "model and instructions are not the key's business");
    assert!(!key_follows(Some(&old), &ai(Provider::Anthropic, Some("https://api.openai.com/v1"))));
    assert!(!key_follows(Some(&old), &ai(Provider::Openai, None)), "another address");
    assert!(!key_follows(None, &old), "nothing stored for an AI bot");
}

#[test]
fn the_lab_escape_lifts_the_host_rule_and_allows_http() {
    assert!(outbound_url("http://sezilab-server:18999/exec", true).is_some());
    assert!(outbound_url("https://10.0.0.5/x", true).is_some());
    assert!(outbound_url("ftp://example.com/x", true).is_none(), "still only http(s)");
    assert!(outbound_url("https://u:p@example.com/x", true).is_none(), "still no credentials");
}

#[test]
fn kind_null_is_program_mode() {
    assert_eq!(put(serde_json::json!({ "kind": null })), Ok(Checked { config: None, api_key: None }));
    assert_eq!(put(serde_json::json!({})), Ok(Checked { config: None, api_key: None }));
}

#[test]
fn a_sheet_bot_needs_its_exec_address() {
    let c = put(serde_json::json!({
        "kind": "sheet", "lang": "en",
        "sheet": { "url": " https://script.google.com/macros/s/AKfy/exec " },
    }))
    .unwrap();
    let cfg = c.config.unwrap();
    assert_eq!(cfg.kind, Kind::Sheet);
    assert_eq!(cfg.lang, Lang::En);
    assert_eq!(cfg.sheet_url.as_deref(), Some("https://script.google.com/macros/s/AKfy/exec"));
    assert!(cfg.ai.is_none() && c.api_key.is_none());
    assert_eq!(
        put(serde_json::json!({ "kind": "sheet", "sheet": { "url": "https://192.168.1.4/exec" } })),
        Err("builtin/sheet-url")
    );
}

#[test]
fn an_ai_bot_is_checked_field_by_field() {
    let ok = |ai: serde_json::Value| put(serde_json::json!({ "kind": "ai", "ai": ai }));
    let c = ok(serde_json::json!({
        "api_key": " sk-ant-abc123 ", "model": "claude-opus-5", "instructions": "  Help.  ",
    }))
    .unwrap();
    let cfg = c.config.unwrap();
    assert_eq!(cfg.lang, Lang::Tr, "Turkish unless said");
    let ai = cfg.ai.unwrap();
    assert_eq!(ai.provider, Provider::Anthropic, "read from the key's prefix");
    assert_eq!((ai.model.as_str(), ai.instructions.as_str()), ("claude-opus-5", "Help."));
    assert_eq!(ai.base_url, None);
    assert_eq!(c.api_key.as_deref(), Some("sk-ant-abc123"));

    let kept = ok(serde_json::json!({
        "provider": "openai", "base_url": "https://api.openai.com/v1/", "model": "gpt-5",
        "instructions": "x",
    }))
    .unwrap();
    assert_eq!(kept.api_key, None, "no key sent: the stored one is kept");
    assert_eq!(kept.config.unwrap().ai.unwrap().base_url.as_deref(), Some("https://api.openai.com/v1"));

    assert_eq!(ok(serde_json::json!({ "model": "m", "instructions": "x" })), Err("builtin/ai-provider"));
    let base = |extra: serde_json::Value| {
        let mut v = serde_json::json!({ "provider": "openai", "model": "m", "instructions": "x" });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        ok(v)
    };
    assert_eq!(base(serde_json::json!({ "model": "" })), Err("builtin/ai-model"));
    assert_eq!(base(serde_json::json!({ "model": "a b" })), Err("builtin/ai-model"));
    assert_eq!(base(serde_json::json!({ "instructions": " " })), Err("builtin/ai-instructions"));
    assert_eq!(
        base(serde_json::json!({ "instructions": "x".repeat(MAX_INSTRUCTIONS_CHARS + 1) })),
        Err("builtin/ai-instructions")
    );
    assert!(base(serde_json::json!({ "instructions": "ş".repeat(MAX_INSTRUCTIONS_CHARS) })).is_ok(), "chars, not bytes");
    assert_eq!(base(serde_json::json!({ "api_key": "sk bad" })), Err("builtin/ai-key"));
    assert_eq!(base(serde_json::json!({ "api_key": "sk\r\nx" })), Err("builtin/ai-key"));
    assert_eq!(base(serde_json::json!({ "base_url": "http://localhost:11434/v1" })), Err("builtin/ai-base-url"));
    assert_eq!(put(serde_json::json!({ "kind": "ai" })), Err("builtin/ai"));
}

#[test]
fn an_ai_bot_keeps_a_sheet_only_when_it_writes_rows() {
    let sheet = serde_json::json!({ "url": "https://script.google.com/macros/s/AKfy/exec" });
    let ai = |tool: bool| {
        put(serde_json::json!({
            "kind": "ai", "sheet": sheet,
            "ai": { "provider": "anthropic", "model": "m", "instructions": "x", "sheet_tool": tool },
        }))
        .unwrap()
        .config
        .unwrap()
    };
    assert!(ai(true).writes_sheet());
    assert!(!ai(false).writes_sheet());
}

#[test]
fn the_owner_reads_the_config_back_without_any_key() {
    let cfg = put(serde_json::json!({
        "kind": "ai", "lang": "en",
        "ai": { "api_key": "sk-or-v1-secret", "model": "openai/gpt-5", "instructions": "Be brief." },
    }))
    .unwrap()
    .config
    .unwrap();
    let v = cfg.to_owner_json(true);
    assert_eq!(
        v,
        serde_json::json!({
            "kind": "ai", "lang": "en", "sheet": null,
            "ai": { "provider": "openai", "base_url": null, "model": "openai/gpt-5",
                    "instructions": "Be brief.", "sheet_tool": false },
            "has_api_key": true,
        })
    );
    assert!(!v.to_string().contains("secret"));
    let stored: Config = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
    assert_eq!(stored, cfg, "the inbox's copy round-trips");
}

#[test]
fn a_sheet_without_its_address_yet_is_accepted_as_not_connected() {
    // The helper's order: copy the script (needs the secret), deploy it, then paste `/exec`.
    for body in [serde_json::json!({ "kind": "sheet", "sheet": {} }), serde_json::json!({ "kind": "sheet" })] {
        let cfg = put(body).unwrap().config.unwrap();
        assert!(cfg.wants_sheet() && cfg.sheet_not_connected() && !cfg.writes_sheet());
        assert_eq!(cfg.to_owner_json(false)["sheet"], serde_json::json!({ "url": null }));
    }
    let ai = put(serde_json::json!({
        "kind": "ai",
        "ai": { "provider": "openai", "model": "m", "instructions": "x", "sheet_tool": true },
    }))
    .unwrap()
    .config
    .unwrap();
    assert!(ai.sheet_not_connected() && !ai.writes_sheet(), "rows on, no address yet");
    let plain = put(serde_json::json!({
        "kind": "ai", "ai": { "provider": "openai", "model": "m", "instructions": "x" },
    }))
    .unwrap()
    .config
    .unwrap();
    assert!(!plain.wants_sheet() && !plain.sheet_not_connected(), "an AI bot without rows has no sheet");
    assert_eq!(plain.to_owner_json(false)["sheet"], serde_json::Value::Null);
    // An address that IS sent is still checked.
    assert_eq!(
        put(serde_json::json!({ "kind": "sheet", "sheet": { "url": "http://script.google.com/x" } })),
        Err("builtin/sheet-url")
    );
}
