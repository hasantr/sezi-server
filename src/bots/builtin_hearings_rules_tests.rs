use super::super::builtin_rules::{validate as put_validate, Checked, Kind, PutBody};
use super::*;

fn put(v: serde_json::Value) -> Result<Checked, &'static str> {
    put_validate(serde_json::from_value::<PutBody>(v).unwrap(), false)
}

fn hearings(extra: serde_json::Value) -> Result<Checked, &'static str> {
    let mut h = serde_json::json!({ "allowed_room": "c0000000-0000-4000-8000-000000000003" });
    for (k, v) in extra.as_object().unwrap() {
        h[k] = v.clone();
    }
    put(serde_json::json!({ "kind": "hearings", "lang": "tr", "hearings": h }))
}

#[test]
fn the_plans_defaults_are_anthropic_sonnet_us_and_rule_only_for_criminal_cases() {
    let c = hearings(serde_json::json!({})).unwrap();
    let cfg = c.config.unwrap();
    assert_eq!(cfg.kind, Kind::Hearings);
    let h = cfg.hearings.clone().unwrap();
    assert!(h.ai);
    assert_eq!(h.provider, Provider::Anthropic);
    assert_eq!(h.base_url, None);
    assert_eq!(h.model, DEFAULT_MODEL);
    assert_eq!(h.inference_geo, Geo::Us);
    assert!(!h.criminal_ai, "decision 3");
    assert_eq!(h.audit_days, DEFAULT_AUDIT_DAYS);
    assert_eq!(h.columns, Columns::defaults(Lang::Tr));
    assert_eq!(h.columns.esas, "Esas No");
    // Meant to write a sheet before its address exists ("not connected").
    assert!(cfg.wants_sheet() && cfg.sheet_not_connected());
    assert_eq!(cfg.model_provider(), Some(Provider::Anthropic));
    assert_eq!(cfg.model_name(), Some(DEFAULT_MODEL));
    assert_eq!(c.api_key, None);
    let owner = cfg.to_owner_json(false);
    assert_eq!(owner["hearings"]["allowed_room"], "c0000000-0000-4000-8000-000000000003");
    assert!(owner.get("api_key").is_none() && owner["hearings"].get("api_key").is_none(), "never the key");
}

#[test]
fn a_rule_only_bot_calls_no_model_and_names_no_provider() {
    let cfg = hearings(serde_json::json!({ "ai": false })).unwrap().config.unwrap();
    assert_eq!(cfg.model_provider(), None);
    assert_eq!(cfg.model_geo(), None, "no model, nowhere to run");
    assert!(!cfg.needs_key());
    assert!(cfg.key_service().is_some(), "a key sent for later is still held for its service");
}

#[test]
fn members_are_told_where_anthropic_runs_the_model_and_nothing_for_the_openai_dialect() {
    let geo = |extra| hearings(extra).unwrap().config.unwrap().model_geo();
    assert_eq!(geo(serde_json::json!({})), Some(Geo::Us), "decision 4's default");
    assert_eq!(geo(serde_json::json!({ "inference_geo": "global" })), Some(Geo::Global));
    // The OpenAI dialect sends no `inference_geo`: where it runs is not this bot's to say.
    let openai = serde_json::json!({ "provider": "openai", "base_url": "https://api.openai.com/v1" });
    assert_eq!(geo(openai), None);
    // Another kind never says one.
    let ai = serde_json::json!({ "provider": "anthropic", "model": DEFAULT_MODEL, "instructions": "x" });
    let ai = put(serde_json::json!({ "kind": "ai", "ai": ai })).unwrap();
    assert_eq!(ai.config.unwrap().model_geo(), None);
}

#[test]
fn the_room_is_required_and_shaped_like_an_id() {
    let no_room = put(serde_json::json!({ "kind": "hearings", "hearings": {} }));
    assert_eq!(no_room, Err("builtin/hearings-room"));
    for bad in ["", " ", "a b", "x'; --", &"a".repeat(65)] {
        assert_eq!(hearings(serde_json::json!({ "allowed_room": bad })), Err("builtin/hearings-room"), "{bad}");
    }
    assert_eq!(put(serde_json::json!({ "kind": "hearings" })), Err("builtin/hearings"));
}

#[test]
fn providers_are_called_direct_never_through_openrouter() {
    for (p, base) in [
        (serde_json::json!("openai"), serde_json::Value::Null),
        (serde_json::json!("openai"), serde_json::json!("https://openrouter.ai/api/v1")),
        (serde_json::json!("anthropic"), serde_json::json!("https://eu.openrouter.ai/x")),
    ] {
        assert_eq!(
            hearings(serde_json::json!({ "provider": p, "base_url": base })),
            Err("builtin/hearings-provider"),
            "{p} {base}"
        );
    }
    // An OpenRouter key picks the OpenAI dialect, and with it OpenRouter's address: refused.
    assert_eq!(hearings(serde_json::json!({ "api_key": "sk-or-v1-abc" })), Err("builtin/hearings-provider"));
    let direct = hearings(serde_json::json!({ "provider": "openai", "base_url": "https://api.openai.com/v1" }));
    let h = direct.unwrap().config.unwrap().hearings.unwrap();
    assert_eq!(h.base_url.as_deref(), Some("https://api.openai.com/v1"));
    assert_eq!(
        hearings(serde_json::json!({ "provider": "openai", "base_url": "http://192.168.1.5:11434/v1" })),
        Err("builtin/ai-base-url"),
        "a LAN model only under the lab's escape"
    );
}

#[test]
fn key_model_geo_columns_and_audit_days_are_checked() {
    let k = hearings(serde_json::json!({ "api_key": " sk-ant-abc " })).unwrap();
    assert_eq!(k.api_key.as_deref(), Some("sk-ant-abc"));
    assert_eq!(hearings(serde_json::json!({ "api_key": "a b" })), Err("builtin/ai-key"));
    assert_eq!(hearings(serde_json::json!({ "model": "claude haiku" })), Err("builtin/ai-model"));
    let haiku = hearings(serde_json::json!({ "model": "claude-haiku-5-5" })).unwrap();
    assert_eq!(haiku.config.unwrap().hearings.unwrap().model, "claude-haiku-5-5");
    let global = hearings(serde_json::json!({ "inference_geo": "global" })).unwrap();
    assert_eq!(global.config.unwrap().hearings.unwrap().inference_geo, Geo::Global);
    assert_eq!(hearings(serde_json::json!({ "inference_geo": "eu" })), Err("builtin/hearings-geo"));
    let cols = hearings(serde_json::json!({ "columns": { "esas": "Dosya No", "court": " " } })).unwrap();
    let c = cols.config.unwrap().hearings.unwrap().columns;
    assert_eq!((c.esas.as_str(), c.court.as_str()), ("Dosya No", "Mahkeme"), "blank keeps the default");
    for bad in [
        serde_json::json!({ "esas": "Mahkeme" }),
        serde_json::json!({ "esas": "mahkeme" }),
        serde_json::json!({ "lawyer": "a\nb" }),
        serde_json::json!({ "notes": "x", "updated": "k".repeat(65) }),
    ] {
        assert_eq!(hearings(serde_json::json!({ "columns": bad })), Err("builtin/hearings-columns"), "{bad}");
    }
    assert_eq!(hearings(serde_json::json!({ "audit_days": 0 })), Err("builtin/hearings-audit-days"));
    assert_eq!(hearings(serde_json::json!({ "audit_days": 731 })), Err("builtin/hearings-audit-days"));
    assert!(hearings(serde_json::json!({ "audit_days": 30 })).is_ok());
}

#[test]
fn the_bots_daily_model_calls_have_a_default_and_a_sane_range() {
    let h = |extra| hearings(extra).map(|c| c.config.unwrap().hearings.unwrap());
    assert_eq!(h(serde_json::json!({})).unwrap().daily_calls, DEFAULT_DAILY_CALLS);
    assert_eq!(DEFAULT_DAILY_CALLS, 300);
    assert_eq!(h(serde_json::json!({ "daily_calls": 1 })).unwrap().daily_calls, 1);
    assert_eq!(h(serde_json::json!({ "daily_calls": 2000 })).unwrap().daily_calls, 2000);
    for bad in [0, 2001, 300_000] {
        assert_eq!(h(serde_json::json!({ "daily_calls": bad })), Err("builtin/hearings-daily-calls"), "{bad}");
    }
    // The owner reads it back; a configuration stored before the setting existed gets the default.
    let cfg = hearings(serde_json::json!({ "daily_calls": 120 })).unwrap().config.unwrap();
    assert_eq!(cfg.to_owner_json(false)["hearings"]["daily_calls"], 120);
    let mut stored = serde_json::to_value(cfg.hearings.as_ref().unwrap()).unwrap();
    stored.as_object_mut().unwrap().remove("daily_calls");
    let old: HearingsConfig = serde_json::from_value(stored).unwrap();
    assert_eq!(old.daily_calls, DEFAULT_DAILY_CALLS);
}

#[test]
fn the_sheet_address_is_the_hearings_objects_or_the_top_levels() {
    let inner = hearings(serde_json::json!({ "sheet": { "url": "https://script.google.com/macros/s/A/exec" } }));
    let cfg = inner.unwrap().config.unwrap();
    assert_eq!(cfg.sheet_url.as_deref(), Some("https://script.google.com/macros/s/A/exec"));
    assert!(cfg.writes_sheet());
    let top = put(serde_json::json!({
        "kind": "hearings",
        "sheet": { "url": "https://script.google.com/macros/s/B/exec" },
        "hearings": { "allowed_room": "r1" },
    }));
    assert_eq!(top.unwrap().config.unwrap().sheet_url.as_deref(), Some("https://script.google.com/macros/s/B/exec"));
    assert_eq!(hearings(serde_json::json!({ "sheet": { "url": "http://x.example.com" } })), Err("builtin/sheet-url"));
}

#[test]
fn the_key_slot_follows_the_service_across_kinds() {
    use super::super::builtin_rules::service_follows;
    let h = hearings(serde_json::json!({})).unwrap().config.unwrap();
    let ai = put(serde_json::json!({
        "kind": "ai", "ai": { "provider": "anthropic", "model": "m", "instructions": "x" },
    }))
    .unwrap()
    .config
    .unwrap();
    assert!(service_follows(Some(&ai), &h), "same provider and address: the key may stay");
    let other = hearings(serde_json::json!({ "provider": "openai", "base_url": "https://api.openai.com/v1" }));
    assert!(!service_follows(Some(&h), &other.unwrap().config.unwrap()));
    assert!(!service_follows(None, &h));
    let sheet = put(serde_json::json!({ "kind": "sheet" })).unwrap().config.unwrap();
    assert!(!service_follows(Some(&sheet), &h));
}
