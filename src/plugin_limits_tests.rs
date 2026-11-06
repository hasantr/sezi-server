//! The owner's plugin limits: read, written, validated, announced.

use super::*;
use serde_json::json;

/// Nothing stored is every default — the constants Wave A built in.
#[test]
fn nothing_stored_is_every_default() {
    let l = PluginLimits::from_stored(None);
    assert_eq!(l.get(RECORD_COUNT), 2_000);
    assert_eq!(l.get(RECORD_BYTES), 16 * MIB);
    assert_eq!(l.log_limits(), crate::plugin_log_budget::LogLimits::default());
    assert_eq!(l.media_limits(), crate::plugin_media::MediaLimits::default());
    assert_eq!(l.ai_daily_calls(), crate::bots::builtin_rules::DEFAULT_AI_DAILY_CALLS);
    for def in ALL {
        assert!(!l.is_set(def));
        assert!(def.min <= def.default && def.default <= def.max, "{} default in range", def.key);
    }
}

/// A stored row is read field by field: what is odd costs only itself.
#[test]
fn a_stored_row_is_read_leniently() {
    let raw = json!({
        "media_bytes": 2 * GIB, "media_objects": "lots", "log_app_bytes": 1,
        "record_count": 5_000, "unknown": 3
    })
    .to_string();
    let l = PluginLimits::from_stored(Some(&raw));
    assert_eq!(l.get(MEDIA_BYTES), 2 * GIB);
    assert_eq!(l.get(MEDIA_OBJECTS), MEDIA_OBJECTS.default, "not a number");
    assert_eq!(l.get(LOG_APP_BYTES), LOG_APP_BYTES.default, "out of range");
    assert_eq!(l.get(RECORD_COUNT), 5_000);
    assert_eq!(PluginLimits::from_stored(Some("not json")), PluginLimits::default());
    assert_eq!(PluginLimits::from_stored(Some("[1]")), PluginLimits::default());
}

/// A write sets, resets with null, and is refused whole when one key is wrong.
#[test]
fn a_write_is_checked_whole() {
    let l = PluginLimits::default()
        .with_write(&json!({ "media_bytes": GIB, "ai_daily_calls": 50 }))
        .unwrap();
    assert_eq!((l.get(MEDIA_BYTES), l.ai_daily_calls()), (GIB, 50));
    let back = l.with_write(&json!({ "media_bytes": null })).unwrap();
    assert!(!back.is_set(MEDIA_BYTES), "null is back to the default");
    assert_eq!(back.get(AI_DAILY_CALLS), 50);
    assert_eq!(
        l.with_write(&json!({ "media_bytes": 2 * GIB, "record_count": 1 })),
        Err((OUT_OF_RANGE, "record_count".to_string()))
    );
    assert_eq!(l.with_write(&json!({ "nope": 1 })), Err((BAD_KEY, "nope".to_string())));
    assert_eq!(l.with_write(&json!({ "media_objects": 1.5 })), Err((OUT_OF_RANGE, "media_objects".into())));
    assert_eq!(l.with_write(&json!({})).map(|_| ()), Err((BAD_KEY, String::new())));
    assert_eq!(l.with_write(&json!([1])).map(|_| ()), Err((BAD_KEY, String::new())));
    // Each bound itself is accepted, one past is not.
    for def in ALL {
        assert!(l.with_write(&json!({ def.key: def.min })).is_ok(), "{} min", def.key);
        assert!(l.with_write(&json!({ def.key: def.max })).is_ok(), "{} max", def.key);
        assert!(l.with_write(&json!({ def.key: def.min - 1 })).is_err(), "{} below", def.key);
        assert!(l.with_write(&json!({ def.key: def.max + 1 })).is_err(), "{} above", def.key);
    }
}

/// Only what was set is stored, and it reads back the same.
#[test]
fn what_is_stored_reads_back() {
    let l = PluginLimits::default().with_write(&json!({ "log_room_bytes": 128 * MIB })).unwrap();
    assert_eq!(l.to_stored(), json!({ "log_room_bytes": 128 * MIB }).to_string());
    assert_eq!(PluginLimits::from_stored(Some(&l.to_stored())), l);
    assert_eq!(PluginLimits::default().to_stored(), "{}");
}

/// `/capabilities` names every limit with the value in force; the owner's view adds the rest.
#[test]
fn the_announcement_and_the_owner_view() {
    let l = PluginLimits::default().with_write(&json!({ "media_objects": 100 })).unwrap();
    let a = l.announced();
    assert_eq!(a.as_object().unwrap().len(), ALL.len());
    assert_eq!(a["media_objects"], 100);
    assert_eq!(a["record_bytes"], 16 * MIB);
    let rows = l.owner_rows();
    let row = rows.as_array().unwrap().iter().find(|r| r["key"] == "media_objects").unwrap();
    assert_eq!(row["value"], 100);
    assert_eq!(row["default"], MEDIA_OBJECTS.default);
    assert_eq!(row["set"], true);
    assert_eq!(row["unit"], "count");
}

#[test]
fn near_is_eighty_percent() {
    assert!(!is_near(79, 100));
    assert!(is_near(80, 100));
    assert!(is_near(150, 100), "past a lowered limit is near too");
    assert!(!is_near(5, 0));
}

/// The defaults ARE the constants the budgets held before — one figure, two names.
#[test]
fn the_defaults_are_the_old_constants() {
    assert_eq!(LOG_APP_BYTES.default, crate::plugin_log_budget::MAX_BYTES_PER_MEMBER_PER_APP);
    assert_eq!(MEDIA_OBJECTS.default, crate::plugin_media::MAX_OBJECTS_PER_MEMBER_PER_ROOM);
    assert!(READ_SQL.contains(CONFIG_KEY));
}
