//! What each wake style puts on the wire: data unchanged, visible generic and nothing more.

use super::*;

const TOKEN: &str = "fcm-token-of-some-length-0123456789";

/// The data wake is the message `send_wake` built before visible wakes existed — the same
/// expression, compared as bytes.
#[test]
fn a_data_wake_is_byte_identical_to_the_old_message() {
    let legacy = serde_json::json!({
        "message": {
            "token": TOKEN,
            "data": { "type": "wake" },
            "android": { "priority": "high" }
        }
    })
    .to_string();
    assert_eq!(fcm_message(TOKEN, WakeStyle::Data).to_string(), legacy);
    assert_eq!(
        relay_body(TOKEN, WakeStyle::Data).to_string(),
        serde_json::json!({ "token": TOKEN }).to_string(),
        "the relay body of a data wake is the old {{token}}"
    );
}

#[test]
fn a_visible_wake_carries_the_generic_notification() {
    let m = fcm_message(TOKEN, WakeStyle::Visible(Lang::Tr));
    let n = &m["message"]["android"]["notification"];
    assert_eq!(n["title"], "Sezi");
    assert_eq!(n["body"], "Yeni mesaj");
    assert_eq!(n["channel_id"], CHANNEL);
    assert_eq!(n["icon"], ICON);
    assert_eq!(n["tag"], TAG);
    assert_eq!(n["notification_priority"], "PRIORITY_HIGH");
    assert_eq!(m["message"]["android"]["priority"], "high");
    assert_eq!(m["message"]["token"], TOKEN);
    // The data part stays, so a tap opens the app and a started app drains.
    assert_eq!(m["message"]["data"], serde_json::json!({ "type": "wake" }));
    let en = fcm_message(TOKEN, WakeStyle::Visible(Lang::En));
    assert_eq!(en["message"]["android"]["notification"]["body"], "New message");
}

/// Nothing but the fixed fields: no top-level `notification` (which iOS and the web would read),
/// no extra data key, no field a later edit could fill with something the server knows.
#[test]
fn a_visible_wake_says_nothing_else() {
    let m = fcm_message(TOKEN, WakeStyle::Visible(Lang::Tr));
    let msg = m["message"].as_object().unwrap();
    let mut keys: Vec<&str> = msg.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["android", "data", "token"]);
    assert_eq!(m["message"]["data"].as_object().unwrap().len(), 1);
    let android = m["message"]["android"].as_object().unwrap();
    let mut keys: Vec<&str> = android.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["notification", "priority"]);
    let n = m["message"]["android"]["notification"].as_object().unwrap();
    let mut keys: Vec<&str> = n.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        ["body", "channel_id", "default_sound", "icon", "notification_priority", "tag", "title"]
    );
}

#[test]
fn the_relay_body_of_a_visible_wake_names_its_style_and_language() {
    assert_eq!(
        relay_body(TOKEN, WakeStyle::Visible(Lang::En)),
        serde_json::json!({ "token": TOKEN, "wake": "visible", "lang": "en" })
    );
}

/// Only `visible` is visible; every other value — no field, an old row, a value from a newer
/// client — is the data wake every token had before. An unknown language is Turkish.
#[test]
fn the_style_parses_conservatively() {
    assert_eq!(WakeStyle::parse(None, None), WakeStyle::Data);
    assert_eq!(WakeStyle::parse(Some("data"), Some("en")), WakeStyle::Data);
    assert_eq!(WakeStyle::parse(Some("loud"), None), WakeStyle::Data);
    assert_eq!(WakeStyle::parse(Some("visible"), None), WakeStyle::Visible(Lang::Tr));
    assert_eq!(WakeStyle::parse(Some("visible"), Some("de")), WakeStyle::Visible(Lang::Tr));
    assert_eq!(WakeStyle::parse(Some("visible"), Some("en")), WakeStyle::Visible(Lang::En));
    assert_eq!(WakeStyle::Data.lang_column(), None);
    assert_eq!(WakeStyle::Visible(Lang::En).column(), "visible");
    assert_eq!(WakeStyle::Visible(Lang::En).lang_column(), Some("en"));
}
