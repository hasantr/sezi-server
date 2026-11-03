//! What each wake style puts on the wire: data unchanged, visible generic and nothing more, on
//! the channel its app said it created.

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
    assert_eq!(fcm_message(TOKEN, WakeStyle::Data, None).to_string(), legacy);
    assert_eq!(
        relay_body(TOKEN, WakeStyle::Data, None, false).to_string(),
        serde_json::json!({ "token": TOKEN }).to_string(),
        "the relay body of a data wake is the old {{token}}"
    );
}

#[test]
fn a_visible_wake_carries_the_generic_notification() {
    let m = fcm_message(TOKEN, WakeStyle::Visible(Lang::Tr, WakeChannel::Messages), None);
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
    let en = fcm_message(TOKEN, WakeStyle::Visible(Lang::En, WakeChannel::Messages), None);
    assert_eq!(en["message"]["android"]["notification"]["body"], "New message");
}

/// Nothing but the fixed fields: no top-level `notification` (which iOS and the web would read),
/// no extra data key, no field a later edit could fill with something the server knows.
#[test]
fn a_visible_wake_says_nothing_else() {
    let m = fcm_message(TOKEN, WakeStyle::Visible(Lang::Tr, WakeChannel::Messages), None);
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
        relay_body(TOKEN, WakeStyle::Visible(Lang::En, WakeChannel::Messages), None, false),
        serde_json::json!({ "token": TOKEN, "wake": "visible", "lang": "en" })
    );
}

/// A data wake carries its frame under `msg`, beside `type` — and nothing else changes.
#[test]
fn a_data_wake_carries_its_frame_under_msg() {
    let frame = r#"{"type":"msg","id":7,"rd":"d1"}"#;
    let m = fcm_message(TOKEN, WakeStyle::Data, Some(frame));
    assert_eq!(m["message"]["data"], serde_json::json!({ "type": "wake", "msg": frame }));
    assert_eq!(m["message"]["android"], serde_json::json!({ "priority": "high" }));
    assert_eq!(
        relay_body(TOKEN, WakeStyle::Data, Some(frame), false),
        serde_json::json!({ "token": TOKEN, "data": { "msg": frame } })
    );
}

/// A visible wake carries nothing, whatever it is handed: the OS draws it without starting the
/// app, and the relay is told only its style and language, as before.
#[test]
fn a_visible_wake_carries_nothing() {
    let frame = r#"{"type":"msg","id":7,"rd":"d1"}"#;
    let m = fcm_message(TOKEN, WakeStyle::Visible(Lang::Tr, WakeChannel::Messages), Some(frame));
    assert_eq!(m, fcm_message(TOKEN, WakeStyle::Visible(Lang::Tr, WakeChannel::Messages), None));
    assert_eq!(
        relay_body(TOKEN, WakeStyle::Visible(Lang::En, WakeChannel::Messages), Some(frame), false),
        relay_body(TOKEN, WakeStyle::Visible(Lang::En, WakeChannel::Messages), None, false)
    );
}

/// Only `visible` is visible; every other value — no field, an old row, a value from a newer
/// client — is the data wake every token had before. An unknown language is Turkish.
#[test]
fn the_style_parses_conservatively() {
    let visible = |l| WakeStyle::Visible(l, WakeChannel::Messages);
    assert_eq!(WakeStyle::parse(None, None, None), WakeStyle::Data);
    assert_eq!(WakeStyle::parse(Some("data"), Some("en"), None), WakeStyle::Data);
    assert_eq!(WakeStyle::parse(Some("loud"), None, None), WakeStyle::Data);
    assert_eq!(WakeStyle::parse(Some("visible"), None, None), visible(Lang::Tr));
    assert_eq!(WakeStyle::parse(Some("visible"), Some("de"), None), visible(Lang::Tr));
    assert_eq!(WakeStyle::parse(Some("visible"), Some("en"), None), visible(Lang::En));
    assert_eq!(WakeStyle::Data.lang_column(), None);
    assert_eq!(visible(Lang::En).column(), "visible");
    assert_eq!(visible(Lang::En).lang_column(), Some("en"));
}

// ---- The channel a visible wake is drawn on (`WakeChannel`) ----

/// The wake channel changes the notification's `channel_id` and nothing else.
#[test]
fn a_visible_wake_on_the_wake_channel_names_it_and_nothing_else_changes() {
    for lang in [Lang::Tr, Lang::En] {
        let quiet = fcm_message(TOKEN, WakeStyle::Visible(lang, WakeChannel::Wake), None);
        let mut loud = fcm_message(TOKEN, WakeStyle::Visible(lang, WakeChannel::Messages), None);
        assert_eq!(loud["message"]["android"]["notification"]["channel_id"], CHANNEL);
        assert_eq!(quiet["message"]["android"]["notification"]["channel_id"], WAKE_CHANNEL);
        loud["message"]["android"]["notification"]["channel_id"] = serde_json::json!(WAKE_CHANNEL);
        assert_eq!(quiet, loud);
    }
    assert_eq!(WAKE_CHANNEL, "sezgi_wake_v1", "the id the app creates (autostart.dart)");
}

/// The shared relay hears the wake channel only when the token asked for it; the message channel
/// sends the body it always sent, byte for byte.
#[test]
fn the_relay_body_names_the_wake_channel_only_for_it() {
    let old = serde_json::json!({ "token": TOKEN, "wake": "visible", "lang": "tr" }).to_string();
    let messages = WakeStyle::Visible(Lang::Tr, WakeChannel::Messages);
    assert_eq!(relay_body(TOKEN, messages, None, false).to_string(), old);
    assert_eq!(
        relay_body(TOKEN, WakeStyle::Visible(Lang::Tr, WakeChannel::Wake), Some("frame"), false),
        serde_json::json!({
            "token": TOKEN, "wake": "visible", "lang": "tr", "wake_channel": "sezgi_wake_v1",
        })
    );
}

/// An allow-list: only the exact id of the channel the app creates. Never a client's own string,
/// never for a data token, and a data wake stays byte-identical whatever channel is stored.
#[test]
fn the_wake_channel_is_allow_listed() {
    assert_eq!(WakeChannel::parse(Some("sezgi_wake_v1")), WakeChannel::Wake);
    for other in [
        None,
        Some(""),
        Some("sezgi_messages_v2"),
        Some("SEZGI_WAKE_V1"),
        Some("sezgi_wake_v1 "),
        Some("sezgi_wake_v2"),
        Some("miscellaneous"),
    ] {
        assert_eq!(WakeChannel::parse(other), WakeChannel::Messages, "{other:?}");
        let style = WakeStyle::parse(Some("visible"), Some("en"), other);
        assert_eq!(style.channel_column(), None, "{other:?}");
        let m = fcm_message(TOKEN, style, None);
        assert_eq!(m["message"]["android"]["notification"]["channel_id"], CHANNEL);
    }
    let data = WakeStyle::parse(Some("data"), None, Some("sezgi_wake_v1"));
    assert_eq!(data, WakeStyle::Data);
    assert_eq!(data.channel_column(), None);
    let legacy = serde_json::json!({
        "message": { "token": TOKEN, "data": { "type": "wake" }, "android": { "priority": "high" } }
    })
    .to_string();
    assert_eq!(fcm_message(TOKEN, data, None).to_string(), legacy);
    assert_eq!(relay_body(TOKEN, data, None, false).to_string(), serde_json::json!({ "token": TOKEN }).to_string());
}

/// What `/push/register` makes of a body: an old app's (no field) is the message channel, a new
/// app's visible register the wake channel, anything else the message channel.
#[test]
fn the_register_body_reads_the_channel_through_the_allow_list() {
    let style = |body: serde_json::Value| {
        serde_json::from_value::<super::super::handlers::RegisterBody>(body).unwrap().style()
    };
    let base = |extra: serde_json::Value| {
        let mut b = serde_json::json!({
            "fcm_token": TOKEN, "device_id": "d0", "platform": "android",
        });
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    assert_eq!(style(base(serde_json::json!({}))), WakeStyle::Data);
    assert_eq!(
        style(base(serde_json::json!({ "wake": "visible", "lang": "en" }))),
        WakeStyle::Visible(Lang::En, WakeChannel::Messages)
    );
    assert_eq!(
        style(base(serde_json::json!({
            "wake": "visible", "lang": "tr", "wake_channel": "sezgi_wake_v1",
        }))),
        WakeStyle::Visible(Lang::Tr, WakeChannel::Wake)
    );
    assert_eq!(
        style(base(serde_json::json!({ "wake": "visible", "wake_channel": "x".repeat(300) }))),
        WakeStyle::Visible(Lang::Tr, WakeChannel::Messages)
    );
    assert_eq!(
        style(base(serde_json::json!({ "wake": "data", "wake_channel": "sezgi_wake_v1" }))),
        WakeStyle::Data
    );
}

/// The column round-trips through the real register SQL: a row from before 0056 reads the message
/// channel, a register naming the wake channel stores it, and the next register that does not
/// (an older app installed again, Autostart turned on) clears it.
#[test]
fn the_register_stores_and_clears_the_channel() {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('u', 'u@x', x'00', 1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at,
                                  wake, wake_lang)
         VALUES ('u', 'd0', 'tok-a', 'android', 1, 1, 'visible', 'tr')",
        [],
    )
    .unwrap();
    // Read back through the wake's own queries, both of them, as the wake loop reads a row.
    let read = || {
        use super::super::wake::{TokenRow, DEVICE_TOKEN_SQL, USER_TOKENS_SQL};
        let row = |r: &rusqlite::Row<'_>| {
            Ok(TokenRow {
                wake: r.get(3)?,
                wake_lang: r.get(4)?,
                wake_channel: r.get(5)?,
                ..Default::default()
            })
        };
        let one = db.query_row(DEVICE_TOKEN_SQL, ["u", "d0"], row).unwrap().style();
        let all = db.query_row(USER_TOKENS_SQL, ["u"], row).unwrap().style();
        assert_eq!(one, all);
        one
    };
    assert_eq!(read(), WakeStyle::Visible(Lang::Tr, WakeChannel::Messages), "before 0056");
    let register = |style: WakeStyle| {
        db.execute(
            super::super::handlers::REGISTER_SQL,
            rusqlite::params![
                "u",
                "d0",
                "tok-a",
                "android",
                2,
                2,
                style.column(),
                style.lang_column(),
                style.channel_column()
            ],
        )
        .unwrap();
    };
    register(WakeStyle::Visible(Lang::En, WakeChannel::Wake));
    assert_eq!(read(), WakeStyle::Visible(Lang::En, WakeChannel::Wake));
    register(WakeStyle::Visible(Lang::En, WakeChannel::Messages));
    assert_eq!(read(), WakeStyle::Visible(Lang::En, WakeChannel::Messages), "an older app");
    register(WakeStyle::Visible(Lang::En, WakeChannel::Wake));
    register(WakeStyle::Data);
    assert_eq!(read(), WakeStyle::Data);
    let stored: Option<String> = db
        .query_row("SELECT wake_channel FROM push_tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, None, "a data token keeps no channel");
}
