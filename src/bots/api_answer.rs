//! Every answer body a program can read from `/bot/v1/:method` (docs/BOTS_BUILD.md §2.5), built
//! in one place — the Worker's and the bot inbox's alike — so the conformance suite
//! (`conformance_tests.rs`) holds each shape to the table.

use serde_json::{json, Value};

/// `{ok:false, error:"bot/<code>"}`.
pub(crate) fn error(code: &str) -> Value {
    json!({ "ok": false, "error": format!("bot/{code}") })
}

/// `bot/rate-limited`, with the seconds to wait (also sent as `Retry-After`).
pub(crate) fn rate_limited(retry_after_s: u64) -> Value {
    json!({ "ok": false, "error": "bot/rate-limited", "retry_after": retry_after_s })
}

/// `getMe`.
pub(crate) fn me(bot_id: &str, name: &str, about: Option<&str>) -> Value {
    json!({ "ok": true, "bot": { "bot_id": bot_id, "name": name, "about": about } })
}

/// `getUpdates`: each stored update with its row id as `update_id`; a row that is not JSON (it
/// never is) is left out rather than failing the poll.
pub(crate) fn updates(rows: impl IntoIterator<Item = (i64, String)>) -> Value {
    let updates: Vec<Value> = rows
        .into_iter()
        .filter_map(|(id, json)| {
            let mut u: Value = serde_json::from_str(&json).ok()?;
            u.as_object_mut()?.insert("update_id".into(), id.into());
            Some(u)
        })
        .collect();
    json!({ "ok": true, "updates": updates })
}

/// `sendMessage`.
pub(crate) fn sent(message_id: &str) -> Value {
    json!({ "ok": true, "message_id": message_id })
}

/// `sendMessage` repeated under its `client_id`: the first send's id.
pub(crate) fn duplicate(message_id: &str) -> Value {
    json!({ "ok": true, "message_id": message_id, "duplicate": true })
}

/// `setWebhook` (the secret, when it set one) and `deleteWebhook`.
pub(crate) fn webhook(secret: Option<&str>) -> Value {
    match secret {
        Some(s) => json!({ "ok": true, "webhook_secret": s }),
        None => json!({ "ok": true }),
    }
}
