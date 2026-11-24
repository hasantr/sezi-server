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

/// The bot API's major version: the `v1` in `/bot/v1/`. Inside it every change is additive (a new
/// method, field, update `kind`, error code or feature), each with its entry in
/// `tools/bots/CHANGELOG.md`; a breaking change is a new major served beside this one at
/// `/bot/v2/`, never a change to what v1 answers.
pub(crate) const API_VERSION: u32 = 1;

/// What this relay's v1 does, by name (`tools/bots/api_v1.json` describes each). A program asks
/// `features` rather than guessing from a server's build: a name is added when its behaviour
/// ships and is never taken back inside v1.
pub(crate) const FEATURES: [&str; 13] = [
    "long_poll",
    "webhook",
    "direct_messages",
    "commands",
    "room_messages",
    "room_replies",
    "idempotent_send",
    "member_files",
    "discovery",
    // `app` updates and `answerApp`: the bot's interface (`docs/BOT_APP_PLAN.md`), since 1.3.
    "bot_app",
    // `sendDocument`: a file into a 1:1 chat (`bots/api_document.rs`), since 1.4.
    "documents",
    // `sendAppFile`: a file for the bot's interface, no message (`bots/api_document.rs`), since 1.5.
    "app_files",
    // `setMyCommands` / `getMyCommands` / `deleteMyCommands`: the menu members see (`bots/commands.rs`), since 1.6.
    "command_menu",
];

/// The bot API as `/capabilities` announces it (`bot_api`): readable before a program holds a
/// key, so a tool can tell which API a server speaks without one.
pub(crate) fn discovery() -> Value {
    json!({ "version": API_VERSION, "path": "/bot/v1/", "features": FEATURES })
}

/// `getMe`: the bot, and (since 1.1) the API version and features this relay serves.
pub(crate) fn me(bot_id: &str, name: &str, about: Option<&str>) -> Value {
    json!({
        "ok": true,
        "bot": { "bot_id": bot_id, "name": name, "about": about },
        "api_version": API_VERSION,
        "features": FEATURES,
    })
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

/// `sendAppFile`: the stored file's manifest — where its blob is and its key — for the program to
/// hand its interface. `media_id` is the blob, the rest opens it (`sezi_file::decrypt_in_memory`).
pub(crate) fn app_file(manifest: &sezi_protocol::inner::FileManifest) -> Value {
    json!({ "ok": true, "file": manifest })
}

/// `setMyCommands` / `deleteMyCommands`: kept.
pub(crate) fn commands_set() -> Value {
    json!({ "ok": true })
}

/// `getMyCommands`: the list the program set, `[]` for none.
pub(crate) fn commands(list: &[super::api_input::BotCommand]) -> Value {
    json!({ "ok": true, "commands": list })
}

/// `answerApp` queued for the member's devices.
pub(crate) fn app_answered() -> Value {
    json!({ "ok": true })
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
