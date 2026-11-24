//! A bot's commands (bot API 1.6): `setMyCommands`, `getMyCommands`, `deleteMyCommands`.
//!
//! The program declares its own list — name, a line saying what it does, and whether choosing it
//! opens the bot's interface (`app`) instead of sending a text. The relay keeps it on the bot's
//! row (`bots.commands_json`, migration 0064) and hands it to every member's app on `GET /bots`
//! (`listing.rs`), which shows it under the chat's Menü and when "/" is typed — in a 1:1 chat as
//! `/name`, in a room the bot was added to as `/name@Bot` (`docs/BOTS_BUILD.md` Phase 4a). What a
//! member sends is still an ordinary text; the update's `command` reads it, listed or not.

use worker::*;

use super::api::bot_err;
use super::api_input::{BotCommand, Refusal};
use super::token::BotAuth;
use crate::d1util::d1_text;

const SET_SQL: &str = "UPDATE bots SET commands_json = ? WHERE bot_id = ?";
const GET_SQL: &str = "SELECT commands_json FROM bots WHERE bot_id = ?";

/// The stored list read back: what was set, or `[]` for none (or for a row an older build wrote).
pub(crate) fn stored(json: Option<&str>) -> Vec<BotCommand> {
    json.and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default()
}

pub(crate) async fn set(db: &D1Database, bot: &BotAuth, parsed: Result<Vec<BotCommand>, Refusal>) -> Result<Response> {
    let commands = match parsed {
        Ok(c) => c,
        Err((status, code)) => return bot_err(status, code),
    };
    let json = (!commands.is_empty()).then(|| serde_json::to_string(&commands).unwrap_or_default());
    let value = json.as_deref().map(d1_text).unwrap_or(wasm_bindgen::JsValue::NULL);
    db.prepare(SET_SQL).bind(&[value, d1_text(&bot.bot_id)])?.run().await?;
    Response::from_json(&super::api_answer::commands_set())
}

pub(crate) async fn get(db: &D1Database, bot: &BotAuth) -> Result<Response> {
    #[derive(serde::Deserialize)]
    struct Row {
        #[serde(default)]
        commands_json: Option<String>,
    }
    let row: Option<Row> = db.prepare(GET_SQL).bind(&[d1_text(&bot.bot_id)])?.first(None).await?;
    let commands = stored(row.and_then(|r| r.commands_json).as_deref());
    Response::from_json(&super::api_answer::commands(&commands))
}

pub(crate) async fn delete(db: &D1Database, bot: &BotAuth) -> Result<Response> {
    set(db, bot, Ok(Vec::new())).await
}

#[cfg(test)]
mod tests {
    use super::super::api_input::{parse_set_commands, BotCommand, MAX_COMMANDS};
    use super::stored;
    use serde_json::json;

    fn one(name: &str, desc: &str) -> serde_json::Value {
        json!({ "commands": [{ "command": name, "description": desc }] })
    }

    #[test]
    fn a_command_is_held_to_its_shape() {
        let ok = parse_set_commands(&one("/raf", "  Rafı aç ")).unwrap();
        assert_eq!(ok, vec![BotCommand { command: "raf".into(), description: "Rafı aç".into(), app: false }]);
        assert!(parse_set_commands(&one("gün_özeti", "x")).is_ok(), "any script, lowercase");
        for bad in ["", "Raf", "raf bul", "raf-bul", &"a".repeat(33)] {
            assert_eq!(parse_set_commands(&one(bad, "x")), Err((400, "bad-command")), "{bad}");
        }
        assert_eq!(parse_set_commands(&one("raf", " ")), Err((400, "bad-command")));
        assert_eq!(parse_set_commands(&one("raf", "a\nb")), Err((400, "bad-command")));
        assert_eq!(parse_set_commands(&one("raf", &"a".repeat(257))), Err((400, "bad-command")));
        let twice = json!({ "commands": [{ "command": "raf", "description": "a" }, { "command": "/raf", "description": "b" }] });
        assert_eq!(parse_set_commands(&twice), Err((400, "bad-command")));
        let many: Vec<_> = (0..=MAX_COMMANDS).map(|i| json!({ "command": format!("c{i}"), "description": "d" })).collect();
        assert_eq!(parse_set_commands(&json!({ "commands": many })), Err((400, "bad-command")));
        assert_eq!(parse_set_commands(&json!({ "commands": [] })), Ok(vec![]));
        assert_eq!(parse_set_commands(&json!({})), Err((400, "bad-request")));
        assert_eq!(parse_set_commands(&json!({ "commands": [{ "command": "raf", "description": "a", "app": "yes" }] })), Err((400, "bad-request")));
    }

    #[test]
    fn an_app_command_keeps_its_flag_and_a_plain_one_writes_none() {
        let c = parse_set_commands(&json!({ "commands": [
            { "command": "raf", "description": "Rafı aç", "app": true },
            { "command": "ara", "description": "Kitap ara" },
        ] }))
        .unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"[{"command":"raf","description":"Rafı aç","app":true},{"command":"ara","description":"Kitap ara"}]"#);
        assert_eq!(stored(Some(&json)), c);
        assert_eq!(stored(None), vec![]);
        assert_eq!(stored(Some("not json")), vec![]);
    }
}
