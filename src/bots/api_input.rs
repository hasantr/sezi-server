//! What a program may send `/bot/v1/:method`, judged before anything is read from D1 or the bot's
//! inbox (docs/BOTS_BUILD.md §2.5). Pure, so the conformance suite (`api_input_tests.rs`) runs the
//! very functions `api.rs` calls.
//!
//! A body is at most [`MAX_BODY_BYTES`], is a JSON OBJECT (an empty body reads as `{}`), and every
//! documented field has its documented type. A field of the wrong type is `bot/bad-request`, never
//! read as absent: until 2026-10-26 `{"offset": "43"}` was taken as offset 0 — nothing was ever
//! confirmed, and the program read the same updates for a day — and `setWebhook {"url": 5}`
//! cleared the webhook. A body that was not JSON at all read as `{}` the same way.

use serde_json::Value;

/// The largest body read. A 4,000-character text is at most 48 KiB as JSON even when every
/// character is escaped as a surrogate pair (`😀`, 12 bytes); nothing bigger has a use.
pub(crate) const MAX_BODY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_TEXT_CHARS: usize = 4000;
pub(crate) const MAX_POLL_SECS: i64 = 25;
pub(crate) const MAX_LIMIT: i64 = 100;
/// A room id as the relay mints them (a UUID) fits with room to spare.
pub(crate) const MAX_ROOM_ID_LEN: usize = 64;
/// A `reply_to` names a member's `msg_uid`, a UUID with a short prefix at most.
pub(crate) const MAX_REPLY_TO_LEN: usize = 128;
/// A `client_id` (idempotent sending): 1..=64 of `A-Z a-z 0-9 . _ : -`.
pub(crate) const MAX_CLIENT_ID_LEN: usize = 64;

/// A `file_id` (`getFile`): the inbox mints `f-<uuid>`; 1..=64 of `A-Z a-z 0-9 -` is accepted.
pub(crate) const MAX_FILE_ID_LEN: usize = 64;

/// A refusal: the HTTP status and the code after `bot/`.
pub(crate) type Refusal = (u16, &'static str);

const BAD_REQUEST: Refusal = (400, "bad-request");

/// The body as a JSON object. `declared_len` is the request's `content-length`, when it sent one:
/// a body announced too big is refused before a byte of it is read.
pub(crate) fn body_too_large(declared_len: Option<u64>) -> bool {
    declared_len.is_some_and(|n| n > MAX_BODY_BYTES as u64)
}

/// Parse a body already read (and judged by its real size, which `content-length` can lie about).
pub(crate) fn parse_body(bytes: &[u8]) -> Result<Value, Refusal> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err((413, "too-large"));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(Default::default()));
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v @ Value::Object(_)) => Ok(v),
        _ => Err(BAD_REQUEST),
    }
}

/// An optional integer field: absent or `null` is `default`; anything but an integer is refused.
fn int_field(body: &Value, key: &str, default: i64) -> Result<i64, Refusal> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v.as_i64().ok_or(BAD_REQUEST),
    }
}

/// An optional string field: absent or `null` is `None`; anything but a string is refused.
fn str_field<'a>(body: &'a Value, key: &str) -> Result<Option<&'a str>, Refusal> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(BAD_REQUEST),
    }
}

/// `getUpdates {offset?, timeout?, limit?}`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UpdatesQuery {
    pub(crate) offset: i64,
    pub(crate) timeout: i64,
    pub(crate) limit: i64,
}

pub(crate) fn parse_updates(body: &Value) -> Result<UpdatesQuery, Refusal> {
    let q = UpdatesQuery {
        offset: int_field(body, "offset", 0)?,
        timeout: int_field(body, "timeout", 0)?,
        limit: int_field(body, "limit", MAX_LIMIT)?,
    };
    let ok = q.offset >= 0 && (0..=MAX_POLL_SECS).contains(&q.timeout) && (1..=MAX_LIMIT).contains(&q.limit);
    ok.then_some(q).ok_or(BAD_REQUEST)
}

/// `setWebhook {url}`: `Some(url)` to set, `None` to clear (`""`, `null` or no `url` at all —
/// Telegram's reading of an empty url). The URL rule itself is `webhook::clean_url`'s.
pub(crate) fn parse_webhook(body: &Value) -> Result<Option<&str>, Refusal> {
    Ok(str_field(body, "url")?.filter(|u| !u.trim().is_empty()))
}

/// `getFile {file_id}`: the id a `kind: "file"` update named.
pub(crate) fn parse_get_file(body: &Value) -> Result<&str, Refusal> {
    let id = str_field(body, "file_id")?.ok_or(BAD_REQUEST)?;
    let ok = (1..=MAX_FILE_ID_LEN).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    ok.then_some(id).ok_or(BAD_REQUEST)
}

/// A `sendDocument`'s query, read as an object of strings (`bots/api_document.rs`): the member,
/// the file name they see, its type.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DocumentReq {
    pub(crate) user_id: String,
    pub(crate) name: String,
    pub(crate) mime: String,
}

/// A file name as it will show: 1..=200 characters, no separator, no control character.
pub(crate) fn document_name_ok(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && n.chars().count() <= 200 && !n.contains(['/', '\\']) && !n.chars().any(char::is_control)
}

/// A content type of the plain `type/subtype` shape, at most 100 bytes.
pub(crate) fn document_mime_ok(mime: &str) -> bool {
    mime.len() <= 100
        && mime.split_once('/').is_some_and(|(a, b)| {
            !a.is_empty() && !b.is_empty() && mime.bytes().all(|c| c.is_ascii_alphanumeric() || b"/.+-_".contains(&c))
        })
}

/// `sendDocument {user_id, name, mime?}` (its query parameters).
pub(crate) fn parse_document(body: &Value) -> Result<DocumentReq, Refusal> {
    let user_id = str_field(body, "user_id")?.ok_or(BAD_REQUEST)?;
    let name = str_field(body, "name")?.ok_or(BAD_REQUEST)?;
    let mime = str_field(body, "mime")?.unwrap_or("application/octet-stream");
    if user_id.len() != 36 || !document_name_ok(name) || !document_mime_ok(mime) {
        return Err(BAD_REQUEST);
    }
    Ok(DocumentReq { user_id: user_id.to_string(), name: name.trim().to_string(), mime: mime.to_string() })
}

/// Where a `sendMessage` goes.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Chat {
    User(String),
    Room(String),
}

/// A `sendMessage` that passed every check that needs no lookup.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SendReq {
    pub(crate) chat: Chat,
    /// Trailing whitespace trimmed.
    pub(crate) text: String,
    pub(crate) reply_to: Option<String>,
    pub(crate) client_id: Option<String>,
}

fn client_id_ok(id: &str) -> bool {
    (1..=MAX_CLIENT_ID_LEN).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// `sendMessage {chat:{user_id}|{room_id}, text, reply_to?, client_id?}`.
///
/// The order of the checks is the order of the answers a program sees, and the conformance suite
/// holds it: the shape (`bad-request`), then `buttons` (`unsupported`, Phase 4), then the text
/// (`bad-text`), then a 1:1 `reply_to` (`unsupported`).
pub(crate) fn parse_send(body: &Value) -> Result<SendReq, Refusal> {
    let chat = match body.get("chat") {
        Some(c @ Value::Object(_)) => c,
        _ => return Err(BAD_REQUEST),
    };
    let text = match body.get("text") {
        Some(Value::String(t)) => t,
        _ => return Err(BAD_REQUEST),
    };
    let reply_to = str_field(body, "reply_to")?;
    let client_id = str_field(body, "client_id")?;
    let user_id = str_field(chat, "user_id")?;
    let room_id = str_field(chat, "room_id")?;
    if reply_to.is_some_and(|r| r.len() > MAX_REPLY_TO_LEN) || client_id.is_some_and(|c| !client_id_ok(c)) {
        return Err(BAD_REQUEST);
    }
    if !matches!(body.get("buttons"), None | Some(Value::Null)) {
        return Err((400, "unsupported"));
    }
    let text = text.trim_end();
    if text.trim().is_empty() || text.chars().count() > MAX_TEXT_CHARS {
        return Err((400, "bad-text"));
    }
    let chat = match (room_id, user_id) {
        (Some(room), None) if !room.is_empty() && room.len() <= MAX_ROOM_ID_LEN => Chat::Room(room.to_string()),
        (None, Some(user)) => {
            // A reply names a room call (`update.message.message_id`); 1:1 replies are not built.
            if reply_to.is_some() {
                return Err((400, "unsupported"));
            }
            if user.len() != 36 {
                return Err(BAD_REQUEST);
            }
            Chat::User(user.to_string())
        }
        _ => return Err(BAD_REQUEST),
    };
    Ok(SendReq {
        chat,
        text: text.to_string(),
        reply_to: reply_to.map(str::to_string),
        client_id: client_id.map(str::to_string),
    })
}

/// The most an `answerApp` may hand the bot's interface: what the member's kernel takes
/// (`core` `features/bot_app.rs` `BOT_APP_DATA_MAX`), with room for the frame around it.
pub(crate) const MAX_APP_DATA_BYTES: usize = 32 * 1024;
/// The longest `request_id` an interface sends (`core` `kernel/bot_app.rs`).
pub(crate) const MAX_APP_REQUEST_ID_LEN: usize = 64;

/// An `answerApp` that passed every check that needs no lookup (`docs/BOT_APP_PLAN.md`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AnswerAppReq {
    pub(crate) user_id: String,
    /// A JSON text, passed to the interface as written.
    pub(crate) data: String,
    pub(crate) request_id: Option<String>,
}

/// `answerApp {user_id, data, request_id?}`: `data` a string of valid JSON (an object or array
/// is stringified first), at most [`MAX_APP_DATA_BYTES`].
pub(crate) fn parse_answer_app(body: &Value) -> Result<AnswerAppReq, Refusal> {
    let user_id = str_field(body, "user_id")?.ok_or(BAD_REQUEST)?;
    let request_id = str_field(body, "request_id")?;
    if user_id.len() != 36 || request_id.is_some_and(|r| r.is_empty() || r.len() > MAX_APP_REQUEST_ID_LEN) {
        return Err(BAD_REQUEST);
    }
    let data = match body.get("data") {
        Some(Value::String(s)) => {
            if serde_json::from_str::<Value>(s).is_err() {
                return Err(BAD_REQUEST);
            }
            s.clone()
        }
        Some(v @ (Value::Object(_) | Value::Array(_))) => v.to_string(),
        _ => return Err(BAD_REQUEST),
    };
    if data.len() > MAX_APP_DATA_BYTES {
        return Err((413, "too-large"));
    }
    Ok(AnswerAppReq { user_id: user_id.to_string(), data, request_id: request_id.map(str::to_string) })
}

/// Is the bot inbox's answer one the program may be handed as it is: a status below 500 and a
/// JSON object carrying a boolean `ok`? Anything else — an inbox that threw, one purged under a
/// call, a plain-text `not found` — is `bot/inbox-unavailable` (502), so every answer a program
/// reads is the documented `{ok, …}` shape.
pub(crate) fn is_program_answer(status: u16, body: &[u8]) -> bool {
    status < 500
        && serde_json::from_slice::<Value>(body)
            .ok()
            .is_some_and(|v| v.get("ok").is_some_and(Value::is_boolean))
}

#[cfg(test)]
#[path = "api_input_tests.rs"]
mod tests;

/// The most commands a bot lists (`setMyCommands`), as Telegram allows.
pub(crate) const MAX_COMMANDS: usize = 100;
/// A command's name: 1..=32 lowercase letters (any script), digits and `_` — what an update's
/// `command.name` can be (`inbox_do/bot/updates.rs` `parse_command` lowercases what it reads).
pub(crate) const MAX_COMMAND_CHARS: usize = 32;
/// What the menu shows beside a command, 1..=256 characters after trimming.
pub(crate) const MAX_COMMAND_DESCRIPTION_CHARS: usize = 256;

/// One command a bot lists, checked. `app`: choosing it in the menu opens the bot's interface
/// with the command as its start (`sezgi.ctx().botStart`) instead of sending a text.
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct BotCommand {
    pub(crate) command: String,
    pub(crate) description: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) app: bool,
}

/// A command name as a menu offers it: a leading `/` dropped, then held to its shape.
pub(crate) fn command_name_ok(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_COMMAND_CHARS).contains(&n)
        && name.chars().all(|c| (c.is_alphanumeric() || c == '_') && !c.is_uppercase())
}

/// `setMyCommands {commands:[{command, description, app?}]}`: the shape (`bad-request`), then each
/// entry (`bad-command`: a name or description out of shape, a name twice, more than 100).
pub(crate) fn parse_set_commands(body: &Value) -> Result<Vec<BotCommand>, Refusal> {
    let Some(Value::Array(list)) = body.get("commands") else {
        return Err(BAD_REQUEST);
    };
    if list.len() > MAX_COMMANDS {
        return Err((400, "bad-command"));
    }
    let mut out: Vec<BotCommand> = Vec::with_capacity(list.len());
    for entry in list {
        let Value::Object(e) = entry else {
            return Err(BAD_REQUEST);
        };
        let (Some(Value::String(name)), Some(Value::String(desc))) = (e.get("command"), e.get("description")) else {
            return Err(BAD_REQUEST);
        };
        let app = match e.get("app") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(BAD_REQUEST),
        };
        let name = name.trim().trim_start_matches('/');
        let desc = desc.trim();
        let desc_ok = (1..=MAX_COMMAND_DESCRIPTION_CHARS).contains(&desc.chars().count())
            && !desc.chars().any(char::is_control);
        if !command_name_ok(name) || !desc_ok || out.iter().any(|c| c.command == name) {
            return Err((400, "bad-command"));
        }
        out.push(BotCommand { command: name.to_string(), description: desc.to_string(), app });
    }
    Ok(out)
}
