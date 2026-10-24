//! Updates: what the bot's program reads (docs/BOTS_BUILD.md §2.5).
//!
//! ```json
//! {"update_id": 42, "kind": "message", "at": 1761200000000,
//!  "chat": {"type": "direct", "user_id": "…"},
//!  "message": {"message_id": "<sender's msg_uid>", "text": "…", "reply_to": null},
//!  "command": {"name": "durusma", "args": "yarın"},
//!  "who": {"user_id": "…", "display_name": "…", "server_role": "member"}}
//! ```
//!
//! `who` is the relay's, from D1 — never the sender's word. `update_id` is the row id, added
//! when read. Kept 24 h (R9 decision 3); `getUpdates` with an `offset` confirms and deletes
//! everything below it, Telegram's way.

use super::*;

/// How long an unconfirmed update is kept.
pub(super) const UPDATE_TTL_MS: i64 = 24 * 3600 * 1000;

/// Bind: json, created_at.
pub(super) const UPDATE_PUSH: &str = "INSERT INTO bot_updates (json, created_at) VALUES (?, ?)";
/// Bind: offset.
pub(super) const UPDATE_CONFIRM: &str = "DELETE FROM bot_updates WHERE update_id < ?";
/// Bind: offset, limit.
pub(super) const UPDATE_READ: &str = "SELECT update_id, json FROM bot_updates
      WHERE update_id >= ? ORDER BY update_id LIMIT ?";
/// Bind: now, offset, last update_id read.
pub(super) const UPDATE_MARK: &str = "UPDATE bot_updates SET delivered_at = ?,
      attempts = attempts + 1 WHERE update_id >= ? AND update_id <= ?";
/// Bind: cutoff.
pub(super) const UPDATE_EXPIRE: &str = "DELETE FROM bot_updates WHERE created_at < ?";

/// The sender as D1 has them.
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Who {
    pub(crate) user_id: String,
    #[serde(default)]
    pub(crate) display_name: Option<String>,
    #[serde(default)]
    pub(crate) server_role: Option<String>,
}

/// `/name args` (or `/name@bot args`) at the very start of a text, else `None`. A name is
/// letters, digits and `_`, at most 32 of them.
pub(crate) fn parse_command(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix('/')?;
    let (head, args) = match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], rest[i..].trim()),
        None => (rest, ""),
    };
    let name = head.split('@').next().unwrap_or("");
    let ok = !name.is_empty()
        && name.chars().count() <= 32
        && name.chars().all(|c| c.is_alphanumeric() || c == '_');
    ok.then(|| (name.to_lowercase(), args.to_string()))
}

/// The update for a 1:1 text a member sent the bot.
pub(crate) fn message_update(
    at_ms: i64,
    from: &str,
    who: Option<&Who>,
    msg_uid: Option<&str>,
    body: &str,
    ext: &serde_json::Value,
) -> serde_json::Value {
    let who = match who {
        Some(w) => serde_json::json!({
            "user_id": w.user_id,
            "display_name": w.display_name,
            "server_role": w.server_role,
        }),
        None => serde_json::json!({ "user_id": from }),
    };
    let reply_to = ext.get("reply").and_then(|r| r.get("msg_uid")).cloned();
    let mut update = serde_json::json!({
        "kind": "message",
        "at": at_ms,
        "chat": { "type": "direct", "user_id": from },
        "message": { "message_id": msg_uid, "text": body, "reply_to": reply_to },
        "who": who,
    });
    if let Some((name, args)) = parse_command(body) {
        update["command"] = serde_json::json!({ "name": name, "args": args });
    }
    update
}

#[derive(Deserialize)]
struct UpdateRow {
    update_id: i64,
    json: String,
}

impl UserInbox {
    pub(super) fn bot_push_update(&self, update: &serde_json::Value, now: i64) {
        let args = vec![JsValue::from_str(&update.to_string()), JsValue::from_f64(now as f64)];
        if let Err(e) = self.state.storage().sql().exec_raw(UPDATE_PUSH, Some(args)) {
            console_log!("[bot] update write failed: {e:?}");
        }
    }

    /// `getUpdates`: confirm below `offset`, then answer what is waiting — or wait for it, up to
    /// `timeout` seconds, re-reading this inbox's own SQLite each second. The wait holds no
    /// storage lock: the alarm that writes a new update runs in between.
    pub(super) async fn bot_get_updates(&self, body: &serde_json::Value) -> Result<Response> {
        let int = |k: &str, d: i64| body.get(k).and_then(|v| v.as_i64()).unwrap_or(d);
        let (offset, timeout, limit) = (int("offset", 0), int("timeout", 0), int("limit", 100));
        let sql = self.state.storage().sql();
        if offset > 0 {
            sql.exec_raw(UPDATE_CONFIRM, Some(vec![JsValue::from_f64(offset as f64)]))?;
        }
        let mut waited = 0;
        let rows: Vec<UpdateRow> = loop {
            let args = vec![JsValue::from_f64(offset as f64), JsValue::from_f64(limit as f64)];
            let rows: Vec<UpdateRow> = sql.exec_raw(UPDATE_READ, Some(args))?.to_array()?;
            if !rows.is_empty() || waited >= timeout {
                break rows;
            }
            worker::Delay::from(std::time::Duration::from_secs(1)).await;
            waited += 1;
        };
        if let Some(last) = rows.last() {
            let now = (now_secs() * 1000) as i64;
            let args = vec![
                JsValue::from_f64(now as f64),
                JsValue::from_f64(offset as f64),
                JsValue::from_f64(last.update_id as f64),
            ];
            let _ = sql.exec_raw(UPDATE_MARK, Some(args));
        }
        let updates: Vec<serde_json::Value> = rows
            .into_iter()
            .filter_map(|r| {
                let mut u: serde_json::Value = serde_json::from_str(&r.json).ok()?;
                u["update_id"] = r.update_id.into();
                Some(u)
            })
            .collect();
        Response::from_json(&serde_json::json!({ "ok": true, "updates": updates }))
    }
}

#[cfg(test)]
#[path = "updates_tests.rs"]
mod tests;
