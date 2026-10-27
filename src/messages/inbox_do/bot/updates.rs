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
//! everything below it that a poll handed out, Telegram's way — and nothing it never handed out.

use super::*;

/// How long an unconfirmed update is kept.
pub(super) const UPDATE_TTL_MS: i64 = 24 * 3600 * 1000;

/// Bind: json, created_at.
pub(super) const UPDATE_PUSH: &str =
    "INSERT INTO bot_updates (json, created_at) VALUES (?, ?) RETURNING update_id";
/// Confirm: every update below the offset that a poll HANDED OUT (`delivered_at`). One never
/// handed out stays, whatever the offset says — a program that sent a wrong offset (a clock,
/// another bot's counter) loses nothing it never saw. Until 2026-10-26 this deleted every row
/// below the offset. Bind: offset.
pub(super) const UPDATE_CONFIRM: &str =
    "DELETE FROM bot_updates WHERE update_id < ? AND delivered_at IS NOT NULL";
/// What a poll answers: from the offset on, plus anything below it never handed out (left there by
/// a wrong offset, or by a webhook since cleared), in update order. Bind: offset, limit.
pub(super) const UPDATE_READ: &str = "SELECT update_id, json FROM bot_updates
      WHERE update_id >= ? OR delivered_at IS NULL ORDER BY update_id LIMIT ?";
/// Bind: now, first update_id read, last update_id read.
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
    // The member's `ext.reply` is `sezi_protocol::reply`'s shape: the original's id is `uid`.
    let reply_to = sezi_protocol::reply::read(ext).map(|r| r.uid);
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

/// The longest file name and type an update carries: the sender's words, cut, never refused.
pub(crate) const MAX_FILE_NAME_CHARS: usize = 255;
pub(crate) const MAX_FILE_MIME_CHARS: usize = 127;

/// The update for a file (or an album) a member sent the bot 1:1 (H3): `kind: "file"`, its
/// `message` the caption rather than a text, and `files` naming each by the `file_id` that
/// `getFile` reads. Name, type and size are the member's own words from the manifest — what a
/// program shows, never what it trusts; the key and the `media_id` stay in the inbox.
pub(crate) fn file_update(
    at_ms: i64,
    from: &str,
    who: Option<&Who>,
    msg_uid: Option<&str>,
    caption: Option<&str>,
    ext: &serde_json::Value,
    files: &[(String, &sezi_protocol::inner::FileManifest)],
) -> serde_json::Value {
    let mut update = message_update(at_ms, from, who, msg_uid, "", ext);
    update["kind"] = "file".into();
    let reply_to = update["message"]["reply_to"].take();
    update["message"] = serde_json::json!({ "message_id": msg_uid, "caption": caption, "reply_to": reply_to });
    let cut = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    update["files"] = files
        .iter()
        .map(|(file_id, m)| {
            serde_json::json!({
                "file_id": file_id,
                "name": cut(&m.filename, MAX_FILE_NAME_CHARS),
                "mime": cut(&m.content_type, MAX_FILE_MIME_CHARS),
                "size": m.size,
            })
        })
        .collect();
    update
}

/// Where a room call came from, as the relay's own tables say (never the caller's word).
pub(crate) struct CallRoom<'a> {
    pub(crate) id: &'a str,
    pub(crate) name: &'a str,
    /// The caller's role in the room (`group_members.role`).
    pub(crate) role: &'a str,
}

/// The update for a member's call in a room (Phase 3). `message.message_id` is the call's id in
/// the room — what `sendMessage {chat:{room_id}, reply_to}` names to answer it; `lang` and
/// `utc_offset_min` are the caller's, when their kernel sent them.
#[allow(clippy::too_many_arguments)]
pub(crate) fn call_update(
    at_ms: i64,
    from: &str,
    who: Option<&Who>,
    room: &CallRoom<'_>,
    msg_uid: &str,
    body: &str,
    lang: Option<&str>,
    utc_offset_min: Option<i32>,
) -> serde_json::Value {
    let mut update = message_update(at_ms, from, who, Some(msg_uid), body, &serde_json::Value::Null);
    update["kind"] = "call".into();
    update["chat"] = serde_json::json!({ "type": "room", "room_id": room.id, "name": room.name });
    update["who"]["room_role"] = room.role.into();
    update["message"]["lang"] = lang.into();
    update["message"]["utc_offset_min"] = utc_offset_min.into();
    update
}

/// The update for the bot being added to a room or removed from it; `who` is the admin, as the
/// Worker read them from D1.
pub(crate) fn room_event_update(
    kind: &str,
    at_ms: i64,
    room_id: &str,
    name: &str,
    who: Option<&serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "at": at_ms,
        "chat": { "type": "room", "room_id": room_id, "name": name },
        "who": who.cloned().unwrap_or(serde_json::Value::Null),
    })
}

#[derive(Deserialize)]
struct UpdateRow {
    update_id: i64,
    json: String,
}

impl UserInbox {
    /// Store an update; its `update_id`, or `None` when the write failed.
    pub(super) fn bot_push_update(&self, update: &serde_json::Value, now: i64) -> Option<i64> {
        #[derive(Deserialize)]
        struct Id {
            update_id: i64,
        }
        let args = vec![JsValue::from_str(&update.to_string()), JsValue::from_f64(now as f64)];
        match self
            .state
            .storage()
            .sql()
            .exec_raw(UPDATE_PUSH, Some(args))
            .and_then(|c| c.to_array::<Id>())
        {
            Ok(rows) => rows.first().map(|r| r.update_id),
            Err(e) => {
                console_log!("[bot] update write failed: {e:?}");
                None
            }
        }
    }

    /// `getUpdates`: confirm below `offset`, then answer what is waiting — or wait for it, up to
    /// `timeout` seconds, re-reading this inbox's own SQLite each second. The wait holds no
    /// storage lock: the alarm that writes a new update runs in between.
    pub(super) async fn bot_get_updates(&self, body: &serde_json::Value) -> Result<Response> {
        let int = |k: &str, d: i64| body.get(k).and_then(|v| v.as_i64()).unwrap_or(d);
        let (offset, timeout, limit) = (int("offset", 0), int("timeout", 0), int("limit", 100));
        if self.bot_store().kv_get("webhook_url").is_some() {
            return crate::bots::api::bot_err(409, "webhook-active");
        }
        if self.builtin_config().is_some() {
            return crate::bots::api::bot_err(409, "builtin-active");
        }
        let ctx = self.bot_ctx()?;
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
            let first = rows.first().map_or(last.update_id, |r| r.update_id);
            let args = vec![
                JsValue::from_f64(now as f64),
                JsValue::from_f64(first as f64),
                JsValue::from_f64(last.update_id as f64),
            ];
            let _ = sql.exec_raw(UPDATE_MARK, Some(args));
            // The program has them: the members' blue ticks go out with the next tick.
            self.bot_updates_taken(&ctx, first, last.update_id, now);
            self.arm_alarm_within(0).await;
        }
        let rows = rows.into_iter().map(|r| (r.update_id, r.json));
        Response::from_json(&crate::bots::api_answer::updates(rows))
    }
}

#[cfg(test)]
#[path = "updates_tests.rs"]
mod tests;
