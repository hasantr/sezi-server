//! How updates leave the bot inbox for its program, and what the program taking one means.
//!
//! Two ways out: the program polls (`getUpdates`, `updates.rs`) or the inbox POSTs each update
//! to the program's webhook (`crate::bots::webhook`). With a webhook set, polling is refused —
//! two consumers of one queue would each see half of it.
//!
//! **Webhook delivery** runs in the alarm's tick, in update order: the oldest update not yet
//! taken goes first, and a failure stops the round, so the program never sees a later update
//! before an earlier one. A failure backs off on the outbox's ladder (5 s, 30 s, 2 min, 10 min,
//! then hourly); the 24 h update window ends the attempts. A taken update is deleted at once:
//! a webhook's 2xx/3xx is its confirmation.
//!
//! **Taken = read.** Whichever way, the moment the program has an update, the member's frame it
//! came from gets a `forward-read` (queued in the outbox), so the member's blue tick means "the
//! program has it". A successful webhook also counts as the program being seen
//! (`bots.program_seen_at`), as an API call does.

use super::outbox::{retry_delay_ms, OutKind};
use super::store::{Arg, Exec};
use super::*;

/// Webhook POSTs one tick may make.
const WEBHOOK_BATCH: i64 = 10;

/// Bind: update_id, from_user, remote_id, msg_uid.
pub(super) const SRC_PUT: &str = "INSERT OR REPLACE INTO bot_update_src
      (update_id, from_user, remote_id, msg_uid) VALUES (?, ?, ?, ?)";
/// Bind: first, last.
pub(super) const SRC_TAKEN: &str = "SELECT from_user, remote_id, msg_uid FROM bot_update_src
      WHERE update_id >= ? AND update_id <= ? ORDER BY update_id";
/// Bind: first, last.
pub(super) const SRC_DROP: &str = "DELETE FROM bot_update_src WHERE update_id >= ? AND update_id <= ?";
/// Sources whose update is gone (confirmed by offset after being taken, or expired).
pub(super) const SRC_ORPHANS: &str =
    "DELETE FROM bot_update_src WHERE update_id NOT IN (SELECT update_id FROM bot_updates)";
/// What the webhook owes, oldest first. Bind: limit.
pub(super) const HOOK_DUE: &str = "SELECT update_id, json, attempts, next_at FROM bot_updates
      WHERE delivered_at IS NULL ORDER BY update_id LIMIT ?";
/// When the head of the webhook's queue is due (0 = now); NULL when nothing waits.
pub(super) const HOOK_NEXT: &str = "SELECT COALESCE(next_at, 0) AS t FROM bot_updates
      WHERE delivered_at IS NULL ORDER BY update_id LIMIT 1";
/// Bind: next_at, update_id.
pub(super) const HOOK_RETRY: &str =
    "UPDATE bot_updates SET attempts = attempts + 1, next_at = ? WHERE update_id = ?";
/// Bind: update_id.
pub(super) const HOOK_DONE: &str = "DELETE FROM bot_updates WHERE update_id = ?";
/// The oldest update the program has not been handed (ms), for "no word from the program".
pub(super) const WAITING_SINCE: &str =
    "SELECT MIN(created_at) AS t FROM bot_updates WHERE delivered_at IS NULL";

/// The webhook in force: (url, secret).
pub(super) fn webhook_of(store: &super::store::SqlBotStore<super::store::DoSql>) -> Option<(String, String)> {
    Some((store.kv_get("webhook_url")?, store.kv_get("webhook_secret")?))
}

/// One member's frames the program just took, as `forward-read` bodies: per sender, the remote
/// ids and their msg_uids, in parallel.
pub(super) fn group_taken(rows: &[(String, i64, Option<String>)]) -> Vec<(String, Vec<i64>, Vec<String>)> {
    let mut out: Vec<(String, Vec<i64>, Vec<String>)> = Vec::new();
    for (from, id, uid) in rows {
        let i = match out.iter().position(|(f, ..)| f == from) {
            Some(i) => i,
            None => {
                out.push((from.clone(), Vec::new(), Vec::new()));
                out.len() - 1
            }
        };
        out[i].1.push(*id);
        out[i].2.push(uid.clone().unwrap_or_default());
    }
    out
}

#[derive(Deserialize)]
struct SrcRow {
    from_user: String,
    remote_id: i64,
    #[serde(default)]
    msg_uid: Option<String>,
}

#[derive(Deserialize)]
struct DueRow {
    update_id: i64,
    json: String,
    attempts: i64,
    #[serde(default)]
    next_at: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct WebhookBody {
    /// `None` clears the webhook.
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    secret: Option<String>,
}

impl UserInbox {
    pub(super) fn bot_note_update_src(&self, update_id: i64, from: &str, remote_id: i64, uid: Option<&str>) {
        self.bot_store().db.run(
            SRC_PUT,
            &[Arg::I(update_id), Arg::T(from), Arg::I(remote_id), Arg::T(uid.unwrap_or(""))],
        );
    }

    /// The program has updates `first..=last`: queue a `forward-read` per member they came from.
    /// Synchronous; the caller arms the alarm that sends them.
    pub(super) fn bot_updates_taken(&self, ctx: &BotCtx, first: i64, last: i64, now: i64) {
        let sql = self.state.storage().sql();
        let range = || Some(vec![JsValue::from_f64(first as f64), JsValue::from_f64(last as f64)]);
        let rows: Vec<SrcRow> = match sql.exec_raw(SRC_TAKEN, range()).and_then(|c| c.to_array()) {
            Ok(r) => r,
            Err(e) => {
                console_log!("[bot] update sources read failed: {e:?}");
                return;
            }
        };
        let rows: Vec<_> = rows
            .into_iter()
            .map(|r| (r.from_user, r.remote_id, r.msg_uid.filter(|u| !u.is_empty())))
            .collect();
        for (to, ids, uids) in group_taken(&rows) {
            let body = serde_json::json!({
                "to": to,
                "payload": { "from": ctx.bot_id, "ids": ids, "uids": uids },
            });
            self.bot_outbox_push(OutKind::ForwardRead, &body, now);
        }
        let _ = sql.exec_raw(SRC_DROP, range());
    }

    /// `/bot/webhook`: set or clear the webhook (the Worker checked the URL and derived the
    /// secret from the program's key).
    pub(super) fn bot_set_webhook(&self, body: WebhookBody) -> Result<Response> {
        let store = self.bot_store();
        match (body.url, body.secret) {
            // A built-in runner is the queue's one reader; the owner turns it off first.
            (Some(_), _) if self.builtin_config().is_some() => {
                return crate::bots::api::bot_err(409, "builtin-active");
            }
            (Some(url), Some(secret)) => {
                store.kv_put("webhook_url", &url);
                store.kv_put("webhook_secret", &secret);
            }
            (None, _) => {
                store.db.run("DELETE FROM bot_kv WHERE k IN ('webhook_url', 'webhook_secret')", &[]);
            }
            (Some(_), None) => return Response::error("secret required", 400),
        }
        Response::empty().map(|r| r.with_status(204))
    }

    /// `/bot/webhook-secret`: a renewed key's secret, for a webhook already set. Without one
    /// there is nothing to sign, and the next `setWebhook` derives it anyway.
    pub(super) fn bot_set_webhook_secret(&self, body: WebhookBody) -> Result<Response> {
        let store = self.bot_store();
        if let (Some(secret), Some(_)) = (body.secret, store.kv_get("webhook_url")) {
            store.kv_put("webhook_secret", &secret);
        }
        Response::empty().map(|r| r.with_status(204))
    }

    /// `/bot/ping`: the owner's "Dene" — a `ping` update, delivered like any other.
    pub(super) async fn bot_ping(&self, who: serde_json::Value) -> Result<Response> {
        let now = (now_secs() * 1000) as i64;
        let owner = who.get("user_id").cloned().unwrap_or(serde_json::Value::Null);
        let update = serde_json::json!({
            "kind": "ping",
            "at": now,
            "chat": { "type": "direct", "user_id": owner },
            "who": who,
        });
        let Some(update_id) = self.bot_push_update(&update, now) else {
            return Response::error("update write failed", 500);
        };
        self.arm_alarm_within(0).await;
        Response::from_json(&serde_json::json!({ "ok": true, "update_id": update_id }))
    }

    /// The tick's webhook round. Errors are logged; the alarm re-arms from `HOOK_NEXT`.
    pub(super) async fn bot_deliver_webhooks(&self, ctx: &BotCtx) {
        let store = self.bot_store();
        let Some((url, secret)) = webhook_of(&store) else {
            return;
        };
        let sql = self.state.storage().sql();
        let due: Vec<DueRow> = match sql
            .exec_raw(HOOK_DUE, Some(vec![JsValue::from_f64(WEBHOOK_BATCH as f64)]))
            .and_then(|c| c.to_array())
        {
            Ok(r) => r,
            Err(e) => {
                console_log!("[bot] webhook queue read failed: {e:?}");
                return;
            }
        };
        let mut took_any = false;
        for row in due {
            let now = (now_secs() * 1000) as i64;
            if row.next_at.is_some_and(|t| t > now) {
                break;
            }
            let Ok(mut update) = serde_json::from_str::<serde_json::Value>(&row.json) else {
                let _ = sql.exec_raw(HOOK_DONE, Some(vec![JsValue::from_f64(row.update_id as f64)]));
                continue;
            };
            update["update_id"] = row.update_id.into();
            let update_json = update.to_string();
            let status = crate::bots::webhook::post(&url, &secret, now, &update_json).await;
            if matches!(status, Ok(s) if crate::bots::webhook::taken(s)) {
                self.bot_updates_taken(ctx, row.update_id, row.update_id, now);
                let _ = sql.exec_raw(HOOK_DONE, Some(vec![JsValue::from_f64(row.update_id as f64)]));
                took_any = true;
                continue;
            }
            console_log!("[bot] webhook attempt {} failed: {:?}", row.attempts + 1, status.map_err(|e| e.to_string()));
            let next = now + retry_delay_ms(row.attempts);
            let _ = sql.exec_raw(
                HOOK_RETRY,
                Some(vec![JsValue::from_f64(next as f64), JsValue::from_f64(row.update_id as f64)]),
            );
            break;
        }
        // The forward-reads it queued go out with this tick's outbox drain, which runs next.
        if took_any {
            crate::bots::mark_program_seen(&self.env, &ctx.bot_id).await;
        }
    }

    /// When the webhook's queue next needs the alarm, if a webhook is set and anything waits.
    pub(super) fn bot_webhook_next(&self) -> Option<i64> {
        let store = self.bot_store();
        webhook_of(&store)?;
        store.db.int(HOOK_NEXT, &[])
    }
}

#[cfg(test)]
#[path = "deliver_tests.rs"]
mod tests;
