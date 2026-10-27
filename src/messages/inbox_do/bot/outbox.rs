//! What the bot inbox owes the network, durable until it is paid.
//!
//! The tick's synchronous block may not `await`, so everything it decides to send is written
//! here and sent after: a `notify` (one Olm envelope into a member's inbox), a
//! `forward_delivered` / `forward_failed` (the member's second tick, or its re-pair cue). One
//! drain sends at most a budget's worth — the 50-subrequest ceiling `messages/budget.rs` assumes,
//! less headroom — and leaves the rest for the next alarm. A row that keeps failing backs off
//! (5 s, 30 s, 2 min, 10 min, then hourly) and is dropped after 24 h.
//!
//! A `room_send` (Phase 3, `room.rs`) is the one row paid in parts: a room post handed to as many
//! members as the drain can pay for, the row rewritten with who has it, and the rest sent at once
//! by the next drain.

use super::room::RoomSendStep;
use super::*;

/// Subrequests one drain may spend (less when a built-in round spent first: `builtin_policy`).
pub(super) const DRAIN_BUDGET: u32 = 35;
/// A `notify` at its worst: the call and the member's wake (`bot_send_notify`).
pub(super) const NOTIFY_WORST: u32 = 5;
/// A row older than this is given up on.
const OUTBOX_TTL_MS: i64 = 24 * 3600 * 1000;

/// Bind: kind, body, next_at, created_at.
pub(super) const OUTBOX_PUSH: &str =
    "INSERT INTO bot_outbox (kind, body, attempts, next_at, created_at) VALUES (?, ?, 0, ?, ?)";
/// Bind: now, limit.
pub(super) const OUTBOX_DUE: &str = "SELECT id, kind, body, attempts FROM bot_outbox
      WHERE next_at <= ? ORDER BY id LIMIT ?";
/// Bind: id.
pub(super) const OUTBOX_DONE: &str = "DELETE FROM bot_outbox WHERE id = ?";
/// Bind: next_at, id.
pub(super) const OUTBOX_RETRY: &str =
    "UPDATE bot_outbox SET attempts = attempts + 1, next_at = ? WHERE id = ?";
/// Bind: cutoff.
pub(super) const OUTBOX_EXPIRE: &str = "DELETE FROM bot_outbox WHERE created_at < ?";
pub(super) const OUTBOX_NEXT: &str = "SELECT MIN(next_at) AS t FROM bot_outbox";
/// A `room_send` row after a part of it went: who has it now, and when the rest goes.
/// Bind: body, attempts, next_at, id.
pub(super) const OUTBOX_REWRITE: &str = "UPDATE bot_outbox SET body = ?, attempts = ?, next_at = ? WHERE id = ?";
/// A `room_send` drain needs at least its two D1 reads and one member call.
const ROOM_SEND_MIN: u32 = 3;
/// Every row still owed for a room the bot left: its key shares and its posts' chunks.
/// Bind: room.
pub(super) const OUTBOX_DROP_ROOM: &str = "DELETE FROM bot_outbox
      WHERE kind IN ('notify', 'room_send') AND json_extract(body, '$.room_id') = ?";
/// The bot is back on: the room posts held off go now. Bind: now.
pub(super) const OUTBOX_WAKE_ROOM_SENDS: &str = "UPDATE bot_outbox SET next_at = ? WHERE kind = 'room_send'";
/// How long a `room_send` waits while the bot is off (its `/bot/wake` pulls it forward).
const ROOM_SEND_HOLD_MS: i64 = super::room_plan::HOLD_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OutKind {
    Notify,
    ForwardDelivered,
    ForwardFailed,
    /// The program took the member's message: their blue tick.
    ForwardRead,
    /// A room post, encrypted, owed to the room's members (Phase 3).
    RoomSend,
}

impl OutKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            OutKind::Notify => "notify",
            OutKind::ForwardDelivered => "forward_delivered",
            OutKind::ForwardFailed => "forward_failed",
            OutKind::ForwardRead => "forward_read",
            OutKind::RoomSend => "room_send",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Notify, Self::ForwardDelivered, Self::ForwardFailed, Self::ForwardRead, Self::RoomSend]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// How long a row that failed `attempts` times (before this failure) waits, in ms.
pub(super) fn retry_delay_ms(attempts: i64) -> i64 {
    match attempts {
        0 => 5_000,
        1 => 30_000,
        2 => 120_000,
        3 => 600_000,
        _ => 3_600_000,
    }
}

#[derive(Deserialize)]
struct DueRow {
    id: i64,
    kind: String,
    body: String,
    attempts: i64,
}

#[derive(Deserialize)]
struct NotifyBody {
    user_id: String,
    device_id: String,
    envelope_b64: String,
    #[serde(default)]
    msg_uid: Option<String>,
    /// A room key share names its room (`room::bot_queue_room_shares`; its `session_id` is there
    /// for diagnosis).
    #[serde(default)]
    room_id: Option<String>,
}

/// May a queued notify still go? A room key share only while the bot still holds a session in
/// that room: once it left, the room is forgotten and the share is dropped. A share of a session
/// since rotated still goes — the post it opens was encrypted for that member while they were one
/// (a removal deletes the room's owed rows outright, `OUTBOX_DROP_ROOM`).
pub(super) fn share_still_current(room: Option<&str>, current: impl Fn(&str) -> Option<String>) -> bool {
    room.is_none_or(|r| current(r).is_some())
}

#[derive(Deserialize)]
struct ForwardBody {
    to: String,
    payload: serde_json::Value,
}

impl UserInbox {
    pub(super) fn bot_outbox_push(&self, kind: OutKind, body: &serde_json::Value, now: i64) {
        let args = vec![
            JsValue::from_str(kind.as_str()),
            JsValue::from_str(&body.to_string()),
            JsValue::from_f64(now as f64),
            JsValue::from_f64(now as f64),
        ];
        if let Err(e) = self.state.storage().sql().exec_raw(OUTBOX_PUSH, Some(args)) {
            console_log!("[bot] outbox write failed: {e:?}");
        }
    }

    /// One Olm envelope for one member device. A pair-ack carries no `msg_uid` and wakes nobody.
    pub(super) fn bot_queue_deliver(
        &self,
        user_id: &str,
        device_id: &str,
        envelope_b64: &str,
        msg_uid: Option<&str>,
        now: i64,
    ) {
        let body = serde_json::json!({
            "user_id": user_id,
            "device_id": device_id,
            "envelope_b64": envelope_b64,
            "msg_uid": msg_uid,
        });
        self.bot_outbox_push(OutKind::Notify, &body, now);
    }

    /// Send what is due, within the drain's own budget.
    pub(super) async fn bot_drain_outbox(&self, ctx: &BotCtx) {
        self.bot_drain_outbox_within(ctx, DRAIN_BUDGET).await;
    }

    /// Send what is due within `budget` subrequests: a row is sent only when its worst case fits.
    pub(super) async fn bot_drain_outbox_within(&self, ctx: &BotCtx, budget: u32) {
        let now = (now_secs() * 1000) as i64;
        let sql = self.state.storage().sql();
        let _ = sql.exec_raw(OUTBOX_EXPIRE, Some(vec![JsValue::from_f64((now - OUTBOX_TTL_MS) as f64)]));
        let due: Vec<DueRow> = match sql
            .exec_raw(OUTBOX_DUE, Some(vec![JsValue::from_f64(now as f64), JsValue::from_f64(budget as f64)]))
            .and_then(|c| c.to_array())
        {
            Ok(rows) => rows,
            Err(e) => {
                console_log!("[bot] outbox read failed: {e:?}");
                return;
            }
        };
        let mut spent = 0u32;
        for row in due {
            let worst = match OutKind::parse(&row.kind) {
                Some(OutKind::Notify) => NOTIFY_WORST,
                Some(OutKind::RoomSend) => ROOM_SEND_MIN,
                Some(_) => 1,
                None => 0,
            };
            if spent + worst > budget {
                break;
            }
            if OutKind::parse(&row.kind) == Some(OutKind::RoomSend) {
                let (step, cost) = self.bot_send_room_chunk(ctx, &row.body, budget - spent).await;
                spent += cost;
                let id = JsValue::from_f64(row.id as f64);
                let rewrite = |body: String, attempts: i64, next: i64| {
                    let args = vec![
                        JsValue::from_str(&body),
                        JsValue::from_f64(attempts as f64),
                        JsValue::from_f64(next as f64),
                        id.clone(),
                    ];
                    let _ = sql.exec_raw(OUTBOX_REWRITE, Some(args));
                };
                match step {
                    RoomSendStep::Done => {
                        let _ = sql.exec_raw(OUTBOX_DONE, Some(vec![id.clone()]));
                    }
                    RoomSendStep::Progress(body) => rewrite(body, 0, now),
                    RoomSendStep::Retry(body) => rewrite(body, row.attempts + 1, now + retry_delay_ms(row.attempts)),
                    RoomSendStep::Hold => rewrite(row.body.clone(), row.attempts, now + ROOM_SEND_HOLD_MS),
                }
                continue;
            }
            let (ok, cost) = match OutKind::parse(&row.kind) {
                Some(OutKind::Notify) => self.bot_send_notify(ctx, &row.body).await,
                Some(kind) => (self.bot_send_forward(kind, &row.body).await, 1),
                None => (true, 0), // an unknown kind from a later version: drop it
            };
            spent += cost;
            let (query, args) = if ok {
                (OUTBOX_DONE, vec![JsValue::from_f64(row.id as f64)])
            } else {
                let next = now + retry_delay_ms(row.attempts);
                (OUTBOX_RETRY, vec![JsValue::from_f64(next as f64), JsValue::from_f64(row.id as f64)])
            };
            let _ = sql.exec_raw(query, Some(args));
        }
    }

    /// One `notify`, then the member's wake when no socket of theirs took it. (sent?, cost).
    async fn bot_send_notify(&self, ctx: &BotCtx, body: &str) -> (bool, u32) {
        let Ok(n) = serde_json::from_str::<NotifyBody>(body) else {
            return (true, 0);
        };
        let store = self.bot_store();
        let current = |r: &str| sezi_bot_engine::RoomStore::room_session(&store, r).map(|s| s.session_id);
        if !share_still_current(n.room_id.as_deref(), current) {
            return (true, 0); // a key share for a room the bot left: drop it
        }
        let Ok(namespace) = self.env.durable_object("USER_INBOX") else {
            return (false, 0);
        };
        let silent = n.msg_uid.is_none();
        let sent = crate::messages::handlers::notify_recipient(
            &namespace,
            &n.user_id,
            &ctx.bot_id,
            &ctx.device_id,
            Some(&n.device_id),
            &n.envelope_b64,
            None,
            silent,
        )
        .await;
        let Ok((pending_id, delivered_live)) = sent else {
            return (false, 2);
        };
        let mut cost = 2;
        if let Some(uid) = &n.msg_uid {
            let _ = self.state.storage().sql().exec_raw(
                "UPDATE bot_sent SET pending_id = ? WHERE msg_uid = ? AND device_id = ?",
                Some(vec![
                    JsValue::from_f64(pending_id as f64),
                    JsValue::from_str(uid),
                    JsValue::from_str(&n.device_id),
                ]),
            );
        }
        if !delivered_live && !silent {
            if let Ok(db) = self.env.d1("DB") {
                crate::push::wake::maybe_push_wake(&self.env, &db, &n.user_id, Some(&n.device_id)).await;
                cost += 3;
            }
        }
        (true, cost)
    }

    async fn bot_send_forward(&self, kind: OutKind, body: &str) -> bool {
        let Ok(f) = serde_json::from_str::<ForwardBody>(body) else {
            return true;
        };
        let path = match kind {
            OutKind::ForwardDelivered => "/forward-delivered",
            OutKind::ForwardRead => "/forward-read",
            _ => "/forward-delivery-failed",
        };
        let sent =
            crate::bots::bot_inbox(&self.env, &f.to, Method::Post, path, Some(f.payload.to_string())).await;
        matches!(sent, Ok(r) if (200..300).contains(&r.status_code()))
    }

    /// Arm the alarm for whatever the bot still owes: now while frames wait, else the outbox's
    /// earliest retry, or the webhook's next attempt. (`arm_alarm_within` only ever pulls an alarm EARLIER.)
    pub(super) async fn bot_rearm(&self) {
        let now = (now_secs() * 1000) as i64;
        let store = self.bot_store();
        use super::store::Exec;
        let pending = store.db.int("SELECT COUNT(*) AS n FROM pending", &[]).unwrap_or(1);
        // Re-pairs a tick's purse could not cover: the next tick, with a fresh purse, pays them.
        let owed = [super::ingest::KV_OWED_RESENDS, super::ingest::KV_OWED_REPAIRS]
            .iter()
            .any(|k| store.kv_get(k).is_some());
        if pending > 0 || owed {
            self.arm_alarm_within(0).await;
            return;
        }
        let next = [
            store.db.int(OUTBOX_NEXT, &[]),
            self.bot_webhook_next(),
            self.bot_builtin_next(),
            self.bot_builtin_expiry_next(),
            self.bot_room_next(),
        ]
            .into_iter()
            .flatten()
            .min();
        if let Some(t) = next {
            self.arm_alarm_within((t - now).max(0)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_back_off_then_settle_at_an_hour() {
        let d: Vec<i64> = (0..7).map(retry_delay_ms).collect();
        assert_eq!(d, vec![5_000, 30_000, 120_000, 600_000, 3_600_000, 3_600_000, 3_600_000]);
    }

    #[test]
    fn every_kind_survives_its_own_name() {
        for k in [OutKind::Notify, OutKind::ForwardDelivered, OutKind::ForwardFailed, OutKind::ForwardRead, OutKind::RoomSend] {
            assert_eq!(OutKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(OutKind::parse("webhook"), None);
    }

    #[test]
    fn the_outbox_sql_queues_retries_and_expires() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        for t in super::super::store::TABLES {
            c.execute_batch(t).unwrap();
        }
        let push = |body: &str, at: i64| {
            c.execute(OUTBOX_PUSH, rusqlite::params!["notify", body, at, at]).unwrap();
        };
        push("a", 1_000);
        push("b", 2_000);
        push("c", 9_000);
        let due = |now: i64| -> Vec<(i64, String)> {
            let mut s = c.prepare(OUTBOX_DUE).unwrap();
            s.query_map(rusqlite::params![now, 35], |r| Ok((r.get(0)?, r.get(2)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(due(5_000).iter().map(|r| r.1.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        let (a, b) = (due(5_000)[0].0, due(5_000)[1].0);
        c.execute(OUTBOX_DONE, [a]).unwrap();
        c.execute(OUTBOX_RETRY, rusqlite::params![20_000, b]).unwrap();
        assert!(due(5_000).is_empty(), "a sent, b backed off");
        let next: i64 = c.query_row(OUTBOX_NEXT, [], |r| r.get(0)).unwrap();
        assert_eq!(next, 9_000, "the earliest owed row arms the alarm");
        let attempts: i64 =
            c.query_row("SELECT attempts FROM bot_outbox WHERE id = ?", [b], |r| r.get(0)).unwrap();
        assert_eq!(attempts, 1);
        c.execute(OUTBOX_EXPIRE, [5_000]).unwrap();
        let left: i64 = c.query_row("SELECT COUNT(*) FROM bot_outbox", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 1, "rows created before the cutoff are given up on");
    }
}
