//! What the bot sends: a program's text, its pair-acks, and resends after a member re-paired.
//!
//! The engine never initiates a PreKey to a device it already has a session with
//! (docs/BOTS_BUILD.md §2.4); the relay's part is to claim a key ONLY for the devices
//! `devices_without_session` names — every claim spends one of the member's one-time keys.

use super::*;
use sezi_bot_engine::{
    devices_without_session, on_delivery_failed, send_direct, send_pair_ack, top_up_otks, ClaimedKey,
    text_payload, DeviceKeys, Effect,
};
use sezi_protocol::inner::ChatPayload;

/// What the bot remembers of a sent message, for a resend; kept 7 days.
const SENT_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
/// How often the tick looks at the bot's one-time-key pool in D1.
const OTK_CHECK_EVERY_MS: i64 = 10 * 60 * 1000;

/// A message id of the bot's: `b-<uuid>`.
pub(super) fn new_msg_uid() -> String {
    format!("b-{}", uuid::Uuid::new_v4())
}

/// Bind: user.
pub(super) const SENT_FAIL_USER: &str = "UPDATE bot_sent SET failed = 1 WHERE user_id = ?";
/// Bind: user, pending_id.
pub(super) const SENT_COUNT_PENDING: &str = "SELECT COUNT(*) FROM bot_sent WHERE user_id = ? AND pending_id = ?";
/// Bind: user, pending_id.
pub(super) const SENT_FAIL_PENDING: &str = "UPDATE bot_sent SET failed = 1 WHERE user_id = ? AND pending_id = ?";
/// Rows whose `/notify` has not answered yet, of one device. Bind: user, device.
pub(super) const SENT_FAIL_UNRECORDED_DEVICE: &str =
    "UPDATE bot_sent SET failed = 1 WHERE user_id = ? AND device_id = ? AND pending_id IS NULL";
/// The same, of every device. Bind: user.
pub(super) const SENT_FAIL_UNRECORDED: &str =
    "UPDATE bot_sent SET failed = 1 WHERE user_id = ? AND pending_id IS NULL";

/// Mark for a resend what a member's `delivery_failed` names.
///
/// `ids` are the member inbox's `pending` row ids of the frames that did not open (its ack path
/// forwards the rows it deleted, `ack.rs`), which is what the outbox wrote into
/// `bot_sent.pending_id` when `/notify` answered. Only those are marked: until 2026-10-27 every
/// message of the member's last 7 days was, and the next pair-ack resent them all.
/// - No ids: the whole member, as before (nothing better is known).
/// - Ids none of which is recorded: the member's device answered before the bot heard `/notify`'s
///   answer, so the frame is one of that device's rows with no `pending_id` yet; those are
///   marked. A resend of one that did open is the same `msg_uid`, which the member's kernel drops.
pub(super) fn mark_failed(db: &impl super::store::Exec, from: &str, device: Option<&str>, ids: &[i64]) {
    use super::store::Arg;
    if ids.is_empty() {
        db.run(SENT_FAIL_USER, &[Arg::T(from)]);
        return;
    }
    let mut recorded = false;
    for &id in ids {
        if db.int(SENT_COUNT_PENDING, &[Arg::T(from), Arg::I(id)]).unwrap_or(0) > 0 {
            recorded = true;
            db.run(SENT_FAIL_PENDING, &[Arg::T(from), Arg::I(id)]);
        }
    }
    if !recorded {
        match device {
            Some(d) => db.run(SENT_FAIL_UNRECORDED_DEVICE, &[Arg::T(from), Arg::T(d)]),
            None => db.run(SENT_FAIL_UNRECORDED, &[Arg::T(from)]),
        }
    }
}

#[derive(Deserialize)]
struct FailedRow {
    device_id: String,
    payload_json: String,
}

impl UserInbox {
    /// A member's active devices, as the engine wants them.
    pub(super) async fn bot_member_devices(&self, user_id: &str) -> Result<Vec<DeviceKeys>> {
        #[derive(Deserialize)]
        struct Row {
            device_id: String,
            ed_pub: Vec<u8>,
            x_pub: Vec<u8>,
        }
        let db = self.env.d1("DB")?;
        let rows: Vec<Row> = db
            .prepare(
                "SELECT device_id, ed_pub, x_pub FROM devices
                  WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY device_id",
            )
            .bind(&[crate::d1util::d1_text(user_id)])?
            .all()
            .await?
            .results()?;
        Ok(rows
            .into_iter()
            .map(|r| DeviceKeys {
                user_id: user_id.to_string(),
                device_id: r.device_id,
                x_pub_b64: crate::utils::b64_encode(&r.x_pub),
                ed_pub_b64: crate::utils::b64_encode(&r.ed_pub),
            })
            .collect())
    }

    /// A key for each device that has no session: its one-time key, else its signed fallback.
    pub(super) async fn bot_claim_keys(&self, user_id: &str, devices: &[String]) -> Result<Vec<ClaimedKey>> {
        let db = self.env.d1("DB")?;
        let mut out = Vec::with_capacity(devices.len());
        for d in devices {
            let Some(slot) = crate::keys::handlers::build_device_bundle(&db, user_id, Some(d)).await? else {
                continue; // no signed prekey published yet: nothing can open a session to it
            };
            let otk = slot["one_time_key"]["prekey_pub_b64"].as_str();
            let spk = slot["signed_prekey"]["prekey_pub_b64"].as_str();
            if let Some(key) = otk.or(spk) {
                out.push(ClaimedKey { device_id: d.clone(), key_b64: key.to_string() });
            }
        }
        Ok(out)
    }

    /// Queue the engine's envelopes; a `msg_uid`'d one is remembered for a resend.
    fn bot_queue_effects(&self, effects: Vec<Effect>, payload_json: Option<&str>, now: i64) {
        for e in effects {
            if let Effect::Deliver { user_id, device_id, envelope_b64, msg_uid } = e {
                if let (Some(uid), Some(p)) = (msg_uid.as_deref(), payload_json) {
                    let _ = self.state.storage().sql().exec_raw(
                        "INSERT INTO bot_sent (msg_uid, user_id, device_id, pending_id, payload_json, created_at, failed)
                         VALUES (?, ?, ?, NULL, ?, ?, 0)
                         ON CONFLICT(msg_uid, device_id) DO UPDATE SET failed = 0",
                        Some(vec![
                            JsValue::from_str(uid),
                            JsValue::from_str(&user_id),
                            JsValue::from_str(&device_id),
                            JsValue::from_str(p),
                            JsValue::from_f64(now as f64),
                        ]),
                    );
                }
                self.bot_queue_deliver(&user_id, &device_id, &envelope_b64, msg_uid.as_deref(), now);
            }
        }
    }

    /// `sendMessage` with text, 1:1, as `msg_uid`. The Worker has already checked that `to` is an
    /// active human who has not blocked the bot.
    pub(super) async fn bot_send_text(&self, ctx: &BotCtx, to: &str, text: &str, msg_uid: &str) -> Result<Response> {
        if self.bot_encrypt_text(ctx, to, text, msg_uid).await?.is_none() {
            return crate::bots::api::bot_err(409, "no-devices");
        }
        // Queued: the outbox delivers it whatever happens to this request from here on, so a
        // retry under its `client_id` is answered, never sent again.
        super::send_replay::mark_sent(&self.bot_store().db, msg_uid);
        self.bot_drain_outbox(ctx).await;
        self.bot_rearm().await;
        Response::from_json(&crate::bots::api_answer::sent(msg_uid))
    }

    /// A built-in bot's text: encrypted and queued, sent by the tick's outbox drain. The
    /// subrequests it took (the device read and the key claims).
    pub(super) async fn bot_send_text_queued(&self, ctx: &BotCtx, to: &str, text: &str) -> Result<u32> {
        Ok(self.bot_encrypt_text(ctx, to, text, &new_msg_uid()).await?.unwrap_or(1))
    }

    /// Encrypt `text` to every device of `to` as `msg_uid` and queue the envelopes: the
    /// subrequests spent, or `None` when `to` has no device.
    async fn bot_encrypt_text(&self, ctx: &BotCtx, to: &str, text: &str, msg_uid: &str) -> Result<Option<u32>> {
        self.bot_encrypt_payload(ctx, to, &text_payload(text, msg_uid)).await
    }

    /// Encrypt any payload to every device of `to` and queue the envelopes (one with a `msg_uid`
    /// is remembered for a resend): the subrequests spent, or `None` when `to` has no device.
    pub(super) async fn bot_encrypt_payload(&self, ctx: &BotCtx, to: &str, payload: &ChatPayload) -> Result<Option<u32>> {
        let devices = self.bot_member_devices(to).await?;
        if devices.is_empty() {
            return Ok(None);
        }
        let need = devices_without_session(&self.bot_store(), to, &devices);
        let claimed = self.bot_claim_keys(to, &need).await?;
        let payload_json = serde_json::to_string(payload).map_err(|e| Error::RustError(e.to_string()))?;
        let now = (now_secs() * 1000) as i64;
        let effects = send_direct(&mut self.bot_store(), &ctx.key, to, &devices, &claimed, payload)
            .map_err(|e| Error::RustError(format!("bot send: {e}")))?;
        self.bot_queue_effects(effects, Some(&payload_json), now);
        // `build_device_bundle` is at most six D1 calls per claimed device (`keys/bundle_slot.rs`).
        Ok(Some(1 + 6 * need.len() as u32))
    }

    /// The engine's `Effect::Repair`: the bot's own pair-ack to every device of `user`, then what
    /// that member could not read. Best effort: a failure waits for the next frame or
    /// `delivery_failed`. The subrequests it spent (at most `builtin_policy::REPAIR_BASE`, save a
    /// resend to a device the pair-ack could not reach).
    pub(super) async fn bot_repair(&self, ctx: &BotCtx, user: &str) -> u32 {
        let mut spent = 0;
        if let Err(e) = self.bot_repair_inner(ctx, user, &mut spent).await {
            console_log!("[bot] repair of {user} failed: {e:?}");
        }
        spent + self.bot_resend_failed(ctx, user).await
    }

    async fn bot_repair_inner(&self, ctx: &BotCtx, user: &str, spent: &mut u32) -> Result<()> {
        *spent += 1;
        let devices = self.bot_member_devices(user).await?;
        if devices.is_empty() {
            return Ok(());
        }
        let need = devices_without_session(&self.bot_store(), user, &devices);
        // `build_device_bundle` is at most six D1 calls per claimed device (`keys/bundle_slot.rs`).
        *spent += 6 * need.len() as u32;
        let claimed = self.bot_claim_keys(user, &need).await?;
        let now = (now_secs() * 1000) as i64;
        let effects = send_pair_ack(&mut self.bot_store(), &ctx.key, user, &devices, &claimed)
            .map_err(|e| Error::RustError(format!("bot pair-ack: {e}")))?;
        self.bot_queue_effects(effects, None, now);
        Ok(())
    }

    /// Send again, to the same device, every message `user` reported it could not read. After a
    /// member's pair-ack this is ALL the host does — the engine already answered the pair-ack.
    /// The subrequests it spent: the member's device read and a key claim per device at most.
    pub(super) async fn bot_resend_failed(&self, ctx: &BotCtx, user: &str) -> u32 {
        let mut spent = 0;
        if let Err(e) = self.bot_resend_inner(ctx, user, &mut spent).await {
            console_log!("[bot] resend to {user} failed: {e:?}");
        }
        spent
    }

    async fn bot_resend_inner(&self, ctx: &BotCtx, user: &str, spent: &mut u32) -> Result<()> {
        let failed: Vec<FailedRow> = self
            .state
            .storage()
            .sql()
            .exec_raw(
                "SELECT device_id, payload_json FROM bot_sent WHERE user_id = ? AND failed = 1 ORDER BY created_at",
                Some(vec![JsValue::from_str(user)]),
            )?
            .to_array()?;
        if failed.is_empty() {
            return Ok(());
        }
        *spent += 1;
        let devices = self.bot_member_devices(user).await?;
        let now = (now_secs() * 1000) as i64;
        // A device is claimed for once: one with no key to claim stays without a session, and
        // asking again for each of its rows would spend six calls a row for nothing.
        let mut claimed_for = std::collections::BTreeSet::new();
        for row in failed {
            let (Ok(payload), Some(device)) = (
                serde_json::from_str::<ChatPayload>(&row.payload_json),
                devices.iter().find(|d| d.device_id == row.device_id),
            ) else {
                continue; // a device since removed, or a payload this build cannot read
            };
            let one = std::slice::from_ref(device);
            let mut need = devices_without_session(&self.bot_store(), user, one);
            need.retain(|d| claimed_for.insert(d.clone()));
            *spent += 6 * need.len() as u32;
            let claimed = self.bot_claim_keys(user, &need).await?;
            match send_direct(&mut self.bot_store(), &ctx.key, user, one, &claimed, &payload) {
                Ok(effects) => self.bot_queue_effects(effects, Some(&row.payload_json), now),
                Err(e) => console_log!("[bot] resend to {user}/{}: {e}", row.device_id),
            }
        }
        Ok(())
    }

    /// `/forward-delivery-failed` in bot mode: a member could not read what the bot sent. Mark it
    /// for a resend, let the engine wipe and (if the bot is the lower id) re-pair; nothing goes
    /// into `forward_queue`, which no socket of a bot would ever drain.
    pub(crate) async fn bot_delivery_failed(&self, from: &str, device: Option<&str>, ids: &[i64]) -> Result<Response> {
        self.bot_tables()?;
        let ctx = self.bot_ctx()?;
        mark_failed(&self.bot_store().db, from, device, ids);
        let now = (now_secs() * 1000) as i64;
        let effects = on_delivery_failed(&mut self.bot_store(), &ctx.bot_id, from, now);
        let repair = effects.iter().any(|e| matches!(e, Effect::Repair { .. }));
        self.bot_queue_effects(effects, None, now);
        if repair {
            self.bot_repair(&ctx, from).await;
        }
        self.bot_drain_outbox(&ctx).await;
        self.bot_rearm().await;
        Response::empty().map(|r| r.with_status(204))
    }

    /// Retention and the one-time-key pool. Best effort.
    pub(super) async fn bot_housekeeping(&self, ctx: &BotCtx) {
        let now = (now_secs() * 1000) as i64;
        let sql = self.state.storage().sql();
        let cutoff = |ttl: i64| Some(vec![JsValue::from_f64((now - ttl) as f64)]);
        let _ = sql.exec_raw(super::updates::UPDATE_EXPIRE, cutoff(super::updates::UPDATE_TTL_MS));
        // A member's file, key and all, goes with its updates' 24 h (`files.rs`).
        let _ = sql.exec_raw(super::files::FILE_EXPIRE, cutoff(super::updates::UPDATE_TTL_MS));
        let _ = sql.exec_raw(super::files::READS_PRUNE, cutoff(super::files::READ_WINDOW_MS));
        let _ = sql.exec_raw("DELETE FROM bot_sent WHERE created_at < ?", cutoff(SENT_TTL_MS));
        let _ = sql.exec_raw(super::store::SEEN_EXPIRE, cutoff(SENT_TTL_MS));
        let _ = sql.exec_raw(super::send_replay::CLIENT_EXPIRE, cutoff(super::send_replay::CLIENT_ID_TTL_MS));
        let _ = sql.exec_raw(super::deliver::SRC_ORPHANS, sql_no_args());
        let _ = sql.exec_raw(super::deliver_order::ASIDE_ORPHANS, sql_no_args());
        let _ = sql.exec_raw(super::backlog::NOTICE_EXPIRE, cutoff(super::backlog::NOTICE_EVERY_MS));
        self.builtin_housekeeping(now);
        self.bot_room_housekeeping(now);
        let store = self.bot_store();
        let checked = store.kv_get("otk_checked_at").and_then(|v| v.parse::<i64>().ok());
        if checked.is_some_and(|t| now - t < OTK_CHECK_EVERY_MS) {
            return;
        }
        store.kv_put("otk_checked_at", &now.to_string());
        if let Err(e) = self.bot_top_up_otks(ctx).await {
            console_log!("[bot] one-time-key top-up failed: {e:?}");
        }
    }

    async fn bot_top_up_otks(&self, ctx: &BotCtx) -> Result<()> {
        use crate::bots::provision::{otk_statements, OTK_LOW_WATER, OTK_POOL_SQL, OTK_POOL_TARGET};
        #[derive(Deserialize)]
        struct N {
            n: i64,
        }
        let db = self.env.d1("DB")?;
        let pool: Option<N> = db
            .prepare(OTK_POOL_SQL)
            .bind(&[crate::d1util::d1_text(&ctx.bot_id), crate::d1util::d1_text(&ctx.device_id)])?
            .first(None)
            .await?;
        let have = pool.map(|p| p.n).unwrap_or(0);
        if have >= OTK_LOW_WATER {
            return Ok(());
        }
        let n = OTK_POOL_TARGET.saturating_sub(have.max(0) as usize);
        let otks = top_up_otks(&mut self.bot_store(), &ctx.key, n)
            .map_err(|e| Error::RustError(format!("bot otks: {e}")))?;
        let stmts = otk_statements(&db, &ctx.bot_id, &ctx.device_id, &otks)?;
        if !stmts.is_empty() {
            db.batch(stmts).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "send_tests.rs"]
mod tests;
