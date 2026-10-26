//! The bot inbox's tick: open what members sent, then pay what the network is owed.
//!
//! The frames are opened in ONE synchronous block — engine, ratchet writes, update rows, the
//! pending rows' delete and the forwards' outbox rows — with no `await` inside, so the DO's
//! SQLite commits a frame's every consequence or none of them. Whatever needs D1 (the senders'
//! device keys, who they are) is read before the block; whatever needs the network (forwards,
//! answers, pair-acks) is queued in it and sent after.

use super::super::ack::{group_acks, AckRow};
use super::outbox::OutKind;
use super::updates::{message_update, Who};
use super::*;
use sezi_bot_engine::{on_envelope, Effect, Envelope, Inbound};
use std::collections::{BTreeSet, HashMap};

/// Frames opened per tick. A PreKey costs an account unpickle; the tick re-arms at once while
/// more are waiting, so this bounds one invocation's CPU, not the throughput.
const TICK_BATCH: i64 = 20;
/// When a failed tick tries again.
const TICK_RETRY_MS: i64 = 5_000;

/// Senders' device keys and profiles, read from D1 before the synchronous block.
struct Prefetch {
    /// (user, device) → the D1 `devices.x_pub` the engine checks a PreKey's identity against.
    x_pub: HashMap<(String, String), String>,
    who: HashMap<String, Who>,
}

impl UserInbox {
    /// The alarm's bot step. Errors are logged, never raised: the alarm's own re-arm and cleanup
    /// must still run. A failed tick (D1 unreachable, say) comes back in a few seconds rather
    /// than at once — frames still waiting would otherwise re-fire the alarm in a hot loop.
    pub(crate) async fn bot_tick(&self) {
        match self.bot_tick_inner().await {
            Ok(()) => self.bot_rearm().await,
            Err(e) => {
                console_log!("[bot] tick failed: {e:?}");
                self.arm_alarm_within(TICK_RETRY_MS).await;
            }
        }
    }

    async fn bot_tick_inner(&self) -> Result<()> {
        self.bot_tables()?;
        let ctx = self.bot_ctx()?;
        let rows: Vec<PendingRow> = self
            .state
            .storage()
            .sql()
            .exec_raw(
                "SELECT id, sender_id, envelope_b64, group_id, sender_device_id, created_at
                   FROM pending ORDER BY id LIMIT ?",
                Some(vec![JsValue::from_f64(TICK_BATCH as f64)]),
            )?
            .to_array()?;
        let mut repairs = BTreeSet::new();
        let mut pair_acks = BTreeSet::new();
        if !rows.is_empty() {
            let pre = self.bot_prefetch(&rows).await?;
            self.bot_open_frames(&ctx, rows, &pre, &mut repairs, &mut pair_acks)?;
        }
        // A member's pair-ack was already answered by the engine (its Deliver is queued): only
        // what that member could not read goes again. A repair is the bot's own pair-ack first.
        for user in &pair_acks {
            self.bot_resend_failed(&ctx, user).await;
        }
        for user in repairs.difference(&pair_acks) {
            self.bot_repair(&ctx, user).await;
        }
        self.bot_deliver_webhooks(&ctx).await;
        // A built-in bot answers here; its replies go out with the drain below.
        // The two share the tick's purse: the drain gets what the round left (`builtin_policy`).
        let round = self.bot_builtin_round(&ctx).await;
        self.bot_drain_outbox_within(&ctx, super::builtin_policy::drain_budget(round)).await;
        self.bot_housekeeping(&ctx).await;
        Ok(())
    }

    async fn bot_prefetch(&self, rows: &[PendingRow]) -> Result<Prefetch> {
        let senders: BTreeSet<&str> = rows.iter().map(|r| r.sender_id.as_str()).collect();
        let list = serde_json::to_string(&senders).map_err(|e| Error::RustError(e.to_string()))?;
        let db = self.env.d1("DB")?;
        #[derive(Deserialize)]
        struct KeyRow {
            user_id: String,
            device_id: String,
            x_pub: Vec<u8>,
        }
        let keys: Vec<KeyRow> = db
            .prepare(
                "SELECT user_id, device_id, x_pub FROM devices
                  WHERE user_id IN (SELECT value FROM json_each(?1)) AND revoked_at IS NULL",
            )
            .bind(&[crate::d1util::d1_text(&list)])?
            .all()
            .await?
            .results()?;
        let who: Vec<Who> = db
            .prepare(
                "SELECT id AS user_id, display_name, role AS server_role FROM users
                  WHERE id IN (SELECT value FROM json_each(?1))",
            )
            .bind(&[crate::d1util::d1_text(&list)])?
            .all()
            .await?
            .results()?;
        Ok(Prefetch {
            x_pub: keys
                .into_iter()
                .map(|k| ((k.user_id, k.device_id), crate::utils::b64_encode(&k.x_pub)))
                .collect(),
            who: who.into_iter().map(|w| (w.user_id.clone(), w)).collect(),
        })
    }

    /// The synchronous block. NO `await` may be added here (see the module doc).
    fn bot_open_frames(
        &self,
        ctx: &BotCtx,
        rows: Vec<PendingRow>,
        pre: &Prefetch,
        repairs: &mut BTreeSet<String>,
        pair_acks: &mut BTreeSet<String>,
    ) -> Result<()> {
        let now = (now_secs() * 1000) as i64;
        let mut store = self.bot_store();
        // (ids, uids) per outcome, parallel.
        let mut acked: [(Vec<i64>, Vec<String>); 2] = Default::default();
        for row in rows {
            let device = row.sender_device_id.clone().unwrap_or_default();
            let x_pub = pre.x_pub.get(&(row.sender_id.clone(), device.clone()));
            let env = Envelope {
                remote_id: row.id,
                sender_id: row.sender_id.clone(),
                sender_device_id: device,
                envelope_b64: row.envelope_b64,
                group_id: row.group_id,
            };
            let effects = on_envelope(&mut store, &ctx.key, &ctx.bot_id, &env, x_pub.map(String::as_str), now);
            let mut answered = false;
            for effect in effects {
                match effect {
                    Effect::Ack { remote_id, success, uid } => {
                        answered = true;
                        let side = &mut acked[usize::from(success)];
                        side.0.push(remote_id);
                        side.1.push(uid.unwrap_or_default());
                    }
                    Effect::Deliver { user_id, device_id, envelope_b64, msg_uid } => {
                        self.bot_queue_deliver(&user_id, &device_id, &envelope_b64, msg_uid.as_deref(), now);
                    }
                    Effect::Repair { user_id } => {
                        repairs.insert(user_id);
                    }
                    Effect::Update(Inbound::Text { from, msg_uid, body, ext, .. }) => {
                        // A kernel resends after a re-pair when its `delivered` came late: the
                        // frame is acked again (above), but the program hears it once.
                        if msg_uid.as_deref().is_some_and(|u| !store.first_sight(&from, u, now)) {
                            continue;
                        }
                        let update = message_update(now, &from, pre.who.get(&from), msg_uid.as_deref(), &body, &ext);
                        if let Some(id) = self.bot_push_update(&update, now) {
                            self.bot_note_update_src(id, &from, env.remote_id, msg_uid.as_deref());
                        }
                    }
                    Effect::Update(Inbound::PairAck { from }) => {
                        pair_acks.insert(from);
                    }
                    // Rooms, taps and room-key requests are Phase 3/4; `Ignored` is read and dropped.
                    Effect::DeliverRoom { .. } | Effect::Update(_) => {}
                }
            }
            // A frame the engine gave no answer for would be retried forever: fail it, so the
            // member's kernel re-pairs instead.
            if !answered {
                acked[0].0.push(env.remote_id);
                acked[0].1.push(String::new());
            }
        }
        for (success, (ids, uids)) in [(false, &acked[0]), (true, &acked[1])] {
            if ids.is_empty() {
                continue;
            }
            let rows = self.delete_acked_rows(ids, Some(&ctx.device_id))?;
            self.bot_queue_forwards(ctx, rows, ids, uids, success, now);
        }
        Ok(())
    }

    /// The `delivered` / `delivery_failed` forwards for acked rows, as outbox rows.
    fn bot_queue_forwards(
        &self,
        ctx: &BotCtx,
        rows: Vec<AckRow>,
        ids: &[i64],
        uids: &[String],
        success: bool,
        now: i64,
    ) {
        let kind = if success { OutKind::ForwardDelivered } else { OutKind::ForwardFailed };
        for ((sender, device), acked, acked_uids) in group_acks(rows, ids, uids, Some(&ctx.device_id)) {
            let body = serde_json::json!({
                "to": sender,
                "payload": {
                    "from": ctx.bot_id,
                    "recipient_device_id": device,
                    "ids": acked,
                    "uids": acked_uids,
                },
            });
            self.bot_outbox_push(kind, &body, now);
        }
    }
}
