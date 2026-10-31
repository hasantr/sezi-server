//! Everything the periodic alarm does, lifted out of `mod.rs` under the file-size ceiling.
//!
//! A pure move: the alarm body itself (`run_alarm`), arming, measuring what is still
//! outstanding, and the W1 stuck-pending FCM backstop. The DECISION of whether to arm at all is
//! `alarm_policy`; this is the I/O half.

use super::{
    alarm_policy::{alarm_needs_arming, next_alarm_delay_ms, AlarmWork},
    sql_no_args, UserInbox, CLEANUP_INTERVAL_MS, FLUSH_INTERVAL_MS, IDLE_INTERVAL_MS,
    LAST_CLEANUP_KEY, PUSH_BACKSTOP_GRACE_SECS, RECIPIENT_UID_KEY, REMOVED_ACCOUNT_KEY,
};
use crate::utils::now_secs;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

impl UserInbox {
    /// Arm within `FLUSH_INTERVAL_MS`. This is the "there is work now" entry point, and since an
    /// idle inbox is now allowed to let its chain END (`alarm_policy`), EVERY door that creates
    /// work has to come through here: `/notify`, `/forward-delivery-failed`, `ws_upgrade`, and
    /// `ensure_init` on a cold start.
    pub(super) async fn ensure_alarm(&self) {
        self.arm_alarm_within(FLUSH_INTERVAL_MS).await;
    }

    /// Make sure an alarm is armed NO LATER than `delay_ms` from now, retrying a bounded number
    /// of times.
    ///
    /// "No later than" rather than "at all" is what lets the slow idle alarm coexist with the fast
    /// flush one: a `/notify` landing in an idle inbox whose alarm sits six hours out must pull it
    /// forward, or the stuck-pending FCM backstop would run six hours late.
    pub(super) async fn arm_alarm_within(&self, delay_ms: i64) {
        let storage = self.state.storage();
        let deadline = (now_secs() * 1000) as i64 + delay_ms;
        let current = storage.get_alarm().await.ok().flatten();
        if !alarm_needs_arming(current, deadline) {
            return;
        }
        // `set_alarm` reads a bare i64 as an OFFSET from now, not an epoch time: handing it
        // `deadline` armed every inbox ~56 years out (2026-09-02 → 2026-10-25), so no alarm ever
        // fired — no backstop push, no cleanup, and a bot's frames never opened. The offset is
        // spelled as a `Duration` so the unit cannot be misread again.
        let offset = std::time::Duration::from_millis(delay_ms.max(0) as u64);
        for _ in 0..3 {
            if storage.set_alarm(offset).await.is_ok() {
                return;
            }
        }
        console_log!(
            "UserInbox: set_alarm failed 3x — the alarm chain is at risk (the next ws_upgrade retries it)"
        );
    }

    /// What is still outstanding, for `alarm_policy::next_alarm_delay_ms`.
    ///
    /// Every count is FAIL-BUSY: an unreadable count answers 1, never 0. Reading a storage error
    /// as "idle" would end the alarm chain of a DO that still owes a client its messages, which is
    /// a far worse failure than one extra wake.
    pub(super) fn measure_alarm_work(&self, account_removed: bool) -> AlarmWork {
        AlarmWork {
            account_removed,
            pending_rows: self.count_or_busy("SELECT COUNT(*) AS n FROM pending"),
            forward_rows: self.count_or_busy("SELECT COUNT(*) AS n FROM forward_queue"),
            sockets: self.state.get_websockets().len(),
            // The three tables only the daily cleanup ever empties. Summed in one statement so
            // this costs a single SQL round trip.
            retained_rows: self.count_or_busy(
                "SELECT (SELECT COUNT(*) FROM receipt_state)
                      + (SELECT COUNT(*) FROM self_read_state)
                      + (SELECT COUNT(*) FROM receipt_uid_state) AS n",
            ),
        }
    }

    /// `SELECT COUNT(*) AS n ...` against DO storage; an error or an empty result answers 1
    /// ("assume there is work"), never 0.
    fn count_or_busy(&self, sql: &str) -> i64 {
        #[derive(Deserialize)]
        struct CountRow {
            n: i64,
        }
        self.state
            .storage()
            .sql()
            .exec_raw(sql, sql_no_args())
            .ok()
            .and_then(|c| c.to_array::<CountRow>().ok())
            .and_then(|rows| rows.into_iter().next())
            .map(|r| r.n)
            .unwrap_or(1)
    }

    /// W1 backstop (Codex HIGH — the definitive closure of W1). Ground truth: a row still sitting in
    /// `pending` is unacked, therefore undelivered. Send an FCM wake for rows whose `push_wake_at` is
    /// NULL (no backstop wake has fired for them yet) and whose grace period has elapsed → this
    /// closes the false-positive window W1 narrowed but could not eliminate (a socket dying right
    /// after a ping). One push per distinct device_id (maybe_push_wake with None means all devices),
    /// then push_wake_at is stamped so the next alarm does not re-push. Idempotent and best-effort.
    ///
    /// `silent` rows are EXCLUDED from the device scan. A control message the sender declined a wake
    /// for is still legitimately unacked while the recipient sleeps, so without this filter the
    /// backstop would wake the device for it after the grace period — converting the removed wake
    /// into a delayed one, which is harder to explain than the original bug. The rows are still
    /// stamped below (the UPDATE is deliberately unfiltered) so a silent row cannot keep the scan
    /// returning it forever.
    pub(super) async fn backstop_push_stale_pending(&self) {
        let storage = self.state.storage();
        let uid: Option<String> = storage.get(RECIPIENT_UID_KEY).await.ok().flatten();
        let uid = match uid {
            Some(u) => u,
            None => return, // RECIPIENT user_id not known yet (no notify has arrived) → no-op
        };
        let db = match self.env.d1("DB") {
            Ok(d) => d,
            Err(_) => return,
        };
        let now = now_secs() as i64;
        let cutoff = now - PUSH_BACKSTOP_GRACE_SECS; // pending.created_at is in SECONDS
                                                     // Distinct recipient devices of the stuck rows (None = device-blind → all devices).
        let cursor = match storage.sql().exec_raw(
            "SELECT DISTINCT device_id FROM pending
             WHERE push_wake_at IS NULL AND created_at < ? AND (silent IS NULL OR silent = 0)",
            Some(vec![JsValue::from_f64(cutoff as f64)]),
        ) {
            Ok(c) => c,
            Err(_) => return,
        };
        #[derive(Deserialize)]
        struct DevRow {
            #[serde(default)]
            device_id: Option<String>,
        }
        let rows: Vec<DevRow> = match cursor.to_array() {
            Ok(r) => r,
            Err(_) => return,
        };
        if rows.is_empty() {
            return;
        }
        // [deliv-telemetry] The W1 backstop fired = it caught a stuck pending row that W1's liveness
        // test missed (a socket dying just after a ping, or a lost ws.rs response). How OFTEN this
        // line appears in `wrangler tail` measures the field impact of W1's residual gap (per Codex,
        // without a counter it cannot be proven). High signal and low frequency, so a per-event log
        // is acceptable.
        console_log!(
            "[deliv] W1-backstop wake: {} device stale-unacked (uid={})",
            rows.len(),
            uid
        );
        // Through the same gate as every wake (`push::coalesce`): a device with a wake still to be
        // fetched is skipped, and its rows are NOT stamped below, so the next alarm — past the
        // window by then — wakes them if that wake brought no drain.
        let marks = self.wake_marks();
        // Never urgent: a ring is long over by the time a row is stale.
        let ask = crate::push::coalesce::WakeAsk::ordinary(crate::utils::now_ms() as i64);
        // Content-free: a backstop wake stands for every stuck row of a device, which its drain
        // fetches together (`push::carry`).
        let none = crate::push::carry::Carried::none();
        let mut coalesced: Vec<String> = Vec::new();
        for r in &rows {
            let t = crate::push::wake::maybe_push_wake(
                &self.env,
                &db,
                &marks,
                &uid,
                r.device_id.as_deref(),
                ask,
                &none,
            )
            .await;
            coalesced.extend(t.coalesced);
        }
        // Stamp the rows so the next alarm does not re-push them (best-effort; if the error is
        // swallowed the worst case is another wake on the next alarm = a harmless extra push).
        let mut args = vec![JsValue::from_f64((now * 1000) as f64), JsValue::from_f64(cutoff as f64)];
        args.extend(coalesced.iter().map(|k| JsValue::from_str(k)));
        let _ = storage.sql().exec_raw(&backstop_stamp_sql(coalesced.len()), Some(args));
    }

    /// The whole periodic alarm: flush, forwards, the FCM backstop, the daily retention cleanup
    /// and the conditional re-arm. `DurableObject::alarm` in `mod.rs` is this one call.
    pub(super) async fn run_alarm(&self) -> Result<Response> {
        // Read BEFORE `ensure_init`, which re-creates the tables and re-arms the alarm. A purged
        // inbox must leave here without arming anything; running init first is exactly how one
        // kept its 90s heartbeat alive.
        let account_removed = self
            .state
            .storage()
            .get::<bool>(REMOVED_ACCOUNT_KEY)
            .await?
            .unwrap_or(false);
        if account_removed {
            return Response::empty();
        }
        self.ensure_init().await?;
        if self.is_bot().await {
            self.bot_tick().await; // opens what members sent, before anything below reads `pending`
        }
        self.flush_pending_to_all();
        // If the sender misses the reconnect, the periodic alarm pushes anyway (idempotent: a
        // repeat is removed by the client's `forward_ack` and the sender side dedups it).
        self.flush_forwards_to_all();
        // Ground truth for delivery: the liveness test narrows the delivered_live false-positive
        // window but cannot close it (a socket that dies right after a ping). Still sitting in
        // pending means unacked means undelivered → wake once the grace period is over.
        self.backstop_push_stale_pending().await;
        let now_ms_val = (now_secs() * 1000) as i64;
        let last: Option<i64> = self
            .state
            .storage()
            .get::<i64>(LAST_CLEANUP_KEY)
            .await
            .ok()
            .flatten();
        let last_val = last.unwrap_or(0);
        if now_ms_val - last_val >= CLEANUP_INTERVAL_MS {
            // Admin-configurable (D1 server_settings), one SELECT per cleanup and therefore at
            // most once per 24h; the helper falls back to 30 days on an error or a missing row.
            let days = crate::server::handlers::fetch_message_retention_days(&self.env).await;
            let cutoff = (now_secs() as i64) - days * 24 * 3600;
            let storage = self.state.storage();
            // BEST-EFFORT, like its siblings: a bare `?` here would abort the handler and skip
            // the `ensure_alarm` re-arm below, killing the alarm chain. The watermark advances
            // ONLY on success, so a transient error is retried on the next alarm rather than
            // skipping retention for 24h.
            let purge_ok = storage
                .sql()
                .exec_raw(
                    "DELETE FROM pending WHERE created_at < ?",
                    Some(vec![JsValue::from_f64(cutoff as f64)]),
                )
                .is_ok();
            // `updated_at` is in ms, hence cutoff*1000. The high-water mark (`receipt_meta`) is
            // never purged → seq stays monotonic and cursors stay consistent.
            let _ = storage.sql().exec_raw(
                "DELETE FROM receipt_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // self_read_state is purged at retention parity, not exempt: it is the live
            // incremental convergence cursor, and a row beyond retention is dead metadata. A new
            // device gets old messages via M4 sibling sync, whose package carries `viewed_at`
            // alongside the message, so read state flows independently of this table. As with
            // receipt_state, the high-water mark (self_read_meta) is never purged. updated_at is ms.
            let _ = storage.sql().exec_raw(
                "DELETE FROM self_read_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // Orphan receipt rows — especially delivery_failed ones the client never
            // forward_acked — otherwise accumulate forever and are replayed unconditionally on a
            // fresh reconnect, re-triggering `delete_all_olm_blobs` on the receiver. `created_at`
            // is in MS here, unlike pending's seconds-based cutoff.
            let _ = storage.sql().exec_raw(
                "DELETE FROM forward_queue WHERE created_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            if purge_ok {
                let _ = storage.put(LAST_CLEANUP_KEY, now_ms_val).await;
            }
        }
        // Re-arm robustly (a blind `let _ = set_alarm` lets one transient error break the chain
        // for the life of this DO instance), and CONDITIONALLY: an inbox with nothing queued and
        // nobody connected stops rather than waking ~960 times a day (see `alarm_policy`). Both
        // events that create work — `/notify` and `ws_upgrade` — call `ensure_alarm`.
        let work = self.measure_alarm_work(account_removed);
        if let Some(delay) = next_alarm_delay_ms(work, FLUSH_INTERVAL_MS, IDLE_INTERVAL_MS) {
            self.arm_alarm_within(delay).await;
        }
        Response::empty()
    }
}

/// The backstop's stamp: every stale row of the scan, except those of a device whose wake was
/// coalesced (`coalesced` placeholders after the two fixed ones). A device-blind row is keyed as
/// the gate keys it, `coalesce::BLIND_KEY`.
fn backstop_stamp_sql(coalesced: usize) -> String {
    let mut sql = String::from(
        "UPDATE pending SET push_wake_at = ? WHERE push_wake_at IS NULL AND created_at < ?",
    );
    if coalesced > 0 {
        let marks = vec!["?"; coalesced].join(", ");
        sql.push_str(&format!(
            " AND COALESCE(device_id, '{}') NOT IN ({marks})",
            crate::push::coalesce::BLIND_KEY
        ));
    }
    sql
}

#[cfg(test)]
mod tests {
    use super::backstop_stamp_sql;

    fn stamped(coalesced: &[&str]) -> Vec<String> {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE pending (id INTEGER PRIMARY KEY, device_id TEXT, created_at INTEGER,
                                   push_wake_at INTEGER);
             INSERT INTO pending (device_id, created_at)
               VALUES ('d0', 1), ('d1', 1), (NULL, 1), ('d0', 99);",
        )
        .unwrap();
        let mut args: Vec<rusqlite::types::Value> = vec![7.into(), 10.into()];
        args.extend(coalesced.iter().map(|k| rusqlite::types::Value::from(k.to_string())));
        db.execute(&backstop_stamp_sql(coalesced.len()), rusqlite::params_from_iter(args))
            .unwrap();
        let mut q = db
            .prepare("SELECT COALESCE(device_id, '*') FROM pending WHERE push_wake_at = 7 ORDER BY id")
            .unwrap();
        q.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
    }

    #[test]
    fn the_backstop_stamps_every_stale_row_when_nothing_was_coalesced() {
        assert_eq!(stamped(&[]), ["d0", "d1", "*"]);
    }

    /// A coalesced device's rows stay unstamped, so the next alarm can still wake for them.
    #[test]
    fn a_coalesced_devices_rows_are_left_for_the_next_alarm() {
        assert_eq!(stamped(&["d0"]), ["d1", "*"]);
        assert_eq!(stamped(&["*", "d1"]), ["d0"]);
    }
}
