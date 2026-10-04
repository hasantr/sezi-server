//! Everything the periodic alarm does, lifted out of `mod.rs` under the file-size ceiling.
//!
//! A pure move: arming, measuring what is still outstanding, and the W1 stuck-pending FCM
//! backstop. The DECISION of whether to arm at all is `alarm_policy`; this is the I/O half.

use super::{
    alarm_policy::{alarm_needs_arming, AlarmWork},
    sql_no_args, UserInbox, FLUSH_INTERVAL_MS, PUSH_BACKSTOP_GRACE_SECS, RECIPIENT_UID_KEY,
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
        for _ in 0..3 {
            if storage.set_alarm(deadline).await.is_ok() {
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
        for r in &rows {
            crate::push::fcm::maybe_push_wake(&self.env, &db, &uid, r.device_id.as_deref()).await;
        }
        // Stamp the rows so the next alarm does not re-push them (best-effort; if the error is
        // swallowed the worst case is another wake on the next alarm = a harmless extra push).
        let _ = storage.sql().exec_raw(
            "UPDATE pending SET push_wake_at = ? WHERE push_wake_at IS NULL AND created_at < ?",
            Some(vec![
                JsValue::from_f64((now * 1000) as f64),
                JsValue::from_f64(cutoff as f64),
            ]),
        );
    }

}
