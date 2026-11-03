//! Rows queued for a device that will never read them (audit 2026-11-03 finding #4).
//!
//! A device that was revoked, lost or reinstalled keeps its `pending` rows. Until 2026-11-03
//! nothing removed them but the 30-day retention: they held the inbox on its 90 s alarm for the
//! whole window, and they shared the 10,000-row cap, whose global-oldest eviction then deleted
//! the LIVE device's undelivered rows mixed in with the dead one's. Three things now:
//!
//! - **Revoked:** a published device list that drops a device tells this inbox
//!   (`POST /devices-changed`, `realtime::drop_revoked_queues_best_effort`), which reads the
//!   account's revoked devices from D1 and deletes their rows. The alarm repeats the same read at
//!   most every [`RECONCILE_EVERY_MS`] while a stalled queue exists, in case that call was lost.
//! - **Stalled** (a device whose oldest row is older than [`STALLED_AFTER_SECS`] and that has not
//!   connected since): its rows no longer count as work a client is waiting for, so they earn the
//!   slow retention alarm, not the 90 s one (`alarm_policy::AlarmWork::stalled_rows`).
//! - **The cap** evicts the least recently connected device's rows first, and a device with a
//!   socket open now last ([`evict_sql`]), so it never deletes a live device's undelivered rows
//!   while a dead device's are still there.
//!
//! All of it is bounded: one D1 read, a DELETE per revoked device, and the cap's one statement.

use super::*;

/// A device whose oldest queued row is older than this and that has not connected since is
/// treated as gone: three days of a queue nothing drains.
pub(crate) const STALLED_AFTER_SECS: i64 = 3 * 24 * 3600;
/// How often the alarm re-reads the revoked devices while a stalled queue exists.
pub(crate) const RECONCILE_EVERY_MS: i64 = 6 * 3600 * 1000;
const RECONCILED_AT_KEY: &str = "revoked_devices_reconciled_ms";
/// The most revoked devices read back; an account revokes a handful in its life.
const REVOKED_READ_LIMIT: i64 = 200;

/// D1: the account's revoked devices. Bind: user_id, limit.
pub(crate) const REVOKED_DEVICES_SQL: &str = "SELECT device_id FROM devices
      WHERE user_id = ?1 AND revoked_at IS NOT NULL ORDER BY revoked_at DESC LIMIT ?2";
/// DO: one device's whole queue. Bind: device_id.
pub(crate) const DROP_DEVICE_ROWS_SQL: &str = "DELETE FROM pending WHERE device_id = ?1";

/// The devices whose queue has stalled. Binds: ?1 the cutoff in seconds (`pending.created_at`),
/// ?2 the same moment in milliseconds (`wake_gate.seen_ms`).
const STALLED_CTE: &str = "WITH stalled AS (
      SELECT device_id FROM pending
       WHERE device_id IS NOT NULL
       GROUP BY device_id
      HAVING MIN(created_at) < ?1
         AND COALESCE((SELECT seen_ms FROM wake_gate g WHERE g.device_id = pending.device_id), 0) < ?2
    )";

/// Pending rows a client is still waiting for (every row but a stalled device's), and the
/// stalled ones, in one statement. Binds as [`STALLED_CTE`].
pub(crate) fn pending_split_sql() -> String {
    format!(
        "{STALLED_CTE}
         SELECT
           (SELECT COUNT(*) FROM pending
             WHERE device_id IS NULL OR device_id NOT IN (SELECT device_id FROM stalled)) AS live,
           (SELECT COUNT(*) FROM pending
             WHERE device_id IN (SELECT device_id FROM stalled)) AS stalled"
    )
}

/// Evict `?1` rows: the least recently connected device's first, a device with an open socket
/// last (`connected` marks after `?2`, the blind key a device-blind row is gated under), oldest
/// first within each. A row with no device belongs to the account's one unpublished device and is
/// ranked by the blind key's last connection.
pub(crate) fn evict_sql(connected: usize) -> String {
    // An integer constant in ORDER BY is a column index, so with nobody connected the first term
    // is left out rather than written as a constant.
    let open = if connected == 0 {
        String::new()
    } else {
        format!(
            "CASE WHEN COALESCE(p.device_id, ?2) IN ({}) THEN 1 ELSE 0 END, ",
            crate::d1util::marks(connected)
        )
    };
    format!(
        "DELETE FROM pending WHERE id IN (
           SELECT p.id FROM pending p
             LEFT JOIN wake_gate g ON g.device_id = COALESCE(p.device_id, ?2)
            ORDER BY {open}COALESCE(g.seen_ms, 0), p.id
            LIMIT ?1)"
    )
}

/// The cutoff binds of [`STALLED_CTE`] for `now_secs`.
pub(crate) fn stalled_binds(now_secs: i64) -> (i64, i64) {
    let cutoff = now_secs - STALLED_AFTER_SECS;
    (cutoff, cutoff.saturating_mul(1000))
}

#[derive(Deserialize)]
struct Split {
    live: i64,
    stalled: i64,
}

#[derive(Deserialize)]
struct DevicesChangedBody {
    user_id: String,
}

impl UserInbox {
    /// `POST /devices-changed {user_id}` → 204: the account's device list was published; drop the
    /// queues of its revoked devices.
    pub(super) async fn devices_changed(&self, mut req: Request) -> Result<Response> {
        let body: DevicesChangedBody = req.json().await?;
        self.drop_revoked_queues(&body.user_id).await;
        Response::empty().map(|r| r.with_status(204))
    }

    /// Read the account's revoked devices from D1 and delete their rows. Best-effort: a failed
    /// read changes nothing, and the alarm tries again.
    pub(super) async fn drop_revoked_queues(&self, user_id: &str) {
        #[derive(Deserialize)]
        struct DevRow {
            device_id: String,
        }
        let Ok(db) = self.env.d1("DB") else { return };
        let revoked: Vec<DevRow> = match db
            .prepare(REVOKED_DEVICES_SQL)
            .bind(&[JsValue::from_str(user_id), JsValue::from_f64(REVOKED_READ_LIMIT as f64)])
        {
            Ok(stmt) => match stmt.all().await.and_then(|r| r.results()) {
                Ok(rows) => rows,
                Err(_) => return,
            },
            Err(_) => return,
        };
        let storage = self.state.storage();
        for d in &revoked {
            let _ = storage
                .sql()
                .exec_raw(DROP_DEVICE_ROWS_SQL, Some(vec![JsValue::from_str(&d.device_id)]));
        }
        let _ = storage
            .put(RECONCILED_AT_KEY, crate::utils::now_ms() as i64)
            .await;
    }

    /// `(live, stalled)` pending rows. FAIL-BUSY like every alarm count: an unreadable split is
    /// one live row, never zero.
    pub(super) fn pending_split(&self) -> (i64, i64) {
        let (secs, ms) = stalled_binds(now_secs() as i64);
        self.state
            .storage()
            .sql()
            .exec_raw(
                &pending_split_sql(),
                Some(vec![JsValue::from_f64(secs as f64), JsValue::from_f64(ms as f64)]),
            )
            .ok()
            .and_then(|c| c.to_array::<Split>().ok())
            .and_then(|rows| rows.into_iter().next())
            .map(|s| (s.live, s.stalled))
            .unwrap_or((1, 0))
    }

    /// The alarm's safety net for a lost `/devices-changed`: with a stalled queue, re-read the
    /// revoked devices at most every [`RECONCILE_EVERY_MS`].
    pub(super) async fn reconcile_revoked_if_stalled(&self, stalled_rows: i64) {
        if stalled_rows == 0 {
            return;
        }
        let storage = self.state.storage();
        let last: i64 = storage.get(RECONCILED_AT_KEY).await.ok().flatten().unwrap_or(0);
        if crate::utils::now_ms() as i64 - last < RECONCILE_EVERY_MS {
            return;
        }
        let uid: Option<String> = storage.get(RECIPIENT_UID_KEY).await.ok().flatten();
        if let Some(uid) = uid {
            self.drop_revoked_queues(&uid).await;
        }
    }

    /// Past `max_rows`, evict the surplus — dead devices' rows first (see [`evict_sql`]).
    pub(super) fn evict_over_cap(&self, count: i64, max_rows: i64) {
        if count <= max_rows {
            return;
        }
        let evict = count - max_rows;
        let mut connected: Vec<String> = Vec::new();
        for ws in self.state.get_websockets() {
            if let Some(d) = super::message::ws_attachment_device(&ws) {
                if !connected.contains(&d) {
                    connected.push(d);
                }
            }
        }
        if !connected.is_empty() {
            // A device-blind row belongs to whichever single device connects.
            connected.push(crate::push::coalesce::BLIND_KEY.to_string());
        }
        connected.truncate(crate::d1util::MAX_BOUND_PARAMS - 2);
        let mut args = vec![
            JsValue::from_f64(evict as f64),
            JsValue::from_str(crate::push::coalesce::BLIND_KEY),
        ];
        args.extend(connected.iter().map(|d| JsValue::from_str(d)));
        let _ = self
            .state
            .storage()
            .sql()
            .exec_raw(&evict_sql(connected.len()), Some(args));
        worker::console_log!(
            "[deliv] W2 pending-cap: evicted {evict} rows, least recently connected device first (count={count})"
        );
    }
}

#[cfg(test)]
#[path = "dead_devices_tests.rs"]
mod tests;
