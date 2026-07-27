//! Usage counters — quota epic **phase 0, SHADOW MODE** (counting only, NO enforcement).
//!
//! The turn.rs budget-guard pattern (turn_usage) generalized to storage:
//! `user_storage` (a live per-user byte counter) + `server_stats` (server-wide media
//! bytes/count in a single row, id=1) + `usage_counters` (day-keyed general counters).
//!
//! **BEST-EFFORT discipline:** NO error while writing a counter may break the real
//! operation (upload/ack/cron cleanup) — it is logged (PII-free, truncated to 80 chars)
//! and execution continues. Drift is accepted: the daily `reconcile_storage` cron
//! recomputes the counters from the truth in the media tables (self-heal). There is no
//! quota REJECTION here — enforcement is phase 1's job; in shadow mode no request is
//! ever refused.

use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;
use serde::Deserialize;
use std::collections::HashMap;
use wasm_bindgen::JsValue;
use worker::*;

/// Counter-error log that cannot leak PII — same rule as the maintenance cleanup path:
/// keep only the first 80 chars.
fn log_fail(what: &str, e: Error) {
    let msg = e.to_string();
    let truncated: String = msg.chars().take(80).collect();
    console_warn!("usage: {} fail: {}", what, truncated);
}

/// Run a single statement best-effort: on a bind/run error, log and continue silently —
/// the caller's real operation is never affected.
async fn run_best_effort(db: &D1Database, what: &str, sql: &str, binds: &[JsValue]) {
    match db.prepare(sql).bind(binds) {
        Ok(stmt) => {
            if let Err(e) = stmt.run().await {
                log_fail(what, e);
            }
        }
        Err(e) => log_fail(what, e),
    }
}

/// Record a media upload in the counters: `user_storage.bytes += size` and
/// `server_stats.media_bytes += size, media_count += 1`. BEST-EFFORT — an error does NOT
/// break the upload. The media_objects INSERT is the source of truth for these counters
/// (reconcile recomputes from it), so this is called immediately after that INSERT.
pub async fn media_added(db: &D1Database, uploader_id: &str, size: i64) {
    let now = now_secs() as i64;
    run_best_effort(
        db,
        "user_storage add",
        "INSERT INTO user_storage (user_id, bytes) VALUES (?, ?) \
         ON CONFLICT(user_id) DO UPDATE SET bytes = bytes + excluded.bytes",
        &[d1_text(uploader_id), d1_int(size)],
    )
    .await;
    run_best_effort(
        db,
        "server_stats add",
        "INSERT INTO server_stats (id, media_bytes, media_count, updated_at) VALUES (1, ?, 1, ?) \
         ON CONFLICT(id) DO UPDATE SET media_bytes = media_bytes + excluded.media_bytes, \
         media_count = media_count + 1, updated_at = excluded.updated_at",
        &[d1_int(size), d1_int(now)],
    )
    .await;
}

/// Decrement the counters for deleted media (ack or cron expiry). Takes a list of
/// `(uploader_id, size_bytes)` — the cron deletes up to 500 rows in one go — aggregates
/// per user and CLAMPS at 0 via `MAX(0, ...)`. BEST-EFFORT: an error does not break the
/// deletion.
pub async fn media_removed(db: &D1Database, removed: &[(String, i64)]) {
    if removed.is_empty() {
        return;
    }
    let now = now_secs() as i64;
    let mut per_user: HashMap<&str, i64> = HashMap::new();
    let mut total: i64 = 0;
    for (uploader_id, size) in removed {
        *per_user.entry(uploader_id.as_str()).or_insert(0) += size;
        total += size;
    }
    for (uploader_id, bytes) in per_user {
        run_best_effort(
            db,
            "user_storage sub",
            "UPDATE user_storage SET bytes = MAX(0, bytes - ?) WHERE user_id = ?",
            &[d1_int(bytes), d1_text(uploader_id)],
        )
        .await;
    }
    run_best_effort(
        db,
        "server_stats sub",
        "UPDATE server_stats SET media_bytes = MAX(0, media_bytes - ?), \
         media_count = MAX(0, media_count - ?), updated_at = ? WHERE id = 1",
        &[d1_int(total), d1_int(removed.len() as i64), d1_int(now)],
    )
    .await;
}

/// The daily authoritative reconcile — repairs drift in the best-effort counters by
/// recomputing them from storage truth (self-heal). Truth is the UNION of TWO tables:
/// `media_objects` (ephemeral user media) and `plugin_media_objects` (persistent member
/// plugin media, 0026). Both feed the user_storage/server_stats counters through
/// `media_added`, so a cap applies to the SUM of the two channels — which is exactly why
/// reconcile MUST sum both tables. If it did not, the daily self-heal would ERASE the
/// plugin-media contribution and the quota would drop below reality. `db.batch` is a
/// single D1 transaction, giving a consistent snapshot. Called from
/// `maintenance::run_daily` (cron and lazy path alike); the caller logs any error and
/// keeps going.
///
/// Pluggable storage phase 1 (ADDITIONAL, plan d): the SAME batch recomputes per-backend
/// `storage_backends.used_bytes`/`object_count`, grouped by `store_id` across THREE meta
/// tables (media ∪ plugin_media ∪ plugin_code). NOTE: the user_storage/server_stats math
/// is UNCHANGED — plugin_code is DELIBERATELY excluded so quota semantics stay
/// bit-identical; plugin_code only counts toward per-backend inventory truth. In
/// single-backend phase 1 everything lands under 'r2-primary'.
pub async fn reconcile_storage(env: &Env) -> Result<()> {
    let db = env.d1("DB")?;
    let now = now_secs() as i64;
    db.batch(vec![
        db.prepare("DELETE FROM user_storage"),
        db.prepare(
            "INSERT INTO user_storage (user_id, bytes) \
             SELECT uploader_id, COALESCE(SUM(size_bytes), 0) FROM ( \
               SELECT uploader_id, size_bytes FROM media_objects \
               UNION ALL \
               SELECT uploader_id, size_bytes FROM plugin_media_objects \
             ) GROUP BY uploader_id",
        ),
        db.prepare("DELETE FROM server_stats WHERE id = 1"),
        db.prepare(
            "INSERT INTO server_stats (id, media_bytes, media_count, updated_at) \
             SELECT 1, COALESCE(SUM(size_bytes), 0), COUNT(*), ? FROM ( \
               SELECT size_bytes FROM media_objects \
               UNION ALL \
               SELECT size_bytes FROM plugin_media_objects \
             )",
        )
        .bind(&[d1_int(now)])?,
        // Per-backend inventory recompute (UNION of the 3 meta tables, grouped by
        // store_id). One correlated subquery per backend row — cheap, since the number
        // of backends is a handful.
        db.prepare(
            "UPDATE storage_backends SET \
               used_bytes = COALESCE(( \
                 SELECT SUM(size_bytes) FROM ( \
                   SELECT store_id, size_bytes FROM media_objects \
                   UNION ALL SELECT store_id, size_bytes FROM plugin_media_objects \
                   UNION ALL SELECT store_id, size_bytes FROM plugin_code_objects \
                 ) u WHERE u.store_id = storage_backends.store_id), 0), \
               object_count = ( \
                 SELECT COUNT(*) FROM ( \
                   SELECT store_id FROM media_objects \
                   UNION ALL SELECT store_id FROM plugin_media_objects \
                   UNION ALL SELECT store_id FROM plugin_code_objects \
                 ) c WHERE c.store_id = storage_backends.store_id), \
               updated_at = ?",
        )
        .bind(&[d1_int(now)])?,
    ])
    .await?;
    Ok(())
}

/// Bump a day-keyed general counter (quota epic **phase 1c**, COUNTING ONLY) — upsert
/// `+by` into today's `(day, kind)` row of `usage_counters`. A generalization of the
/// `media_added` pattern: BEST-EFFORT, so an error NEVER breaks the caller's real
/// operation (upload/download) — log and continue. Hooked into media upload
/// (`upload_bytes`/`upload_count`) and download (`download_count`/`download_bytes`);
/// /admin/stats reads it back with `read_today`.
pub async fn count_bump(db: &D1Database, kind: &str, by: i64) {
    run_best_effort(
        db,
        "count_bump",
        "INSERT INTO usage_counters (day, kind, count) VALUES (?, ?, ?) \
         ON CONFLICT(day, kind) DO UPDATE SET count = count + excluded.count",
        &[d1_text(&today_utc()), d1_text(kind), d1_int(by)],
    )
    .await;
}

/// Read today's `kind` row from `usage_counters` — missing row or error yields 0
/// (fail-open, following turn.rs's counter-read pattern: stats does not 500 even if the
/// table was never migrated). Since phase 1c the `count_bump` hooks feed it with
/// upload/download volume; the `requests` kind is still a stub, since request counting
/// comes from phase 3 CF Analytics.
pub async fn read_today(db: &D1Database, kind: &str) -> i64 {
    #[derive(Deserialize)]
    struct Row {
        count: i64,
    }
    match db
        .prepare("SELECT count FROM usage_counters WHERE day = ? AND kind = ? LIMIT 1")
        .bind(&[d1_text(&today_utc()), d1_text(kind)])
    {
        Ok(stmt) => stmt
            .first::<Row>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.count)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Read this month's total for `kind` from `usage_counters` (the monthly detail report)
/// as the SUM over day rows. The month window is derived from turn.rs
/// `current_month_utc` — day is "YYYY-MM-DD", so the prefix is "YYYY-MM%" — keeping the
/// window aligned with the TURN budget. Fail-open: a bind/first error or a missing table
/// yields 0 (same as read_today; stats does not 500). Feeds the "month" block of
/// /admin/stats.
pub async fn read_month(db: &D1Database, kind: &str) -> i64 {
    #[derive(Deserialize)]
    struct Row {
        total: i64,
    }
    match db
        .prepare(
            "SELECT COALESCE(SUM(count), 0) AS total FROM usage_counters \
             WHERE kind = ? AND day LIKE ?",
        )
        .bind(&[
            d1_text(kind),
            d1_text(&format!("{}%", crate::turn::current_month_utc())),
        ]) {
        Ok(stmt) => stmt
            .first::<Row>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.total)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// epoch → "YYYY-MM-DD" (UTC) — the day key for usage_counters. This is the day-level
/// version of turn.rs `current_month_utc`'s civil-from-days algorithm (Howard Hinnant),
/// so no chrono dependency is needed.
///
/// `pub(crate)` because cf_analytics (phase 3) derives its today-00:00Z CF query window
/// from the SAME day key, keeping the self-reported counters and CF's numbers aligned.
pub(crate) fn today_utc() -> String {
    let secs = now_secs() as i64;
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}
