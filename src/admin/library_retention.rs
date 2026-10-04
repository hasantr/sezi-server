//! "Shorten retention" for the group library — previewed, then applied on an explicit confirm
//! (campus plan Wave F; board R4-Operator-Library frame 2; round-4 default: "shorten retention
//! applies at the nightly sweep, after a preview; lengthening affects only new uploads").
//!
//! ```text
//! GET  /admin/library/retention-preview?days=180          admin or owner
//! 200 {
//!   "days": 180, "current_days": 365 | null, "cutoff": <epoch s>,
//!   "shortens": true,               // false: nothing existing changes (lengthening, or equal)
//!   "objects", "bytes", "groups",   // what the NEXT sweep deletes because of this change
//!   "top": [{"room_id", "name" | null, "bytes", "objects"}],   // the largest 3 groups
//!   "rest": {"groups", "bytes", "objects"},                    // everything after the top 3
//!   "later_objects",                // not due yet, but their expiry moves earlier
//!   "sweep_days"                    // days the nightly sweep needs at its per-run bound
//! }
//! 400 bad_days                      // days missing or outside 1..=3650
//!
//! POST /admin/library/retention   {"days": 180, "confirm": true}     OWNER only
//! 200 {"days", "updated_objects", "due_objects", "due_bytes"}
//! 400 bad_days · 400 confirm_required
//! POST /admin/library/retention   {"days": 0, "confirm": true}       // keep until deleted
//! ```
//!
//! **What applying does.** It stores `library_retention_days` (what every NEW upload freezes into
//! its row, as `PATCH /admin/server-settings` does) AND moves the expiry of every existing part
//! EARLIER where the new retention ends sooner — never later: an object uploaded under a shorter
//! promise keeps it. Nothing is deleted here. Parts whose new expiry has passed are unreadable and
//! unlisted at once (`410 expired`), and the daily sweep (`room_library_cleanup.rs`) deletes them
//! from the store at its per-run bound — which is why the preview says how many nights that takes.
//! `0` (keep until deleted) is a lengthening and changes no existing row.
//!
//! **Why the preview counts by `created_at`.** A part's new expiry is `created_at + days`; the
//! ones that are due at the next sweep are exactly those uploaded before `now - days`. Parts
//! already past their old expiry are left out: they go at the next sweep whatever is decided here.
//! The server knows sizes, dates and group names, never content — the preview shows nothing else.

use serde::Deserialize;
use worker::*;

use crate::auth::middleware::{require_active_auth, require_admin, require_owner};
use crate::d1util::{d1_int, d1_opt_int};
use crate::respond::json_err;
use crate::room_library::LIBRARY_RETENTION_RANGE;
use crate::utils::now_secs;

const DAY: i64 = 24 * 60 * 60;
/// Groups the preview names; the board shows three and sums the rest.
const PREVIEW_TOP: i64 = 3;
/// Mirrors `room_library_cleanup.rs::SWEEP_LIMIT` for the estimate; the sweep owns the number.
const SWEEP_PER_NIGHT: i64 = 100;

/// What the next sweep deletes because of the new retention. Binds: `?1` cutoff, `?2` now.
pub(crate) const PREVIEW_TOTALS_SQL: &str = "SELECT COUNT(*) AS objects,
            COALESCE(SUM(size_bytes), 0) AS bytes, COUNT(DISTINCT room_id) AS groups
       FROM room_library_objects
      WHERE created_at < ?1 AND (expires_at IS NULL OR expires_at >= ?2)";

/// The same set per group, largest first. Binds: `?1` cutoff, `?2` now, `?3` limit.
pub(crate) const PREVIEW_TOP_SQL: &str = "SELECT l.room_id AS room_id, g.name AS name,
            SUM(l.size_bytes) AS bytes, COUNT(*) AS objects
       FROM room_library_objects l LEFT JOIN groups g ON g.id = l.room_id
      WHERE l.created_at < ?1 AND (l.expires_at IS NULL OR l.expires_at >= ?2)
      GROUP BY l.room_id
      ORDER BY bytes DESC, l.room_id ASC
      LIMIT ?3";

/// Not due yet, but their expiry moves earlier. Binds: `?1` retention in seconds, `?2` cutoff.
pub(crate) const PREVIEW_LATER_SQL: &str = "SELECT COUNT(*) AS objects FROM room_library_objects
      WHERE created_at >= ?2 AND (expires_at IS NULL OR expires_at > created_at + ?1)";

/// Move existing expiries EARLIER where the new retention ends sooner. Binds: `?1` seconds.
pub(crate) const SHORTEN_EXPIRY_SQL: &str = "UPDATE room_library_objects
        SET expires_at = created_at + ?1
      WHERE expires_at IS NULL OR expires_at > created_at + ?1";

/// The setting new uploads freeze. Binds: days (NULL = keep until deleted), now.
pub(crate) const SET_RETENTION_SQL: &str =
    "INSERT INTO server_settings (id, library_retention_days, updated_at)
     VALUES (1, ?1, ?2)
     ON CONFLICT(id) DO UPDATE SET
        library_retention_days = excluded.library_retention_days,
        updated_at = excluded.updated_at";

const CURRENT_SQL: &str = "SELECT library_retention_days AS days FROM server_settings WHERE id = 1";

/// `days` for a preview: 1..=3650.
fn preview_days(raw: Option<&str>) -> Option<i64> {
    raw.and_then(|v| v.parse::<i64>().ok())
        .filter(|d| LIBRARY_RETENTION_RANGE.contains(d))
}

/// Does `new` end sooner than `current` for something? `None` current = kept until deleted.
fn shortens(new: i64, current: Option<i64>) -> bool {
    current.is_none_or(|c| new < c)
}

#[derive(Deserialize)]
struct CountRow {
    objects: i64,
}

async fn current_days(db: &D1Database) -> Result<Option<i64>> {
    #[derive(Deserialize)]
    struct Row {
        days: Option<i64>,
    }
    Ok(db
        .prepare(CURRENT_SQL)
        .first::<Row>(None)
        .await?
        .and_then(|r| r.days))
}

pub async fn preview(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let Some(days) = preview_days(crate::page_cursor::query(&req, "days").as_deref()) else {
        return json_err(400, "bad_days");
    };
    let now = now_secs() as i64;
    let cutoff = now - days * DAY;
    let db = ctx.env.d1("DB")?;
    let current = current_days(&db).await?;

    #[derive(Deserialize)]
    struct Totals {
        objects: i64,
        bytes: i64,
        groups: i64,
    }
    #[derive(Deserialize)]
    struct Group {
        room_id: String,
        name: Option<String>,
        bytes: i64,
        objects: i64,
    }
    let totals: Totals = db
        .prepare(PREVIEW_TOTALS_SQL)
        .bind(&[d1_int(cutoff), d1_int(now)])?
        .first(None)
        .await?
        .unwrap_or(Totals {
            objects: 0,
            bytes: 0,
            groups: 0,
        });
    let top: Vec<Group> = db
        .prepare(PREVIEW_TOP_SQL)
        .bind(&[d1_int(cutoff), d1_int(now), d1_int(PREVIEW_TOP)])?
        .all()
        .await?
        .results()?;
    let later = db
        .prepare(PREVIEW_LATER_SQL)
        .bind(&[d1_int(days * DAY), d1_int(cutoff)])?
        .first::<CountRow>(None)
        .await?
        .map(|r| r.objects)
        .unwrap_or(0);
    let top_bytes: i64 = top.iter().map(|g| g.bytes).sum();
    let top_objects: i64 = top.iter().map(|g| g.objects).sum();
    let rest = serde_json::json!({
        "groups": (totals.groups - top.len() as i64).max(0),
        "bytes": (totals.bytes - top_bytes).max(0),
        "objects": (totals.objects - top_objects).max(0),
    });
    let top: Vec<serde_json::Value> = top
        .into_iter()
        .map(|g| {
            serde_json::json!({
                "room_id": g.room_id, "name": g.name, "bytes": g.bytes, "objects": g.objects,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({
        "days": days,
        "current_days": current,
        "cutoff": cutoff,
        "shortens": shortens(days, current),
        "objects": totals.objects,
        "bytes": totals.bytes,
        "groups": totals.groups,
        "top": top,
        "rest": rest,
        "later_objects": later,
        "sweep_days": (totals.objects + SWEEP_PER_NIGHT - 1) / SWEEP_PER_NIGHT,
    }))
}

#[derive(Deserialize, Default)]
struct ApplyBody {
    days: Option<i64>,
    #[serde(default)]
    confirm: bool,
}

/// Owner-only, like every other write of server-wide policy (`update_settings`).
pub async fn apply(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: ApplyBody = req.json().await.unwrap_or_default();
    // 0 = keep until deleted (the settings' 0-clears convention); otherwise the library range.
    let days = match body.days {
        Some(0) => None,
        Some(d) if LIBRARY_RETENTION_RANGE.contains(&d) => Some(d),
        _ => return json_err(400, "bad_days"),
    };
    // An irreversible change to what the server keeps: the client must say it saw the preview.
    if !body.confirm {
        return json_err(400, "confirm_required");
    }
    let now = now_secs() as i64;
    let db = ctx.env.d1("DB")?;
    let mut due = (0i64, 0i64);
    if let Some(d) = days {
        #[derive(Deserialize)]
        struct Totals {
            objects: i64,
            bytes: i64,
        }
        if let Some(t) = db
            .prepare(PREVIEW_TOTALS_SQL)
            .bind(&[d1_int(now - d * DAY), d1_int(now)])?
            .first::<Totals>(None)
            .await?
        {
            due = (t.objects, t.bytes);
        }
    }
    let mut stmts = vec![db
        .prepare(SET_RETENTION_SQL)
        .bind(&[d1_opt_int(days), d1_int(now)])?];
    if let Some(d) = days {
        stmts.push(db.prepare(SHORTEN_EXPIRY_SQL).bind(&[d1_int(d * DAY)])?);
    }
    let results = db.batch(stmts).await?;
    let updated = results
        .get(1)
        .and_then(|r| r.meta().ok().flatten())
        .and_then(|m| m.changes)
        .unwrap_or(0);
    Response::from_json(&serde_json::json!({
        "days": days,
        "updated_objects": updated,
        "due_objects": due.0,
        "due_bytes": due.1,
    }))
}

#[cfg(test)]
#[path = "library_retention_tests.rs"]
mod tests;
