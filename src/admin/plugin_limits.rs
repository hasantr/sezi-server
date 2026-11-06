//! `GET /admin/plugin-limits` (admin/owner) + `PATCH /admin/plugin-limits` (owner) — the plugin
//! limits a server's owner sets (`crate::plugin_limits`, Hasan 2026-11-06).
//!
//! - **GET** answers `{"limits":[{key,value,default,min,max,unit,set}…],"near":[…],"near_percent":80}`.
//!   `near` lists who holds 80 % or more of a PLUGIN MEDIA limit in a room — the one figure the
//!   relay keeps in D1 and can sum cheaply: `{user_id,display_name,room_id,key,used,limit}`, the
//!   fullest first, at most [`NEAR_ROWS`]. The plugin log's usage lives in each room's Durable
//!   Object and the record share on members' devices; neither is listed (yet).
//! - **PATCH** takes `{key: N | null, …}`: a number sets the limit (inside its range), `null`
//!   returns it to the default. The whole write is checked before anything is stored —
//!   `400 {"error":"plugin-limits/bad-key"|"plugin-limits/out-of-range","key":…}` — and the answer
//!   is the GET's. Lowering a limit deletes nothing: it only refuses what would add to it.

use crate::auth::middleware::{require_active_auth, require_admin, require_owner};
use crate::d1util::d1_int;
use crate::plugin_limits::{self as limits, PluginLimits};
use crate::respond::{json_err, json_status};
use serde::Deserialize;
use worker::*;

/// The most rows the `near` list carries.
pub(crate) const NEAR_ROWS: i64 = 100;

/// Who holds at least `near_percent` of a plugin media limit in a room. Binds: the byte
/// threshold, the object threshold, the row cap. The thresholds are computed in Rust
/// (`threshold`) so the SQL compares integers only.
pub(crate) const NEAR_MEDIA_SQL: &str = "SELECT p.room_id AS room_id, p.uploader_id AS user_id, \
        u.display_name AS display_name, SUM(p.size_bytes) AS bytes, COUNT(*) AS objects \
     FROM plugin_media_objects p LEFT JOIN users u ON u.id = p.uploader_id \
     GROUP BY p.room_id, p.uploader_id \
     HAVING SUM(p.size_bytes) >= ?1 OR COUNT(*) >= ?2 \
     ORDER BY SUM(p.size_bytes) DESC LIMIT ?3";

/// The smallest usage that is [`limits::NEAR_PERCENT`] of `limit` (rounded up).
pub(crate) fn threshold(limit: i64) -> i64 {
    (limit.saturating_mul(limits::NEAR_PERCENT) + 99) / 100
}

#[derive(Deserialize)]
pub(crate) struct NearMediaRow {
    pub room_id: String,
    pub user_id: String,
    pub display_name: Option<String>,
    pub bytes: i64,
    pub objects: i64,
}

/// One aggregated row → the near-list entries it makes (bytes, objects, or both).
pub(crate) fn near_entries(row: &NearMediaRow, l: &PluginLimits) -> Vec<serde_json::Value> {
    let m = l.media_limits();
    let mut out = Vec::new();
    for (key, used, limit) in
        [(limits::MEDIA_BYTES.key, row.bytes, m.bytes), (limits::MEDIA_OBJECTS.key, row.objects, m.objects)]
    {
        if limits::is_near(used, limit) {
            out.push(serde_json::json!({
                "user_id": row.user_id,
                "display_name": row.display_name,
                "room_id": row.room_id,
                "key": key,
                "used": used,
                "limit": limit,
            }));
        }
    }
    out
}

/// The GET's body.
async fn view(db: &D1Database, l: &PluginLimits) -> serde_json::Value {
    let m = l.media_limits();
    let rows: Vec<NearMediaRow> = match db
        .prepare(NEAR_MEDIA_SQL)
        .bind(&[d1_int(threshold(m.bytes)), d1_int(threshold(m.objects)), d1_int(NEAR_ROWS)])
    {
        Ok(stmt) => stmt.all().await.and_then(|r| r.results()).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let near: Vec<serde_json::Value> = rows.iter().flat_map(|r| near_entries(r, l)).collect();
    serde_json::json!({
        "limits": l.owner_rows(),
        "near": near,
        "near_percent": limits::NEAR_PERCENT,
    })
}

pub async fn get_plugin_limits(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let l = limits::read(&db).await;
    Response::from_json(&view(&db, &l).await)
}

pub async fn set_plugin_limits(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let Ok(body) = req.json::<serde_json::Value>().await else {
        return json_err(400, limits::BAD_KEY);
    };
    let db = ctx.env.d1("DB")?;
    let current = limits::read(&db).await;
    let next = match current.with_write(&body) {
        Ok(n) => n,
        Err((code, key)) => {
            return json_status(400, &serde_json::json!({ "error": code, "key": key }));
        }
    };
    limits::store(&db, &next).await?;
    Response::from_json(&view(&db, &next).await)
}

#[cfg(test)]
#[path = "plugin_limits_tests.rs"]
mod tests;
