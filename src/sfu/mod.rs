//! Group calls through Cloudflare Realtime SFU (F3; contract in `docs/F3_GROUP_SFU.md`).
//!
//! The relay holds the SFU app's token and the members do not: every SFU API call a member makes
//! goes through here, which checks it is an active member of the room, that the session it acts
//! on is its own, and that a pull names only tracks of the same room and call. Media never passes
//! through the relay (the members connect to Cloudflare directly) and is sealed end to end
//! (FrameCryptor) with a key the relay never sees.
//!
//! The month's egress is counted from the members' own reports (what each received), clamped to
//! what the elapsed time could carry; the cap and the owner's warnings run on that figure.

pub mod cf;
pub mod config;
pub mod policy;


use crate::d1util::{d1_int, d1_text};
use crate::groups::{group_role, require_live_device_auth};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

pub(crate) const SQL_GROUP_SETTINGS: &str = "SELECT settings_json FROM groups WHERE id = ? LIMIT 1";
pub(crate) const SQL_USAGE: &str =
    "SELECT egress_bytes, warned_80, warned_100 FROM sfu_usage WHERE month = ? LIMIT 1";
pub(crate) const SQL_INSERT_SESSION: &str = "INSERT INTO sfu_sessions \
     (session_id, room_id, call_id, user_id, created_at) VALUES (?, ?, ?, ?, ?)";
pub(crate) const SQL_SESSION: &str = "SELECT room_id, call_id, user_id, created_at, last_report_at \
     FROM sfu_sessions WHERE session_id = ? LIMIT 1";
pub(crate) const SQL_CALL_SESSIONS: &str =
    "SELECT session_id FROM sfu_sessions WHERE room_id = ? AND call_id = ?";
/// Whether a call is going on: how many of its sessions reported media since a moment (a
/// session only opened says nothing — opening one is what is being decided), and when its first
/// session opened (the call's age).
pub(crate) const SQL_CALL_LIVE: &str = "SELECT \
     (SELECT COUNT(*) FROM sfu_sessions WHERE room_id = ?1 AND call_id = ?2 AND last_report_at >= ?3) AS n, \
     (SELECT MIN(created_at) FROM sfu_sessions WHERE room_id = ?1 AND call_id = ?2) AS first_at";
pub(crate) const SQL_ADD_USAGE: &str = "INSERT INTO sfu_usage (month, egress_bytes) VALUES (?, ?) \
     ON CONFLICT(month) DO UPDATE SET egress_bytes = egress_bytes + excluded.egress_bytes";
pub(crate) const SQL_ADD_ROOM_USAGE: &str = "INSERT INTO sfu_room_usage (month, room_id, egress_bytes) \
     VALUES (?, ?, ?) ON CONFLICT(month, room_id) \
     DO UPDATE SET egress_bytes = egress_bytes + excluded.egress_bytes";
pub(crate) const SQL_SET_WARNED: &str = "UPDATE sfu_usage SET warned_80 = MAX(warned_80, ?), \
     warned_100 = MAX(warned_100, ?) WHERE month = ?";
pub(crate) const SQL_TOUCH_REPORT: &str =
    "UPDATE sfu_sessions SET last_report_at = ? WHERE session_id = ?";
/// Where a member's next report is counted from: their latest report — or newest session's
/// opening — on ANY of their sessions. The clamp is a member's, not a session's: per session, a
/// member who opened a few hundred sessions could each claim 2.25 GB every five minutes and spend
/// the month's cap within the hour, turning the SFU off for every group call on the server.
/// Bind: user.
pub(crate) const SQL_USER_REPORTED_SINCE: &str =
    "SELECT MAX(COALESCE(last_report_at, created_at)) AS t FROM sfu_sessions WHERE user_id = ?";
pub(crate) const SQL_PRUNE_SESSIONS: &str = "DELETE FROM sfu_sessions WHERE created_at < ?";
/// Sessions a member opened since a moment (`policy::MAX_SESSIONS_PER_DAY`). Bind: user, since.
pub(crate) const SQL_USER_SESSIONS_SINCE: &str =
    "SELECT COUNT(*) AS n FROM sfu_sessions WHERE user_id = ? AND created_at >= ?";

/// A session row is kept this long (a day); older rows are pruned when a new one is opened.
const SESSION_KEEP_SECS: i64 = 24 * 60 * 60;
/// What a member past the day's session bound is told to wait. The count slides over a day, so
/// the exact moment would take another read; a fixed hour says "not soon" without guessing.
const SESSION_BOUND_RETRY_SECS: u64 = 60 * 60;

#[derive(Deserialize)]
pub(crate) struct UsageRow {
    pub egress_bytes: i64,
    pub warned_80: i64,
    pub warned_100: i64,
}

#[derive(Deserialize)]
struct SessionRow {
    room_id: String,
    call_id: String,
    user_id: String,
    created_at: i64,
    last_report_at: Option<i64>,
}

/// The month's usage row; zeros when there is none (or the table is missing — fail open).
pub(crate) async fn month_usage(db: &D1Database, month: &str) -> UsageRow {
    let row = match db.prepare(SQL_USAGE).bind(&[d1_text(month)]) {
        Ok(stmt) => stmt.first::<UsageRow>(None).await.ok().flatten(),
        Err(_) => None,
    };
    row.unwrap_or(UsageRow { egress_bytes: 0, warned_80: 0, warned_100: 0 })
}

async fn decision_for(env: &Env, db: &D1Database, room_id: &str) -> Result<policy::Decision> {
    #[derive(Deserialize)]
    struct S {
        settings_json: Option<String>,
    }
    let settings: Option<S> = db.prepare(SQL_GROUP_SETTINGS).bind(&[d1_text(room_id)])?.first(None).await?;
    let group_direct = policy::group_is_direct(settings.and_then(|s| s.settings_json).as_deref());
    let configured = config::app(env, db).await.is_some();
    let route = config::route(env, db).await;
    let used = month_usage(db, &crate::turn::current_month_utc()).await.egress_bytes;
    Ok(policy::decide(configured, route, group_direct, used, config::cap_gb(env, db).await))
}

/// The caller, an active member of `room_id` — or the response that refuses it.
async fn member(req: &Request, env: &Env, db: &D1Database, room_id: &str) -> std::result::Result<String, Response> {
    let uid = require_live_device_auth(req, env).await?;
    match group_role(db, room_id, &uid).await {
        Ok(Some(_)) => Ok(uid),
        Ok(None) => Err(json_err(403, "not_member").unwrap_or_else(|_| Response::empty().unwrap())),
        Err(_) => Err(json_err(500, "internal").unwrap_or_else(|_| Response::empty().unwrap())),
    }
}

/// `GET /calls/sfu/status?room_id=` — may a call in this room go through the SFU now?
pub async fn status(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let room_id = req
        .url()?
        .query_pairs()
        .find(|(k, _)| k == "room_id")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    if room_id.is_empty() {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    if let Err(resp) = member(&req, &ctx.env, &db, &room_id).await {
        return Ok(resp);
    }
    let d = decision_for(&ctx.env, &db, &room_id).await?;
    Response::from_json(&serde_json::json!({
        "available": d.available,
        "route": d.route.as_str(),
        "reason": d.reason,
        "max_video": policy::MAX_VIDEO,
        "crowded_above": policy::CROWDED_ABOVE,
    }))
}

#[derive(Deserialize, Default)]
struct NewSessionBody {
    room_id: String,
    call_id: String,
}

/// `POST /calls/sfu/sessions` `{room_id, call_id}` → `{session_id}`.
pub async fn new_session(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: NewSessionBody = req.json().await.unwrap_or_default();
    if body.room_id.is_empty() || body.call_id.is_empty() || body.call_id.len() > 128 {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    let uid = match member(&req, &ctx.env, &db, &body.room_id).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let now = now_secs() as i64;
    // Each session is a call to Cloudflare on the owner's app: braked per member in KV, bounded
    // per member in D1 (the brake fails open).
    let brake = crate::ratelimit::admit_env(
        &ctx.env,
        &policy::session_rate_key(&uid),
        policy::SESSIONS_PER_WINDOW,
        policy::SESSION_WINDOW_SECS,
    )
    .await;
    if let crate::ratelimit::Admission::Refused { retry_after_s } = brake {
        return crate::respond::rate_limited(retry_after_s);
    }
    #[derive(Deserialize)]
    struct Opened {
        n: i64,
    }
    let opened = db
        .prepare(SQL_USER_SESSIONS_SINCE)
        .bind(&[d1_text(&uid), d1_int(now - SESSION_KEEP_SECS)])?
        .first::<Opened>(None)
        .await?
        .map_or(0, |o| o.n);
    if !policy::session_within_bound(opened) {
        return crate::respond::rate_limited(SESSION_BOUND_RETRY_SECS);
    }
    let d = decision_for(&ctx.env, &db, &body.room_id).await?;
    if !d.available {
        // Past the month's limit a call already going on is still joined through the SFU.
        #[derive(Deserialize)]
        struct Live {
            n: i64,
            first_at: Option<i64>,
        }
        let running = d.reason == Some("capped")
            && db
                .prepare(SQL_CALL_LIVE)
                .bind(&[
                    d1_text(&body.room_id),
                    d1_text(&body.call_id),
                    d1_int(now - policy::RUNNING_CALL_WINDOW_SECS),
                ])?
                .first::<Live>(None)
                .await?
                .is_some_and(|l| policy::call_is_running(l.n, l.first_at, now));
        if !policy::admits_running_call(&d, running) {
            return json_err(409, d.reason.unwrap_or("unavailable"));
        }
    }
    let Some((app_id, token)) = config::app(&ctx.env, &db).await else {
        return json_err(409, "not_configured");
    };
    let Some(session_id) = cf::new_session(&app_id, &token).await? else {
        return json_err(502, "sfu_upstream_error");
    };
    db.prepare(SQL_INSERT_SESSION)
        .bind(&[d1_text(&session_id), d1_text(&body.room_id), d1_text(&body.call_id), d1_text(&uid), d1_int(now)])?
        .run()
        .await?;
    if let Ok(stmt) = db.prepare(SQL_PRUNE_SESSIONS).bind(&[d1_int(now - SESSION_KEEP_SECS)]) {
        let _ = stmt.run().await;
    }
    Response::from_json(&serde_json::json!({ "session_id": session_id }))
}

/// The caller's own session, still a member of its room — or the refusal.
async fn own_session(
    req: &Request,
    env: &Env,
    db: &D1Database,
    session_id: &str,
) -> std::result::Result<(String, SessionRow), Response> {
    let uid = require_live_device_auth(req, env).await?;
    let refuse = |code: &str| json_err(403, code).unwrap_or_else(|_| Response::empty().unwrap());
    let row: Option<SessionRow> = match db.prepare(SQL_SESSION).bind(&[d1_text(session_id)]) {
        Ok(stmt) => stmt.first(None).await.ok().flatten(),
        Err(_) => None,
    };
    let Some(row) = row.filter(|r| r.user_id == uid) else {
        return Err(refuse("not_your_session"));
    };
    match group_role(db, &row.room_id, &uid).await {
        Ok(Some(_)) => Ok((uid, row)),
        _ => Err(refuse("not_member")),
    }
}

fn session_param(ctx: &RouteContext<()>) -> Option<String> {
    ctx.param("sid").filter(|s| !s.is_empty() && s.len() <= 128).cloned()
}

async fn forward(env: &Env, db: &D1Database, method: Method, path: String, body: String) -> Result<Response> {
    let Some((app_id, token)) = config::app(env, db).await else {
        return json_err(409, "not_configured");
    };
    let (status, text) = cf::call(&app_id, &token, method, &path, Some(body)).await?;
    let mut resp = Response::ok(text)?.with_status(status);
    resp.headers_mut().set("content-type", "application/json")?;
    Ok(resp)
}

/// `POST /calls/sfu/sessions/:sid/tracks` — CF `tracks/new`, pulls limited to the same call.
pub async fn tracks(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    checked_forward(&mut req, &ctx, Method::Post, "tracks/new").await
}

/// `PUT /calls/sfu/sessions/:sid/tracks/update` — a pulled track's layer (`simulcast.preferredRid`)
/// or a transceiver re-pointed at another track. It names remote sessions as `tracks/new` does, so
/// it passes the same check: only tracks of the same room and call.
pub async fn update_tracks(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    checked_forward(&mut req, &ctx, Method::Put, "tracks/update").await
}

/// A track call on the caller's own session whose remote tracks must all belong to the same
/// room and call.
async fn checked_forward(
    req: &mut Request,
    ctx: &RouteContext<()>,
    method: Method,
    tail: &str,
) -> Result<Response> {
    let Some(sid) = session_param(ctx) else { return json_err(400, "bad_request") };
    let text = req.text().await.unwrap_or_default();
    let Ok(body) = serde_json::from_str::<serde_json::Value>(&text) else {
        return json_err(400, "bad_request");
    };
    let db = ctx.env.d1("DB")?;
    let (_, row) = match own_session(req, &ctx.env, &db, &sid).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    #[derive(Deserialize)]
    struct Sid {
        session_id: String,
    }
    let allowed: Vec<String> = db
        .prepare(SQL_CALL_SESSIONS)
        .bind(&[d1_text(&row.room_id), d1_text(&row.call_id)])?
        .all()
        .await?
        .results::<Sid>()?
        .into_iter()
        .map(|s| s.session_id)
        .collect();
    if !policy::remote_tracks_ok(&body, &allowed) {
        return json_err(403, "foreign_track");
    }
    forward(&ctx.env, &db, method, format!("sessions/{sid}/{tail}"), text).await
}

/// `PUT /calls/sfu/sessions/:sid/renegotiate` — passed through for the session's owner.
pub async fn renegotiate(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    passthrough_put(&mut req, &ctx, "renegotiate").await
}

/// `PUT /calls/sfu/sessions/:sid/tracks/close` — passed through for the session's owner.
pub async fn close_tracks(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    passthrough_put(&mut req, &ctx, "tracks/close").await
}

async fn passthrough_put(req: &mut Request, ctx: &RouteContext<()>, tail: &str) -> Result<Response> {
    let Some(sid) = session_param(ctx) else { return json_err(400, "bad_request") };
    let text = req.text().await.unwrap_or_default();
    if serde_json::from_str::<serde_json::Value>(&text).is_err() {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    if let Err(resp) = own_session(req, &ctx.env, &db, &sid).await {
        return Ok(resp);
    }
    forward(&ctx.env, &db, Method::Put, format!("sessions/{sid}/{tail}"), text).await
}

#[derive(Deserialize, Default)]
struct UsageBody {
    session_id: String,
    egress_bytes: i64,
}

/// `POST /calls/sfu/usage` `{session_id, egress_bytes}` — what this member received since its last
/// report; counted toward the month and the room, clamped, and the owner's warnings set.
pub async fn usage(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: UsageBody = req.json().await.unwrap_or_default();
    if body.session_id.is_empty() {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    let (_, row) = match own_session(&req, &ctx.env, &db, &body.session_id).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let now = now_secs() as i64;
    #[derive(Deserialize)]
    struct Since {
        t: Option<i64>,
    }
    let member_since: Option<i64> = match db.prepare(SQL_USER_REPORTED_SINCE).bind(&[d1_text(&row.user_id)]) {
        Ok(stmt) => stmt.first::<Since>(None).await.ok().flatten().and_then(|s| s.t),
        Err(_) => None,
    };
    let since = member_since.unwrap_or(row.last_report_at.unwrap_or(row.created_at));
    let counted = policy::clamp_report(body.egress_bytes, now - since);
    // A report of nothing changes nothing — not even "last reported": that moment is what keeps
    // a call counted as going on past the month's limit (`admits_running_call`), and only media
    // that actually arrives may keep it so.
    if counted <= 0 {
        return Response::from_json(&serde_json::json!({ "counted": 0 }));
    }
    let month = crate::turn::current_month_utc();
    db.batch(vec![
        db.prepare(SQL_ADD_USAGE).bind(&[d1_text(&month), d1_int(counted)])?,
        db.prepare(SQL_ADD_ROOM_USAGE).bind(&[d1_text(&month), d1_text(&row.room_id), d1_int(counted)])?,
        db.prepare(SQL_TOUCH_REPORT).bind(&[d1_int(now), d1_text(&body.session_id)])?,
    ])
    .await?;
    let after = month_usage(&db, &month).await;
    let cap = config::cap_gb(&ctx.env, &db).await;
    let (w80, w100) = policy::crossed(after.egress_bytes, cap, after.warned_80 != 0, after.warned_100 != 0);
    if w80 || w100 {
        db.prepare(SQL_SET_WARNED)
            .bind(&[d1_int(w80 as i64), d1_int(w100 as i64), d1_text(&month)])?
            .run()
            .await?;
    }
    Response::from_json(&serde_json::json!({ "counted": counted }))
}

pub(crate) const SQL_TOP_ROOMS: &str = "SELECT room_id, egress_bytes FROM sfu_room_usage \
     WHERE month = ? ORDER BY egress_bytes DESC LIMIT 5";

/// The `sfu` block of `/admin/stats`: whether an app is set (never its values), the route, the cap,
/// the month's reported egress, whether the owner was warned, and the five groups that spent the
/// most. `measured: false` says the figure is the members' reports, not Cloudflare's bill.
/// Fails open: any read error leaves zeros, stats never 500s.
pub(crate) async fn stats_block(env: &Env, db: &D1Database) -> serde_json::Value {
    #[derive(Deserialize)]
    struct Top {
        room_id: String,
        egress_bytes: i64,
    }
    let month = crate::turn::current_month_utc();
    let usage = month_usage(db, &month).await;
    let top: Vec<serde_json::Value> = match db.prepare(SQL_TOP_ROOMS).bind(&[d1_text(&month)]) {
        Ok(stmt) => match stmt.all().await {
            Ok(rows) => rows
                .results::<Top>()
                .unwrap_or_default()
                .into_iter()
                .map(|t| serde_json::json!({ "room_id": t.room_id, "egress_bytes": t.egress_bytes }))
                .collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    serde_json::json!({
        "configured": config::app(env, db).await.is_some(),
        "route": config::route(env, db).await.as_str(),
        "cap_gb": config::cap_gb(env, db).await,
        "egress_bytes_month": usage.egress_bytes,
        "warned_80": usage.warned_80 != 0,
        "warned_100": usage.warned_100 != 0,
        "measured": false,
        "top_rooms": top,
    })
}

#[cfg(test)]
#[path = "sql_tests.rs"]
mod sql_tests;
