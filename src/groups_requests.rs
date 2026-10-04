//! Join requests — people who came in through a class invite and wait for a group admin
//! (migration 0044; `auth/landing.rs` writes them at verify).
//!
//! ```text
//! GET  /groups/:id/join-requests?limit=&cursor=     group owner/admin
//!   200 {"requests": [{"user_id","display_name","invite_label","requested_at"}],
//!        "next": <cursor>|null, "pending": <count>}
//! POST /groups/:id/join-requests/:user_id/approve   group owner/admin → 204
//!   404 no_request · 409 group_full
//! POST /groups/:id/join-requests/:user_id/deny      group owner/admin → 204 · 404 no_request
//! POST /groups/:id/join-requests/approve-all        group owner/admin
//!   200 {"approved": n, "pending": remaining}   (oldest first, ≤100 per call, within the ceiling)
//! GET  /join-requests/mine                          any member — their own requests only
//!   200 {"requests": [{"room_id","group_name","state","invite_label","requested_at","decided_at"}]}
//! ```
//! Every handler answers 403 `not_member` / `forbidden` like the rest of the group surface.
//!
//! **Approval is an ordinary invitation.** It writes the consent row every invitee gets
//! (`status = 'pending'`, `added_by` = the APPROVING admin) and marks the request approved, in one
//! batch. The requester's client accepts that row on its own — it asked to come in — and its
//! `GroupJoinAccepted` goes to the approver, who is online right now and distributes the room key.
//! So the E2E consent and key path is the one `add_member` uses, unchanged.
//!
//! Group admins decide, never the server's owner as such: running the server grants nothing inside
//! a group (AGENTS.md, "Who the server owner is").

use serde::{Deserialize, Serialize};
use worker::*;

use super::{group_role, is_group_admin, notify, require_live_device_auth};
use crate::d1util::{d1_int, d1_null, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;

const PAGE_DEFAULT: i64 = 50;
const PAGE_MAX: i64 = 200;
/// Requests one "approve all" admits. Each becomes a consent row and each requester then pulls the
/// room; a hundred at a time keeps one press inside a request's budget and lets the admin see the
/// count fall.
pub(crate) const APPROVE_ALL_BATCH: i64 = 100;
/// The requester's own list is short by nature (one request per landing group).
const MINE_LIMIT: i64 = 50;

/// A page of a group's pending requests, newest first. Binds: `?1` group, `?2` cursor time (NULL
/// on the first page), `?3` cursor user, `?4` limit.
pub(crate) const LIST_PENDING_SQL: &str =
    "SELECT r.user_id AS user_id, u.display_name AS display_name,
            r.invite_label AS invite_label, r.requested_at AS requested_at
       FROM group_join_requests r JOIN users u ON u.id = r.user_id
      WHERE r.group_id = ?1 AND r.state = 'pending'
        AND (?2 IS NULL OR r.requested_at < ?2 OR (r.requested_at = ?2 AND r.user_id > ?3))
      ORDER BY r.requested_at DESC, r.user_id ASC
      LIMIT ?4";

/// Binds: group.
pub(crate) const PENDING_COUNT_SQL: &str =
    "SELECT COUNT(*) AS c FROM group_join_requests WHERE group_id = ? AND state = 'pending'";

/// The consent row for ONE request, only while the group has room. Binds: `?1` group, `?2` user,
/// `?3` now, `?4` approver, `?5` ceiling.
pub(crate) const ADMIT_ONE_SQL: &str = "INSERT OR IGNORE INTO group_members
       (group_id, user_id, role, joined_at, status, added_by)
     SELECT r.group_id, r.user_id, 'member', ?3, 'pending', ?4 FROM group_join_requests r
      WHERE r.group_id = ?1 AND r.user_id = ?2 AND r.state = 'pending'
        AND (SELECT COUNT(*) FROM group_members c WHERE c.group_id = ?1) < ?5";

/// The consent rows for the oldest pending requests. Binds: `?1` group, `?2` now, `?3` approver,
/// `?4` how many (the caller has already fitted it under the ceiling).
pub(crate) const ADMIT_OLDEST_SQL: &str = "INSERT OR IGNORE INTO group_members
       (group_id, user_id, role, joined_at, status, added_by)
     SELECT r.group_id, r.user_id, 'member', ?2, 'pending', ?3 FROM group_join_requests r
      WHERE r.group_id = ?1 AND r.state = 'pending'
      ORDER BY r.requested_at, r.user_id
      LIMIT ?4";

/// Mark approved exactly the pending requests that now have a membership row — the statement after
/// an ADMIT in the same batch, so a request the ceiling refused stays pending, and a requester
/// someone added by hand meanwhile is settled too. Binds: `?1` group, `?2` user (NULL = every one),
/// `?3` now, `?4` approver.
pub(crate) const MARK_APPROVED_SQL: &str = "UPDATE group_join_requests
        SET state = 'approved', decided_at = ?3, decided_by = ?4
      WHERE group_id = ?1 AND state = 'pending' AND (?2 IS NULL OR user_id = ?2)
        AND EXISTS (SELECT 1 FROM group_members m
                     WHERE m.group_id = ?1 AND m.user_id = group_join_requests.user_id)
     RETURNING user_id";

/// Binds: `?1` group, `?2` user, `?3` now, `?4` admin.
pub(crate) const DENY_SQL: &str = "UPDATE group_join_requests
        SET state = 'denied', decided_at = ?3, decided_by = ?4
      WHERE group_id = ?1 AND user_id = ?2 AND state = 'pending'
     RETURNING user_id";

/// The requester's own view: every request, decided ones included until the 30-day sweep. The
/// group's NAME is shown — the invite that sent them there named it — and nothing else about it.
/// Binds: `?1` user, `?2` limit.
pub(crate) const MINE_SQL: &str =
    "SELECT r.group_id AS room_id, g.name AS group_name, r.state AS state,
            r.invite_label AS invite_label, r.requested_at AS requested_at,
            r.decided_at AS decided_at
       FROM group_join_requests r LEFT JOIN groups g ON g.id = r.group_id
      WHERE r.user_id = ?1
      ORDER BY r.requested_at DESC
      LIMIT ?2";

/// The group's admins, who are the ones a new request concerns. Binds: group, limit.
const ADMINS_SQL: &str = "SELECT user_id FROM group_members
      WHERE group_id = ? AND status = 'active' AND role IN ('owner', 'admin')
      ORDER BY user_id LIMIT ?";

#[derive(Deserialize)]
struct CountRow {
    c: i64,
}

#[derive(Deserialize)]
struct UserRow {
    user_id: String,
}

#[derive(Serialize, Deserialize)]
struct Cursor {
    t: i64,
    u: String,
}

/// Wake whoever a landing concerns. An `added` joiner changed the room's member sheet, so the room
/// is nudged with the joiner named first; a `requested` one changed nothing any member can see,
/// so only the admins — who hold the list — are woken.
pub(crate) async fn nudge_landing(
    env: &Env,
    db: &D1Database,
    room: &str,
    user: &str,
    requested: bool,
) {
    if !requested {
        notify::nudge_room(env, db, room, &[user]).await;
        return;
    }
    let admins: Vec<String> = match db
        .prepare(ADMINS_SQL)
        .bind(&[d1_text(room), d1_int(notify::GROUP_NUDGE_LIMIT as i64)])
    {
        Ok(stmt) => match stmt.all().await.and_then(|r| r.results::<UserRow>()) {
            Ok(rows) => rows.into_iter().map(|r| r.user_id).collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    notify::nudge_users(env, room, admins).await;
}

/// The caller, the group id from the path, and proof the caller administers it.
async fn admin_gate(
    req: &Request,
    ctx: &RouteContext<()>,
) -> std::result::Result<(String, String), Response> {
    let caller = require_live_device_auth(req, &ctx.env).await?;
    let Some(group_id) = ctx.param("id").cloned() else {
        return Err(json_err(400, "bad_request").unwrap());
    };
    let db = ctx
        .env
        .d1("DB")
        .map_err(|_| json_err(503, "db_unavailable").unwrap())?;
    match group_role(&db, &group_id, &caller).await {
        Ok(Some(role)) if is_group_admin(&role) => Ok((caller, group_id)),
        Ok(Some(_)) => Err(json_err(403, "forbidden").unwrap()),
        Ok(None) => Err(json_err(403, "not_member").unwrap()),
        Err(_) => Err(json_err(503, "db_unavailable").unwrap()),
    }
}

async fn pending_count(db: &D1Database, group_id: &str) -> Result<i64> {
    Ok(db
        .prepare(PENDING_COUNT_SQL)
        .bind(&[d1_text(group_id)])?
        .first::<CountRow>(None)
        .await?
        .map(|r| r.c)
        .unwrap_or(0))
}

pub async fn list_join_requests(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (_, group_id) = match admin_gate(&req, &ctx).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let cursor: Option<Cursor> = match crate::page_cursor::from_request(&req) {
        Ok(c) => c,
        Err(()) => return json_err(400, "bad_cursor"),
    };
    let limit = crate::page_cursor::limit(
        crate::page_cursor::query(&req, "limit").as_deref(),
        PAGE_DEFAULT,
        PAGE_MAX,
    );
    let db = ctx.env.d1("DB")?;
    #[derive(Deserialize)]
    struct Row {
        user_id: String,
        display_name: Option<String>,
        invite_label: Option<String>,
        requested_at: i64,
    }
    let (after_t, after_u) = match &cursor {
        Some(c) => (d1_int(c.t), d1_text(&c.u)),
        None => (d1_null(), d1_text("")),
    };
    let mut rows: Vec<Row> = db
        .prepare(LIST_PENDING_SQL)
        .bind(&[d1_text(&group_id), after_t, after_u, d1_int(limit + 1)])?
        .all()
        .await?
        .results()?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = more
        .then(|| {
            rows.last().map(|r| {
                crate::page_cursor::encode(&Cursor {
                    t: r.requested_at,
                    u: r.user_id.clone(),
                })
            })
        })
        .flatten();
    let pending = pending_count(&db, &group_id).await?;
    let requests: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "user_id": r.user_id,
                "display_name": r.display_name,
                "invite_label": r.invite_label,
                "requested_at": r.requested_at,
            })
        })
        .collect();
    Response::from_json(
        &serde_json::json!({ "requests": requests, "next": next, "pending": pending }),
    )
}

pub async fn approve_join_request(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (caller, group_id) = match admin_gate(&req, &ctx).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let Some(user) = ctx.param("user").cloned() else {
        return json_err(400, "bad_request");
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;
    let results = db
        .batch(vec![
            db.prepare(ADMIT_ONE_SQL).bind(&[
                d1_text(&group_id),
                d1_text(&user),
                d1_int(now),
                d1_text(&caller),
                d1_int(crate::auth::landing::LANDING_GROUP_CEILING),
            ])?,
            db.prepare(MARK_APPROVED_SQL).bind(&[
                d1_text(&group_id),
                d1_text(&user),
                d1_int(now),
                d1_text(&caller),
            ])?,
        ])
        .await?;
    let approved = results
        .get(1)
        .map(|r| !r.results::<UserRow>().unwrap_or_default().is_empty())
        .unwrap_or(false);
    if !approved {
        // Nothing approved: either there is no pending request, or the ceiling refused it.
        #[derive(Deserialize)]
        struct StateRow {
            #[allow(dead_code)] // read for its presence
            state: String,
        }
        let still_pending: Option<StateRow> = db
            .prepare(
                "SELECT state FROM group_join_requests
                  WHERE group_id = ? AND user_id = ? AND state = 'pending' LIMIT 1",
            )
            .bind(&[d1_text(&group_id), d1_text(&user)])?
            .first(None)
            .await?;
        return match still_pending {
            Some(_) => json_err(409, "group_full"),
            None => json_err(404, "no_request"),
        };
    }
    notify::nudge_room(&ctx.env, &db, &group_id, &[&user]).await;
    no_content()
}

pub async fn deny_join_request(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (caller, group_id) = match admin_gate(&req, &ctx).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let Some(user) = ctx.param("user").cloned() else {
        return json_err(400, "bad_request");
    };
    let db = ctx.env.d1("DB")?;
    let denied: Vec<UserRow> = db
        .prepare(DENY_SQL)
        .bind(&[
            d1_text(&group_id),
            d1_text(&user),
            d1_int(now_secs() as i64),
            d1_text(&caller),
        ])?
        .all()
        .await?
        .results()?;
    if denied.is_empty() {
        return json_err(404, "no_request");
    }
    // Only the requester's view changed; the room never saw the request.
    notify::nudge_users(&ctx.env, &group_id, vec![user]).await;
    no_content()
}

pub async fn approve_all_join_requests(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (caller, group_id) = match admin_gate(&req, &ctx).await {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let members = db
        .prepare("SELECT COUNT(*) AS c FROM group_members WHERE group_id = ?")
        .bind(&[d1_text(&group_id)])?
        .first::<CountRow>(None)
        .await?
        .map(|r| r.c)
        .unwrap_or(0);
    // Counted then written, the same shape `add_member` uses for the same soft ceiling: two admins
    // pressing at once can overshoot by one batch, which widens a fan-out, not a permission.
    let room = (crate::auth::landing::LANDING_GROUP_CEILING - members).clamp(0, APPROVE_ALL_BATCH);
    let now = now_secs() as i64;
    let mut approved: Vec<UserRow> = Vec::new();
    if room > 0 {
        let results = db
            .batch(vec![
                db.prepare(ADMIT_OLDEST_SQL).bind(&[
                    d1_text(&group_id),
                    d1_int(now),
                    d1_text(&caller),
                    d1_int(room),
                ])?,
                db.prepare(MARK_APPROVED_SQL).bind(&[
                    d1_text(&group_id),
                    d1_null(),
                    d1_int(now),
                    d1_text(&caller),
                ])?,
            ])
            .await?;
        approved = results
            .get(1)
            .map(|r| r.results::<UserRow>().unwrap_or_default())
            .unwrap_or_default();
    }
    let pending = pending_count(&db, &group_id).await?;
    if !approved.is_empty() {
        notify::nudge_users(
            &ctx.env,
            &group_id,
            approved.iter().map(|r| r.user_id.clone()).collect(),
        )
        .await;
    }
    if pending > 0 && room == 0 {
        return json_err(409, "group_full");
    }
    Response::from_json(&serde_json::json!({ "approved": approved.len(), "pending": pending }))
}

pub async fn my_join_requests(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    #[derive(Deserialize)]
    struct Row {
        room_id: String,
        group_name: Option<String>,
        state: String,
        invite_label: Option<String>,
        requested_at: i64,
        decided_at: Option<i64>,
    }
    let rows: Vec<Row> = db
        .prepare(MINE_SQL)
        .bind(&[d1_text(&user_id), d1_int(MINE_LIMIT)])?
        .all()
        .await?
        .results()?;
    let requests: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "room_id": r.room_id,
                "group_name": r.group_name,
                "state": r.state,
                "invite_label": r.invite_label,
                "requested_at": r.requested_at,
                "decided_at": r.decided_at,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "requests": requests }))
}

#[cfg(test)]
#[path = "groups_requests_tests.rs"]
mod tests;
