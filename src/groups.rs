//! Group chat — membership plus in-group authority (Faz 1).
//!
//! Groups are sub-communities WITHIN a server. The in-group role (owner/admin/member) is
//! INDEPENDENT of the server role: whoever creates a group becomes its owner, and ANY member
//! of the server may create one. The server `owner` role means server ADMINISTRATION only —
//! invites, settings, storage, the admin endpoints — and carries no authority inside a group.
//! Reading a group's messages therefore requires being IN that group, which running the server
//! does not make you. What bounds creation now is a per-user cap on groups owned
//! (`MAX_OWNED_GROUPS`) plus a rate limit, not a role. Opening creation does NOT turn this into
//! a discovery or matchmaking surface: `add_member` takes a `user_id` the caller must already
//! know, from a 1:1 pairing or an out-of-band channel, and the addee stays `pending` until they
//! accept.
//!
//! E2E: the server never sees group CONTENT. This module manages only the membership table;
//! message crypto is Megolm on the client and message distribution is the Faz 2 fan-out (in
//! `messages`). The authority matrix is the group-scoped copy of the server-authority epic.

// Four coherent blocks lifted out under the 800-line ceiling, each declared here rather than in
// `lib.rs` so the group surface stays one module from the outside: the ownership-transfer write,
// the teardown batch, the live nudges, and the two read projections.
#[path = "groups_delete.rs"]
mod delete;
#[path = "groups_notify.rs"]
mod notify;
#[path = "groups_read.rs"]
mod read;
#[path = "groups_transfer.rs"]
mod transfer;

use crate::auth::middleware::{device_revoked, require_existing_account_auth};
use crate::d1util::{d1_int, d1_null, d1_opt_text, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

const MAX_NAME_CHARS: usize = 100;
const MAX_INITIAL_MEMBERS: usize = 200;
/// M12 (fan-out amplification — DoS): ceiling on group membership. Every group send
/// fan-outs into N (members × devices) DO writes, so with unbounded membership a single
/// message becomes enormous amplification. add_member rejects any addition past this
/// ceiling with a 4xx. Consistent with MAX_INITIAL_MEMBERS (200) and reasonably above it.
const MAX_GROUP_MEMBERS: usize = 256;
/// Per-user ceiling on groups you currently OWN. Group creation was server-owner-only until
/// 2026-08-05, and that gate was the de-facto limiter; with creation open to every member,
/// something has to bound it or one account can fill D1 by itself. Each creation writes one
/// `groups` row plus up to `MAX_INITIAL_MEMBERS + 1` membership rows, so 64 caps a single
/// account at roughly 13k rows — bounded, while sitting far above what a person plausibly
/// runs (whoever organises a real community owns a handful of groups, not dozens).
///
/// It bounds BOTH writes that can mint an owner row — creation here and the transfer in
/// `groups_transfer.rs`. A cap on creation alone would have been a cap on nothing: an account at
/// the ceiling could hand its 64 groups to one person, who then cannot create one of their own.
///
/// Hard-coded deliberately, for now. The right long-term home is the pattern the storage
/// quotas already use — a nullable cap column on `server_settings` (see `quota.rs` and
/// migration `0023_quota_caps.sql`) where NULL means unlimited and the owner sets the value
/// through `PATCH /admin/server-settings`. That needs a migration and an admin handler, so it
/// is the follow-up; this constant is the bound until then.
const MAX_OWNED_GROUPS: usize = 64;
/// Ceiling on the opaque `settings_json` bag, in BYTES of UTF-8.
///
/// The column is TEXT the server never interprets, writable by any group admin and read back by
/// every member on every `GET /groups` — so unbounded it was both a D1 filler and a response
/// amplifier, one admin's paste inflating a list call for the whole room forever.
///
/// 2 KiB is chosen against what the field actually carries. Today that is a P2P toggle:
/// `core`'s `room_p2p_enabled` parses `{"p2p":true}` out of it — thirteen bytes — and the doc
/// comments around it name a theme and plugin configuration as the intended company. 2 KiB is
/// roughly 150× that, which is room for a real settings bag rather than a ration, while keeping
/// the worst case bounded where it actually bites: `MAX_GROUPS_PAGE` (200) × 2 KiB caps this
/// field's contribution to one list response in the hundreds of kilobytes instead of megabytes.
/// A group that genuinely needs more than 2 KiB of client configuration wants a table, not a bag.
const MAX_SETTINGS_JSON_BYTES: usize = 2048;

/// The gate EVERY handler in this file goes through: a valid token, an account that still
/// exists, and a calling device that has not been revoked. Returns the caller's `user_id`.
///
/// Until this existed, all ten handlers gated on the bare stateless JWT — the string
/// `device_revoked` did not appear in this file at all. Revoking a device deletes its refresh
/// token but cannot expire its ACCESS token, which stays valid for ~15 more minutes, so a device
/// the owner had just removed kept full in-group authority for that window: `DELETE /groups/:id`,
/// `remove-member`, `set-role`. `admin/mod.rs` carries a compile-time guard against exactly this
/// pattern, scoped to the admin modules; the group surface had the same hole and no guard.
///
/// Why not `require_active_auth`, which is what the admin surface uses? Because it fails CLOSED
/// on a device with no `devices` row at all, and registration does not create one — the first
/// rows appear only when the client publishes its device list. A freshly registered account
/// would be locked out of its own group list until then. Revocation does not need that: removing
/// a device SETS `revoked_at` on the row rather than deleting it (`put_list`'s omission-revoke),
/// so a revoked device always has a row and `device_revoked` always sees it. This closes the hole
/// without inventing a new bootstrap deadlock; it is the same pairing `plugin_blob::gate` uses.
async fn require_live_device_auth(
    req: &Request,
    env: &Env,
) -> std::result::Result<String, Response> {
    let auth = require_existing_account_auth(req, env).await?;
    // FAIL-CLOSED on a D1 error, at parity with `push::register`: reading a failed lookup as
    // "not revoked" would hand a revoked device a window whenever the database wobbles.
    match device_revoked(env, &auth.user_id, &auth.device_id).await {
        Ok(false) => {}
        Ok(true) => return Err(json_err(401, "device_revoked").unwrap()),
        Err(_) => return Err(json_err(503, "revoke_check_unavailable").unwrap()),
    }
    Ok(auth.user_id)
}

#[derive(Deserialize)]
struct GroupRoleRow {
    role: String,
}

/// A user's in-group role ('owner' | 'admin' | 'member'), or None if they are not an ACTIVE
/// member. IMPORTANT (Faz 6 #3): only `status='active'` rows count — a 'pending' invitee who
/// has not accepted yet is NOT a member and can neither receive messages, administer the
/// group, nor see the member list. `pub(crate)` because the fan-out
/// (messages::handlers::send) and every group authority gate goes through this.
pub(crate) async fn group_role(
    db: &D1Database,
    group_id: &str,
    user_id: &str,
) -> Result<Option<String>> {
    let row: Option<GroupRoleRow> = db
        .prepare(
            "SELECT role FROM group_members
             WHERE group_id = ? AND user_id = ? AND status = 'active' LIMIT 1",
        )
        .bind(&[d1_text(group_id), d1_text(user_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.role))
}

/// A user's raw membership STATUS ('pending' | 'active'), or None when no row exists. The
/// accept/decline handlers rely on this, since group_role cannot see 'pending'.
async fn membership_status(
    db: &D1Database,
    group_id: &str,
    user_id: &str,
) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct StatusRow {
        status: String,
    }
    let row: Option<StatusRow> = db
        .prepare("SELECT status FROM group_members WHERE group_id = ? AND user_id = ? LIMIT 1")
        .bind(&[d1_text(group_id), d1_text(user_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.status))
}

pub(crate) fn is_group_admin(role: &str) -> bool {
    role == "owner" || role == "admin"
}

/// Is this a valid `visibility` value? (Part of the settings substrate — a column the server
/// actually acts on.) Unknown values are rejected; forward compatibility means extending
/// this function when a new value is introduced.
fn valid_visibility(v: &str) -> bool {
    v == "private" || v == "public"
}

// ---------------------------------------------------------------------------
// POST /groups — create a group; the creator becomes its group-owner. AUTHORITY (2026-08-05):
// ANY member of the server may create a group. The route was owner-only between 2026-07-03 and
// 2026-08-05; that gate is gone and is not coming back. The reason it went: `owner` is a
// SERVER-administration role (invites, settings, storage, admin endpoints) and must grant
// nothing inside a group, but combined with `owner_cannot_leave` (see remove_member) an
// owner-only creation route made the server owner a permanent member of every single group on
// the server. Reading a group's messages should require being in that group; running the box
// should not be a way in. What limits creation now is the per-user `MAX_OWNED_GROUPS` cap plus
// a creation rate limit — a bound, not a privilege. The optional member_ids adds the initial
// members, who must be already-known peers.
// ---------------------------------------------------------------------------
#[derive(Deserialize, Default)]
struct CreateGroupBody {
    name: String,
    member_ids: Option<Vec<String>>,
    // Settings bag (substrate Faz 1) — all optional; omitted fields take the schema default.
    visibility: Option<String>,
    auto_join: Option<bool>,
    settings_json: Option<String>,
}

pub async fn create_group(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // ⚠ TWO DIFFERENT `role` COLUMNS SPELLED WITH THE SAME THREE WORDS. `users.role` is the
    // SERVER role ('owner' | 'admin' | 'member'); `group_members.role` is the IN-GROUP role and
    // uses those identical value strings. They are unrelated, and this route no longer reads
    // `users.role` at all — nothing lines the two up any more, so a server 'owner' is a group
    // 'member', or nothing at all, exactly like everybody else. Mistaking one for the other
    // here would silently hand every group on the server to whoever administers it, which is
    // the precise outcome removing the owner-only gate exists to prevent. Every `role` in this
    // file is the in-group one.
    let body: CreateGroupBody = req.json().await.unwrap_or_default();
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return json_err(400, "bad_name");
    }
    let members = body.member_ids.unwrap_or_default();
    if members.len() > MAX_INITIAL_MEMBERS {
        return json_err(400, "too_many_members");
    }
    // Settings substrate: validate visibility (defaulting to 'private'); auto_join is 0/1.
    let visibility = body.visibility.unwrap_or_else(|| "private".to_string());
    if !valid_visibility(&visibility) {
        return json_err(400, "bad_visibility");
    }
    let auto_join = if body.auto_join.unwrap_or(false) { 1 } else { 0 };
    let settings_json = body.settings_json; // opaque; the server never interprets it
    if settings_json.as_deref().unwrap_or("").len() > MAX_SETTINGS_JSON_BYTES {
        return json_err(400, "settings_too_large");
    }

    // Everything above is pure validation and writes nothing, so it runs BEFORE the two limits:
    // a malformed request should not spend the caller's creation budget.
    //
    // A BRAKE, NOT A BOUND. `check_rate_limit_env` FAILS OPEN when the `RATE_LIMIT` KV binding
    // is missing (see ratelimit.rs), so this shapes bursts wherever the namespace exists — which
    // is prod and the self-host template both — and does nothing on a hand-rolled deployment that
    // omitted it. It is the COUNT cap below, which needs no KV, that actually bounds group
    // creation; never lean on this line for correctness. Ten per hour is
    // far above the human cadence of "make a group" while stopping a script from walking
    // straight to MAX_OWNED_GROUPS in one burst.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("group:create:{user_id}"),
        10,
        3600,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }

    let now = now_secs() as i64;
    let group_id = Uuid::new_v4().to_string();
    let db = ctx.env.d1("DB")?;

    // THE BOUND: how many groups does this caller own RIGHT NOW? The counting query, what it
    // counts and why it fails closed all live in `groups_transfer.rs` beside the OTHER write that
    // can mint an owner row — a cap counted two different ways in two places is two caps.
    if transfer::owned_group_count(&db, &user_id).await? as usize >= MAX_OWNED_GROUPS {
        return json_err(409, "too_many_groups");
    }

    // ONE batch for the whole creation. D1 wraps a batch in an implicit transaction and runs the
    // statements in order, so the `groups` row exists before the membership rows whose FK points
    // at it, and a failure anywhere leaves NOTHING behind. This was previously 1 + 1 + up to
    // MAX_INITIAL_MEMBERS awaited round trips — 202 in the worst case, inside a single request —
    // and a failure partway through could leave a group with no owner row at all: invisible to
    // list_my_groups, and undeletable through delete_group, which needs an owner row to permit
    // the delete.
    let mut stmts = Vec::with_capacity(2 + members.len());
    stmts.push(
        db.prepare(
            "INSERT INTO groups (id, name, created_by, created_at, updated_at,
                                 visibility, auto_join, settings_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&[
            d1_text(&group_id),
            d1_text(&name),
            d1_text(&user_id),
            d1_int(now),
            d1_int(now),
            d1_text(&visibility),
            d1_int(auto_join),
            d1_opt_text(settings_json.as_deref()),
        ])?,
    );
    // The creator is owner and ACTIVE: they count as having joined the group they created.
    stmts.push(
        db.prepare(
            "INSERT INTO group_members (group_id, user_id, role, joined_at, status, added_by)
             VALUES (?, ?, 'owner', ?, 'active', NULL)",
        )
        .bind(&[d1_text(&group_id), d1_text(&user_id), d1_int(now)])?,
    );
    // Initial members other than the creator are inserted as member + PENDING (consent-first,
    // Faz 6 #3): they receive an invite and do NOT count as members until they accept.
    // added_by is the creator.
    //
    // INSERT … SELECT FROM users rather than VALUES, and that is the whole point of the shape: a
    // member_ids entry naming a user who does not exist must be SILENTLY SKIPPED, which is what
    // the old per-row `INSERT OR IGNORE` achieved by letting the FK violation land on that row
    // and nothing else. Inside a batch the same violation would roll back the entire
    // transaction and fail a creation that used to succeed, so the existence filter moves INTO
    // the statement: the SELECT matches no row, the INSERT writes no row, the batch is fine.
    // OR IGNORE still covers what it always covered — a user_id repeated in member_ids.
    for m in members.iter().filter(|m| m.as_str() != user_id.as_str()) {
        stmts.push(
            db.prepare(
                "INSERT OR IGNORE INTO group_members
                    (group_id, user_id, role, joined_at, status, added_by)
                 SELECT ?, id, 'member', ?, 'pending', ? FROM users WHERE id = ?",
            )
            .bind(&[
                d1_text(&group_id),
                d1_int(now),
                d1_text(&user_id),
                d1_text(m),
            ])?,
        );
    }
    db.batch(stmts).await?;

    // The invitees, and only them. The creator is the caller and the group has no other rows yet,
    // so the recipient set is already in hand and a room query would be a wasted subrequest.
    // Without this a person invited at creation learns of the invite at their next boot — the
    // plainest case of the gap `groups_notify.rs` exists to close.
    notify::nudge_users(
        &ctx.env,
        &group_id,
        members
            .into_iter()
            .filter(|m| m.as_str() != user_id.as_str())
            .collect(),
    )
    .await;

    Response::from_json(&serde_json::json!({
        "id": group_id,
        "name": name,
        "role": "owner",
        "created_at": now,
        "visibility": visibility,
        "auto_join": auto_join != 0,
        "settings_json": settings_json,
    }))
}

// ---------------------------------------------------------------------------
// GET /groups — the groups I belong to and the invites I have received, with my own role and the
// member count. The page, its ordering and its truncation signal live in `groups_read.rs`.
// ---------------------------------------------------------------------------
pub async fn list_my_groups(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    Response::from_json(&read::my_groups_page(&db, &user_id).await?)
}

// ---------------------------------------------------------------------------
// GET /groups/:id/members — the group's members; only a member may read this. The projection —
// and the argument for the column it no longer selects — lives in `groups_read.rs`.
// ---------------------------------------------------------------------------
pub async fn group_members(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    if group_role(&db, &group_id, &user_id).await?.is_none() {
        return json_err(403, "not_member");
    }
    Response::from_json(&read::member_list(&db, &group_id).await?)
}

// ---------------------------------------------------------------------------
// POST /groups/:id/add-member — add a member (group owner/admin). Body: {user_id}.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct UserIdBody {
    user_id: String,
}

pub async fn add_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: UserIdBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.user_id.is_empty() {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if is_group_admin(&role) => {}
        Some(_) => return json_err(403, "forbidden"),
        None => return json_err(403, "not_member"),
    }
    // M12 (fan-out amplification — DoS): the membership ceiling. If the target is ALREADY a
    // member or invitee the ceiling is not applied, because an idempotent re-add is an
    // INSERT OR IGNORE no-op and an existing row does not grow the group. Otherwise, once the
    // group's row count (active + pending) has reached MAX_GROUP_MEMBERS, a new addition is
    // rejected with 409. Pending rows count too: they become active on acceptance and widen
    // the fan-out.
    let already_known = membership_status(&db, &group_id, &body.user_id).await?.is_some();
    if !already_known {
        #[derive(Deserialize)]
        struct CountRow {
            c: i64,
        }
        let count: Option<CountRow> = db
            .prepare("SELECT COUNT(*) AS c FROM group_members WHERE group_id = ?")
            .bind(&[d1_text(&group_id)])?
            .first(None)
            .await?;
        if count.map(|r| r.c).unwrap_or(0) as usize >= MAX_GROUP_MEMBERS {
            return json_err(409, "group_full");
        }
    }
    let now = now_secs() as i64;
    // PENDING (consent-first, Faz 6 #3): the person added receives an invite and does NOT
    // count as a member — nor receive messages — until they accept. added_by records who added
    // them, so on acceptance a GroupJoinAccepted goes to that person, who then distributes the
    // key. INSERT OR IGNORE makes this a no-op if they are already a member or invitee.
    db.prepare(
        "INSERT OR IGNORE INTO group_members
            (group_id, user_id, role, joined_at, status, added_by)
         VALUES (?, ?, 'member', ?, 'pending', ?)",
    )
    .bind(&[
        d1_text(&group_id),
        d1_text(&body.user_id),
        d1_int(now),
        d1_text(&requester),
    ])?
    .run()
    .await?;
    // The target FIRST — they are the person the invite is for, and until this existed an invite
    // simply did not arrive at a running app. The rest of the room follows because the member list
    // returns pending rows too, so everyone's member sheet just changed. Skipped when the row
    // already existed: the INSERT was an OR IGNORE no-op, nothing changed for anybody, and an
    // idempotent re-add must not become a way to make the server fan out on demand.
    if !already_known {
        notify::nudge_room(&ctx.env, &db, &group_id, &[&body.user_id]).await;
    }
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/accept — ACCEPT an invite (pending → active; Faz 6 #3). Only one's own
// pending row. Fan-out and key material flow only AFTER acceptance (E2E consent).
// ---------------------------------------------------------------------------
pub async fn accept_invite(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    match membership_status(&db, &group_id, &user_id).await? {
        Some(s) if s == "pending" => {}
        Some(_) => return no_content(), // already active → idempotent
        None => return json_err(404, "no_invite"),
    }
    db.prepare(
        "UPDATE group_members SET status = 'active'
         WHERE group_id = ? AND user_id = ? AND status = 'pending'",
    )
    .bind(&[d1_text(&group_id), d1_text(&user_id)])?
    .run()
    .await?;
    // The whole room: an acceptance moves `member_count` for every member and turns a pending row
    // into an active one in every member sheet. The accepter needs no naming here — the row is
    // theirs and the query runs after the UPDATE, so the snapshot already contains them (which
    // also converges their other devices).
    notify::nudge_room(&ctx.env, &db, &group_id, &[]).await;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/decline — DECLINE an invite by deleting the pending row (Faz 6 #3). Only
// one's own pending invite; leaving an active membership is remove-member instead.
// ---------------------------------------------------------------------------
pub async fn decline_invite(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    // RETURNING rather than a preceding SELECT: the handler has to know whether a row actually
    // went before it spends a fan-out, and a re-declined invite must stay the free no-op it is.
    // Deserialized as raw JSON rather than into a named row type: only the COUNT of returned rows
    // is read, so a struct here would be a dead field the moment clippy looked at it.
    let declined = db
        .prepare(
            "DELETE FROM group_members
             WHERE group_id = ? AND user_id = ? AND status = 'pending'
             RETURNING user_id",
        )
        .bind(&[d1_text(&group_id), d1_text(&user_id)])?
        .all()
        .await?
        .results::<serde_json::Value>()?;
    if !declined.is_empty() {
        // The decliner is named because their row no longer exists to be found; the inviter and
        // the rest of the room come out of the query, and their member sheet lost a row.
        notify::nudge_room(&ctx.env, &db, &group_id, &[&user_id]).await;
    }
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/remove-member — remove a member, or leave the group. Body: {user_id}.
// Authority: leaving yourself is free except for the owner; removing someone else requires
// owner/admin; the owner cannot be removed; and an admin cannot remove another admin (the
// server-authority pattern).
// ---------------------------------------------------------------------------
pub async fn remove_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: UserIdBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    let target = body.user_id;
    if target.is_empty() {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;

    let req_role = match group_role(&db, &group_id, &requester).await? {
        Some(r) => r,
        None => return json_err(403, "not_member"),
    };
    let target_role = match group_role(&db, &group_id, &target).await? {
        Some(r) => r,
        None => return no_content(), // already not a member → idempotent
    };

    if target == requester {
        // Leaving yourself: the owner cannot leave — transfer ownership or delete the group.
        if req_role == "owner" {
            return json_err(403, "owner_cannot_leave");
        }
    } else {
        // Removing someone else.
        if !is_group_admin(&req_role) {
            return json_err(403, "forbidden");
        }
        if target_role == "owner" {
            return json_err(403, "cannot_remove_owner");
        }
        // An admin may only remove members, never another admin; the owner may remove anyone.
        if req_role == "admin" && target_role == "admin" {
            return json_err(403, "forbidden");
        }
    }

    db.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")
        .bind(&[d1_text(&group_id), d1_text(&target)])?
        .run()
        .await?;
    // FORWARD SECRECY (Faz-D): a kick or self-leave bumps the plugin server-log epoch FLOOR,
    // so a removed member can no longer append new data to the OLD epoch — the append gate
    // answers 409 epoch_stale. The server stays BLIND; it only ever handles an integer.
    // Best-effort: even if this fails the removal itself succeeded (no_content).
    let _ = crate::plugin_log::bump_epoch_floor(&db, &group_id).await;
    // The removed member is named — the room query cannot find them any more, and they are the
    // one party whose own group LIST changed, so leaving them out would keep a kicked device
    // showing a room it can no longer read. On a self-leave they are the caller, which converges
    // their other devices. The remaining room follows for the member count and the sheet.
    notify::nudge_room(&ctx.env, &db, &group_id, &[&target]).await;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/set-role — assign an in-group role; group-owner only.
// Body: {user_id, role} with role ∈ {admin, member, owner}.
//
// role='owner' is a TRANSFER of the group, and it is why this route exists in its present shape.
// Since 2026-08-05 any member of the server may create a group, but `remove_member` answers
// `owner_cannot_leave` to an owner's self-leave — so without a transfer path every creator is
// permanently bound to every group they make. The transfer hands the group to another ACTIVE
// member and demotes the caller to 'admin' in the same batch, which puts them back under the
// ordinary leave rule. A solo owner with nobody to hand the group to uses DELETE /groups/:id.
//
// Who may RECEIVE a group — the `admin`-only rule and the owned-groups cap, the argument for each
// and the alternatives rejected — is in `groups_transfer.rs` and is not repeated here.
//
// NO RATE LIMIT ON THIS ROUTE, decided rather than overlooked. `create_group` carries one and its
// own comment explains why that is a brake and not a bound: it fails OPEN when the KV binding is
// absent, so only the COUNT cap bounds anything. Here the counting argument is already complete —
// a successful transfer demotes the caller, so it cannot be repeated against the same group, and
// how many groups can be piled on one person is bounded by their own MAX_OWNED_GROUPS, on top of
// which each one needs that person to have ACCEPTED an invite and then been made an admin. What is
// left over is an owner flipping a member between 'admin' and 'member' to spend the 12-device nudge
// fan-out — equally true of add-member, remove-member and settings, available only to a group's own
// owner against their own room, and strictly less destructive than the DELETE they may already
// issue. Rate-limiting one of four equivalent routes buys nothing and implies the other three were
// examined and found safe.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct SetRoleBody {
    user_id: String,
    role: String,
}

pub async fn set_role(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: SetRoleBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.role != "admin" && body.role != "member" && body.role != "owner" {
        return json_err(400, "bad_role");
    }
    let db = ctx.env.d1("DB")?;
    // Only the group-owner may assign roles — and therefore only the owner may hand the group on.
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if role == "owner" => {}
        Some(_) => return json_err(403, "owner_required"),
        None => return json_err(403, "not_member"),
    }
    // Transferring to yourself changes nothing while looking like a state change; refuse it
    // rather than run a batch that demotes and re-promotes the same row (admin/handlers.rs's
    // `transfer_ownership` refuses the same way, with the same code). Scoped to the transfer:
    // a self-targeted admin/member demotion still falls through to `cannot_change_owner` below,
    // which is the accurate answer to "the owner tried to demote themselves".
    if body.role == "owner" && body.user_id == requester {
        return json_err(400, "already_owner");
    }
    // The target must be an ACTIVE member — `group_role` ignores 'pending', so an invitee who
    // has not accepted cannot be handed the group — and must not already be the owner. For a
    // transfer that second arm reads "you cannot transfer to the sitting owner"; for
    // admin/member it is the old rule that the owner row never changes through the plain UPDATE.
    let target_role = match group_role(&db, &group_id, &body.user_id).await? {
        Some(role) if role == "owner" => return json_err(403, "cannot_change_owner"),
        Some(role) => role,
        None => return json_err(404, "not_member_target"),
    };
    // Authorised as far as the CALLER goes. Everything past this point in a transfer is about the
    // recipient — may they hold another group, and should this one be handed to them at all — and
    // it lives with the write it gates, in `groups_transfer.rs`.
    if body.role == "owner" {
        return transfer::transfer_to(
            &ctx.env,
            &db,
            &group_id,
            &requester,
            &body.user_id,
            &target_role,
        )
        .await;
    }
    db.prepare("UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ? AND role != 'owner'")
        .bind(&[d1_text(&body.role), d1_text(&group_id), d1_text(&body.user_id)])?
        .run()
        .await?;
    // Room-wide rather than target-only, which is the cheaper choice and the wrong one: a role IS
    // the member sheet, so every member is looking at a stale one until they refresh. Role changes
    // are rare enough that the 12-call ceiling is not a hot path.
    notify::nudge_room(&ctx.env, &db, &group_id, &[]).await;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/settings — update the group's SETTINGS (owner/admin; substrate Faz 1).
// Body: {visibility?, auto_join?, settings_json?}. PARTIAL: only the fields supplied change,
// via COALESCE. settings_json is opaque — the server never interprets it. Returns 204.
// ---------------------------------------------------------------------------
#[derive(Deserialize, Default)]
struct UpdateSettingsBody {
    visibility: Option<String>,
    auto_join: Option<bool>,
    settings_json: Option<String>,
}

pub async fn update_settings(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: UpdateSettingsBody = req.json().await.unwrap_or_default();
    if let Some(v) = &body.visibility {
        if !valid_visibility(v) {
            return json_err(400, "bad_visibility");
        }
    }
    // The same ceiling as `create_group`, and it has to be in BOTH: capping only creation would
    // leave the unbounded write reachable one request later, through the endpoint that is easier
    // to reach (any admin, not just the creator, and repeatedly).
    if body.settings_json.as_deref().unwrap_or("").len() > MAX_SETTINGS_JSON_BYTES {
        return json_err(400, "settings_too_large");
    }
    let db = ctx.env.d1("DB")?;
    // Only a group owner/admin may change settings.
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if is_group_admin(&role) => {}
        Some(_) => return json_err(403, "forbidden"),
        None => return json_err(403, "not_member"),
    }
    // Partial update: COALESCE(?, current) leaves any omitted field untouched.
    let now = now_secs() as i64;
    db.prepare(
        "UPDATE groups SET
            visibility    = COALESCE(?, visibility),
            auto_join     = COALESCE(?, auto_join),
            settings_json = COALESCE(?, settings_json),
            updated_at    = ?
         WHERE id = ?",
    )
    .bind(&[
        d1_opt_text(body.visibility.as_deref()),
        match body.auto_join {
            Some(b) => d1_int(if b { 1 } else { 0 }),
            None => d1_null(),
        },
        d1_opt_text(body.settings_json.as_deref()),
        d1_int(now),
        d1_text(&group_id),
    ])?
    .run()
    .await?;
    // BEYOND "membership changed", deliberately. `visibility`, `auto_join` and `settings_json` are
    // all returned in every member's `GET /groups` row, and the P2P toggle inside `settings_json`
    // is not decoration: `core`'s `room_p2p_enabled` reads it to decide how that member's client
    // TRANSPORTS messages. A stale copy is behaviour, not cosmetics, so it gets the same fan-out.
    notify::nudge_room(&ctx.env, &db, &group_id, &[]).await;
    no_content()
}

// ---------------------------------------------------------------------------
// DELETE /groups/:id — delete the group; group-owner only. The teardown itself — blobs to
// `storage_orphans`, the room-scoped plugin metadata, the membership, the group and its epoch
// floor, as ONE ordered batch — is `groups_delete.rs`.
// ---------------------------------------------------------------------------
pub async fn delete_group(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if role == "owner" => {}
        Some(_) => return json_err(403, "owner_required"),
        None => return json_err(403, "not_member"),
    }
    // Read the recipients BEFORE the batch — afterwards there is no `group_members` row left to
    // ask. This is the one handler where the affected party IS the whole room, invitees included:
    // every one of them is holding a group that no longer exists.
    let recipients: Vec<String> = notify::room_recipients(&db, &group_id).await;
    delete::delete_group_rows(&db, &group_id, now_secs() as i64).await?;
    notify::nudge_users(&ctx.env, &group_id, recipients).await;
    no_content()
}

/// Source-level guards over the authorization shape of this file — the revocation-aware gate on
/// every handler, and the absence of a server-owner gate on creation. Split out because
/// `groups.rs` reached the 800-line ceiling; `devices/link.rs` is the worked example of the move.
#[cfg(test)]
#[path = "groups_tests.rs"]
mod tests;
