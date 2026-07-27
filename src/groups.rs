//! Group chat — membership plus in-group authority (Faz 1).
//!
//! Groups are sub-communities WITHIN a server. The in-group role (owner/admin/member) is
//! INDEPENDENT of the server role: whoever creates a group becomes its owner. Creating a
//! group, however, is restricted to the server OWNER (Hasan, 2026-07-03; `create_group`
//! calls require_owner). This is NOT a discovery or matchmaking mechanism
//! ([[directory-pairing-REJECTED]]): to add someone you must ALREADY know their `user_id`,
//! from a 1:1 pairing or an out-of-band channel.
//!
//! E2E: the server never sees group CONTENT. This module manages only the membership table;
//! message crypto is Megolm on the client and message distribution is the Faz 2 fan-out (in
//! `messages`). The authority matrix is the group-scoped copy of the server-authority epic.

use crate::auth::middleware::{require_auth, require_owner};
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
// POST /groups — create a group; the creator becomes its group-owner. AUTHORITY (Hasan
// 2026-07-03): only the SERVER owner may create a group — this used to be open to ANY server
// member, and "anyone can create a group" was removed. The optional member_ids adds the
// initial members, who must be already-known peers.
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
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // AUTHORITY GATE (Hasan 2026-07-03, owner-only): group creation is restricted to the
    // server OWNER. Server-authoritative, so the client cannot bypass it — the UI hides the
    // action too, but THIS is the real gate. `users.role` is 'owner' | 'admin' | 'member',
    // separate from the in-group role. Not even an admin may create a group (Hasan's call).
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
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

    let now = now_secs() as i64;
    let group_id = Uuid::new_v4().to_string();
    let db = ctx.env.d1("DB")?;

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
    ])?
    .run()
    .await?;

    // The creator is owner and ACTIVE: they count as having joined the group they created.
    db.prepare(
        "INSERT INTO group_members (group_id, user_id, role, joined_at, status, added_by)
         VALUES (?, ?, 'owner', ?, 'active', NULL)",
    )
    .bind(&[d1_text(&group_id), d1_text(&user_id), d1_int(now)])?
    .run()
    .await?;

    // Initial members other than the creator are inserted as member + PENDING (consent-first,
    // Faz 6 #3): they receive an invite and do NOT count as members until they accept.
    // added_by is the creator. INSERT OR IGNORE swallows repeats and conflicts.
    for m in members.iter().filter(|m| m.as_str() != user_id.as_str()) {
        let _ = db
            .prepare(
                "INSERT OR IGNORE INTO group_members
                    (group_id, user_id, role, joined_at, status, added_by)
                 VALUES (?, ?, 'member', ?, 'pending', ?)",
            )
            .bind(&[d1_text(&group_id), d1_text(m), d1_int(now), d1_text(&user_id)])?
            .run()
            .await;
    }

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
// GET /groups — the groups I belong to, with my own role and the member count.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct MyGroupRow {
    id: String,
    name: String,
    role: String,
    member_count: i64,
    created_at: i64,
    visibility: String,
    auto_join: i64,
    settings_json: Option<String>,
    status: String,
    added_by: Option<String>,
}

pub async fn list_my_groups(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    // Rows with status='pending' are INVITES I have received; the client separates them out.
    // member_count counts ACTIVE members only, so pending invitees are not counted until they
    // join.
    let rows: Vec<MyGroupRow> = db
        .prepare(
            "SELECT g.id, g.name, gm.role,
                    (SELECT COUNT(*) FROM group_members x
                       WHERE x.group_id = g.id AND x.status = 'active') AS member_count,
                    g.created_at, g.visibility, g.auto_join, g.settings_json,
                    gm.status, gm.added_by
             FROM groups g
             JOIN group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = ?
             ORDER BY g.updated_at DESC LIMIT 200",
        )
        .bind(&[d1_text(&user_id)])?
        .all()
        .await?
        .results()?;
    let groups: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "role": r.role,
                "member_count": r.member_count,
                "created_at": r.created_at,
                "visibility": r.visibility,
                "auto_join": r.auto_join != 0,
                "settings_json": r.settings_json,
                "status": r.status,
                "added_by": r.added_by,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "groups": groups }))
}

// ---------------------------------------------------------------------------
// GET /groups/:id/members — the group's members; only a member may read this.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct MemberRow {
    user_id: String,
    email: Option<String>,
    display_name: Option<String>,
    role: String,
    joined_at: i64,
    status: String,
}

pub async fn group_members(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
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
    let rows: Vec<MemberRow> = db
        .prepare(
            "SELECT gm.user_id, u.email, u.display_name, gm.role, gm.joined_at, gm.status
             FROM group_members gm
             JOIN users u ON u.id = gm.user_id
             WHERE gm.group_id = ?
             ORDER BY gm.joined_at ASC LIMIT 500",
        )
        .bind(&[d1_text(&group_id)])?
        .all()
        .await?
        .results()?;
    let members: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "user_id": r.user_id,
                "email": r.email,
                "display_name": r.display_name,
                "role": r.role,
                "joined_at": r.joined_at,
                "status": r.status,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "members": members }))
}

// ---------------------------------------------------------------------------
// POST /groups/:id/add-member — add a member (group owner/admin). Body: {user_id}.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct UserIdBody {
    user_id: String,
}

pub async fn add_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
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
    if membership_status(&db, &group_id, &body.user_id).await?.is_none() {
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
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/accept — ACCEPT an invite (pending → active; Faz 6 #3). Only one's own
// pending row. Fan-out and key material flow only AFTER acceptance (E2E consent).
// ---------------------------------------------------------------------------
pub async fn accept_invite(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
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
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/decline — DECLINE an invite by deleting the pending row (Faz 6 #3). Only
// one's own pending invite; leaving an active membership is remove-member instead.
// ---------------------------------------------------------------------------
pub async fn decline_invite(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let group_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "DELETE FROM group_members
         WHERE group_id = ? AND user_id = ? AND status = 'pending'",
    )
    .bind(&[d1_text(&group_id), d1_text(&user_id)])?
    .run()
    .await?;
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/remove-member — remove a member, or leave the group. Body: {user_id}.
// Authority: leaving yourself is free except for the owner; removing someone else requires
// owner/admin; the owner cannot be removed; and an admin cannot remove another admin (the
// server-authority pattern).
// ---------------------------------------------------------------------------
pub async fn remove_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
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
    no_content()
}

// ---------------------------------------------------------------------------
// POST /groups/:id/set-role — assign an in-group role; group-owner only.
// Body: {user_id, role} with role ∈ {admin, member}. 'owner' can neither be assigned nor
// changed through this route.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct SetRoleBody {
    user_id: String,
    role: String,
}

pub async fn set_role(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
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
    if body.role != "admin" && body.role != "member" {
        return json_err(400, "bad_role");
    }
    let db = ctx.env.d1("DB")?;
    // Only the group-owner may assign roles.
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if role == "owner" => {}
        Some(_) => return json_err(403, "owner_required"),
        None => return json_err(403, "not_member"),
    }
    // The target must be a member and must NOT be the owner: the owner role never changes here.
    match group_role(&db, &group_id, &body.user_id).await? {
        Some(role) if role == "owner" => return json_err(403, "cannot_change_owner"),
        Some(_) => {}
        None => return json_err(404, "not_member_target"),
    }
    db.prepare("UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ? AND role != 'owner'")
        .bind(&[d1_text(&body.role), d1_text(&group_id), d1_text(&body.user_id)])?
        .run()
        .await?;
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
    let requester = match require_auth(&req, &ctx.env) {
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
    no_content()
}

// ---------------------------------------------------------------------------
// DELETE /groups/:id — delete the group; group-owner only. The FK CASCADE removes members.
// ---------------------------------------------------------------------------
pub async fn delete_group(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let requester = match require_auth(&req, &ctx.env) {
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
    // group_members is cleaned up by ON DELETE CASCADE on its group_id FK; the explicit DELETE
    // is belt-and-braces.
    db.prepare("DELETE FROM group_members WHERE group_id = ?")
        .bind(&[d1_text(&group_id)])?
        .run()
        .await?;
    db.prepare("DELETE FROM groups WHERE id = ?")
        .bind(&[d1_text(&group_id)])?
        .run()
        .await?;
    // FORWARD SECRECY (Faz-D): deleting a group at server level means every member was
    // removed, so bump the epoch FLOOR. Best-effort — the group is gone, so the log is already
    // unreachable through the membership gate, but we keep the floor consistent anyway.
    let _ = crate::plugin_log::bump_epoch_floor(&db, &group_id).await;
    no_content()
}
