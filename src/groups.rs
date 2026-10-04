//! Group chat — membership plus in-group authority.
//!
//! Groups are sub-communities WITHIN a server, and the in-group role (owner/admin/member) is
//! INDEPENDENT of the server role: whoever creates a group becomes its owner, and ANY member of
//! the server may create one. The server `owner` role means server ADMINISTRATION only and
//! carries no authority inside a group, so reading a group's messages requires being IN that
//! group — running the server is not a way in. Creation is bounded by `MAX_OWNED_GROUPS` plus a
//! rate limit, not by a role. That does NOT make this a discovery surface: `add_member` takes a
//! `user_id` the caller must already know, and the addee stays `pending` until they accept.
//!
//! E2E: the server never sees group CONTENT. This module manages only the membership table;
//! message crypto is Megolm on the client and distribution is the fan-out in `messages`.

// Five blocks declared here rather than in `lib.rs`, so the group surface stays one module from
// the outside: the ownership-transfer write, the teardown batch, the live nudges, the two
// read projections, and the join requests a class invite leaves behind.
#[path = "groups_delete.rs"]
mod delete;
#[path = "groups_notify.rs"]
mod notify;
#[path = "groups_read.rs"]
mod read;
#[path = "groups_requests.rs"]
mod requests;
pub(crate) use requests::nudge_landing;
pub use requests::{
    approve_all_join_requests, approve_join_request, deny_join_request, list_join_requests,
    my_join_requests,
};
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
/// Membership ceiling, against fan-out amplification: every group send becomes N (members ×
/// devices) DO writes, so unbounded membership makes one message enormous amplification.
const MAX_GROUP_MEMBERS: usize = 256;
/// Per-user ceiling on groups currently OWNED. With creation open to every member something has
/// to bound it, or one account can fill D1 by itself; each creation writes one `groups` row plus
/// up to `MAX_INITIAL_MEMBERS + 1` membership rows, so 64 caps an account at roughly 13k rows
/// while sitting far above what a person plausibly runs.
///
/// It bounds BOTH writes that can mint an owner row — creation here and the transfer in
/// `groups_transfer.rs`. A cap on creation alone would be a cap on nothing: an account at the
/// ceiling could hand its groups to one person, who then cannot create one of their own.
///
/// Hard-coded for now. The right long-term home is the pattern the storage quotas use — a
/// nullable cap column on `server_settings` where NULL means unlimited, set through
/// `PATCH /admin/server-settings` — which needs a migration and an admin handler.
const MAX_OWNED_GROUPS: usize = 64;
/// Ceiling on the opaque `settings_json` bag, in BYTES of UTF-8. The column is TEXT the server
/// never interprets, writable by any group admin and read back by every member on every
/// `GET /groups`, so unbounded it is both a D1 filler and a response amplifier — one admin's
/// paste inflating a list call for the whole room forever.
///
/// 2 KiB is ~150× what the field actually carries today (`core`'s `room_p2p_enabled` parses
/// thirteen bytes of `{"p2p":true}`, with theme and plugin configuration the intended company),
/// so it is room for a real settings bag while `MAX_GROUPS_PAGE` × 2 KiB keeps one list response
/// in the hundreds of kilobytes. A group needing more than this wants a table, not a bag.
const MAX_SETTINGS_JSON_BYTES: usize = 2048;

/// The gate EVERY handler in this file goes through: a valid token, an account that still
/// exists, and a calling device that has not been revoked. Returns the caller's `user_id`.
///
/// The revocation half is load-bearing. Revoking a device deletes its refresh token but cannot
/// expire its ACCESS token, so on a bare JWT gate a just-removed device keeps full in-group
/// authority — `DELETE /groups/:id`, `remove-member`, `set-role` — for ~15 minutes.
///
/// NOT `require_active_auth`, which the admin surface uses: that fails CLOSED on a device with no
/// `devices` row, and registration does not create one (the first rows appear when the client
/// publishes its device list), so a fresh account would be locked out of its own group list.
/// Revocation needs no such row-existence rule — removing a device SETS `revoked_at` rather than
/// deleting the row — so this closes the hole without a bootstrap deadlock. Same pairing as
/// `plugin_blob::gate`.
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
/// member. Only `status='active'` counts: a 'pending' invitee is NOT a member and can neither
/// receive messages, administer the group, nor see the member list. `pub(crate)` because the
/// fan-out and every group authority gate goes through this.
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

/// Is this a valid `visibility` value? Unknown values are rejected, so introducing a new one
/// means extending this function.
fn valid_visibility(v: &str) -> bool {
    v == "private" || v == "public"
}

// ---------------------------------------------------------------------------
// POST /groups (auth required), body {name, member_ids?, visibility?, auto_join?,
// settings_json?} → the created group. The creator becomes its group-owner, and the optional
// member_ids adds initial members, who must be already-known peers.
//
// ⚠ ANY member of the server may create a group, and the owner-only gate that used to stand here
// is not coming back: `owner` is a SERVER-administration role that must grant nothing inside a
// group, and combined with `owner_cannot_leave` an owner-only creation route made whoever runs
// the box a permanent member of every group on it. What limits creation is `MAX_OWNED_GROUPS`
// plus a rate limit — a bound, not a privilege.
// ---------------------------------------------------------------------------
#[derive(Deserialize, Default)]
struct CreateGroupBody {
    name: String,
    member_ids: Option<Vec<String>>,
    // Settings bag — all optional; omitted fields take the schema default.
    visibility: Option<String>,
    auto_join: Option<bool>,
    settings_json: Option<String>,
}

pub async fn create_group(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // ⚠ TWO DIFFERENT `role` COLUMNS SPELLED WITH THE SAME THREE WORDS: `users.role` is the
    // SERVER role and `group_members.role` the IN-GROUP one, with identical value strings. They
    // are unrelated, nothing lines them up, and every `role` in this file is the in-group one.
    // Mistaking them would silently hand every group on the server to whoever administers it.
    let body: CreateGroupBody = req.json().await.unwrap_or_default();
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return json_err(400, "bad_name");
    }
    let members = body.member_ids.unwrap_or_default();
    if members.len() > MAX_INITIAL_MEMBERS {
        return json_err(400, "too_many_members");
    }
    let visibility = body.visibility.unwrap_or_else(|| "private".to_string());
    if !valid_visibility(&visibility) {
        return json_err(400, "bad_visibility");
    }
    let auto_join = if body.auto_join.unwrap_or(false) { 1 } else { 0 };
    let settings_json = body.settings_json; // opaque; the server never interprets it
    if settings_json.as_deref().unwrap_or("").len() > MAX_SETTINGS_JSON_BYTES {
        return json_err(400, "settings_too_large");
    }

    // Validation runs first and writes nothing, so a malformed request does not spend the
    // caller's creation budget.
    //
    // A BRAKE, NOT A BOUND: `check_rate_limit_env` FAILS OPEN when the KV binding is missing, so
    // it shapes bursts where the namespace exists and does nothing where it does not. The COUNT
    // cap below, which needs no KV, is what actually bounds creation — never lean on this line
    // for correctness. Ten per hour sits far above the human cadence of "make a group" while
    // stopping a script from walking straight to MAX_OWNED_GROUPS in one burst.
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

    // THE BOUND. The counting query, what it counts and why it fails closed live in
    // `groups_transfer.rs` beside the other write that can mint an owner row — a cap counted two
    // different ways in two places is two caps.
    if transfer::owned_group_count(&db, &user_id).await? as usize >= MAX_OWNED_GROUPS {
        return json_err(409, "too_many_groups");
    }

    // ONE batch for the whole creation. D1 wraps a batch in an implicit transaction and runs the
    // statements in order, so the `groups` row exists before the membership rows whose FK points
    // at it, and a failure anywhere leaves NOTHING behind. As separate awaited round trips (up to
    // 202 of them) a failure partway through could leave a group with no owner row: invisible to
    // list_my_groups and undeletable, since delete_group needs an owner row to permit the delete.
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
    // Initial members other than the creator go in as member + PENDING (consent-first): they
    // receive an invite and do not count as members until they accept. added_by is the creator.
    //
    // INSERT … SELECT FROM users rather than VALUES, and that is the point of the shape: a
    // member_ids entry naming a user who does not exist must be SILENTLY SKIPPED, and inside a
    // batch the FK violation that used to do that would roll back the whole transaction. With the
    // existence filter in the statement, the SELECT matches nothing and the batch is fine.
    // OR IGNORE still covers a user_id repeated in member_ids.
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

    // The invitees, and only them: the creator is the caller and the group has no other rows yet,
    // so the recipient set is in hand and a room query would be a wasted subrequest. Without this
    // a person invited at creation learns of it at their next boot.
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

// GET /groups (auth required) → the groups I belong to and the invites I have received, with my
// own role and the member count. The page, its ordering and its truncation signal live in
// `groups_read.rs`.
pub async fn list_my_groups(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    Response::from_json(&read::my_groups_page(&db, &user_id).await?)
}

// GET /groups/:id/members (auth required) → the group's members; only a member may read it. The
// projection — and the argument for the column it does not select — lives in `groups_read.rs`.
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

// POST /groups/:id/add-member (group owner/admin), body {user_id} → 204.
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
    // The membership ceiling, counting active + pending rows: a pending row becomes active on
    // acceptance and widens the fan-out. Skipped when the target is already a member or invitee,
    // since that re-add is an INSERT OR IGNORE no-op and does not grow the group.
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
    // PENDING (consent-first): the person receives an invite and does not count as a member — nor
    // receive messages — until they accept. added_by records who added them, so on acceptance a
    // GroupJoinAccepted reaches that person, who distributes the key. OR IGNORE makes a re-add a
    // no-op. ⚠ The block list is deliberately NOT consulted here (blocking is not a moderation
    // system; the remedy for a problem member is removal).
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
    // The target FIRST — they are who the invite is for — then the rest of the room, whose member
    // sheets just changed (the list returns pending rows too). Skipped when the row already
    // existed: nothing changed for anybody, and an idempotent re-add must not become a way to
    // make the server fan out on demand.
    if !already_known {
        notify::nudge_room(&ctx.env, &db, &group_id, &[&body.user_id]).await;
    }
    no_content()
}

// POST /groups/:id/accept (auth required) → 204. Accept an invite (pending → active), only one's
// own row. Fan-out and key material flow only AFTER acceptance — this is the E2E consent point.
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
    // The whole room: an acceptance moves `member_count` and turns a pending row into an active
    // one in every member sheet. The accepter needs no naming — the query runs after the UPDATE,
    // so the snapshot already contains them, which also converges their other devices.
    notify::nudge_room(&ctx.env, &db, &group_id, &[]).await;
    no_content()
}

// POST /groups/:id/decline (auth required) → 204. Deletes one's own PENDING row; leaving an
// active membership is remove-member instead.
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
    // RETURNING rather than a preceding SELECT: the handler must know whether a row actually went
    // before it spends a fan-out, and a re-declined invite stays a free no-op. Raw JSON rather
    // than a named row type because only the COUNT of rows is read, and a struct would be a dead
    // field the moment clippy looked at it.
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

// POST /groups/:id/remove-member (auth required), body {user_id} → 204. Remove a member, or leave
// the group. Authority: leaving yourself is free except for the owner; removing someone else
// requires owner/admin; the owner cannot be removed; an admin cannot remove another admin.
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
    // FORWARD SECRECY: a kick or self-leave bumps the plugin server-log epoch FLOOR, so a removed
    // member can no longer append to the OLD epoch — the append gate answers 409 epoch_stale. The
    // server stays blind; it only ever handles an integer. Best-effort, since the removal itself
    // already succeeded.
    let _ = crate::plugin_log::bump_epoch_floor(&db, &group_id).await;
    // The removed member is NAMED: the room query can no longer find them, and they are the one
    // party whose own group LIST changed, so leaving them out would keep a kicked device showing
    // a room it can no longer read. On a self-leave they are the caller, which converges their
    // other devices.
    notify::nudge_room(&ctx.env, &db, &group_id, &[&target]).await;
    no_content()
}

// POST /groups/:id/set-role (group owner only), body {user_id, role} with role ∈ {admin, member,
// owner} → 204.
//
// role='owner' is a TRANSFER of the group, and it is why this route exists in its present shape:
// `remove_member` answers `owner_cannot_leave` to an owner's self-leave, so without a transfer
// path every creator is permanently bound to every group they make. The transfer hands the group
// to another ACTIVE member and demotes the caller to 'admin' in the same batch, which puts them
// back under the ordinary leave rule. A solo owner with nobody to hand it to uses DELETE.
//
// Who may RECEIVE a group — the `admin`-only rule and the owned-groups cap — is in
// `groups_transfer.rs` and is not repeated here.
//
// NO RATE LIMIT, decided rather than overlooked. The counting argument is already complete: a
// successful transfer demotes the caller, so it cannot be repeated against the same group, and
// how many groups can be piled on one person is bounded by their own MAX_OWNED_GROUPS, each
// needing them to have accepted an invite and been made an admin. What is left is an owner
// flipping a member between 'admin' and 'member' to spend the nudge fan-out — equally true of
// add-member, remove-member and settings, available only against their own room, and strictly
// less destructive than the DELETE they may already issue.
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
    // rather than run a batch that demotes and re-promotes the same row (the same code
    // `admin/handlers.rs::transfer_ownership` uses). Scoped to the transfer: a self-targeted
    // admin/member demotion falls through to `cannot_change_owner` below, which is the accurate
    // answer to "the owner tried to demote themselves".
    if body.role == "owner" && body.user_id == requester {
        return json_err(400, "already_owner");
    }
    // The target must be an ACTIVE member — `group_role` ignores 'pending', so an invitee who has
    // not accepted cannot be handed the group — and must not already be the owner. For
    // admin/member that second arm is the rule that the owner row never changes via plain UPDATE.
    let target_role = match group_role(&db, &group_id, &body.user_id).await? {
        Some(role) if role == "owner" => return json_err(403, "cannot_change_owner"),
        Some(role) => role,
        None => return json_err(404, "not_member_target"),
    };
    // Authorised as far as the CALLER goes. Everything past this point in a transfer concerns the
    // recipient and lives with the write it gates, in `groups_transfer.rs`.
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
    // Room-wide rather than target-only, which is cheaper and wrong: a role IS the member sheet,
    // so every member holds a stale one until they refresh. Role changes are rare enough that the
    // fan-out ceiling is not a hot path.
    notify::nudge_room(&ctx.env, &db, &group_id, &[]).await;
    no_content()
}

// POST /groups/:id/settings (group owner/admin), body {visibility?, auto_join?, settings_json?}
// → 204. PARTIAL: only the fields supplied change, via COALESCE. settings_json is opaque — the
// server never interprets it.
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
    // The same ceiling as `create_group`, and it has to be in BOTH: capping only creation leaves
    // the unbounded write reachable one request later, through the easier endpoint (any admin,
    // repeatedly).
    if body.settings_json.as_deref().unwrap_or("").len() > MAX_SETTINGS_JSON_BYTES {
        return json_err(400, "settings_too_large");
    }
    let db = ctx.env.d1("DB")?;
    match group_role(&db, &group_id, &requester).await? {
        Some(role) if is_group_admin(&role) => {}
        Some(_) => return json_err(403, "forbidden"),
        None => return json_err(403, "not_member"),
    }
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
    // A settings change gets the same fan-out as a membership change, deliberately: all three
    // fields are returned in every member's `GET /groups` row, and the P2P toggle inside
    // `settings_json` is not decoration — `core`'s `room_p2p_enabled` reads it to decide how that
    // member's client TRANSPORTS messages, so a stale copy is behaviour, not cosmetics.
    notify::nudge_room(&ctx.env, &db, &group_id, &[]).await;
    no_content()
}

// DELETE /groups/:id (group owner only) → 204. The teardown itself — blobs to `storage_orphans`,
// the room-scoped plugin metadata, the membership, the group and its epoch floor, as ONE ordered
// batch — is `groups_delete.rs`.
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
    // Read the recipients BEFORE the batch — afterwards no `group_members` row is left to ask.
    // The affected party here is the whole room, invitees included: every one of them holds a
    // group that no longer exists.
    let recipients: Vec<String> = notify::room_recipients(&db, &group_id).await;
    delete::delete_group_rows(&db, &group_id, now_secs() as i64).await?;
    notify::nudge_users(&ctx.env, &group_id, recipients).await;
    no_content()
}

/// Source-level guards over the authorization shape of this file — the revocation-aware gate on
/// every handler, and the absence of a server-owner gate on creation.
#[cfg(test)]
#[path = "groups_tests.rs"]
mod tests;
