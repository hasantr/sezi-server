use crate::auth::middleware::{fetch_role, require_active_auth, require_admin, require_owner};
use crate::d1util::{d1_int, d1_opt_int, d1_text};
use crate::respond::json_err;
use crate::utils::{now_secs, random_b64u};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct UpdateSettingsBody {
    name: Option<String>,
    join_mode: Option<String>,
    directory_mode: Option<String>,
    dm_policy: Option<String>,
    retention_days: Option<i64>,
    /// Message retention in days — how long an undelivered message may sit in the
    /// DO `pending` queue. None → keep the current value.
    message_retention_days: Option<i64>,
    /// Server-wide storage cap in bytes. Convention: 0 CLEARS the cap (NULL =
    /// unlimited), > 0 sets it, None keeps the current value.
    max_storage_bytes: Option<i64>,
    /// Per-user storage cap in bytes — same 0-clears convention.
    max_user_storage_bytes: Option<i64>,
    /// "Delete for everyone" window in hours: how long after a message was SENT it
    /// may still be deleted for everyone (owner-configurable, DEFAULT 48). The
    /// receiving side is what will ENFORCE it; the server only carries the value.
    /// None → keep the current value (twin of the retention pattern).
    delete_window_hours: Option<i64>,
    /// Group-library retention in days, frozen into each object at upload. 0 CLEARS it (NULL =
    /// keep until deleted, the default), 1..=3650 sets it, None keeps the current value — the
    /// caps' 0-clears convention, because "keep" is a real setting here and not an error.
    library_retention_days: Option<i64>,
    /// Per-group library cap in bytes — same 0-clears convention as the storage caps.
    max_room_library_bytes: Option<i64>,
}

/// The `server_settings` upsert behind `PATCH /admin/server-settings`, lifted out of the handler
/// so the column list can be checked against the real migrations (`room_library_tests.rs`).
/// Binds, in order: name, join_mode, directory_mode, dm_policy, retention_days,
/// message_retention_days, max_storage_bytes, max_user_storage_bytes, delete_window_hours,
/// library_retention_days, max_room_library_bytes, updated_at.
pub(crate) const UPSERT_SERVER_SETTINGS_SQL: &str = "INSERT INTO server_settings \
        (id, name, join_mode, directory_mode, dm_policy, retention_days, message_retention_days, \
         max_storage_bytes, max_user_storage_bytes, delete_window_hours, \
         library_retention_days, max_room_library_bytes, updated_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        join_mode = excluded.join_mode,
        directory_mode = excluded.directory_mode,
        dm_policy = excluded.dm_policy,
        retention_days = excluded.retention_days,
        message_retention_days = excluded.message_retention_days,
        max_storage_bytes = excluded.max_storage_bytes,
        max_user_storage_bytes = excluded.max_user_storage_bytes,
        delete_window_hours = excluded.delete_window_hours,
        library_retention_days = excluded.library_retention_days,
        max_room_library_bytes = excluded.max_room_library_bytes,
        updated_at = excluded.updated_at";

/// `PATCH /admin/settings` — OWNER-only, not admin. Every field here is server-wide POLICY
/// rather than day-to-day moderation: `directory_mode`/`dm_policy` decide who is discoverable
/// and contactable (`join_mode` is still accepted, but only as `invite_only`), the retention pair
/// decides how long undelivered content lives on the server, the library pair decides how long a
/// group's library is kept and how large it may grow, and `delete_window_hours` bounds
/// the "delete for everyone" promise made to every user. Changing what the server IS sits with
/// `set_role` and `transfer_ownership`; admins keep invites, the member list and removals,
/// which are separate handlers. `admin/storage.rs` draws the same line — owner mutates, admin
/// reads.
pub async fn update_settings(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: UpdateSettingsBody = req.json().await.unwrap_or_default();
    if body.name.is_none()
        && body.join_mode.is_none()
        && body.directory_mode.is_none()
        && body.dm_policy.is_none()
        && body.retention_days.is_none()
        && body.message_retention_days.is_none()
        && body.max_storage_bytes.is_none()
        && body.max_user_storage_bytes.is_none()
        && body.delete_window_hours.is_none()
        && body.library_retention_days.is_none()
        && body.max_room_library_bytes.is_none()
    {
        return json_err(400, "bad_request");
    }
    if let Some(n) = &body.name {
        if n.is_empty() || n.len() > 64 {
            return json_err(400, "bad_request");
        }
    }
    // `open` is refused by name (`server::join_mode`); `invite_only` is accepted and changes
    // nothing, since it is the only mode there is.
    if let Some(m) = &body.join_mode {
        if let Err(code) = crate::server::join_mode::check_requested(m) {
            return json_err(400, code);
        }
    }
    if let Some(m) = &body.directory_mode {
        if !matches!(m.as_str(), "off" | "opt_in" | "all_members") {
            return json_err(400, "bad_request");
        }
    }
    if let Some(m) = &body.dm_policy {
        if !matches!(m.as_str(), "members" | "requests" | "contacts_only") {
            return json_err(400, "bad_request");
        }
    }
    if let Some(d) = body.retention_days {
        if !(1..=3650).contains(&d) {
            return json_err(400, "bad_request");
        }
    }
    if let Some(d) = body.message_retention_days {
        if !(1..=365).contains(&d) {
            return json_err(400, "bad_request");
        }
    }
    // "Delete for everyone" window in hours: minimum 1 to avoid the same "what does
    // 0 mean" ambiguity retention has, maximum 8760 = 365 days (the hour-scale twin
    // of message_retention's 365-day bound).
    if let Some(h) = body.delete_window_hours {
        if !(1..=8760).contains(&h) {
            return json_err(400, "bad_request");
        }
    }
    // Quota cap validation: negative is meaningless (0 = clear, > 0 = set).
    if body.max_storage_bytes.is_some_and(|v| v < 0)
        || body.max_user_storage_bytes.is_some_and(|v| v < 0)
    {
        return json_err(400, "bad_request");
    }
    // The two library settings share one rule (`room_library::library_setting`); validated here,
    // before any read, and applied against the current row below.
    use crate::room_library::{library_setting, LIBRARY_CAP_RANGE, LIBRARY_RETENTION_RANGE};
    if library_setting(body.library_retention_days, None, LIBRARY_RETENTION_RANGE).is_err()
        || library_setting(body.max_room_library_bytes, None, LIBRARY_CAP_RANGE).is_err()
    {
        return json_err(400, "bad_request");
    }

    let now = now_secs();
    let db = ctx.env.d1("DB")?;
    // Read the current row (defaults if absent) so that omitted fields keep their
    // existing values.
    #[derive(Deserialize)]
    struct CurRow {
        name: String,
        directory_mode: String,
        dm_policy: String,
        retention_days: i64,
        message_retention_days: i64,
        // Quota caps — NULLABLE columns (NULL = unlimited).
        max_storage_bytes: Option<i64>,
        max_user_storage_bytes: Option<i64>,
        delete_window_hours: i64,
        // NULLABLE too: NULL = keep until deleted / unlimited.
        library_retention_days: Option<i64>,
        max_room_library_bytes: Option<i64>,
    }
    let cur: Option<CurRow> = db
        .prepare(
            "SELECT name, directory_mode, dm_policy, retention_days, message_retention_days, \
             max_storage_bytes, max_user_storage_bytes, delete_window_hours, \
             library_retention_days, max_room_library_bytes \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first(None)
        .await?;
    let cur_name = cur
        .as_ref()
        .map(|c| c.name.clone())
        .unwrap_or_else(|| "Sezi".into());
    let cur_directory_mode = cur
        .as_ref()
        .map(|c| c.directory_mode.clone())
        .unwrap_or_else(|| "off".into());
    let cur_dm_policy = cur
        .as_ref()
        .map(|c| c.dm_policy.clone())
        .unwrap_or_else(|| "members".into());
    let cur_retention = cur.as_ref().map(|c| c.retention_days).unwrap_or(30);
    let cur_msg_retention = cur.as_ref().map(|c| c.message_retention_days).unwrap_or(30);
    let cur_max_storage = cur.as_ref().and_then(|c| c.max_storage_bytes);
    let cur_max_user_storage = cur.as_ref().and_then(|c| c.max_user_storage_bytes);
    let cur_delete_window = cur.as_ref().map(|c| c.delete_window_hours).unwrap_or(48);
    let new_name = body.name.unwrap_or(cur_name);
    // Always the one mode, never the stored value: a server that stored `open` before it was
    // refused is rewritten to `invite_only` by its owner's next save of anything.
    let new_mode = crate::server::join_mode::JOIN_MODE;
    let new_directory_mode = body
        .directory_mode
        .unwrap_or_else(|| cur_directory_mode.clone());
    let new_dm_policy = body.dm_policy.unwrap_or(cur_dm_policy);
    let directory_policy_changed = new_directory_mode != cur_directory_mode;
    let new_retention = body.retention_days.unwrap_or(cur_retention);
    let new_msg_retention = body.message_retention_days.unwrap_or(cur_msg_retention);
    // Effective quota cap: 0 → NULL (cleared = unlimited), > 0 → set, absent field
    // → keep the current value.
    let new_max_storage = body
        .max_storage_bytes
        .map(|v| if v == 0 { None } else { Some(v) })
        .unwrap_or(cur_max_storage);
    let new_max_user_storage = body
        .max_user_storage_bytes
        .map(|v| if v == 0 { None } else { Some(v) })
        .unwrap_or(cur_max_user_storage);
    let new_delete_window = body.delete_window_hours.unwrap_or(cur_delete_window);
    // Validated above, so the Err arm is unreachable; falling back to the current value keeps
    // even that impossible case from writing something the owner did not ask for.
    let cur_library_retention = cur.as_ref().and_then(|c| c.library_retention_days);
    let cur_room_library_cap = cur.as_ref().and_then(|c| c.max_room_library_bytes);
    let new_library_retention = library_setting(
        body.library_retention_days,
        cur_library_retention,
        LIBRARY_RETENTION_RANGE,
    )
    .unwrap_or(cur_library_retention);
    let new_room_library_cap = library_setting(
        body.max_room_library_bytes,
        cur_room_library_cap,
        LIBRARY_CAP_RANGE,
    )
    .unwrap_or(cur_room_library_cap);

    let settings_stmt = db.prepare(UPSERT_SERVER_SETTINGS_SQL).bind(&[
        d1_text(&new_name),
        d1_text(new_mode),
        d1_text(&new_directory_mode),
        d1_text(&new_dm_policy),
        d1_int(new_retention),
        d1_int(new_msg_retention),
        d1_opt_int(new_max_storage),
        d1_opt_int(new_max_user_storage),
        d1_int(new_delete_window),
        d1_opt_int(new_library_retention),
        d1_opt_int(new_room_library_cap),
        d1_int(now as i64),
    ])?;
    let mut stmts = vec![settings_stmt];
    if directory_policy_changed {
        stmts.push(
            db.prepare(
                "INSERT INTO directory_revisions
                   (event_id, user_id, change_type, profile_revision, created_at)
                 VALUES (?, NULL, 'reset', NULL, ?)",
            )
            .bind(&[d1_text(&random_b64u(18)), d1_int(now as i64)])?,
        );
    }
    db.batch(stmts).await?;

    Response::from_json(&serde_json::json!({
        "name": new_name,
        "join_mode": new_mode,
        "directory_mode": new_directory_mode,
        "dm_policy": new_dm_policy,
        "retention_days": new_retention,
        "message_retention_days": new_msg_retention,
        "max_storage_bytes": new_max_storage,
        "max_user_storage_bytes": new_max_user_storage,
        "delete_window_hours": new_delete_window,
        "library_retention_days": new_library_retention,
        "max_room_library_bytes": new_room_library_cap,
    }))
}

#[derive(Deserialize)]
struct UserRow {
    id: String,
    email: String,
    display_name: Option<String>,
    role: String,
    created_at: i64,
    last_seen_at: Option<i64>,
}

/// One page of members, oldest first, ties by id. Binds: `?1` cursor created_at (NULL on the first
/// page), `?2` cursor id, `?3` limit.
pub(crate) const USERS_PAGE_SQL: &str = "SELECT id, email, display_name, role, created_at, last_seen_at
       FROM users
      WHERE ?1 IS NULL OR created_at > ?1 OR (created_at = ?1 AND id > ?2)
      ORDER BY created_at ASC, id ASC
      LIMIT ?3";

/// The keyset position after a page of members.
#[derive(serde::Serialize, Deserialize)]
struct UsersCursor {
    c: i64,
    i: String,
}

/// List the server's members (admin), a page at a time: `?limit=` (default 200 — what the list
/// returned in one go before, so a client that never pages sees what it always saw — max 500) and
/// `?cursor=` from the previous page's `next`. `total` is the whole count, for the "Members 1,840"
/// line. The owner works from this list when assigning roles.
///
/// `200 {"members": [{id, email, display_name, role, created_at, last_seen_at}], "next", "total"}`;
/// a cursor this server did not issue is `400 bad_cursor`.
pub async fn list_users(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let cursor: Option<UsersCursor> = match crate::page_cursor::from_request(&req) {
        Ok(c) => c,
        Err(()) => return json_err(400, "bad_cursor"),
    };
    let limit =
        crate::page_cursor::limit(crate::page_cursor::query(&req, "limit").as_deref(), 200, 500);
    let (after_c, after_i) = match &cursor {
        Some(k) => (d1_int(k.c), d1_text(&k.i)),
        None => (crate::d1util::d1_null(), d1_text("")),
    };
    let db = ctx.env.d1("DB")?;
    let mut rows: Vec<UserRow> = db
        .prepare(USERS_PAGE_SQL)
        .bind(&[after_c, after_i, d1_int(limit + 1)])?
        .all()
        .await?
        .results()?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().map(|r| {
            crate::page_cursor::encode(&UsersCursor {
                c: r.created_at,
                i: r.id.clone(),
            })
        })
    } else {
        None
    };
    #[derive(Deserialize)]
    struct CountRow {
        n: i64,
    }
    let total = db
        .prepare("SELECT COUNT(*) AS n FROM users")
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);
    let members: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "email": r.email,
                "display_name": r.display_name,
                "role": r.role,
                "created_at": r.created_at,
                "last_seen_at": r.last_seen_at,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "members": members, "next": next, "total": total }))
}

#[derive(Deserialize, Default)]
struct SetRoleBody {
    user_id: String,
    role: String,
}

#[derive(Deserialize)]
struct RoleOnly {
    role: String,
}

/// Set a member's role (owner only). role ∈ {admin, member}. An owner can NEVER
/// be changed: an owner target yields 403, which also means the owner cannot
/// demote themselves.
pub async fn set_role(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller_auth = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth,
        Err(resp) => return Ok(resp),
    };
    let caller = caller_auth.user_id.clone();
    if let Err(resp) = require_owner(&caller, &ctx.env).await {
        return Ok(resp);
    }
    let body: SetRoleBody = req.json().await.unwrap_or_default();
    if body.user_id.is_empty() || (body.role != "admin" && body.role != "member") {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    let target: Option<RoleOnly> = db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&body.user_id)])?
        .first(None)
        .await?;
    match target {
        None => return json_err(404, "user_not_found"),
        Some(r) if r.role == "owner" => return json_err(403, "owner_immutable"),
        _ => {}
    }
    let now = now_secs() as i64;
    db.batch(vec![
        db.prepare(
            "UPDATE users SET role = ?, profile_revision = profile_revision + 1
              WHERE id = ? AND role != 'owner' AND role != ?",
        )
        .bind(&[
            d1_text(&body.role),
            d1_text(&body.user_id),
            d1_text(&body.role),
        ])?,
        db.prepare(
            "INSERT INTO directory_revisions
               (event_id, user_id, change_type, profile_revision, created_at)
             SELECT ?, id, 'upsert', profile_revision, ? FROM users WHERE id = ?",
        )
        .bind(&[
            d1_text(&random_b64u(18)),
            d1_int(now),
            d1_text(&body.user_id),
        ])?,
    ])
    .await?;
    Response::from_json(&serde_json::json!({
        "user_id": body.user_id,
        "role": body.role,
    }))
}

#[derive(Deserialize, Default)]
struct RemoveMemberBody {
    user_id: String,
}

/// Remove (kick) a member from the server: deletes the account and its dependent
/// data.
///
/// **Authority:** an owner may remove anyone except an owner; an admin may remove
/// only a `member` (removing another admin or the owner → 403). Nobody may remove
/// themselves through this endpoint — leaving is a separate flow, so self-removal
/// returns `cannot_remove_self`.
///
/// The shared membership primitive commits every D1 authorization/device/group/
/// contact projection plus the UserInbox purge outbox in a single batch. After the
/// commit any open WS is closed immediately; if the DO fails transiently, cron
/// replays the durable outbox.
pub async fn remove_member(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller_auth = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth,
        Err(resp) => return Ok(resp),
    };
    let caller = caller_auth.user_id.clone();
    if let Err(resp) = require_admin(&caller, &ctx.env).await {
        return Ok(resp);
    }
    let body: RemoveMemberBody = req.json().await.unwrap_or_default();
    if body.user_id.is_empty() {
        return json_err(400, "bad_request");
    }
    if body.user_id == caller {
        return json_err(403, "cannot_remove_self");
    }

    let db = ctx.env.d1("DB")?;
    let target: Option<RoleOnly> = db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&body.user_id)])?
        .first(None)
        .await?;
    let target_role = match target {
        None => {
            return Response::from_json(&serde_json::json!({
                "ok": true,
                "removed": body.user_id,
                "already_removed": true
            }))
        }
        Some(r) if r.role == "owner" => return json_err(403, "owner_immutable"),
        Some(r) => r.role,
    };
    // An admin cannot remove another admin — only the owner can.
    let caller_role = match fetch_role(&caller, &ctx.env).await {
        Ok(Some(r)) => r,
        _ => return json_err(403, "forbidden"),
    };
    if caller_role == "admin" && target_role == "admin" {
        return json_err(403, "forbidden");
    }
    let outcome = match crate::membership::delete_membership(
        &ctx.env,
        &body.user_id,
        crate::membership::RemovalReason::Removed,
        crate::membership::RemovalAuthority::Administrator {
            caller_id: &caller,
            caller_device_id: &caller_auth.device_id,
        },
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(crate::membership::DeleteError::NotFound) => {
            return Response::from_json(&serde_json::json!({
                "ok": true,
                "removed": body.user_id,
                "already_removed": true
            }))
        }
        Err(crate::membership::DeleteError::OwnerTransferRequired) => {
            return json_err(409, "owner_transfer_required")
        }
        Err(crate::membership::DeleteError::AuthorizationChanged) => {
            return json_err(409, "membership_roles_changed")
        }
        Err(crate::membership::DeleteError::Worker(error)) => return Err(error),
    };
    crate::membership::finish_removal(&ctx.env, &body.user_id, &outcome).await;
    Response::from_json(&serde_json::json!({
        "ok": true,
        "removed": body.user_id,
        "already_removed": false
    }))
}

#[derive(Deserialize, Default)]
struct TransferBody {
    user_id: String,
}

/// Transfer ownership to another member (owner only). The target becomes `owner`
/// and the former owner (the caller) is demoted to `admin`, keeping their access
/// rather than being locked out. The single-owner rule is preserved with two
/// ORDERED statements in one D1 batch: demote the caller to admin FIRST, then
/// promote the new owner. The intermediate state may briefly have 0 owners but
/// NEVER 2, so the `idx_one_owner` partial UNIQUE index is never violated.
/// Transferring to yourself is rejected.
pub async fn transfer_ownership(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&caller, &ctx.env).await {
        return Ok(resp);
    }
    let body: TransferBody = req.json().await.unwrap_or_default();
    if body.user_id.is_empty() {
        return json_err(400, "bad_request");
    }
    if body.user_id == caller {
        return json_err(400, "already_owner");
    }
    let db = ctx.env.d1("DB")?;
    let target: Option<RoleOnly> = db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&body.user_id)])?
        .first(None)
        .await?;
    if target.is_none() {
        return json_err(404, "user_not_found");
    }
    // Atomic swap: old owner (the caller) -> admin FIRST, then the target -> owner. Two
    // ORDERED statements in a D1 batch, NOT one CASE UPDATE: SQLite scans `IN(...)` in row
    // order, so a single statement can promote the new owner while the caller is STILL
    // owner → 2 owners → the `idx_one_owner` partial UNIQUE index fires and the request
    // 500s, non-deterministically, depending on how the UUIDs sort. The batch order is
    // guaranteed, so the owner count goes 1 → 0 → 1 and is never 2.
    db.batch(vec![
        db.prepare(
            "UPDATE users SET role = 'admin', profile_revision = profile_revision + 1 WHERE id = ?",
        )
        .bind(&[d1_text(&caller)])?,
        db.prepare(
            "UPDATE users SET role = 'owner', profile_revision = profile_revision + 1 WHERE id = ?",
        )
        .bind(&[d1_text(&body.user_id)])?,
        db.prepare(
            "INSERT INTO directory_revisions
               (event_id, user_id, change_type, profile_revision, created_at)
             SELECT ?, id, 'upsert', profile_revision, ? FROM users WHERE id = ?",
        )
        .bind(&[
            d1_text(&random_b64u(18)),
            d1_int(now_secs() as i64),
            d1_text(&caller),
        ])?,
        db.prepare(
            "INSERT INTO directory_revisions
               (event_id, user_id, change_type, profile_revision, created_at)
             SELECT ?, id, 'upsert', profile_revision, ? FROM users WHERE id = ?",
        )
        .bind(&[
            d1_text(&random_b64u(18)),
            d1_int(now_secs() as i64),
            d1_text(&body.user_id),
        ])?,
    ])
    .await?;
    Response::from_json(&serde_json::json!({
        "ok": true,
        "new_owner": body.user_id,
        "former_owner": caller,
    }))
}

#[cfg(test)]
mod tests {
    use super::USERS_PAGE_SQL;
    use rusqlite::params;

    /// The keyset walks every member exactly once across a tie in `created_at` — the 200-row cap
    /// this replaced hid everyone past the two hundredth student.
    #[test]
    fn the_member_list_pages_past_any_cap_without_gaps() {
        let db = crate::test_schema::full_schema();
        for (id, at) in [("a", 1), ("b", 2), ("c", 2), ("d", 2), ("e", 3)] {
            db.execute(
                "INSERT INTO users (id, email, identity_pubkey, created_at)
                 VALUES (?1, ?1 || '@x', x'00', ?2)",
                params![id, at],
            )
            .unwrap();
        }
        let page = |after: Option<(i64, &str)>| -> Vec<(String, i64)> {
            let (c, i) = match after {
                Some((c, i)) => (Some(c), i.to_string()),
                None => (None, String::new()),
            };
            db.prepare(USERS_PAGE_SQL)
                .unwrap()
                .query_map(params![c, i, 2], |r| {
                    Ok((r.get("id")?, r.get("created_at")?))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let mut seen = Vec::new();
        let mut after: Option<(i64, String)> = None;
        loop {
            let p = page(after.as_ref().map(|(c, i)| (*c, i.as_str())));
            let Some(last) = p.last().cloned() else {
                break;
            };
            seen.extend(p.into_iter().map(|(id, _)| id));
            after = Some((last.1, last.0));
        }
        assert_eq!(seen, ["a", "b", "c", "d", "e"]);
    }
}

