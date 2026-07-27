use crate::auth::hashing::sha256_hex;
use crate::auth::middleware::{fetch_role, require_active_auth, require_admin, require_owner};
use crate::d1util::{d1_int, d1_opt_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{now_secs, random_b64u};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct CreateInviteBody {
    email_hint: Option<String>,
    ttl_hours: Option<u64>,
    /// Minute-grained short TTL for in-person invites (5/15/60 min). The
    /// `ttl_hours` granularity (1 hour minimum) was far too long for handing a
    /// code to someone face to face. When present this WINS over `ttl_hours`;
    /// when absent the `ttl_hours` path works exactly as before, so older
    /// clients that still send `ttl_hours` keep working.
    ttl_minutes: Option<u64>,
}

/// Resolve and validate the invite TTL in seconds. Precedence: `ttl_minutes`
/// (minute-grained short TTL) > `ttl_hours` (backwards compatibility, older
/// clients) > a 24 hour default. If both are present `ttl_minutes` WINS. Out of
/// range → `Err(())`, which the caller turns into 400 bad_request:
///   - ttl_minutes: 1..=43200 (30 days = 43200 min)
///   - ttl_hours:   1..=24*30 (30 days — the pre-existing rule, unchanged)
fn resolve_invite_ttl_secs(
    ttl_minutes: Option<u64>,
    ttl_hours: Option<u64>,
) -> core::result::Result<u64, ()> {
    if let Some(m) = ttl_minutes {
        if !(1..=43200).contains(&m) {
            return Err(());
        }
        return Ok(m * 60);
    }
    if let Some(h) = ttl_hours {
        if !(1..=24 * 30).contains(&h) {
            return Err(());
        }
        return Ok(h * 60 * 60);
    }
    Ok(24 * 60 * 60)
}

pub async fn create_invite(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: CreateInviteBody = req.json().await.unwrap_or_default();
    // `email_hint` is now a free-text LABEL/NAME (optional; the admin notes who the
    // invite was minted for). Redeem does NOT match it against the e-mail — see
    // invite.rs, where the old email binding was removed because it was useless
    // against synthetic u...@sezgi.local addresses. The `@` requirement is GONE
    // (any name/label is allowed); only the length bound remains, as a DoS guard.
    if let Some(h) = &body.email_hint {
        if h.len() > 254 {
            return json_err(400, "bad_request");
        }
    }
    // TTL resolution: ttl_minutes > ttl_hours > 24h default (validated in the
    // helper).
    let ttl = match resolve_invite_ttl_secs(body.ttl_minutes, body.ttl_hours) {
        Ok(secs) => secs,
        Err(()) => return json_err(400, "bad_request"),
    };

    let now = now_secs();
    let token = random_b64u(18); // 24 char b64u
    let token_hash = sha256_hex(&token);
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "INSERT INTO invite_tokens
           (token, token_hash, email_hint, used, used_by, owner_user_id, expires_at, created_at)
         VALUES (?, ?, ?, 0, NULL, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&token),
        d1_text(&token_hash),
        d1_opt_text(body.email_hint.as_deref()),
        d1_text(&user_id),
        d1_int((now + ttl) as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "token": token,
        "email_hint": body.email_hint,
        "expires_at": now + ttl,
        "created_at": now,
    }))
}

#[derive(Deserialize)]
struct InviteRow {
    token: String,
    email_hint: Option<String>,
    used: i32,
    used_by: Option<String>,
    owner_user_id: Option<String>,
    used_by_email: Option<String>,
    owner_email: Option<String>,
    expires_at: i64,
    created_at: i64,
}

pub async fn list_invites(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    // Who minted it (owner_email) and who used it (used_by_email) are resolved by
    // JOIN. P0: used invites that TTL-GC already dropped from invite_tokens are
    // still listed, from the durable invite_attributions ledger, under the SAME
    // response schema. When a live row also has a ledger entry the ledger wins for
    // used/used_by, so the very narrow window between the claim and the legacy
    // `used` UPDATE never shows up as "unused" in the admin UI.
    let rows: Vec<InviteRow> = db
        .prepare(
            "WITH invite_history AS (
               SELECT it.token AS token,
                      COALESCE(it.email_hint, ia.email_hint) AS email_hint,
                      CASE WHEN ia.invite_token_hash IS NULL THEN it.used ELSE 1 END AS used,
                      COALESCE(ia.used_by, it.used_by) AS used_by,
                      COALESCE(ia.inviter_user_id, it.owner_user_id) AS owner_user_id,
                      it.expires_at AS expires_at,
                      it.created_at AS created_at
                 FROM invite_tokens it
                 LEFT JOIN invite_attributions ia ON ia.invite_token_hash = it.token_hash
               UNION ALL
               SELECT 'used:' || substr(ia.invite_token_hash, 1, 12) AS token,
                      ia.email_hint, 1 AS used,
                      ia.used_by, ia.inviter_user_id AS owner_user_id,
                      ia.expires_at, ia.created_at
                 FROM invite_attributions ia
                WHERE NOT EXISTS (
                  SELECT 1 FROM invite_tokens it
                   WHERE it.token_hash = ia.invite_token_hash
                )
             )
             SELECT ih.token, ih.email_hint, ih.used, ih.used_by, ih.owner_user_id,
                    ub.email AS used_by_email, ob.email AS owner_email,
                    ih.expires_at, ih.created_at
               FROM invite_history ih
               LEFT JOIN users ub ON ih.used_by = ub.id
               LEFT JOIN users ob ON ih.owner_user_id = ob.id
              ORDER BY ih.created_at DESC LIMIT 100",
        )
        .all()
        .await?
        .results()?;
    let now = now_secs();
    let invites: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "token": r.token,
                "email_hint": r.email_hint,
                "used": r.used == 1,
                "used_by": r.used_by,
                "used_by_email": r.used_by_email,
                "owner_user_id": r.owner_user_id,
                "owner_email": r.owner_email,
                "expires_at": r.expires_at,
                "created_at": r.created_at,
                "expired": (r.expires_at as u64) <= now,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "invites": invites }))
}

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
    /// Quota Faz 1a: server-wide storage cap in bytes. Convention: 0 CLEARS the
    /// cap (NULL = unlimited), > 0 sets it, None keeps the current value.
    max_storage_bytes: Option<i64>,
    /// Quota Faz 1a: per-user storage cap in bytes — same 0-clears convention.
    max_user_storage_bytes: Option<i64>,
    /// "Delete for everyone" window in hours: how long after a message was SENT it
    /// may still be deleted for everyone (owner-configurable, DEFAULT 48). The
    /// receiving side is what will ENFORCE it; the server only carries the value.
    /// None → keep the current value (twin of the retention pattern).
    delete_window_hours: Option<i64>,
}

/// OWNER-only, not admin. Every field on this endpoint is server-wide POLICY rather than day-to-day
/// moderation: `join_mode` decides whether anyone can walk in, `directory_mode`/`dm_policy` decide who
/// is discoverable and contactable, the retention pair decides how long undelivered content lives on
/// the server, and `delete_window_hours` bounds the "delete for everyone" promise made to every user.
///
/// It used to be `require_admin`, which accepts admin OR owner, so any admin could change all of it.
/// Three things said that was not the intent: the app's delete-window, storage-limit and retention
/// editors all describe themselves as owner-only, `UpdateSettingsBody.delete_window_hours`'s own doc
/// says "owner-configurable", and `admin/storage.rs` already gates configuration MUTATIONS on the owner
/// while leaving reads to admins. This endpoint was the one configuration mutation sitting on the admin
/// side of that line.
///
/// Admins keep what admins need — invites, the member list, removing a member — because those are
/// separate handlers. Compare `set_role` and `transfer_ownership`, which have always been owner-only:
/// this now sits with them, where changing what the server IS belongs.
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
    {
        return json_err(400, "bad_request");
    }
    if let Some(n) = &body.name {
        if n.is_empty() || n.len() > 64 {
            return json_err(400, "bad_request");
        }
    }
    if let Some(m) = &body.join_mode {
        if m != "open" && m != "invite_only" {
            return json_err(400, "bad_request");
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

    let now = now_secs();
    let db = ctx.env.d1("DB")?;
    // Read the current row (defaults if absent) so that omitted fields keep their
    // existing values.
    #[derive(Deserialize)]
    struct CurRow {
        name: String,
        join_mode: String,
        directory_mode: String,
        dm_policy: String,
        retention_days: i64,
        message_retention_days: i64,
        // Quota caps — NULLABLE columns (NULL = unlimited).
        max_storage_bytes: Option<i64>,
        max_user_storage_bytes: Option<i64>,
        delete_window_hours: i64,
    }
    let cur: Option<CurRow> = db
        .prepare(
            "SELECT name, join_mode, directory_mode, dm_policy, retention_days, message_retention_days, \
             max_storage_bytes, max_user_storage_bytes, delete_window_hours \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first(None)
        .await?;
    let cur_name = cur
        .as_ref()
        .map(|c| c.name.clone())
        .unwrap_or_else(|| "Sezi".into());
    let cur_mode = cur
        .as_ref()
        .map(|c| c.join_mode.clone())
        .unwrap_or_else(|| "invite_only".into());
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
    let new_mode = body.join_mode.unwrap_or(cur_mode);
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

    let settings_stmt = db.prepare(
        "INSERT INTO server_settings \
            (id, name, join_mode, directory_mode, dm_policy, retention_days, message_retention_days, \
             max_storage_bytes, max_user_storage_bytes, delete_window_hours, updated_at)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            updated_at = excluded.updated_at",
    )
    .bind(&[
        d1_text(&new_name),
        d1_text(&new_mode),
        d1_text(&new_directory_mode),
        d1_text(&new_dm_policy),
        d1_int(new_retention),
        d1_int(new_msg_retention),
        d1_opt_int(new_max_storage),
        d1_opt_int(new_max_user_storage),
        d1_int(new_delete_window),
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
    }))
}

#[derive(Deserialize, Default)]
struct RevokeInviteBody {
    token: String,
}

/// Revoke an unused invite (admin). A used invite is never deleted.
pub async fn revoke_invite(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: RevokeInviteBody = req.json().await.unwrap_or_default();
    if body.token.is_empty() || body.token.len() > 128 {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    // If a ledger claim exists the invite has been used even when the legacy `used`
    // flag is still 0, and revoke must not delete it: the claim INSERT is redeem's
    // linearization point.
    db.prepare(
        "DELETE FROM invite_tokens
          WHERE token = ? AND used = 0
            AND NOT EXISTS (
              SELECT 1 FROM invite_attributions ia
               WHERE ia.invite_token_hash = invite_tokens.token_hash
            )",
    )
    .bind(&[d1_text(&body.token)])?
    .run()
    .await?;
    Response::from_json(&serde_json::json!({ "ok": true }))
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

/// List the server's members (admin). The owner works from this list when
/// assigning roles.
pub async fn list_users(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let rows: Vec<UserRow> = db
        .prepare(
            "SELECT id, email, display_name, role, created_at, last_seen_at
             FROM users ORDER BY created_at ASC LIMIT 200",
        )
        .all()
        .await?
        .results()?;
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
    Response::from_json(&serde_json::json!({ "members": members }))
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
            caller_device_id: caller_auth.device_id.as_deref(),
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
    // Atomic swap: old owner (the caller) -> admin FIRST, then the target -> owner.
    // FIX-1 (BLOCKER): a single-statement CASE UPDATE COLLIDES with `idx_one_owner`
    // (the 0018 partial UNIQUE index WHERE role='owner'). SQLite scans `IN(...)` in
    // order, so if new_owner_id sorts before the caller, the row-by-row UPDATE
    // promotes new_owner to 'owner' while the caller is STILL owner → 2 owners →
    // partial-UNIQUE violation → "UNIQUE constraint failed: users.role" → 500. That
    // failure is non-deterministic (~50%, depending on UUID ordering). FIX: two
    // ORDERED statements in a D1 batch, where the order IS guaranteed — demote the
    // caller to 'admin' first (owner count drops to 0), then promote new_owner
    // (owner count back to 1), so there are never 2 owners at once.
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
    use super::*;

    #[test]
    fn davet_ttl_cozumleme() {
        // ttl_minutes=5 → 300 s (expires_at ≈ now+300, the in-person invite).
        assert_eq!(resolve_invite_ttl_secs(Some(5), None), Ok(300));
        // With both fields present, ttl_minutes WINS.
        assert_eq!(resolve_invite_ttl_secs(Some(5), Some(2)), Ok(300));
        // ttl_minutes bounds: 0 → 400, 43201 (30 days + 1) → 400, 43200 → OK.
        assert_eq!(resolve_invite_ttl_secs(Some(0), None), Err(()));
        assert_eq!(resolve_invite_ttl_secs(Some(43201), None), Err(()));
        assert_eq!(resolve_invite_ttl_secs(Some(43200), None), Ok(43200 * 60));
        // Backwards compatibility: the ttl_hours-only path keeps the existing rule
        // (1..=24*30, hours → seconds).
        assert_eq!(resolve_invite_ttl_secs(None, Some(1)), Ok(3600));
        assert_eq!(
            resolve_invite_ttl_secs(None, Some(24 * 30)),
            Ok(24 * 30 * 3600)
        );
        assert_eq!(resolve_invite_ttl_secs(None, Some(0)), Err(()));
        assert_eq!(resolve_invite_ttl_secs(None, Some(24 * 30 + 1)), Err(()));
        // Neither field → the 24 hour default.
        assert_eq!(resolve_invite_ttl_secs(None, None), Ok(24 * 60 * 60));
    }
}
