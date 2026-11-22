//! Drive spaces (docs/DRIVE_PLAN.md §8.1).
//!
//! A Drive space is a ROOM with no chat: a `groups` row whose `kind` is not `'group'` (migration
//! 0062). Its only content is its library — the parts on `/room-library/:room/…`, gated by room
//! membership like every other room's (`plugin_blob::gate`) — and the records that name them,
//! which travel end to end between members and never reach the relay. The relay therefore learns
//! only that a space exists, who is in it, and the size of each part: never a name, a folder or a
//! type. Its `groups.name` is the constant [`SPACE_NAME`] for the same reason — a group's name is
//! plaintext here.
//!
//! Phase 1 has one kind of space, a member's PERSONAL drive (`'drive_personal'`): one per member
//! per server, made on demand by `PUT /drive/personal`, never listed to an app that does not ask
//! for it (`GET /groups?kinds=all`), never given another member, a bot, a role change, a join
//! request or new settings ([`refuse_personal`]). Deleting it is `DELETE /groups/:id`, whose
//! teardown already queues its parts.

use crate::d1util::{d1_int, d1_text};
use crate::groups::require_live_device_auth;
use crate::respond::json_err;
use crate::storage::StorageRouter;
use crate::utils::now_secs;
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

/// The kind of a member's own drive.
pub(crate) const KIND_PERSONAL: &str = "drive_personal";

/// What every space is called on the relay. A group's name is plaintext here; a space's real name
/// (Phase 3) is a record its members read.
pub(crate) const SPACE_NAME: &str = "drive";

/// The refusal a personal space answers to every write that would give it a second member or
/// change what it is.
pub(crate) const ERR_PERSONAL: &str = "drive_personal";

/// Make the caller's personal space unless it exists. Binds: ?1 new id, ?2 user, ?3 now,
/// ?4 [`SPACE_NAME`].
///
/// `INSERT OR IGNORE … WHERE NOT EXISTS`: the existence filter makes a repeated call write nothing,
/// and of two racing calls that both passed the filter the unique index
/// (`idx_groups_personal_drive`) refuses the second, which OR IGNORE turns into "wrote nothing".
/// Not charged to `MAX_OWNED_GROUPS`: it can exist once, and the owned-group count leaves spaces
/// out (`groups_transfer.rs` `OWNED_GROUP_COUNT_SQL`).
pub(crate) const ENSURE_PERSONAL_SQL: &str =
    "INSERT OR IGNORE INTO groups (id, name, created_by, created_at, updated_at,
                                   visibility, auto_join, settings_json, kind)
     SELECT ?1, ?4, ?2, ?3, ?3, 'private', 0, NULL, 'drive_personal'
      WHERE NOT EXISTS (SELECT 1 FROM groups WHERE created_by = ?2 AND kind = 'drive_personal')";

/// The owner's ACTIVE membership of their personal space, whichever call made it. Binds: ?1 user,
/// ?2 now. OR IGNORE: the row of an earlier call stays as it is.
pub(crate) const ENSURE_PERSONAL_MEMBER_SQL: &str =
    "INSERT OR IGNORE INTO group_members (group_id, user_id, role, joined_at, status, added_by)
     SELECT g.id, ?1, 'owner', ?2, 'active', NULL
       FROM groups g WHERE g.created_by = ?1 AND g.kind = 'drive_personal'";

/// The caller's personal space. Bind: ?1 user.
pub(crate) const PERSONAL_SQL: &str =
    "SELECT id FROM groups WHERE created_by = ?1 AND kind = 'drive_personal' LIMIT 1";

/// A room's kind; no row = no such room. Bind: ?1 group id.
pub(crate) const KIND_SQL: &str = "SELECT kind FROM groups WHERE id = ?1";

#[derive(Deserialize)]
struct IdRow {
    id: String,
}

#[derive(Deserialize)]
struct KindRow {
    kind: String,
}

/// A room's kind, `None` when there is no such room.
pub(crate) async fn space_kind(db: &D1Database, group_id: &str) -> Result<Option<String>> {
    let row: Option<KindRow> = db
        .prepare(KIND_SQL)
        .bind(&[d1_text(group_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.kind))
}

/// `Some(400 drive_personal)` when `group_id` is a personal space: the guard every membership,
/// role, settings, bot and join-request write runs before it writes. A failed read refuses too —
/// a guard that fails open would let a second member into someone's drive.
pub(crate) async fn refuse_personal(db: &D1Database, group_id: &str) -> Option<Response> {
    match space_kind(db, group_id).await {
        Ok(Some(kind)) if kind == KIND_PERSONAL => json_err(400, ERR_PERSONAL).ok(),
        Ok(_) => None,
        Err(_) => json_err(503, "db_unavailable").ok(),
    }
}

/// `PUT /drive/personal` → `200 {"id", "created"}`: the caller's personal space, made if it did not
/// exist. Idempotent. `503 media_not_configured` on a server with no store: a drive whose files
/// cannot be stored is not offered (the `features.drive` announcement says the same).
pub async fn put_personal(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_live_device_auth(&req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let router = StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    let now = now_secs() as i64;
    let fresh = Uuid::new_v4().to_string();
    db.batch(vec![
        db.prepare(ENSURE_PERSONAL_SQL)
            .bind(&[d1_text(&fresh), d1_text(&user_id), d1_int(now), d1_text(SPACE_NAME)])?,
        db.prepare(ENSURE_PERSONAL_MEMBER_SQL)
            .bind(&[d1_text(&user_id), d1_int(now)])?,
    ])
    .await?;
    let row: Option<IdRow> = db
        .prepare(PERSONAL_SQL)
        .bind(&[d1_text(&user_id)])?
        .first(None)
        .await?;
    match row {
        Some(r) => Response::from_json(&serde_json::json!({
            "created": r.id == fresh,
            "id": r.id,
        })),
        None => json_err(503, "db_unavailable"),
    }
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod tests;
