//! A room's bots (docs/BOTS_BUILD.md §2.2, §2.5, Phase 3).
//!
//! | Route | What |
//! |---|---|
//! | `GET /groups/:id/bots` | every bot of the server not deleted, with `in_room` — the admin's "Bot ekle" picker |
//! | `POST /groups/:id/bots {bot_id}` | add one; idempotent → 204 |
//! | `DELETE /groups/:id/bots/:bot_id` | remove one; idempotent → 204 |
//!
//! **Who may do this: the room's ACTIVE owner or admins, and nobody else** (R9 decision 6). The
//! server owner gets no power here: they turn a bot off or delete it (`bots/admin.rs`), and see
//! which rooms it is in, read-only. Running the box is not a way into a room, and putting a bot
//! there — something that reads what members send it — is not a server-administration act.
//!
//! **A room bot is not a member.** It never gets a `group_members` row, so no client ever hands it
//! a room key; what lets it speak in the room is a row here, which the relay checks on every room
//! send of the bot ([`ROOM_BOT_SQL`]). Members learn of it through `room_bots` in
//! `GET /groups/:id/members` (`groups_read.rs`), which is why adding and removing nudge the room
//! like any membership change. Adding needs the bot enabled; turning a bot off keeps its rooms,
//! and deleting it drops them (`bots/provision.rs`).
//!
//! After the write the bot's inbox is told (`added` / `removed`, `/bot/room-event`), best effort:
//! the row is the truth, and a lost event costs the program a greeting, not access.

use super::{group_role, is_group_admin, notify, require_live_device_auth};
use crate::d1util::{d1_int, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// Is this bot one of this room's bots? Bind: ?1 group_id, ?2 bot_id. A row (`ok`) only when the
/// pair is in `group_bots` and the bot is not deleted. A DISABLED bot still counts — turning a
/// bot off keeps its rooms; what stops it speaking then is its own disabled state.
pub(crate) const ROOM_BOT_SQL: &str = "SELECT 1 AS ok
       FROM group_bots gb JOIN bots b ON b.bot_id = gb.bot_id
      WHERE gb.group_id = ?1 AND gb.bot_id = ?2 AND b.deleted_at IS NULL
      LIMIT 1";

/// Every room a bot is in, for the owner's read-only listing. Bind: ?1 bot_id.
pub(crate) const BOT_ROOMS_SQL: &str = "SELECT gb.group_id, g.name
       FROM group_bots gb JOIN groups g ON g.id = gb.group_id
      WHERE gb.bot_id = ?1
      ORDER BY g.name, gb.group_id";

/// The picker: every bot not deleted, and whether it is in this room. Bind: ?1 group_id.
pub(super) const ROOM_BOT_PICKER_SQL: &str = "SELECT b.bot_id, b.name, b.about, b.builtin,
            b.ai_provider, b.disabled_at, gb.added_by, gb.added_at
       FROM bots b
       LEFT JOIN group_bots gb ON gb.bot_id = b.bot_id AND gb.group_id = ?1
      WHERE b.deleted_at IS NULL
      ORDER BY b.name, b.bot_id";

/// A bot as the add path sees it. Bind: ?1 bot_id. No row = no such bot (or deleted).
pub(super) const BOT_STATE_SQL: &str =
    "SELECT disabled_at FROM bots WHERE bot_id = ?1 AND deleted_at IS NULL";

/// The add itself. Bind: ?1 group_id, ?2 bot_id, ?3 added_by, ?4 now (seconds). It re-checks
/// the bot in the same statement, so a bot deleted or turned off since `BOT_STATE_SQL` read it
/// is not added; `OR IGNORE` makes a re-add a no-op, and `RETURNING` says whether a row is new.
pub(super) const ADD_ROOM_BOT_SQL: &str = "INSERT OR IGNORE INTO group_bots
       (group_id, bot_id, added_by, added_at)
     SELECT ?1, b.bot_id, ?3, ?4 FROM bots b
      WHERE b.bot_id = ?2 AND b.deleted_at IS NULL AND b.disabled_at IS NULL
     RETURNING bot_id";

/// The remove. Bind: ?1 group_id, ?2 bot_id. `RETURNING` says whether a row went.
pub(super) const REMOVE_ROOM_BOT_SQL: &str =
    "DELETE FROM group_bots WHERE group_id = ?1 AND bot_id = ?2 RETURNING bot_id";

/// What the bot's `added` / `removed` event names: the room and the admin who did it.
/// Bind: ?1 group_id, ?2 user_id. `server_role` is information for the program, never authority.
pub(super) const ROOM_EVENT_SQL: &str = "SELECT g.name AS room_name, u.display_name,
            u.role AS server_role
       FROM groups g JOIN users u ON u.id = ?2
      WHERE g.id = ?1";

/// Is `bot_id` a (non-deleted) bot of `group_id`? See [`ROOM_BOT_SQL`].
pub(crate) async fn is_room_bot(db: &D1Database, group_id: &str, bot_id: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct Hit {
        #[allow(dead_code)] // an existence check; the value is never read
        ok: i64,
    }
    let row: Option<Hit> = db
        .prepare(ROOM_BOT_SQL)
        .bind(&[d1_text(group_id), d1_text(bot_id)])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

/// The caller, checked: a live device of an ACTIVE owner/admin of the room in `:id`.
struct RoomAdmin {
    db: D1Database,
    user_id: String,
    group_id: String,
    room_role: String,
}

/// The one gate of this file. The in-group role decides; the server role is never read here.
async fn gate(
    req: &Request,
    ctx: &RouteContext<()>,
) -> Result<std::result::Result<RoomAdmin, Response>> {
    let user_id = match require_live_device_auth(req, &ctx.env).await {
        Ok(uid) => uid,
        Err(resp) => return Ok(Err(resp)),
    };
    let Some(group_id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request").map(Err);
    };
    let db = ctx.env.d1("DB")?;
    let room_role = match group_role(&db, &group_id, &user_id).await? {
        Some(role) if is_group_admin(&role) => role,
        Some(_) => return json_err(403, "forbidden").map(Err),
        None => return json_err(403, "not_member").map(Err),
    };
    Ok(Ok(RoomAdmin {
        db,
        user_id,
        group_id,
        room_role,
    }))
}

#[derive(Deserialize)]
struct PickerRow {
    bot_id: String,
    name: String,
    #[serde(default)]
    about: Option<String>,
    #[serde(default)]
    builtin: Option<String>,
    #[serde(default)]
    ai_provider: Option<String>,
    #[serde(default)]
    disabled_at: Option<i64>,
    #[serde(default)]
    added_by: Option<String>,
    #[serde(default)]
    added_at: Option<i64>,
}

// GET /groups/:id/bots (the room's owner/admins) →
// {"bots": [{bot_id, name, about, builtin, ai_provider, disabled, in_room, added_by, added_at}]}.
pub async fn list_room_bots(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let admin = match gate(&req, &ctx).await? {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let rows: Vec<PickerRow> = admin
        .db
        .prepare(ROOM_BOT_PICKER_SQL)
        .bind(&[d1_text(&admin.group_id)])?
        .all()
        .await?
        .results()?;
    let bots: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "bot_id": r.bot_id,
                "name": r.name,
                "about": r.about,
                "builtin": r.builtin,
                "ai_provider": r.ai_provider,
                "disabled": r.disabled_at.is_some(),
                "in_room": r.added_at.is_some(),
                "added_by": r.added_by,
                "added_at": r.added_at,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "bots": bots }))
}

#[derive(Deserialize)]
struct AddBody {
    bot_id: String,
}

/// A bot id is a v4 UUID; anything empty or far longer is not one.
const MAX_BOT_ID_CHARS: usize = 64;

// POST /groups/:id/bots (the room's owner/admins), body {bot_id} → 204. 404 `bot_not_found`,
// 409 `bot_disabled`. A bot already in the room is a 204 that does nothing else.
pub async fn add_room_bot(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let admin = match gate(&req, &ctx).await? {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let body: AddBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.bot_id.is_empty() || body.bot_id.len() > MAX_BOT_ID_CHARS {
        return json_err(400, "bad_request");
    }
    #[derive(Deserialize)]
    struct State {
        #[serde(default)]
        disabled_at: Option<i64>,
    }
    let state: Option<State> = admin
        .db
        .prepare(BOT_STATE_SQL)
        .bind(&[d1_text(&body.bot_id)])?
        .first(None)
        .await?;
    match state {
        None => return json_err(404, "bot_not_found"),
        Some(s) if s.disabled_at.is_some() => return json_err(409, "bot_disabled"),
        Some(_) => {}
    }
    let added = admin
        .db
        .prepare(ADD_ROOM_BOT_SQL)
        .bind(&[
            d1_text(&admin.group_id),
            d1_text(&body.bot_id),
            d1_text(&admin.user_id),
            d1_int(now_secs() as i64),
        ])?
        .all()
        .await?
        .results::<serde_json::Value>()?;
    if !added.is_empty() {
        // Every member's `room_bots` just changed. An idempotent re-add skips this, so it can
        // never become a way to make the server fan out on demand.
        notify::nudge_room(&ctx.env, &admin.db, &admin.group_id, &[]).await;
        tell_bot(&ctx.env, &admin, &body.bot_id, "added").await;
    }
    no_content()
}

// DELETE /groups/:id/bots/:bot_id (the room's owner/admins) → 204, whether or not it was there.
pub async fn remove_room_bot(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let admin = match gate(&req, &ctx).await? {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let Some(bot_id) = ctx.param("bot_id").cloned() else {
        return json_err(400, "bad_request");
    };
    let removed = admin
        .db
        .prepare(REMOVE_ROOM_BOT_SQL)
        .bind(&[d1_text(&admin.group_id), d1_text(&bot_id)])?
        .all()
        .await?
        .results::<serde_json::Value>()?;
    if !removed.is_empty() {
        notify::nudge_room(&ctx.env, &admin.db, &admin.group_id, &[]).await;
        tell_bot(&ctx.env, &admin, &bot_id, "removed").await;
    }
    no_content()
}

/// The bot's `added` / `removed` event, best effort: logged, never failing the handler — the
/// write it reports has already committed.
async fn tell_bot(env: &Env, admin: &RoomAdmin, bot_id: &str, kind: &str) {
    #[derive(Deserialize)]
    struct EventRow {
        room_name: String,
        #[serde(default)]
        display_name: Option<String>,
        server_role: String,
    }
    let row: Option<EventRow> = match admin
        .db
        .prepare(ROOM_EVENT_SQL)
        .bind(&[d1_text(&admin.group_id), d1_text(&admin.user_id)])
    {
        Ok(stmt) => match stmt.first(None).await {
            Ok(row) => row,
            Err(e) => {
                console_warn!("room bot event lookup failed group={} bot={bot_id}: {e:?}", admin.group_id);
                return;
            }
        },
        Err(e) => {
            console_warn!("room bot event bind failed group={} bot={bot_id}: {e:?}", admin.group_id);
            return;
        }
    };
    let Some(row) = row else {
        console_warn!("room bot event skipped group={} bot={bot_id}: no room row", admin.group_id);
        return;
    };
    let body = serde_json::json!({
        "kind": kind,
        "room_id": admin.group_id,
        "name": row.room_name,
        "who": {
            "user_id": admin.user_id,
            "display_name": row.display_name,
            "server_role": row.server_role,
            "room_role": admin.room_role,
        },
    });
    match crate::bots::bot_inbox(env, bot_id, Method::Post, "/bot/room-event", Some(body.to_string())).await {
        Ok(resp) if (200..300).contains(&resp.status_code()) => {}
        Ok(resp) => console_warn!(
            "room bot event {kind} answered {} group={} bot={bot_id}",
            resp.status_code(),
            admin.group_id
        ),
        Err(e) => console_warn!("room bot event {kind} failed group={} bot={bot_id}: {e:?}", admin.group_id),
    }
}

#[cfg(test)]
#[path = "groups_bots_tests.rs"]
mod tests;
