//! Catalogs: a folder of the server's disk its owner opens to a group (`disk.rs` is the disk
//! itself). Members browse and search the folder and open any file in it; an opened file is made
//! readable in the room as a `room_library_disk` item and its key handed to the member who opened
//! it — no library record is written, so opening a book adds nothing to the group's library.
//!
//! The catalog IS the folder, read when asked: a file the owner puts into it later is in the
//! catalog at once, whatever way it got there.
//!
//! # Routes (every one behind `room_gate`: an active member of `:room`)
//!
//! - `GET /room-library/:room/catalogs` — `{catalogs: [{catalog_id, name, path}]}`.
//! - `POST /room-library/:room/catalogs` `{path, name}` — the server owner, as an admin of the
//!   group, opens a folder of the disk: `{catalog_id, name, path}`.
//! - `DELETE /room-library/:room/catalogs/:cid` — an admin of the group closes it. The disk and
//!   the items already opened stay.
//! - `GET /room-library/:room/catalogs/:cid/list?path=<rel>` — a folder of the catalog.
//! - `GET /room-library/:room/catalogs/:cid/search?q=<words>` — names under the catalog.
//! - `POST /room-library/:room/catalogs/:cid/open` `{path}` — read a file for its item: `202
//!   {state: "hashing", …}` while the box reads it, then `200 {state: "ready", item: {…}}` with
//!   the item key, the item now readable in the room.
//!
//! Every path a member sends is RELATIVE TO THE CATALOG, and every path answered is too: a member
//! never names, or learns, anything of the disk outside the folder they were given.

use serde::Deserialize;
use serde_json::json;
use worker::*;

use crate::auth::middleware::require_owner;
use crate::d1util::{d1_int, d1_text};
use crate::disk::{admit_item, call, unavailable, BASE};
use crate::groups::is_group_admin;
use crate::respond::{json_err, no_content};
use crate::utils::{now_secs, random_bytes};

const MAX_NAME_CHARS: usize = 80;
/// Catalogs one group may hold.
const MAX_CATALOGS: i64 = 50;

// ── Pure helpers ──────────────────────────────────────────────────────────────────────────

/// A catalog's name as stored: trimmed, 1..=80 characters, no control characters.
pub(crate) fn clean_name(name: &str) -> Option<String> {
    let n = name.trim();
    (!n.is_empty() && n.chars().count() <= MAX_NAME_CHARS && !n.chars().any(char::is_control))
        .then(|| n.to_string())
}

/// A relative path's shape, as the gateway checks it (`sezi-disk-gateway` `paths.rs`): no root,
/// no `.`/`..`, no empty or hidden segment, no backslash or NUL. `""` is the folder itself.
pub(crate) fn valid_rel(rel: &str) -> bool {
    if rel.is_empty() {
        return true;
    }
    rel.len() <= 1024
        && !rel.contains(['\0', '\\'])
        && !rel.starts_with('/')
        && rel.split('/').all(|s| !s.is_empty() && s != "." && s != ".." && !s.starts_with('.'))
}

/// `rel` (relative to the catalog) as a path relative to the disk's media folder.
pub(crate) fn join(base: &str, rel: &str) -> Option<String> {
    if !valid_rel(rel) {
        return None;
    }
    Some(match (base.is_empty(), rel.is_empty()) {
        (_, true) => base.to_string(),
        (true, false) => rel.to_string(),
        (false, false) => format!("{base}/{rel}"),
    })
}

/// A path the gateway answered (relative to the media folder) as one relative to the catalog;
/// `None` for anything outside it.
pub(crate) fn strip(base: &str, path: &str) -> Option<String> {
    if base.is_empty() {
        return Some(path.to_string());
    }
    if path == base {
        return Some(String::new());
    }
    path.strip_prefix(base)?.strip_prefix('/').map(str::to_string)
}

/// A listing or search answer with every entry's path made catalog-relative; entries outside
/// the catalog are dropped.
pub(crate) fn rebase(base: &str, mut body: serde_json::Value) -> serde_json::Value {
    if let Some(path) = body.get("path").and_then(|p| p.as_str()).map(str::to_string) {
        body["path"] = json!(strip(base, &path).unwrap_or_default());
    }
    if let Some(entries) = body.get_mut("entries").and_then(|e| e.as_array_mut()) {
        entries.retain_mut(|e| {
            let Some(p) = e.get("path").and_then(|p| p.as_str()).and_then(|p| strip(base, p)) else {
                return false;
            };
            e["path"] = json!(p);
            true
        });
    }
    body
}

// ── SQL ───────────────────────────────────────────────────────────────────────────────────

pub(crate) const LIST_SQL: &str = "SELECT catalog_id, name, path FROM disk_catalogs \
     WHERE room_id = ? ORDER BY name";
pub(crate) const SELECT_SQL: &str =
    "SELECT path FROM disk_catalogs WHERE room_id = ? AND catalog_id = ? LIMIT 1";
/// Binds (numbered): room, catalog, path, name, added_by, created_at, the cap.
pub(crate) const INSERT_SQL: &str = "INSERT INTO disk_catalogs \
       (room_id, catalog_id, path, name, added_by, created_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE EXISTS (SELECT 1 FROM groups WHERE id = ?1) \
       AND (SELECT COUNT(*) FROM disk_catalogs WHERE room_id = ?1) < ?7";
pub(crate) const DELETE_SQL: &str =
    "DELETE FROM disk_catalogs WHERE room_id = ? AND catalog_id = ?";

#[derive(Deserialize)]
struct Row {
    catalog_id: String,
    name: String,
    path: String,
}

#[derive(Deserialize)]
struct PathRow {
    path: String,
}

async fn base_of(db: &D1Database, room: &str, catalog: &str) -> Result<Option<String>> {
    Ok(db
        .prepare(SELECT_SQL)
        .bind(&[d1_text(room), d1_text(catalog)])?
        .first::<PathRow>(None)
        .await?
        .map(|r| r.path))
}

fn query_param(req: &Request, name: &str) -> String {
    req.url()
        .ok()
        .and_then(|u| u.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned()))
        .unwrap_or_default()
}

/// The gateway's JSON answer, its paths rebased onto the catalog.
async fn rebased(base: &str, resp: std::result::Result<Response, ()>) -> Result<Response> {
    let Ok(mut resp) = resp else { return unavailable() };
    let status = resp.status_code();
    let Ok(body) = resp.json::<serde_json::Value>().await else { return unavailable() };
    let body = if status == 200 { rebase(base, body) } else { body };
    Ok(Response::from_json(&body)?.with_status(status))
}

// ── Routes ────────────────────────────────────────────────────────────────────────────────

pub async fn list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (_user, room_id, _role) = match crate::plugin_blob::room_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let rows: Vec<Row> = db
        .prepare(LIST_SQL)
        .bind(&[d1_text(&room_id)])?
        .all()
        .await?
        .results()?;
    let catalogs: Vec<_> = rows
        .into_iter()
        .map(|r| json!({ "catalog_id": r.catalog_id, "name": r.name, "path": r.path }))
        .collect();
    Response::from_json(&json!({ "catalogs": catalogs }))
}

#[derive(Deserialize)]
struct ShareBody {
    path: String,
    name: String,
}

pub async fn share(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, role) = match crate::plugin_blob::room_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    if !is_group_admin(&role) {
        return json_err(403, "not_admin");
    }
    let Ok(body) = req.json::<ShareBody>().await else { return json_err(400, "bad_request") };
    let Some(name) = clean_name(&body.name) else { return json_err(400, "disk/bad-name") };
    if !valid_rel(&body.path) {
        return json_err(400, "disk/bad-path");
    }
    // The folder must be one: a listing of it answers 200.
    let mut url = Url::parse(&format!("{BASE}/v1/list"))?;
    url.query_pairs_mut().append_pair("path", &body.path);
    match call(&ctx.env, Method::Get, url.as_str(), None, None).await {
        Ok(r) if r.status_code() == 200 => {}
        Ok(mut r) => {
            let status = r.status_code();
            let b = r.json::<serde_json::Value>().await.unwrap_or_else(|_| json!({}));
            return Ok(Response::from_json(&b)?.with_status(status));
        }
        Err(()) => return unavailable(),
    }
    let catalog_id = hex::encode(random_bytes(12));
    let db = ctx.env.d1("DB")?;
    let written = db
        .prepare(INSERT_SQL)
        .bind(&[
            d1_text(&room_id),
            d1_text(&catalog_id),
            d1_text(&body.path),
            d1_text(&name),
            d1_text(&user_id),
            d1_int(now_secs() as i64),
            d1_int(MAX_CATALOGS),
        ])?
        .run()
        .await?
        .meta()?
        .and_then(|m| m.changes)
        .unwrap_or(0);
    if written == 0 {
        return json_err(409, "disk/too-many-catalogs");
    }
    Response::from_json(&json!({ "catalog_id": catalog_id, "name": name, "path": body.path }))
}

pub async fn unshare(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (_user, room_id, role) = match crate::plugin_blob::room_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    if !is_group_admin(&role) {
        return json_err(403, "not_admin");
    }
    let Some(cid) = ctx.param("cid").cloned() else { return json_err(400, "bad_request") };
    ctx.env
        .d1("DB")?
        .prepare(DELETE_SQL)
        .bind(&[d1_text(&room_id), d1_text(&cid)])?
        .run()
        .await?;
    no_content()
}

/// The member gate plus the catalog: `(user, room, catalog's folder)`.
async fn catalog_gate(
    req: &Request,
    ctx: &RouteContext<()>,
) -> std::result::Result<(String, String, String), Response> {
    let (user, room_id, _role) = crate::plugin_blob::room_gate(req, ctx).await?;
    let fail = |s, c| json_err(s, c).unwrap_or_else(|_| Response::empty().unwrap());
    let cid = ctx.param("cid").cloned().ok_or_else(|| fail(400, "bad_request"))?;
    let db = ctx.env.d1("DB").map_err(|_| fail(503, "db_unavailable"))?;
    match base_of(&db, &room_id, &cid).await {
        Ok(Some(base)) => Ok((user, room_id, base)),
        Ok(None) => Err(fail(404, "disk/no-catalog")),
        Err(_) => Err(fail(503, "db_unavailable")),
    }
}

pub async fn browse(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (_user, _room, base) = match catalog_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    let Some(path) = join(&base, &query_param(&req, "path")) else {
        return json_err(400, "disk/bad-path");
    };
    let mut url = Url::parse(&format!("{BASE}/v1/list"))?;
    url.query_pairs_mut().append_pair("path", &path);
    rebased(&base, call(&ctx.env, Method::Get, url.as_str(), None, None).await).await
}

pub async fn search(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (_user, _room, base) = match catalog_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    let q: String = query_param(&req, "q").chars().take(200).collect();
    let mut url = Url::parse(&format!("{BASE}/v1/search"))?;
    url.query_pairs_mut().append_pair("under", &base).append_pair("q", &q);
    rebased(&base, call(&ctx.env, Method::Get, url.as_str(), None, None).await).await
}

#[derive(Deserialize)]
struct OpenBody {
    path: String,
}

pub async fn open(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, base) = match catalog_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    let Ok(body) = req.json::<OpenBody>().await else { return json_err(400, "bad_request") };
    let Some(path) = join(&base, &body.path).filter(|_| !body.path.is_empty()) else {
        return json_err(400, "disk/bad-path");
    };
    let payload = json!({ "path": path }).to_string();
    let Ok(mut resp) =
        call(&ctx.env, Method::Post, &format!("{BASE}/v1/prepare"), Some(payload), None).await
    else {
        return unavailable();
    };
    let status = resp.status_code();
    let Ok(mut answer) = resp.json::<serde_json::Value>().await else { return unavailable() };
    if status != 200 {
        return Ok(Response::from_json(&answer)?.with_status(status));
    }
    let Some(item_id) = answer["item"]["item_id"].as_str().map(str::to_string) else {
        return unavailable();
    };
    if !crate::disk::valid_item_id(&item_id) {
        return json_err(502, "disk/bad-layout");
    }
    let db = ctx.env.d1("DB")?;
    if let Err(resp) = admit_item(&ctx.env, &db, &room_id, &item_id, &user_id).await? {
        return Ok(resp);
    }
    // The member sees the file's path inside the catalog, never the disk's.
    answer["item"]["path"] = json!(body.path);
    Response::from_json(&answer)
}

#[cfg(test)]
#[path = "disk_catalog_tests.rs"]
mod tests;
