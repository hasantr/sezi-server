//! The server's own disk as a source of group-library items (docs/DRIVE_PLAN.md §6, "6b").
//!
//! A self-hosted relay can sit beside a disk full of films, books and recordings. Its owner puts
//! files in one folder, and the box's disk gateway (`core/crates/sezi-disk-gateway`) offers them:
//! it lists the folder, reads a file once for its BLAKE3 and gives it an item key, and seals each
//! part of it on demand, byte for byte what an uploading device would have sent. Members read
//! those parts through the ordinary `GET /room-library/:room/:id`; nothing is uploaded and no
//! second copy is stored.
//!
//! The relay reaches the gateway ONLY through the `SEZI_DISK` service binding — an external
//! service at `127.0.0.1:8790` that `scripts/workerd_config.py` writes into the bare-workerd
//! config. Its outbound network stays public-only. On Cloudflare, or a box without the gateway,
//! the binding is absent or refuses the connection and every route here answers
//! `503 disk/unavailable`; `/capabilities` says `features.server_disk: false`.
//!
//! # Routes
//!
//! - `GET /admin/disk?path=<rel>` (server owner) — a folder of the disk: the gateway's listing.
//! - `POST /admin/disk/prepare` `{path}` (server owner) — read a file for its item: `202
//!   {state: "hashing", done, size}` until `200 {state: "ready", item: {…, key_b64}}`. The key
//!   goes to the owner's device, which writes it into the end-to-end library record; the relay
//!   only passes it on — the box that holds the plain file holds its key too.
//! - `POST /room-library/:room/disk` `{item_id}` (server owner, and an admin of that group) —
//!   make a prepared item's parts readable in the room. The layout is the GATEWAY's, never the
//!   caller's. One `room_library_disk` row per item; it charges no room and no server total.
//!
//! Who: only the server's owner — the person whose disk it is. A group admin who does not run
//! the server sees nothing of it.

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::groups::is_group_admin;
use crate::respond::json_err;
use crate::utils::now_secs;

/// The service binding the bare-workerd config gives the relay.
pub(crate) const BINDING: &str = "SEZI_DISK";
/// The host part is ignored by an external service; the path is the gateway's.
pub(crate) const BASE: &str = "http://sezi-disk";

/// The library's limits, as the core and the gateway hold them (`sezi_file::part`).
const CHUNK: u64 = 64 * 1024;
const TAG: u64 = 16;
const MIN_PART: u64 = CHUNK;
const MAX_PART: u64 = 32 * 1024 * 1024;
const MAX_ITEM_BYTES: u64 = 64 * 1024 * 1024 * 1024;

// ── Pure helpers (the testable half) ──────────────────────────────────────────────────────

/// `sezi_file::part::part_count`.
pub(crate) fn part_count(size: u64, part_size: u64) -> u64 {
    if part_size == 0 {
        return 0;
    }
    size.div_ceil(part_size).max(1)
}

/// Whether a layout the gateway answered is one a member's device will read.
pub(crate) fn valid_layout(size: u64, part_size: u64, parts: u64) -> bool {
    size > 0
        && size <= MAX_ITEM_BYTES
        && (MIN_PART..=MAX_PART).contains(&part_size)
        && parts == part_count(size, part_size)
}

/// The ciphertext length of part `index`: its plaintext plus one tag per 64 KiB chunk —
/// `sezi_file::part::part_ciphertext_len(part_plain_len(..))`. `None` past the last part.
pub(crate) fn part_ciphertext_size(size: u64, part_size: u64, index: u64) -> Option<u64> {
    if index >= part_count(size, part_size) {
        return None;
    }
    let plain = size.saturating_sub(index * part_size).min(part_size);
    Some(plain + plain.div_ceil(CHUNK).max(1) * TAG)
}

/// `<item id>-<index>` → (item id, index). Item ids may hold `-`; the index follows the last.
pub(crate) fn split_object_id(object_id: &str) -> Option<(&str, u64)> {
    let (item, index) = object_id.rsplit_once('-')?;
    if item.is_empty() || index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((item, index.parse().ok()?))
}

/// Item ids as the library writes them: `[A-Za-z0-9_-]`, 16..=64.
pub(crate) fn valid_item_id(id: &str) -> bool {
    (16..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ── SQL ───────────────────────────────────────────────────────────────────────────────────

/// One item's row in a room. Binds: room, item.
pub(crate) const SELECT_ITEM_SQL: &str = "SELECT adder_id, size_bytes, part_size, parts \
     FROM room_library_disk WHERE room_id = ? AND item_id = ? LIMIT 1";

/// Add an item to a room, only while the group exists. Binds (numbered): room, item, adder,
/// size, part_size, parts, created_at.
pub(crate) const INSERT_ITEM_SQL: &str = "INSERT INTO room_library_disk \
       (room_id, item_id, adder_id, size_bytes, part_size, parts, created_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE EXISTS (SELECT 1 FROM groups WHERE id = ?1) \
     ON CONFLICT(room_id, item_id) DO NOTHING";

/// Binds: room, item.
pub(crate) const DELETE_ITEM_SQL: &str =
    "DELETE FROM room_library_disk WHERE room_id = ? AND item_id = ?";

#[derive(Deserialize)]
pub(crate) struct ItemRow {
    pub adder_id: String,
    pub size_bytes: i64,
    pub part_size: i64,
    pub parts: i64,
}

pub(crate) async fn load_item(db: &D1Database, room: &str, item: &str) -> Result<Option<ItemRow>> {
    db.prepare(SELECT_ITEM_SQL)
        .bind(&[d1_text(room), d1_text(item)])?
        .first(None)
        .await
}

// ── The gateway ───────────────────────────────────────────────────────────────────────────

/// One request to the gateway. `Err(())` = no binding, or nothing answered.
pub(crate) async fn call(
    env: &Env,
    method: Method,
    url: &str,
    body: Option<String>,
    range_from: Option<u64>,
) -> std::result::Result<Response, ()> {
    let fetcher = env.service(BINDING).map_err(|_| ())?;
    let headers = Headers::new();
    if body.is_some() {
        headers.set("content-type", "application/json").map_err(|_| ())?;
    }
    if let Some(n) = range_from.filter(|n| *n > 0) {
        headers.set("range", &format!("bytes={n}-")).map_err(|_| ())?;
    }
    let mut init = RequestInit::new();
    init.with_method(method).with_headers(headers);
    if let Some(b) = body {
        init.with_body(Some(JsValue::from_str(&b)));
    }
    let resp = fetcher.fetch(url.to_string(), Some(init)).await.map_err(|_| ())?;
    Response::try_from(resp).map_err(|_| ())
}

pub(crate) fn unavailable() -> Result<Response> {
    json_err(503, "disk/unavailable")
}

/// Whether a gateway answers — what `/capabilities` announces as `features.server_disk`. A
/// connection refused on loopback answers at once, so the probe costs nothing where there is no
/// gateway.
pub(crate) async fn reachable(env: &Env) -> bool {
    match call(env, Method::Get, &format!("{BASE}/healthz"), None, None).await {
        Ok(r) => r.status_code() == 200,
        Err(()) => false,
    }
}

/// The gateway's answer handed on: its status and its JSON, nothing added.
pub(crate) async fn pass_on(resp: std::result::Result<Response, ()>) -> Result<Response> {
    let Ok(mut resp) = resp else { return unavailable() };
    let status = resp.status_code();
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    Ok(Response::from_json(&body)?.with_status(status))
}

async fn owner(req: &Request, env: &Env) -> std::result::Result<String, Response> {
    let user_id = require_active_auth(req, env).await?.user_id;
    require_owner(&user_id, env).await?;
    Ok(user_id)
}

/// `GET /admin/disk?path=<rel>`.
pub async fn list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let path = req
        .url()?
        .query_pairs()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let mut url = Url::parse(&format!("{BASE}/v1/list"))?;
    url.query_pairs_mut().append_pair("path", &path);
    pass_on(call(&ctx.env, Method::Get, url.as_str(), None, None).await).await
}

#[derive(Deserialize)]
struct PrepareBody {
    path: String,
}

/// `POST /admin/disk/prepare` `{path}`.
pub async fn prepare(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = owner(&req, &ctx.env).await {
        return Ok(resp);
    }
    let Ok(body) = req.json::<PrepareBody>().await else {
        return json_err(400, "bad_request");
    };
    let payload = json!({ "path": body.path }).to_string();
    pass_on(call(&ctx.env, Method::Post, &format!("{BASE}/v1/prepare"), Some(payload), None).await)
        .await
}

#[derive(Deserialize)]
struct AddBody {
    item_id: String,
}

#[derive(Deserialize)]
pub(crate) struct Layout {
    pub size: u64,
    pub part_size: u64,
    pub parts: u64,
}

/// `POST /room-library/:room/disk` `{item_id}`.
pub async fn add_to_room(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, role) = match crate::plugin_blob::room_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    // A group's materials are its admins' to add (the core's rule, `library/publish.rs`).
    if !is_group_admin(&role) {
        return json_err(403, "not_admin");
    }
    let Ok(body) = req.json::<AddBody>().await else {
        return json_err(400, "bad_request");
    };
    if !valid_item_id(&body.item_id) {
        return json_err(400, "bad_id");
    }
    let db = ctx.env.d1("DB")?;
    match admit_item(&ctx.env, &db, &room_id, &body.item_id, &user_id).await? {
        Ok(layout) => Response::from_json(&json!({
            "item_id": body.item_id,
            "size": layout.size,
            "part_size": layout.part_size,
            "parts": layout.parts,
        })),
        Err(resp) => Ok(resp),
    }
}

/// Make a prepared item's parts readable in `room_id`: its layout read from the GATEWAY (never a
/// caller's word), checked, and one `room_library_disk` row written while the group exists.
/// `Err(response)` is the refusal to answer with.
pub(crate) async fn admit_item(
    env: &Env,
    db: &D1Database,
    room_id: &str,
    item_id: &str,
    adder: &str,
) -> Result<std::result::Result<Layout, Response>> {
    let Ok(mut resp) = call(env, Method::Get, &format!("{BASE}/v1/item/{item_id}"), None, None).await
    else {
        return Ok(Err(unavailable()?));
    };
    match resp.status_code() {
        200 => {}
        404 => return Ok(Err(json_err(404, "disk/not-found")?)),
        _ => return Ok(Err(unavailable()?)),
    }
    let Ok(layout) = resp.json::<Layout>().await else {
        return Ok(Err(unavailable()?));
    };
    if !valid_layout(layout.size, layout.part_size, layout.parts) {
        return Ok(Err(json_err(502, "disk/bad-layout")?));
    }
    db.prepare(INSERT_ITEM_SQL)
        .bind(&[
            d1_text(room_id),
            d1_text(item_id),
            d1_text(adder),
            d1_int(layout.size as i64),
            d1_int(layout.part_size as i64),
            d1_int(layout.parts as i64),
            d1_int(now_secs() as i64),
        ])?
        .run()
        .await?;
    match load_item(db, room_id, item_id).await? {
        Some(_) => Ok(Ok(layout)),
        // Nothing written: the group was deleted in between.
        None => Ok(Err(json_err(403, "not_member")?)),
    }
}

/// A part of a disk item, for `GET /room-library/:room/:id` when the id names no stored object.
/// `None` = not a disk item of this room either (the caller answers 404).
pub(crate) async fn get_part(
    env: &Env,
    db: &D1Database,
    room_id: &str,
    object_id: &str,
    range: Option<&str>,
) -> Result<Option<Response>> {
    let Some((item_id, index)) = split_object_id(object_id) else { return Ok(None) };
    let Some(row) = load_item(db, room_id, item_id).await? else { return Ok(None) };
    let Some(size) = part_ciphertext_size(row.size_bytes as u64, row.part_size as u64, index)
        .filter(|_| index < row.parts as u64)
    else {
        return Ok(None);
    };
    let offset = match crate::instrument_pack::parse_range(range, size) {
        crate::instrument_pack::RangeAsk::Whole => 0,
        crate::instrument_pack::RangeAsk::From(n) => n,
        crate::instrument_pack::RangeAsk::Unsatisfiable => {
            let headers = Headers::new();
            headers.set("content-range", &format!("bytes */{size}"))?;
            return Ok(Some(Response::empty()?.with_status(416).with_headers(headers)));
        }
    };
    let url = format!("{BASE}/v1/part/{object_id}");
    let Ok(mut resp) = call(env, Method::Get, &url, None, Some(offset)).await else {
        return Ok(Some(unavailable()?));
    };
    let code = resp.status_code();
    let expected = if offset > 0 { 206 } else { 200 };
    if code != expected {
        // The file changed under its item (`disk/changed`), vanished, or the gateway erred:
        // its own word, with its own status.
        let body: serde_json::Value =
            resp.json().await.unwrap_or_else(|_| json!({ "error": "disk/unavailable" }));
        let status = if (400..600).contains(&code) { code } else { 503 };
        return Ok(Some(Response::from_json(&body)?.with_status(status)));
    }
    let sent = size - offset;
    crate::usage::count_bump(db, "download_count", 1).await;
    crate::usage::count_bump(db, "download_bytes", sent as i64).await;
    let headers = Headers::new();
    headers.set("content-type", "application/octet-stream")?;
    headers.set("content-length", &sent.to_string())?;
    headers.set("accept-ranges", "bytes")?;
    headers.set("cache-control", "private, no-store")?;
    let status = if offset > 0 {
        headers.set("content-range", &format!("bytes {offset}-{}/{size}", size - 1))?;
        206
    } else {
        200
    };
    let stream = crate::storage::BlobStream::Pumped(resp.stream()?);
    Ok(Some(stream.into_response(status, headers)?))
}

/// A DELETE of a disk item's part, when the id names no stored object: the item leaves the room
/// (its first part's delete takes the row, the rest find nothing). The file stays on the disk.
/// `None` = not a disk item of this room.
pub(crate) async fn delete_part(
    db: &D1Database,
    room_id: &str,
    object_id: &str,
    user_id: &str,
    role: &str,
) -> Result<Option<Response>> {
    let Some((item_id, _)) = split_object_id(object_id) else { return Ok(None) };
    let Some(row) = load_item(db, room_id, item_id).await? else { return Ok(None) };
    if row.adder_id != user_id && !is_group_admin(role) {
        return Ok(Some(json_err(403, "not_uploader_or_admin")?));
    }
    db.prepare(DELETE_ITEM_SQL)
        .bind(&[d1_text(room_id), d1_text(item_id)])?
        .run()
        .await?;
    Ok(Some(crate::respond::no_content()?))
}

#[cfg(test)]
#[path = "disk_tests.rs"]
mod tests;
