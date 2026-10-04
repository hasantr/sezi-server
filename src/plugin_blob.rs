//! Plugin CODE blob storage — a PERSISTENT, group-gated R2 blob.
//!
//! Plugin code (html/bundle) is not carried inline on the wire — the 64KB envelope makes a large
//! web app impossible — so it sits ENCRYPTED in a persistent R2 blob and devices download it.
//! Kept SEPARATE from the media path (`media/handlers.rs`) because the semantics are the opposite:
//!   - No ack-delete and no TTL: code lives for years and every new device/member downloads it again.
//!   - IDOR closed at the key: it is **room-scoped** (`plugin-code/{room}/{id}`) and every access
//!     passes the active-membership + device-revoked gate. Media cannot do this — it has no
//!     recipient/room relation on the server — but here the room is in the path.
//!
//! The server is BLIND: the blob is opaque ciphertext (XChaCha20-Poly1305 STREAM, with the key only
//! ever on the group E2E channel — `PluginCodeRefV1.key_b64` inside the Olm/epoch-key protected
//! wire). The server CANNOT read the code; integrity is double-checked on the client via
//! `blob_hash` (BLAKE3) and the AEAD tag.

use crate::auth::middleware::{device_revoked, require_auth_device};
use crate::d1util::{d1_int, d1_text};
use crate::groups::{group_role, is_group_admin};
use crate::respond::json_err;
use crate::utils::now_secs;
use worker::*;

/// Ceiling for a plugin-code blob — enough for a large web bundle, below the 50MB media limit, and a
/// DoS bound. Core's assign path caps the plaintext at 8 MiB, while XChaCha20-STREAM ciphertext adds
/// ~16B of tag overhead per chunk (~2KB for 8 MiB), so 64 KiB of headroom is added — without it,
/// code sitting exactly at the 8 MiB plaintext limit gets a 413 from the worker.
const MAX_CODE_SIZE: u64 = 8 * 1024 * 1024 + 64 * 1024;

/// The shared precondition gate: JWT + device-revoked + path params + active membership.
/// Ok → (user, room, id, role) — `role` feeds the admin check in PUT.
///
/// `pub(crate)` because `plugin_media` (the member-PUT sibling channel) reuses the SAME gate
/// (device-revoked + active membership); it has no admin check and simply ignores `role`. Defining
/// the IDOR/revoke gate once keeps the two channels from diverging. `room_library` reuses it too.
pub(crate) async fn gate(req: &Request, ctx: &RouteContext<()>) -> std::result::Result<(String, String, String, String), Response> {
    let (user_id, room_id, role) = room_gate(req, ctx).await?;
    let blob_id = match ctx.param("id") {
        Some(p) => p.clone(),
        None => return Err(json_err(400, "bad_request").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    Ok((user_id, room_id, blob_id, role))
}

/// `gate` for a route that names a room and no object — the group library's listing. The same
/// checks in the same order; only the `:id` parameter is not asked for. Ok → (user, room, role).
pub(crate) async fn room_gate(req: &Request, ctx: &RouteContext<()>) -> std::result::Result<(String, String, String), Response> {
    // Device binding + revoked: a removed or revoked device must not be able to fetch or upload
    // code for the remaining lifetime of its token.
    let (user_id, device_id) = require_auth_device(req, &ctx.env)?;
    // 503, NOT 500, for every transient dependency failure in this gate — and the same spelling
    // the rest of the worker uses. A failed revoke check is "ask again shortly", which is what a
    // client's retry classification keys on; 500 says "this request is broken, do not repeat it",
    // so a D1 wobble would turn a retryable blip into a hard plugin-code failure. `groups.rs`
    // answers `503 revoke_check_unavailable` for this exact check, `auth/middleware.rs` answers
    // `503 auth_check_unavailable`.
    match device_revoked(&ctx.env, &user_id, &device_id).await {
        Ok(true) => return Err(json_err(401, "device_revoked").unwrap_or_else(|_| Response::empty().unwrap())),
        Ok(false) => {}
        Err(_) => return Err(json_err(503, "revoke_check_unavailable").unwrap_or_else(|_| Response::empty().unwrap())),
    }
    let room_id = match ctx.param("room") {
        Some(r) => r.clone(),
        None => return Err(json_err(400, "bad_request").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    // Active-membership gate (anti-IDOR: a non-member can neither fetch nor upload code).
    // Both of these are the same class as the revoke check above: the database is momentarily
    // unreachable, not the request malformed. 503 so the client retries instead of surfacing a
    // permanent failure. `not_member` stays 403 — that one IS a verdict about the caller.
    let db = match ctx.env.d1("DB") {
        Ok(d) => d,
        Err(_) => return Err(json_err(503, "db_unavailable").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    let role = match group_role(&db, &room_id, &user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(json_err(403, "not_member").unwrap_or_else(|_| Response::empty().unwrap())),
        Err(_) => return Err(json_err(503, "role_check_unavailable").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    Ok((user_id, room_id, role))
}

/// `POST /plugin-blob/:room/:id` — upload (encrypted) plugin code. PERSISTENT. Admins/owners only
/// (see the `is_group_admin` gate below); plain members can only GET.
pub async fn put_code(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, blob_id, role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Only an admin/owner may UPLOAD code (assigning a plugin is an admin action). If any member
    // could upload, a malicious one would OVERWRITE legit code with garbage → DoS. The client's
    // hash verification already stops code injection, but restricting upload rights is what closes
    // the overwrite DoS. Members only DOWNLOAD (GET).
    if !is_group_admin(&role) {
        return json_err(403, "not_admin");
    }
    // R2 is OPTIONAL: without the binding there is nowhere to put server-hosted code → the SAME
    // clean 503 as the media path (the client treats it as nonretryable). AFTER the authorization
    // check (403 before service state) but BEFORE the rate limit and the body read.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Per-user upload rate limit, guarding R2 storage/egress against DoS. The KV binding is
    // OPTIONAL: without it `check_rate_limit_env` fails open.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("pcode:put:{user_id}"), 60, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    // Size ceiling (content-length pre-check → reject a huge body before reading it).
    let size: u64 = req
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if size == 0 || size > MAX_CODE_SIZE {
        return json_err(413, "bad_size");
    }
    let bytes = req.bytes().await?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CODE_SIZE {
        return json_err(413, "bad_size");
    }
    // Priority overflow + per-backend max_bytes + PUT fallback. This is a persistent class, so a
    // full backend gives 429 quota_exceeded/server_storage (never an automatic delete) and
    // "every attempt failed" gives 503.
    let store_id = match router
        .put_new(
            crate::storage::StorageClass::PluginCode,
            &crate::storage::code_key(&room_id, &blob_id),
            bytes,
            "application/octet-stream",
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => return crate::storage::placement_err_response(e),
    };
    // Inventory (plugin_code_objects) — the meta record saying where this blob lives.
    // BEST-EFFORT: the put already succeeded, so a meta-DB failure does NOT break the upload, and
    // a missing row is picked up by the daily maintenance backfill (R2 list → INSERT OR IGNORE).
    // Deliberately NOT included in the quota counters. ON CONFLICT DO UPDATE refreshes
    // size/store_id when the code is overwritten with a new version.
    if let Ok(db) = ctx.env.d1("DB") {
        if let Ok(stmt) = db
            .prepare(
                "INSERT INTO plugin_code_objects (room_id, blob_id, uploader_id, size_bytes, store_id, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(room_id, blob_id) DO UPDATE SET \
                   uploader_id = excluded.uploader_id, size_bytes = excluded.size_bytes, store_id = excluded.store_id",
            )
            .bind(&[
                d1_text(&room_id),
                d1_text(&blob_id),
                d1_text(&user_id),
                d1_int(size as i64),
                d1_text(&store_id),
                d1_int(now_secs() as i64),
            ])
        {
            let _ = stmt.run().await;
        }
    }
    Response::from_json(&serde_json::json!({ "ok": true, "blob_id": blob_id }))
}

/// `GET /plugin-blob/:room/:id` — download (encrypted) plugin code. Active members only.
pub async fn get_code(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Download is open to EVERY active member (no admin requirement — members are the ones who run
    // the plugin).
    let (_user_id, room_id, blob_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Without the binding there is no code to download → the same 503 as put_code.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Resolve the blob's backend from the meta row. A code blob predating plugin_code_objects may
    // have no meta row until the daily backfill runs, so no meta → FALL BACK to 'r2-primary' (a
    // blob that old is always on R2). New put_code calls write the meta inline.
    let store_id = code_store_id(&ctx, &room_id, &blob_id)
        .await
        .unwrap_or_else(|| crate::storage::PRIMARY_STORE_ID.to_string());
    // Backend unreachable → 503 storage_backend_unavailable (retryable) plus the router's health
    // mark; blob absent → 404.
    match router
        .get(&store_id, &crate::storage::code_key(&room_id, &blob_id))
        .await
    {
        Ok(Some(obj)) => {
            let mut resp = Response::from_bytes(obj.bytes)?;
            resp.headers_mut()
                .set("content-type", "application/octet-stream")?;
            Ok(resp)
        }
        Ok(None) => json_err(404, "not_found"),
        Err(_) => json_err(503, "storage_backend_unavailable"),
    }
}

/// The code blob's backend (plugin_code_objects.store_id), for GET resolution. No meta row / a D1
/// error → None, and the caller falls back to 'r2-primary' (a not-yet backfilled blob is always on
/// R2). Best-effort: an error never breaks the GET, it just falls back.
async fn code_store_id(ctx: &RouteContext<()>, room_id: &str, blob_id: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct StoreRow {
        store_id: String,
    }
    let db = ctx.env.d1("DB").ok()?;
    let row: Option<StoreRow> = db
        .prepare("SELECT store_id FROM plugin_code_objects WHERE room_id = ? AND blob_id = ? LIMIT 1")
        .bind(&[d1_text(room_id), d1_text(blob_id)])
        .ok()?
        .first(None)
        .await
        .ok()?;
    row.map(|r| r.store_id)
}
