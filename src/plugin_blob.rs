//! Plugin CODE blob storage (Faz-4 server-code) — a PERSISTENT, group-gated R2 blob.
//!
//! Plugin code (html/bundle) is no longer carried inline on the wire (the 64KB envelope pain made
//! a large web app impossible); it sits ENCRYPTED in a persistent R2 blob on the server and devices
//! download it. Kept SEPARATE from the media path (`media/handlers.rs`) because the semantics are
//! the opposite:
//!   - No ack-delete and no TTL: code lives for years and every new device/member downloads it again.
//!   - IDOR closed: the R2 key is **room-scoped** (`plugin-code/{room}/{id}`) and every access
//!     passes the active-membership + device-revoked gate → the media M11 IDOR is NOT reproduced
//!     here (media has no recipient/room relation on the server; here the room is in the path and
//!     membership-gated).
//!
//! The server is BLIND: the blob is opaque ciphertext (XChaCha20-Poly1305 STREAM, with the key only
//! ever on the group E2E channel — `PluginCodeRefV1.key_b64` inside the Olm/epoch-key protected
//! wire). The server CANNOT read the code; integrity is double-checked on the client via
//! `blob_hash` (BLAKE3) and the AEAD tag.

use crate::auth::jwt::device_id_from_token;
use crate::auth::middleware::{device_revoked, extract_bearer, require_auth};
use crate::d1util::{d1_int, d1_text};
use crate::groups::{group_role, is_group_admin};
use crate::respond::json_err;
use crate::utils::now_secs;
use worker::*;

/// Ceiling for a plugin-code blob — enough for a large web bundle, below the 50MB media limit, and a
/// DoS bound. Core's assign path caps the plaintext at 8 MiB, while XChaCha20-STREAM ciphertext adds
/// ~16B of tag overhead per chunk (~2KB for 8 MiB), so 64 KiB of headroom is added to make sure valid
/// code sitting exactly at the 8 MiB plaintext limit can still be uploaded (Codex#10: without it,
/// borderline code got a 413 from the worker).
const MAX_CODE_SIZE: u64 = 8 * 1024 * 1024 + 64 * 1024;

/// The shared precondition gate: JWT + device-revoked + path params + active membership.
/// Ok → (user, room, id, role) — `role` feeds the admin check in PUT.
///
/// `pub(crate)` because `plugin_media` (the member-PUT sibling channel) reuses the SAME gate
/// (device-revoked + active membership); it has no admin check and simply ignores `role`. Defining
/// the IDOR/revoke gate once keeps the two channels from diverging.
pub(crate) async fn gate(req: &Request, ctx: &RouteContext<()>) -> std::result::Result<(String, String, String, String), Response> {
    let user_id = require_auth(req, &ctx.env)?;
    // Device binding + revoked (the B6 pattern): a removed or revoked device must not be able to
    // fetch or upload code for the remaining lifetime of its token.
    let token_device =
        extract_bearer(req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    let device_id = match token_device {
        Some(d) => d,
        None => return Err(json_err(403, "device_required").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    match device_revoked(&ctx.env, &user_id, &device_id).await {
        Ok(true) => return Err(json_err(401, "device_revoked").unwrap_or_else(|_| Response::empty().unwrap())),
        Ok(false) => {}
        Err(_) => return Err(json_err(500, "revoked_check_failed").unwrap_or_else(|_| Response::empty().unwrap())),
    }
    let room_id = match ctx.param("room") {
        Some(r) => r.clone(),
        None => return Err(json_err(400, "bad_request").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    let blob_id = match ctx.param("id") {
        Some(p) => p.clone(),
        None => return Err(json_err(400, "bad_request").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    // Active-membership gate (anti-IDOR: a non-member can neither fetch nor upload code).
    let db = match ctx.env.d1("DB") {
        Ok(d) => d,
        Err(_) => return Err(json_err(500, "db_unavailable").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    let role = match group_role(&db, &room_id, &user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(json_err(403, "not_member").unwrap_or_else(|_| Response::empty().unwrap())),
        Err(_) => return Err(json_err(500, "role_check_failed").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    Ok((user_id, room_id, blob_id, role))
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
    // Lite install (R2 is OPTIONAL): plugin code is stored in R2, so without the binding there is
    // nowhere to put server-hosted code → the SAME clean 503 as the media path (the client treats it
    // as nonretryable). AFTER the authorization check (403 before service state) but BEFORE the rate
    // limit and the body read.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Per-user upload rate limit (the media-upload pattern; guards R2 storage/egress against DoS).
    // The KV binding is OPTIONAL (template diet): without it we continue unlimited — see
    // ratelimit::check_rate_limit_env.
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
    // FAZ 3: priority overflow + per-backend max_bytes + PUT fallback. This is a persistent class, so
    // a full backend gives 429 quota_exceeded/server_storage (never an automatic delete) and
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
    // Inventory (plugin_code_objects, migration 0028) — the FIRST meta record for plugin code; until
    // now "where does this blob live" was unknowable. BEST-EFFORT: the put already succeeded, so a
    // meta-DB failure does NOT break the upload (put_code had no meta at all before, so a meta
    // failure never affected it = behaviour unchanged). A missing row is picked up by the daily
    // maintenance backfill (R2 list → INSERT OR IGNORE). NOT included in the quota counters (plan
    // c.3: user_storage/server_stats stay bit-identical). ON CONFLICT DO UPDATE refreshes
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
    // Lite install (R2 is OPTIONAL): without the binding there is no code to download → the same 503
    // as put_code.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Faz 2 multi-backend: resolve the blob's backend from the meta row. plugin_code_objects is NEW
    // as of Faz 1 (0028), so OLD code blobs may have no meta row until the daily backfill runs: no
    // meta → FALL BACK to 'r2-primary' (a legacy blob is always on R2, and after the backfill it
    // becomes meta-driven). New put_code calls write the meta inline, so they are meta-driven at once.
    let store_id = code_store_id(&ctx, &room_id, &blob_id)
        .await
        .unwrap_or_else(|| crate::storage::PRIMARY_STORE_ID.to_string());
    // FAZ 3 (plan f#2): backend unreachable → 503 storage_backend_unavailable (retryable) plus the
    // router's opportunistic health mark; blob absent → 404.
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

/// The code blob's backend (plugin_code_objects.store_id) — Faz 2 multi-backend GET resolution.
/// No meta row / a D1 error → None, and the caller falls back to 'r2-primary' (a legacy, not-yet
/// backfilled blob is always on R2). Best-effort: an error never breaks the GET, it just falls back.
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
