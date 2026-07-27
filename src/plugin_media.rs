//! Member-uploadable PERSISTENT plugin-MEDIA blob channel — the member-PUT, large-payload
//! sibling of the `plugin_blob` (plugin CODE) pattern.
//!
//! A deliberate hybrid sitting BETWEEN the two existing channels:
//!   - INHERITED from `plugin_blob`: room-scoped R2 key (IDOR closed) + active-membership +
//!     device-revoked gate (the SHARED `plugin_blob::gate`) + PERSISTENT (no TTL, no ack-delete).
//!   - INHERITED from `media`: the 50 MiB ceiling + quota/usage accounting (the SAME
//!     `check_upload` / `media_added` / `count_bump` counters → the storage cap applies to the SUM
//!     of both channels).
//!
//! The one place it DIVERGES from `plugin_blob`: there is NO admin gate. Any active member may
//! upload, because this is user-generated media inside a plugin (photos/files). CODE is
//! admin-only (to close the "overwrite legit code" DoS); MEDIA is user data → member PUT.
//!
//! The server is BLIND: request and response bodies are opaque ciphertext (the client encrypts
//! end-to-end; the key travels on the group channel). Meta lives in `plugin_media_objects` (0026),
//! SEPARATE from `media_objects`: it has no `expires_at` (persistent, and the daily cleanup cron
//! never touches this table) → the quota reconcile sums both tables (see
//! `usage::reconcile_storage`).

use crate::d1util::{d1_int, d1_text};
use crate::plugin_blob::gate;
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// Blob ceiling for member plugin media — the SAME as the `media` channel (50 MiB). The
/// end-to-end ciphertext body may fill this raw ceiling (the client keeps the plaintext below it
/// anyway).
const MAX_PLUGIN_MEDIA_SIZE: u64 = 50 * 1024 * 1024;

/// `POST /plugin-media/:room/:id` — upload (encrypted) member plugin media. PERSISTENT.
/// Auth: ANY active member of that room (admin NOT required). Quota and usage land on the SAME
/// counters as `media`. Idempotent: the same (room,id) again → 200 with NO re-upload.
pub async fn put_media(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Gate: active member + device-revoked (SHARED with plugin_blob). `role` is IGNORED — admin is
    // not required (like media, any member may upload); an Ok from the gate already proves
    // membership.
    let (user_id, room_id, blob_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Lite install (R2 is OPTIONAL): with no binding, answer a clean 503 (symmetric with
    // media/plugin_blob; the client treats it as nonretryable). AFTER the authorization gate,
    // BEFORE the rate limit and the body read.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Per-user upload rate limit — the SAME constants as media upload (60 per 5 min) on the SAME
    // infrastructure (KV is optional; with no binding it fails open, i.e. unlimited). Guards
    // against R2 storage/egress DoS.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plugmedia:put:{user_id}"), 60, 5 * 60).await {
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
    if size == 0 || size > MAX_PLUGIN_MEDIA_SIZE {
        return json_err(413, "bad_size");
    }
    let db = ctx.env.d1("DB")?;
    // IDEMPOTENT (retry-safe): if that (room,id) already exists, return 200 — the client generates
    // blob_id RANDOMLY (metadata privacy; it is not content-addressed), so in practice a collision
    // only ever means a retry. No re-upload (the 50 MiB body is never read) and no double counting
    // of quota (check_upload is not even reached). Consistent with plugin_blob's overwrite
    // idempotency and the core client's "2xx = success" contract.
    if let Some(existing) = existing_size(&db, &room_id, &blob_id).await? {
        return Response::from_json(&serde_json::json!({ "id": blob_id, "size": existing }));
    }
    // Quota Faz-1a (ENFORCEMENT): the SAME check_upload as `media` (server_stats + user_storage vs
    // the owner's caps). FAIL-OPEN: if a cap or counter cannot be read, nothing is rejected; a NULL
    // cap means unlimited. Runs BEFORE the body is buffered — no point holding 50 MiB we are about
    // to reject.
    if let Some(scope) = crate::quota::check_upload(&db, &user_id, size as i64).await {
        let resp = Response::from_json(&serde_json::json!({ "error": "quota_exceeded", "scope": scope }))?;
        return Ok(resp.with_status(429));
    }
    let bytes = req.bytes().await?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PLUGIN_MEDIA_SIZE {
        return json_err(413, "bad_size");
    }
    // BLOB FIRST, meta second — deliberately the OPPOSITE of `media`, because plugin-media has no
    // TTL/cleanup cron. `media` writes meta first since its cleanup is D1-driven (blob-first would
    // leave a meta-less blob that the cron never sees = orphan). Here there is no cleanup at all,
    // so a phantom meta row left behind by a failed PUT would mean permanent quota inflation plus a
    // GET that 404s. Hence meta is written only after a successful put_new → no phantom meta can
    // exist; a failed meta write self-heals on the client's retry (R2 overwrite is idempotent and
    // the meta INSERT simply runs again). put_new returns the store_id it wrote to (Faz 1 single
    // backend: 'r2-primary'). FAZ 3: priority overflow + per-backend max_bytes + PUT fallback
    // (degraded write). This is a persistent class, so a full backend gives 429
    // quota_exceeded/server_storage and "every attempt failed the PUT" gives 503.
    let store_id = match router
        .put_new(
            crate::storage::StorageClass::PluginMedia,
            &crate::storage::plugin_media_key(&room_id, &blob_id),
            bytes,
            "application/octet-stream",
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => return crate::storage::placement_err_response(e),
    };
    // The meta INSERT is the source of truth for quota (reconcile recomputes from it). ON CONFLICT
    // DO NOTHING RETURNING means only a row that was ACTUALLY inserted bumps the counters: of two
    // concurrent PUTs — even if both passed the existence check — one loses, so nothing is counted
    // twice.
    if insert_meta(&db, &room_id, &blob_id, &user_id, size as i64, &store_id).await? {
        // Quota Faz-0 (SHADOW) + Faz-1c (COUNTING ONLY): the SAME counters as media. BEST-EFFORT —
        // a counter failure does NOT break the upload, and the daily reconcile repairs the drift.
        crate::usage::media_added(&db, &user_id, size as i64).await;
        crate::usage::count_bump(&db, "upload_bytes", size as i64).await;
        crate::usage::count_bump(&db, "upload_count", 1).await;
    }
    Response::from_json(&serde_json::json!({ "id": blob_id, "size": size }))
}

/// `GET /plugin-media/:room/:id` — download (encrypted) member plugin media. Gated on active
/// membership + device-revoked (the plugin_blob GET pattern). Rate limit 600 per 5 min, matching
/// media download.
pub async fn get_media(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, blob_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Lite install: with no binding, the same 503 as put.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Per-user download rate limit — the SAME as media download (600 per 5 min; R2-egress DoS guard).
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plugmedia:get:{user_id}"), 600, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    // Faz 2 multi-backend: resolve the blob's backend from the meta row
    // (plugin_media_objects.store_id). Migration 0028 gave that column a DEFAULT of 'r2-primary', so
    // OLD rows are populated too, and put ALWAYS writes a store_id (this channel needs no backfill)
    // → no meta row means the blob was never uploaded → 404.
    let db = ctx.env.d1("DB")?;
    let store_id = match media_store_id(&db, &room_id, &blob_id).await? {
        Some(s) => s,
        None => return json_err(404, "not_found"),
    };
    // FAZ 3 (plan f#2): backend unreachable → 503 storage_backend_unavailable plus the router's
    // opportunistic health mark; blob absent → 404.
    match router
        .get(
            &store_id,
            &crate::storage::plugin_media_key(&room_id, &blob_id),
        )
        .await
    {
        Ok(Some(obj)) => {
            let bytes = obj.bytes;
            // Quota Faz-1c (COUNTING ONLY): only a SUCCESSFUL download hits the daily counters, as
            // with media. The bytes are already in hand (no extra query). BEST-EFFORT — a counter
            // failure never breaks the download.
            let n = bytes.len() as i64;
            crate::usage::count_bump(&db, "download_count", 1).await;
            crate::usage::count_bump(&db, "download_bytes", n).await;
            let mut resp = Response::from_bytes(bytes)?;
            let headers = resp.headers_mut();
            headers.set("content-type", "application/octet-stream")?;
            headers.set("cache-control", "private, no-store")?;
            Ok(resp)
        }
        Ok(None) => json_err(404, "not_found"),
        Err(_) => json_err(503, "storage_backend_unavailable"),
    }
}

/// The blob's backend (plugin_media_objects.store_id) — Faz 2 multi-backend GET resolution.
/// No meta row → None (the blob was never uploaded → the caller 404s). On a single-backend install
/// this is always 'r2-primary'.
async fn media_store_id(db: &D1Database, room_id: &str, blob_id: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct StoreRow {
        store_id: String,
    }
    let row: Option<StoreRow> = db
        .prepare("SELECT store_id FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? LIMIT 1")
        .bind(&[d1_text(room_id), d1_text(blob_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.store_id))
}

/// Does a meta row for (room,id) exist? Returns its `size_bytes` if so (the idempotent-PUT
/// short-circuit).
async fn existing_size(db: &D1Database, room_id: &str, blob_id: &str) -> Result<Option<i64>> {
    #[derive(Deserialize)]
    struct SizeRow {
        size_bytes: i64,
    }
    let row: Option<SizeRow> = db
        .prepare("SELECT size_bytes FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? LIMIT 1")
        .bind(&[d1_text(room_id), d1_text(blob_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.size_bytes))
}

/// Write the meta row; returns whether it was ACTUALLY inserted. `ON CONFLICT DO NOTHING
/// RETURNING` gives race-safe double-count protection: the losing isolate gets 0 rows back and
/// SKIPS the counter bump.
async fn insert_meta(
    db: &D1Database,
    room_id: &str,
    blob_id: &str,
    uploader_id: &str,
    size: i64,
    store_id: &str,
) -> Result<bool> {
    #[derive(Deserialize)]
    struct IdRow {
        #[allow(dead_code)]
        blob_id: String,
    }
    let now = now_secs() as i64;
    let res = db
        .prepare(
            "INSERT INTO plugin_media_objects (room_id, blob_id, uploader_id, size_bytes, store_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(room_id, blob_id) DO NOTHING \
             RETURNING blob_id",
        )
        .bind(&[
            d1_text(room_id),
            d1_text(blob_id),
            d1_text(uploader_id),
            d1_int(size),
            d1_text(store_id),
            d1_int(now),
        ])?
        .all()
        .await?;
    Ok(res.results::<IdRow>().map(|r| !r.is_empty()).unwrap_or(false))
}
