use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::respond::{json_err, json_err_msg};
use crate::utils::now_secs;
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

const MAX_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB

pub async fn upload(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };

    // Lite install (R2 is OPTIONAL): with no MEDIA binding the media path is off, so return
    // a clean 503 FIRST — after auth, but before rate-limit/quota/D1. The D1 insert is never
    // reached: a binding-less install produces no orphan meta rows and no inflated counters.
    // The client treats "media_not_configured" as nonretryable (op_result.rs): every attempt
    // stays 503 until the owner adds the binding from the dashboard, so retrying is pointless.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }

    // S2 (Fable HIGH — quota/DoS): per-user upload rate-limit. A steady stream of 50MB
    // uploads could run up the R2 storage + CF egress bill; media has no budget guard like
    // turn.rs. KV sliding-window (the SAME infrastructure as auth redeem/verify). 60 uploads
    // / 5min sits far above legitimate media sharing while cutting off automated abuse.
    // The KV binding is OPTIONAL (template diet): with none we continue unlimited — see
    // ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("media:upload:{user_id}"),
        60,
        5 * 60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }

    let size_str = req.headers().get("content-length").ok().flatten();
    let size: u64 = match size_str.and_then(|s| s.parse().ok()) {
        Some(n) if n > 0 && n <= MAX_SIZE => n,
        Some(_) => return json_err_msg(413, "bad_size", &MAX_SIZE.to_string()),
        None => return json_err(411, "content_length_required"),
    };

    // Quota Faz-1a (ENFORCEMENT): 429 when the owner set a cap and used+size exceeds it.
    // FAIL-OPEN: if the cap or the counter cannot be read we never reject (quota.rs); a NULL
    // cap means unlimited, so a default install behaves exactly as before. Checked BEFORE
    // the body is buffered — no point holding 50MiB we are about to reject.
    let db = ctx.env.d1("DB")?;
    if let Some(scope) = crate::quota::check_upload(&db, &user_id, size as i64).await {
        let resp =
            Response::from_json(&serde_json::json!({ "error": "quota_exceeded", "scope": scope }))?;
        return Ok(resp.with_status(429));
    }

    let content_type = req
        .headers()
        .get("content-type")
        .ok()
        .flatten()
        .unwrap_or_else(|| "application/octet-stream".into());

    // IDOR gate (audit #2): the uploader declares the target and download enforces it.
    // scope_kind='peer' (1:1, scope_id = the other user_id) | 'room' (group, scope_id =
    // group_id). No declaration (older client) → NULL → only the uploader can download
    // (fail-closed). The headers are set client-side (core upload_media).
    let scope_kind = req.headers().get("x-sezi-scope-kind").ok().flatten();
    let scope_id = req.headers().get("x-sezi-scope-id").ok().flatten();
    // Validation: kind ∈ {peer,room} and a non-empty id; otherwise both are NULL (fail-closed).
    let (scope_kind, scope_id) = match (scope_kind.as_deref(), scope_id.as_deref()) {
        (Some(k), Some(i)) if (k == "peer" || k == "room") && !i.is_empty() => {
            (Some(k.to_string()), Some(i.to_string()))
        }
        _ => (None, None),
    };

    // Read the body as bytes (50 MiB ceiling).
    let bytes = req.bytes().await?;

    let id = Uuid::new_v4().to_string();
    let now = now_secs();
    // The retention window is owner-configured (server_settings.retention_days) and read
    // from the SAME source as the /capabilities announcement, so the advertised "kept this
    // long" matches actual behaviour.
    let retention_days = crate::server::handlers::fetch_retention_days(&ctx.env).await as u64;

    // Write the D1 meta BEFORE the R2 PUT (correctness): if the PUT then fails, the meta row
    // is swept at expiry (download 404s; nothing is orphaned). With PUT-then-INSERT a failing
    // INSERT would leave a blob in R2 that cleanup — being D1-driven — would NEVER see: a
    // permanently orphaned blob.
    // store_id: migration 0028's DEFAULT ('r2-primary') labels existing rows correctly, so a
    // single-store install need not name it in the INSERT. content_type is kept in D1 for
    // type assurance on external backends (in Faz 1 the read path still uses whatever the
    // backend reports — behaviour-preserving; Faz 3 gives D1 priority).
    db.prepare(
        "INSERT INTO media_objects (blob_id, uploader_id, size_bytes, created_at, expires_at, content_type, scope_kind, scope_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&id),
        d1_text(&user_id),
        d1_int(size as i64),
        d1_int(now as i64),
        d1_int((now + retention_days * 24 * 3600) as i64),
        d1_text(&content_type),
        d1_opt_text(scope_kind.as_deref()),
        d1_opt_text(scope_id.as_deref()),
    ])?
    .run()
    .await?;

    // Bump the storage counters. These landed as Faz-0 shadow accounting, but they are no
    // longer observation-only: they are exactly what the Faz-1a enforcement check above
    // reads. The media_objects INSERT is the source of counter truth — the daily reconcile
    // recomputes from it — so the hook sits immediately after the INSERT: even if the R2 PUT
    // later fails, the meta row is removed by expiry-cleanup and the counter is decremented
    // there (consistent). BEST-EFFORT: a counter error NEVER breaks the upload (usage.rs
    // logs and carries on).
    crate::usage::media_added(&db, &user_id, size as i64).await;

    // Quota Faz-1c (COUNT-ONLY): daily volume counters for the "TODAY" section of
    // /admin/stats. Same discipline as media_added — BEST-EFFORT, never breaks the upload.
    crate::usage::count_bump(&db, "upload_bytes", size as i64).await;
    crate::usage::count_bump(&db, "upload_count", 1).await;

    // Write through the single choke-point (crate::storage StorageRouter), which returns the
    // store_id it actually wrote to. FAZ 3: priority overflow + per-store max_bytes + PUT
    // fallback (degraded write). All stores full → 429 quota_exceeded/server_storage; every
    // attempt failing its PUT → 503 upload_failed.
    let store_id = match router
        .put_new(
            crate::storage::StorageClass::Media,
            &crate::storage::media_key(&id),
            bytes,
            &content_type,
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => {
            // ROLLBACK (2026-07-10 audit HIGH): no put_new failure variant (AllFull /
            // AllFailed / NoActive) writes a blob, so the meta-first row and the quota
            // counters would describe something that does not exist. The old behaviour
            // ("expiry-cleanup will drop it") takes a whole retention window (~30 days by
            // default), and during that window the reconcile counts the row as REAL and can
            // lock the user out of their own quota (store-full scenario). So undo it at once:
            // delete the row and decrement the counter (media_removed clamps at 0).
            // Best-effort — the original error response is preserved, and even a failed
            // rollback still leaves expiry-cleanup as the last line of defence.
            db.prepare("DELETE FROM media_objects WHERE blob_id = ?")
                .bind(&[d1_text(&id)])?
                .run()
                .await
                .ok();
            crate::usage::media_removed(&db, &[(user_id.clone(), size as i64)]).await;
            return crate::storage::placement_err_response(e);
        }
    };
    // The meta INSERT landed with the store_id='r2-primary' DEFAULT; if put_new wrote to a
    // different store (Faz 2+ overflow/fallback) a single UPDATE corrects it — the meta-first
    // discipline is untouched (on PUT failure expiry-cleanup sweeps the row anyway). On a
    // Faz 1 single-store install store_id is always 'r2-primary' == DEFAULT, so the UPDATE
    // never runs: no extra D1 write, bit-identical behaviour.
    if store_id != crate::storage::PRIMARY_STORE_ID {
        db.prepare("UPDATE media_objects SET store_id = ? WHERE blob_id = ?")
            .bind(&[d1_text(&store_id), d1_text(&id)])?
            .run()
            .await?;
    }

    Response::from_json(&serde_json::json!({ "id": id, "size": size }))
}

#[derive(Deserialize)]
struct MediaRow {
    size_bytes: i64,
    expires_at: i64,
    // Pluggable storage: which store holds the blob → router.get routes there
    // (single-store Faz 1: always 'r2-primary').
    store_id: String,
    // IDOR gate (audit #2): the uploader can ALWAYS download, and so can the scope recipients.
    uploader_id: String,
    scope_kind: Option<String>,
    scope_id: Option<String>,
}

#[derive(Deserialize)]
struct OwnerRow {
    uploader_id: String,
    // The size is fetched too, so the ack-delete can decrement the storage counter.
    size_bytes: i64,
    // Pluggable storage: which store holds the blob → router.delete routes there
    // (single-store Faz 1: always 'r2-primary').
    store_id: String,
}

/// POST /media/:id/ack — the UPLOADER confirms the blob is no longer needed; the server
/// deletes the R2 blob and the D1 meta row IMMEDIATELY. This is the "being forgotten
/// here is the default" half of the vision: media leaves no trace on the server. If the
/// ack never arrives, the retention TTL sweeps it as a fallback (owner-configured
/// `server_settings.retention_days`, 30 by default).
///
/// An ack from anyone other than the uploader is a silent 204 no-op — see the S1 gate
/// below for why the ownership check exists.
///
/// Idempotent: called again it returns 204 (the R2 delete + DELETE are no-ops).
pub async fn ack(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let uid = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    // S1 (Fable HIGH — media IDOR / ack-delete): only the uploader may trigger the delete.
    // Because blob_id travels to EVERY group member in the Megolm manifest, without an
    // ownership gate a malicious member (or simply the first recipient to download) could
    // PERMANENTLY delete shared media via `POST /media/:id/ack` before anyone else fetched
    // it. A call from anyone but the uploader is a 204 no-op — silent, so it does not leak
    // whether the blob exists; the media is then cleaned up by the retention TTL (the client
    // already treats ack as fire-and-forget and expects the TTL fallback).
    let db = ctx.env.d1("DB")?;
    let owner: Option<OwnerRow> = db
        .prepare(
            "SELECT uploader_id, size_bytes, store_id FROM media_objects WHERE blob_id = ? LIMIT 1",
        )
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let row = match owner {
        Some(o) if o.uploader_id == uid => o, // authorized: the uploader → delete
        _ => return crate::respond::no_content(), // missing OR not the uploader → 204 no-op
    };
    // Delete the R2 blob first (correctness): a genuine R2 error propagates and the D1 meta
    // row is KEPT, which prevents an orphaned blob — the next ack or cleanup retries. R2
    // delete is idempotent, so a missing blob is not an error and a repeat call still 204s.
    // Only once that succeeds do we delete the D1 meta.
    // Lite-install edge: with NO binding (R2 may have been switched OFF from the dashboard
    // later, leaving meta rows behind in D1) the R2 delete is SKIPPED but the D1 meta delete
    // still happens — the blob is unreachable anyway, and keeping the meta only pollutes the
    // counters and cron. (If the binding comes back, that blob may sit orphaned in R2: an
    // accepted edge, since ack-delete is best-effort with a TTL fallback.)
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if router.any_available() {
        // FAZ 3 (plan f#3): on a store error, mark health opportunistically and propagate the
        // Err so the D1 meta STAYS (no orphaned blob; the next ack/TTL retries). This is a
        // single delete, hence a single health write — router.delete does not mark health
        // itself, so it is done here.
        if let Err(e) = router
            .delete(&row.store_id, &crate::storage::media_key(&id))
            .await
        {
            crate::storage::write_health(
                &ctx.env,
                &row.store_id,
                false,
                Some(&e.to_string().chars().take(120).collect::<String>()),
            )
            .await;
            return Err(e);
        }
    }
    db.prepare("DELETE FROM media_objects WHERE blob_id = ?")
        .bind(&[d1_text(&id)])?
        .run()
        .await?;
    // Storage counters (best-effort): subtract the deleted media, clamped at 0. A counter
    // error does not break the ack; the daily reconcile repairs any drift.
    crate::usage::media_removed(&db, &[(row.uploader_id, row.size_bytes)]).await;
    crate::respond::no_content()
}

/// GET /media/:id — download an opaque (E2E-encrypted) blob.
///
/// IDOR gate (audit #2 — FIXED 2026-07-10, migration 0029): download is gated by the
/// `scope_kind`/`scope_id` declared at upload time (uploader always; peer → the other
/// party; room → active member; NULL → uploader only). Layered defence: (1) the scope
/// gate below, (2) blob_id is an unguessable capability that exists only inside the E2E
/// manifest, (3) the blob is opaque ciphertext the downloader cannot decrypt, (4) an
/// expired blob 404s, closing the post-retention window.
pub async fn download(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let uid = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // Lite install (R2 is OPTIONAL): with no binding download is off too — a 503 symmetric
    // with upload, returned before we touch rate-limit or D1.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // W12 (media hardening, 2026-07-02): per-user DOWNLOAD rate-limit. Upload was gated at
    // 60/5min while download was UNLIMITED — an asymmetry. Download is the R2-EGRESS path, so
    // unlimited fetching runs up the CF egress bill: the very cost the upload guard protects
    // against, and media has no turn.rs-style budget. 600/5min sits above a legitimate
    // gallery-viewing burst (the sliding window is burst-tolerant) and cuts off runaway
    // egress DoS. A KV error fails open (lesson of 2026-06-28).
    // NOTE: this does NOT fix M11-IDOR (that is the cross-layer recipient/room-binding epic);
    // it is an egress-DoS defence.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("media:download:{uid}"),
        600,
        5 * 60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let meta: Option<MediaRow> = db
        .prepare("SELECT size_bytes, expires_at, store_id, uploader_id, scope_kind, scope_id FROM media_objects WHERE blob_id = ? LIMIT 1")
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let meta = match meta {
        Some(m) => m,
        None => return json_err(404, "not_found"),
    };
    // IDOR gate (audit #2, 2026-07-10): blob_id is already a capability carried in the E2E
    // manifest (an unguessable UUID) — but with no server-side authorization, anyone who
    // OBTAINED a blob_id (from a log, or as a member who has since left) could fetch it.
    // Hence the scope gate:
    //   • uploader → ALWAYS (their own blob; their other devices fetch it themselves).
    //   • scope 'peer' → the other party only (1:1).
    //   • scope 'room' → ACTIVE group members only (access ends when they leave).
    //   • scope NULL (undeclared/legacy) → uploader only (fail-closed).
    // 404 rather than 403 → do not leak whether the blob EXISTS (enumeration defence).
    if uid != meta.uploader_id {
        let allowed = match (meta.scope_kind.as_deref(), meta.scope_id.as_deref()) {
            (Some("peer"), Some(peer)) => uid == peer,
            (Some("room"), Some(room)) => crate::groups::group_role(&db, room, &uid)
                .await
                .ok()
                .flatten()
                .is_some(),
            _ => false,
        };
        if !allowed {
            return json_err(404, "not_found");
        }
    }
    // M11 (partial defence-in-depth — narrowing the IDOR window): never serve an EXPIRED
    // blob. Cleanup runs only from the daily cron (lib.rs), so a blob with expires_at < now
    // stayed downloadable in R2 for up to ~24 hours: post-retention exposure. Answer 404 for
    // an expired row (a legitimate recipient downloads WITHIN retention, so nothing breaks).
    // NOTE: this is NOT the full IDOR fix (see the scope gate above and the audit report);
    // it only pulls the window back to the retention boundary.
    if (meta.expires_at as u64) < now_secs() {
        return json_err(404, "not_found");
    }
    // Read through the single choke-point (crate::storage StorageRouter), from the blob's own
    // store. FAZ 3 (plan f#2): store unreachable → 503 storage_backend_unavailable
    // (retryable), the opportunistic health mark having ALREADY been done inside the router;
    // absent (None) → 404 not_found_r2.
    let obj = match router
        .get(&meta.store_id, &crate::storage::media_key(&id))
        .await
    {
        Ok(Some(o)) => o,
        Ok(None) => return json_err(404, "not_found_r2"),
        Err(_) => return json_err(503, "storage_backend_unavailable"),
    };

    // Quota Faz-1c (COUNT-ONLY): daily download counters — only a SUCCESSFUL download (the
    // R2 get returned) is counted; bytes comes from size_bytes in the D1 meta we already
    // have, so no extra query. BEST-EFFORT: a counter error never breaks the download.
    crate::usage::count_bump(&db, "download_count", 1).await;
    crate::usage::count_bump(&db, "download_bytes", meta.size_bytes).await;

    let headers = Headers::new();
    headers.set("content-type", &obj.content_type)?;
    headers.set("content-length", &meta.size_bytes.to_string())?;
    headers.set("cache-control", "private, no-store")?;

    let resp = Response::from_bytes(obj.bytes)?.with_headers(headers);
    Ok(resp)
}
