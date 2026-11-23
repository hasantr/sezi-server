//! Storing one media blob: its `media_objects` row first, the counters, then the store, and the row
//! undone if no store took it. The member upload (`handlers.rs` `upload`) and a bot's document
//! (`bots/api_document.rs`) go through this one path, so the meta-first discipline and the
//! rollback are written once.

use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::utils::now_secs;
use uuid::Uuid;
use worker::*;

/// Store `bytes` as a new blob uploaded by `uploader`, readable as `scope` says (`("peer",
/// user)`, `("room", group)`, or `None` = the uploader alone). `Ok(Ok(id))`, or `Ok(Err(answer))`
/// with the placement refusal to hand on (all stores full, all failing).
pub(crate) async fn store_media_blob(
    env: &Env,
    db: &D1Database,
    router: &crate::storage::StorageRouter,
    uploader: &str,
    scope: Option<(&str, &str)>,
    bytes: Vec<u8>,
    content_type: &str,
) -> Result<std::result::Result<String, Response>> {
    let size = bytes.len() as i64;
    let id = Uuid::new_v4().to_string();
    let now = now_secs();
    // The retention window is owner-configured and read from the SAME source as the /capabilities
    // announcement, so the advertised "kept this long" matches actual behaviour.
    let retention_days = crate::server::handlers::fetch_retention_days(env).await as u64;
    // The D1 meta BEFORE the store PUT: if the PUT then fails, the row is undone below (or swept
    // at expiry); PUT-then-INSERT with a failing INSERT would leave a blob cleanup never sees.
    db.prepare(
        "INSERT INTO media_objects (blob_id, uploader_id, size_bytes, created_at, expires_at, content_type, scope_kind, scope_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&id),
        d1_text(uploader),
        d1_int(size),
        d1_int(now as i64),
        d1_int((now + retention_days * 24 * 3600) as i64),
        d1_text(content_type),
        d1_opt_text(scope.map(|s| s.0)),
        d1_opt_text(scope.map(|s| s.1)),
    ])?
    .run()
    .await?;
    // The row is the counters' truth (the daily reconcile recomputes from it); best-effort.
    crate::usage::media_added(db, uploader, size).await;
    crate::usage::count_bump(db, "upload_bytes", size).await;
    crate::usage::count_bump(db, "upload_count", 1).await;
    let store_id = match router
        .put_new(crate::storage::StorageClass::Media, &crate::storage::media_key(&id), bytes, content_type)
        .await
    {
        Ok(sid) => sid,
        Err(e) => {
            // No placement failure wrote a blob: undo the row and the counter at once, or the
            // reconcile counts a blob that does not exist against the uploader's quota.
            db.prepare("DELETE FROM media_objects WHERE blob_id = ?")
                .bind(&[d1_text(&id)])?
                .run()
                .await
                .ok();
            crate::usage::media_removed(db, &[(uploader.to_string(), size)]).await;
            return Ok(Err(crate::storage::placement_err_response(e)?));
        }
    };
    // The row landed with the primary store as its DEFAULT; a write elsewhere corrects it.
    if store_id != crate::storage::PRIMARY_STORE_ID {
        db.prepare("UPDATE media_objects SET store_id = ? WHERE blob_id = ?")
            .bind(&[d1_text(&store_id), d1_text(&id)])?
            .run()
            .await?;
    }
    Ok(Ok(id))
}
