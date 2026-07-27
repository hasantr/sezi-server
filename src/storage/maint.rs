//! Storage-inventory maintenance jobs — invoked from the daily run (`maintenance::run_daily`).
//! Split out of the lazy-scheduling/cleanup core in `maintenance.rs` (file budget + single
//! responsibility): only inventory work specific to pluggable storage lives here.
//!   - `insert_orphans` — blobs that could not be deleted → a `storage_orphans` tombstone.
//!   - `retry_orphans`  — re-delete orphan tombstones (rows that succeed are dropped). Plan f#4.
//!   - `backfill_plugin_code` — backfill legacy `plugin-code/` blobs into `plugin_code_objects`.

use serde::Deserialize;
use worker::*;

use super::StorageRouter;
use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;

/// Tombstone blobs that could not be deleted into `storage_orphans` (Faz 3, plan f#4). Callers:
/// TTL cleanup, avatar replacement and the drain engine. Idempotent (`ON CONFLICT DO NOTHING`,
/// so a second run does not duplicate a row). One `db.batch` = one subrequest. Best-effort: a
/// failed orphan write never breaks the caller.
pub(crate) async fn insert_orphans(db: &D1Database, orphans: &[(String, String, i64)]) {
    let now = now_secs() as i64;
    let mut stmts: Vec<D1PreparedStatement> = Vec::new();
    for (store_id, key, size) in orphans {
        if let Ok(stmt) = db
            .prepare(
                "INSERT INTO storage_orphans (store_id, key, size_bytes, created_at, retry_count) \
                 VALUES (?, ?, ?, ?, 0) ON CONFLICT(store_id, key) DO NOTHING",
            )
            .bind(&[d1_text(store_id), d1_text(key), d1_int(*size), d1_int(now)])
        {
            stmts.push(stmt);
        }
    }
    if !stmts.is_empty() {
        let _ = db.batch(stmts).await;
    }
}

/// Retry orphan-blob tombstones (Faz 3, plan f#4). Re-delete the oldest ≤50 orphans through
/// the router: success (idempotent 204/404→Ok) DROPS the row; failure (backend still down, or a
/// deleted backend that no longer resolves) does `retry_count++` and keeps the row for the next
/// day. One batch turns all the drops and increments into a single subrequest. Router.delete
/// does no health marking on the bulk path, so this stays quiet (the owner sees health via the
/// manual probe).
pub(crate) async fn retry_orphans(env: &Env) -> Result<()> {
    #[derive(Deserialize)]
    struct OrphanRow {
        store_id: String,
        key: String,
    }
    let db = env.d1("DB")?;
    let rows: Vec<OrphanRow> = db
        .prepare("SELECT store_id, key FROM storage_orphans ORDER BY created_at ASC LIMIT 50")
        .all()
        .await?
        .results()?;
    if rows.is_empty() {
        return Ok(());
    }
    let router = StorageRouter::from_env(env).await?;
    let mut stmts: Vec<D1PreparedStatement> = Vec::new();
    for r in rows {
        let stmt = if router.delete(&r.store_id, &r.key).await.is_ok() {
            db.prepare("DELETE FROM storage_orphans WHERE store_id=? AND key=?")
        } else {
            db.prepare(
                "UPDATE storage_orphans SET retry_count = retry_count + 1 \
                 WHERE store_id=? AND key=?",
            )
        };
        if let Ok(s) = stmt.bind(&[d1_text(&r.store_id), d1_text(&r.key)]) {
            stmts.push(s);
        }
    }
    if !stmts.is_empty() {
        db.batch(stmts).await?;
    }
    Ok(())
}

/// Backfill the `plugin-code/` R2 blobs into the `plugin_code_objects` inventory (Faz 1).
/// Idempotent (INSERT OR IGNORE PRESERVES existing rows such as the inline put_code meta and
/// only fills the gaps; everything lands on 'r2-primary'). R2 list is paginated, so a run walks
/// a bounded number of pages with the cursor (free-plan subrequest budget) and the daily repeat
/// converges. One `db.batch` per page = one subrequest, not an INSERT per blob.
pub(crate) async fn backfill_plugin_code(env: &Env) -> Result<()> {
    // No binding (a Lite install) makes an R2 list impossible → exit quietly (nothing to index).
    let Ok(bucket) = env.bucket("MEDIA") else {
        return Ok(());
    };
    let db = env.d1("DB")?;
    let now = now_secs() as i64;
    // ≤5×1000 blobs per run; plugin code is rare in practice (only admins upload it), so most
    // installs finish in a single page.
    const MAX_PAGES: usize = 5;
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut listing = bucket.list().prefix("plugin-code/").limit(1000);
        if let Some(c) = cursor.take() {
            listing = listing.cursor(c);
        }
        let page = listing.execute().await?;
        let mut stmts: Vec<D1PreparedStatement> = Vec::new();
        for obj in page.objects() {
            let key = obj.key();
            let Some((room_id, blob_id)) = parse_code_key(&key) else {
                continue; // unexpected shape → skip
            };
            // uploader_id is unknown during a backfill → empty string (satisfies NOT NULL; the
            // inventory alone is what matters here). INSERT OR IGNORE leaves an existing
            // inline-meta row with the real uploader untouched.
            let stmt = db
                .prepare(
                    "INSERT OR IGNORE INTO plugin_code_objects \
                     (room_id, blob_id, uploader_id, size_bytes, store_id, created_at) \
                     VALUES (?, ?, ?, ?, 'r2-primary', ?)",
                )
                .bind(&[
                    d1_text(room_id),
                    d1_text(blob_id),
                    d1_text(""),
                    d1_int(obj.size() as i64),
                    d1_int(now),
                ])?;
            stmts.push(stmt);
        }
        if !stmts.is_empty() {
            db.batch(stmts).await?;
        }
        // Continue only while the listing is truncated AND hands back a cursor; otherwise done.
        match (page.truncated(), page.cursor()) {
            (true, Some(c)) => cursor = Some(c),
            _ => break,
        }
    }
    Ok(())
}

/// Extract (room, blob) from a "plugin-code/{room}/{blob}" R2 key — exactly the
/// `storage::code_key` scheme. Unexpected shapes (missing segment, a '/' inside blob) → None
/// (skip).
fn parse_code_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix("plugin-code/")?;
    let (room, blob) = rest.split_once('/')?;
    if room.is_empty() || blob.is_empty() || blob.contains('/') {
        return None;
    }
    Some((room, blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Key parsing for the plugin-code backfill: exactly the `storage::code_key` scheme
    /// ("plugin-code/{room}/{blob}"); unexpected shapes are skipped (None).
    #[test]
    fn parse_code_key_semasi() {
        assert_eq!(
            parse_code_key("plugin-code/room1/blob1"),
            Some(("room1", "blob1"))
        );
        // Wrong prefix / missing segment / empty segment / extra '/' inside blob → None.
        assert_eq!(parse_code_key("media/abc"), None);
        assert_eq!(parse_code_key("plugin-code/roomonly"), None);
        assert_eq!(parse_code_key("plugin-code//blob"), None);
        assert_eq!(parse_code_key("plugin-code/room/"), None);
        assert_eq!(parse_code_key("plugin-code/room/sub/blob"), None);
    }
}
