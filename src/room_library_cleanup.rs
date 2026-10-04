//! The group library's ways out: the daily retention sweep, and the statements the three
//! teardowns borrow — deleting a group (`groups_delete.rs`), deleting an account that closes its
//! groups (`membership.rs`) and wiping the server (`admin/reset.rs`).
//!
//! The teardown SQL lives here, beside the class, rather than in each teardown, because every
//! statement spells the store key by hand (`'room-library/' || room_id || '/' || object_id`, the
//! shape of `storage::library_key`) and one spelling is easier to keep right than three.
//!
//! Every teardown follows `groups_delete.rs`'s rule: the blobs go into `storage_orphans` in the
//! SAME batch, and BEFORE, the statement that drops the rows naming them — the orphan statement
//! reads the very rows the delete removes. The daily `retry_orphans` then deletes them from the
//! store.

use serde::Deserialize;
use worker::*;

use crate::d1util::{d1_int, d1_text};
use crate::storage::{library_key, StorageRouter};
use crate::utils::now_secs;

/// Expired parts handled per daily run. Each costs one store delete (a subrequest), so the
/// bound is what keeps the daily set inside its budget beside the media sweep; a larger expiry
/// wave — a whole semester reaching its retention on one day — converges over the following
/// days, and an expired part is unreadable (`410 expired`) and unlisted from the moment it
/// expires, so the only cost of waiting is bytes still on disk.
const SWEEP_LIMIT: i64 = 100;

// ── The daily sweep ─────────────────────────────────────────────────────────────────────

/// The oldest-expiring parts past their retention. Binds: now, limit. Reads only the partial
/// index `idx_room_library_expiry`: keep-forever rows are not in it.
pub(crate) const EXPIRED_BATCH_SQL: &str = "SELECT room_id, object_id, size_bytes, store_id \
     FROM room_library_objects WHERE expires_at IS NOT NULL AND expires_at < ? \
     ORDER BY expires_at LIMIT ?";

/// Drop one swept row — only if it is still expired AND still on the store whose blob was just
/// deleted. The store condition is the drain's race (`storage/drain.rs`): a part moved to another
/// store between the SELECT and here keeps its row, and the next sweep deletes it where it now
/// lives instead of leaving its new copy behind with nothing naming it. RETURNING counts what
/// actually left, for the counters. Binds: room, id, now, store.
pub(crate) const DELETE_EXPIRED_SQL: &str = "DELETE FROM room_library_objects \
     WHERE room_id = ? AND object_id = ? AND expires_at IS NOT NULL AND expires_at < ? \
       AND store_id = ? RETURNING size_bytes";

/// The library's retention sweep — a leg of `maintenance::run_daily`. Returns how many parts it
/// removed.
///
/// BLOB FIRST, row second — the media sweep's order (`maintenance::cleanup_expired`), for the
/// media sweep's reason: the expired ROW is the work queue. If the worker dies after a blob
/// delete and before the row delete, the row is still expired, still unreadable, and the next
/// run deletes the (already absent) blob again — deletes are idempotent — and then the row. The
/// opposite order would leave a blob that nothing names. A blob that cannot be deleted becomes a
/// `storage_orphans` tombstone and its row still goes, as in the media sweep.
pub(crate) async fn sweep_expired(env: &Env) -> Result<usize> {
    #[derive(Deserialize)]
    struct Row {
        room_id: String,
        object_id: String,
        size_bytes: i64,
        store_id: String,
    }
    let db = env.d1("DB")?;
    let now = now_secs() as i64;
    let rows: Vec<Row> = db
        .prepare(EXPIRED_BATCH_SQL)
        .bind(&[d1_int(now), d1_int(SWEEP_LIMIT)])?
        .all()
        .await?
        .results()?;
    if rows.is_empty() {
        return Ok(0);
    }
    let router = StorageRouter::from_env(env).await?;
    let mut orphans: Vec<(String, String, i64)> = Vec::new();
    for r in &rows {
        let key = library_key(&r.room_id, &r.object_id);
        // No `any_available` short-cut, unlike the media sweep: a part on a DISABLED store is
        // still deletable there (the router keeps disabled stores for reads and deletes), and a
        // store that cannot be reached at all leaves a tombstone instead of a forgotten blob.
        if router.delete(&r.store_id, &key).await.is_err() {
            orphans.push((r.store_id.clone(), key, r.size_bytes));
        }
    }
    if !orphans.is_empty() {
        crate::storage::maint::insert_orphans(&db, &orphans).await;
        let mut marked: Vec<&str> = Vec::new();
        for (sid, _, _) in &orphans {
            if !marked.contains(&sid.as_str()) {
                marked.push(sid);
                crate::storage::write_health(env, sid, false, Some("delete_failed_library_sweep"))
                    .await;
            }
        }
    }
    let mut stmts = Vec::with_capacity(rows.len());
    for r in &rows {
        stmts.push(db.prepare(DELETE_EXPIRED_SQL).bind(&[
            d1_text(&r.room_id),
            d1_text(&r.object_id),
            d1_int(now),
            d1_text(&r.store_id),
        ])?);
    }
    #[derive(Deserialize)]
    struct Removed {
        size_bytes: i64,
    }
    let mut bytes = 0i64;
    let mut count = 0i64;
    for res in db.batch(stmts).await? {
        for removed in res.results::<Removed>().unwrap_or_default() {
            bytes += removed.size_bytes;
            count += 1;
        }
    }
    crate::usage::library_removed(&db, bytes, count).await;
    console_log!("cleanup: {} expired library parts removed", count);
    Ok(count as usize)
}

// ── Teardown statements ─────────────────────────────────────────────────────────────────

/// One room's parts → `storage_orphans`. Binds: now, room. `INSERT OR IGNORE`: the outbox is keyed
/// `(store_id, key)`, so a replayed teardown cannot multiply rows.
pub(crate) const ORPHAN_ROOM_SQL: &str =
    "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
     SELECT store_id,'room-library/' || room_id || '/' || object_id,size_bytes,?,0
       FROM room_library_objects WHERE room_id = ?";

/// Give one room's bytes back to the server total in the same transaction that drops them, so an
/// operator who deletes a large course to make room can upload again at once instead of after the
/// next daily reconcile. Binds: room, room. Runs BEFORE [`DELETE_ROOM_SQL`] (it sums those rows).
pub(crate) const RELEASE_ROOM_SQL: &str = "UPDATE server_stats SET
       media_bytes = MAX(0, media_bytes -
         (SELECT COALESCE(SUM(size_bytes), 0) FROM room_library_objects WHERE room_id = ?)),
       media_count = MAX(0, media_count -
         (SELECT COUNT(*) FROM room_library_objects WHERE room_id = ?))
     WHERE id = 1";

/// Drop one room's rows. Binds: room.
pub(crate) const DELETE_ROOM_SQL: &str = "DELETE FROM room_library_objects WHERE room_id = ?";

/// The account-deletion shape: every part whose group no longer exists. It runs AFTER the
/// statement that closes the departing account's groups, inside the same batch, so it sees
/// exactly the rooms that just closed — and not the rooms the account merely uploaded into: a
/// library belongs to its group and outlives the person who pressed record. No binds beyond now.
pub(crate) const ORPHAN_ROOMLESS_SQL: &str =
    "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
     SELECT store_id,'room-library/' || room_id || '/' || object_id,size_bytes,?,0
       FROM room_library_objects l
      WHERE NOT EXISTS (SELECT 1 FROM groups g WHERE g.id = l.room_id)";

/// [`RELEASE_ROOM_SQL`] for the rows [`ORPHAN_ROOMLESS_SQL`] just queued. No binds.
pub(crate) const RELEASE_ROOMLESS_SQL: &str = "UPDATE server_stats SET
       media_bytes = MAX(0, media_bytes -
         (SELECT COALESCE(SUM(size_bytes), 0) FROM room_library_objects l
           WHERE NOT EXISTS (SELECT 1 FROM groups g WHERE g.id = l.room_id))),
       media_count = MAX(0, media_count -
         (SELECT COUNT(*) FROM room_library_objects l
           WHERE NOT EXISTS (SELECT 1 FROM groups g WHERE g.id = l.room_id)))
     WHERE id = 1";

/// Drop the rows [`ORPHAN_ROOMLESS_SQL`] queued. No binds.
pub(crate) const DELETE_ROOMLESS_SQL: &str = "DELETE FROM room_library_objects
      WHERE NOT EXISTS (SELECT 1 FROM groups g WHERE g.id = room_library_objects.room_id)";

/// The server wipe: every part. Binds: now.
pub(crate) const ORPHAN_ALL_SQL: &str =
    "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
     SELECT store_id,'room-library/' || room_id || '/' || object_id,size_bytes,?,0
       FROM room_library_objects";

#[cfg(test)]
#[path = "room_library_cleanup_tests.rs"]
mod tests;
