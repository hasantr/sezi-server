//! The library pin's admin half (0041). Placement itself is `router.rs` (`pinned_only`); this is
//! the one question the owner's DRAIN must ask because of it.
//!
//! While any store is pinned, a library part may only be placed on a pinned store — new uploads
//! and parts the drain moves alike. So draining the last ACTIVE pinned store would leave the
//! library nowhere it is allowed to go: every upload refused, and the drain stuck on its first
//! library part. Worse than stuck — the move engine stops its batch at the first part it cannot
//! place (`MoveOutcome::NoTarget`) and takes candidates oldest first, so a stranded library part
//! would hold every other class's blobs on that store too. `POST /admin/storage/:id/drain`
//! therefore refuses up front, as it already does when no active store at all would remain
//! (`409 no_active_target`): the owner pins another store, or clears the pin, first.

use serde::Deserialize;
use worker::*;

use crate::d1util::d1_text;

/// Everything the decision needs, in one read. Binds (numbered): the store about to drain.
pub(crate) const LIBRARY_DRAIN_SQL: &str = "SELECT \
       (SELECT COUNT(*) FROM storage_backends WHERE library_pin = 1) AS pinned, \
       (SELECT COUNT(*) FROM storage_backends \
         WHERE library_pin = 1 AND state = 'active' AND store_id != ?1) AS other_active_pinned, \
       COALESCE((SELECT library_pin FROM storage_backends WHERE store_id = ?1), 0) AS this_pinned, \
       EXISTS (SELECT 1 FROM room_library_objects WHERE store_id = ?1) AS holds_library";

/// Would draining this store strand the library? Only while the library is pinned at all, only
/// when no OTHER active pinned store would remain, and only when this store matters to the
/// library — it is pinned itself (new uploads would have nowhere to go) or it holds library parts
/// (they would have nowhere to move). An unpinned store holding no library parts drains as before.
pub(crate) fn drain_strands_library(
    pinned: i64,
    other_active_pinned: i64,
    this_pinned: bool,
    holds_library: bool,
) -> bool {
    pinned > 0 && other_active_pinned == 0 && (this_pinned || holds_library)
}

/// The D1 half of [`drain_strands_library`].
pub(crate) async fn drain_would_strand_library(db: &D1Database, store_id: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct Row {
        pinned: i64,
        other_active_pinned: i64,
        this_pinned: i64,
        holds_library: i64,
    }
    let row: Option<Row> = db
        .prepare(LIBRARY_DRAIN_SQL)
        .bind(&[d1_text(store_id)])?
        .first(None)
        .await?;
    Ok(row.is_some_and(|r| {
        drain_strands_library(
            r.pinned,
            r.other_active_pinned,
            r.this_pinned != 0,
            r.holds_library != 0,
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    #[test]
    fn a_drain_strands_the_library_only_when_nothing_pinned_would_remain() {
        // Nothing pinned: the pin is not in play at all.
        assert!(!drain_strands_library(0, 0, false, true));
        // The last active pinned store, pinned itself: uploads would have nowhere to go.
        assert!(drain_strands_library(1, 0, true, false));
        // An unpinned store holding parts while no pinned store is active: they cannot move.
        assert!(drain_strands_library(1, 0, false, true));
        // Another active pinned store remains: parts and uploads go there.
        assert!(!drain_strands_library(2, 1, true, true));
        // An unpinned store with no library parts is none of the library's business.
        assert!(!drain_strands_library(1, 0, false, false));
    }

    fn db() -> Connection {
        let db = crate::test_schema::full_schema();
        db.execute_batch(
            "INSERT INTO storage_backends (store_id, kind, label, state, priority, created_at,
                                           updated_at, library_pin)
             VALUES ('s3-campus1', 's3', 'Campus MinIO', 'active', 10, 1, 1, 1),
                    ('s3-backup1', 's3', 'Backup', 'active', 20, 1, 1, 0);
             INSERT INTO room_library_objects
               (room_id, object_id, uploader_id, size_bytes, store_id, created_at)
             VALUES ('r1', 'obj-000000000001', 'u1', 10, 'r2-primary', 1);",
        )
        .unwrap();
        db
    }

    fn read(db: &Connection, store: &str) -> (i64, i64, i64, i64) {
        db.query_row(LIBRARY_DRAIN_SQL, params![store], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
    }

    /// The read against the real schema: the campus store is the only pinned one, so draining it
    /// strands the library; draining R2, which still holds a part from before the pin, does not
    /// — the part moves to the campus store, which is active; a second active pinned store lifts
    /// the block, and stops lifting it once it is no longer active.
    #[test]
    fn the_drain_read_answers_from_the_real_schema() {
        let db = db();
        let (p, other, this, holds) = read(&db, "s3-campus1");
        assert_eq!((p, other, this, holds), (1, 0, 1, 0));
        assert!(drain_strands_library(p, other, this != 0, holds != 0));

        let (p, other, this, holds) = read(&db, "r2-primary");
        assert_eq!((p, other, this, holds), (1, 1, 0, 1));
        assert!(!drain_strands_library(p, other, this != 0, holds != 0));

        db.execute("UPDATE storage_backends SET library_pin = 1 WHERE store_id = 's3-backup1'", [])
            .unwrap();
        let (p, other, this, holds) = read(&db, "s3-campus1");
        assert!(!drain_strands_library(p, other, this != 0, holds != 0));

        // A pinned store that is not active does not count as somewhere to go.
        db.execute("UPDATE storage_backends SET state = 'readonly' WHERE store_id = 's3-backup1'", [])
            .unwrap();
        let (p, other, this, holds) = read(&db, "s3-campus1");
        assert!(drain_strands_library(p, other, this != 0, holds != 0));
    }
}
