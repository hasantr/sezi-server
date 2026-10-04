//! Tests for the group library's ways out — the retention sweep and the three teardowns — run
//! against the real migration chain (`crate::test_schema::full_schema`), plus the source-level
//! guards on the batches that borrow these statements.

use super::*;
use crate::room_library::tests::{insert, library_db, obj, OTHER_ROOM, ROOM};
use rusqlite::{params, Connection};

const NOW: i64 = 1_780_000_000;

fn orphan_keys(db: &Connection) -> Vec<String> {
    db.prepare("SELECT key FROM storage_orphans ORDER BY key")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn library_ids(db: &Connection) -> Vec<(String, String)> {
    db.prepare("SELECT room_id, object_id FROM room_library_objects ORDER BY room_id, object_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn server_stats(db: &Connection) -> (i64, i64) {
    db.query_row("SELECT media_bytes, media_count FROM server_stats WHERE id = 1", [], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .unwrap()
}

/// `server_stats` as the counters would hold it: chat media worth `other` bytes in `other_n`
/// objects, plus every library row.
fn seed_stats(db: &Connection, other: i64, other_n: i64) {
    db.execute(
        "INSERT INTO server_stats (id, media_bytes, media_count, updated_at)
         SELECT 1, ? + COALESCE(SUM(size_bytes), 0), ? + COUNT(*), 0 FROM room_library_objects",
        params![other, other_n],
    )
    .unwrap();
}

// ── The retention sweep ─────────────────────────────────────────────────────────────────

/// The sweep reads only what has expired — strictly before now — oldest expiry first, and never a
/// keep-forever part, however old.
#[test]
fn the_sweep_selects_expired_parts_oldest_first() {
    let db = library_db();
    insert(&db, ROOM, &obj(1), "u1", 10, "r2-primary", Some(NOW - 10));
    insert(&db, ROOM, &obj(2), "u1", 10, "r2-primary", Some(NOW - 500));
    insert(&db, OTHER_ROOM, &obj(3), "u1", 10, "r2-primary", Some(NOW - 50));
    insert(&db, ROOM, &obj(4), "u1", 10, "r2-primary", Some(NOW));
    insert(&db, ROOM, &obj(5), "u1", 10, "r2-primary", Some(NOW + 86_400));
    insert(&db, ROOM, &obj(6), "u1", 10, "r2-primary", None);

    let batch = |limit: i64| -> Vec<String> {
        db.prepare(EXPIRED_BATCH_SQL)
            .unwrap()
            .query_map(params![NOW, limit], |r| r.get(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(batch(100), [obj(2), obj(3), obj(1)]);
    assert_eq!(batch(2), [obj(2), obj(3)], "the per-run bound holds");
}

/// The row delete is conditional on the store the blob was just deleted from. If the drain moved
/// the part in between, the row stays, and the next sweep deletes the part where it now lives —
/// the alternative is a new copy with nothing left to name it.
#[test]
fn the_sweep_leaves_a_part_the_drain_moved_meanwhile() {
    let db = library_db();
    insert(&db, ROOM, &obj(1), "u1", 700, "s3-old0000", Some(NOW - 1));
    insert(&db, ROOM, &obj(2), "u1", 300, "s3-old0000", Some(NOW - 1));
    // The drain's conditional UPDATE lands between the sweep's SELECT and its DELETE.
    db.execute(
        "UPDATE room_library_objects SET store_id = 's3-new0000' WHERE object_id = ?",
        params![obj(2)],
    )
    .unwrap();

    let delete = |id: &str| -> Option<i64> {
        db.query_row(DELETE_EXPIRED_SQL, params![ROOM, id, NOW, "s3-old0000"], |r| r.get(0))
            .ok()
    };
    assert_eq!(delete(&obj(1)), Some(700));
    assert_eq!(delete(&obj(2)), None, "moved to another store: not this sweep's to drop");
    assert_eq!(library_ids(&db), [(ROOM.to_string(), obj(2))]);
}

/// A part that is no longer expired by the time the delete runs — it cannot happen today, since
/// nothing extends an expiry, but the guard is in the statement rather than in that assumption.
#[test]
fn the_sweep_never_drops_a_part_that_is_not_expired() {
    let db = library_db();
    insert(&db, ROOM, &obj(1), "u1", 10, "r2-primary", None);
    insert(&db, ROOM, &obj(2), "u1", 10, "r2-primary", Some(NOW + 1));
    for id in [obj(1), obj(2)] {
        let n = db
            .execute(DELETE_EXPIRED_SQL, params![ROOM, id, NOW, "r2-primary"])
            .unwrap();
        assert_eq!(n, 0, "{id} must survive the sweep");
    }
}

/// Blob first, row second, in the source — the media sweep's order. Reversed, a worker that dies
/// between the two leaves a blob with no row, which nothing will ever find again.
#[test]
fn the_sweep_deletes_blobs_before_rows() {
    let src = include_str!("room_library_cleanup.rs");
    let body = &src[src.find("pub(crate) async fn sweep_expired").unwrap()..];
    let body = &body[..body.find("// ── Teardown statements").unwrap()];
    let blob = body.find("router.delete(").expect("the sweep must delete blobs");
    let rows = body.find("db.batch(stmts)").expect("the sweep must drop rows in one batch");
    assert!(blob < rows);
    assert!(body.contains("insert_orphans("), "a blob that will not delete must be tombstoned");
}

/// The sweep is a leg of the daily set, before the reconcile that recomputes the counters.
#[test]
fn the_daily_set_runs_the_sweep_before_the_reconcile() {
    let src = include_str!("maintenance.rs");
    let daily = &src[src.find("pub(crate) async fn run_daily").unwrap()..];
    let sweep = daily.find("room_library::sweep_expired(").expect("run_daily must sweep");
    let reconcile = daily.find("usage::reconcile_storage(").unwrap();
    assert!(sweep < reconcile);
}

// ── Deleting a group ────────────────────────────────────────────────────────────────────

/// The group teardown: the room's parts are queued under their store keys, their bytes leave the
/// server total at once, the rows go — and the room next door keeps everything.
#[test]
fn deleting_a_group_queues_its_library_and_frees_the_server_total() {
    let db = library_db();
    insert(&db, ROOM, &obj(1), "u1", 700, "s3-campus01", None);
    insert(&db, ROOM, &obj(2), "u2", 300, "r2-primary", Some(NOW + 9));
    insert(&db, OTHER_ROOM, &obj(3), "u1", 50, "r2-primary", None);
    seed_stats(&db, 4000, 2);
    assert_eq!(server_stats(&db), (5050, 5));

    db.execute(ORPHAN_ROOM_SQL, params![NOW, ROOM]).unwrap();
    db.execute(RELEASE_ROOM_SQL, params![ROOM, ROOM]).unwrap();
    db.execute(DELETE_ROOM_SQL, params![ROOM]).unwrap();

    assert_eq!(
        orphan_keys(&db),
        [library_key(ROOM, &obj(1)), library_key(ROOM, &obj(2))]
    );
    assert_eq!(server_stats(&db), (4050, 3), "the room's 1000 bytes in 2 parts are released");
    assert_eq!(library_ids(&db), [(OTHER_ROOM.to_string(), obj(3))]);

    // Replayed: no second tombstone, no second release.
    db.execute(ORPHAN_ROOM_SQL, params![NOW, ROOM]).unwrap();
    db.execute(RELEASE_ROOM_SQL, params![ROOM, ROOM]).unwrap();
    assert_eq!(orphan_keys(&db).len(), 2);
    assert_eq!(server_stats(&db), (4050, 3));
}

// ── Deleting an account ─────────────────────────────────────────────────────────────────

/// An account deletion closes the groups that have no one left to inherit them. Their libraries
/// go; the parts the departing account uploaded into a group that SURVIVES stay, because a
/// library belongs to its group.
#[test]
fn an_account_deletion_takes_only_the_libraries_of_groups_it_closed() {
    let db = library_db();
    // `owner` uploaded into both rooms; room-a closes with them, room-b lives on.
    insert(&db, ROOM, &obj(1), "owner", 700, "r2-primary", None);
    insert(&db, OTHER_ROOM, &obj(2), "owner", 50, "r2-primary", None);
    insert(&db, OTHER_ROOM, &obj(3), "u2", 25, "r2-primary", None);
    seed_stats(&db, 0, 0);

    // What membership.rs's batch has done by the time these run: room-a is closed.
    db.execute("DELETE FROM groups WHERE id = ?", params![ROOM]).unwrap();
    db.execute(ORPHAN_ROOMLESS_SQL, params![NOW]).unwrap();
    db.execute(RELEASE_ROOMLESS_SQL, []).unwrap();
    db.execute(DELETE_ROOMLESS_SQL, []).unwrap();

    assert_eq!(orphan_keys(&db), [library_key(ROOM, &obj(1))]);
    assert_eq!(server_stats(&db), (75, 2));
    assert_eq!(
        library_ids(&db),
        [(OTHER_ROOM.to_string(), obj(2)), (OTHER_ROOM.to_string(), obj(3))],
        "the uploader's part in a surviving group is the group's, and stays"
    );
}

/// The three library statements sit in membership.rs's batch AFTER the statement that closes the
/// groups — before it, "rooms with no group" does not yet include the rooms being closed, and
/// their parts would outlive them unqueued — and in orphan → release → delete order.
#[test]
fn the_account_deletion_batch_runs_the_library_statements_after_closing_groups() {
    let src = include_str!("membership.rs");
    let close = src
        .find("\"DELETE FROM groups WHERE created_by=?\"")
        .expect("the account deletion no longer closes groups — re-point this guard");
    let orphan = src.find("cleanup::ORPHAN_ROOMLESS_SQL").expect("orphan left the batch");
    let release = src.find("cleanup::RELEASE_ROOMLESS_SQL").expect("release left the batch");
    let delete = src.find("cleanup::DELETE_ROOMLESS_SQL").expect("delete left the batch");
    assert!(close < orphan && orphan < release && release < delete);
    assert!(
        !src.contains("room_library_objects WHERE uploader_id"),
        "the library must never be deleted by uploader — it belongs to the group"
    );
}

// ── Wiping the server ───────────────────────────────────────────────────────────────────

#[test]
fn a_server_wipe_queues_every_part_first() {
    let db = library_db();
    insert(&db, ROOM, &obj(1), "u1", 10, "r2-primary", None);
    insert(&db, OTHER_ROOM, &obj(2), "u2", 20, "s3-campus01", Some(NOW));
    db.execute(ORPHAN_ALL_SQL, params![NOW]).unwrap();
    assert_eq!(
        orphan_keys(&db),
        [library_key(ROOM, &obj(1)), library_key(OTHER_ROOM, &obj(2))]
    );

    let src = include_str!("admin/reset.rs");
    let orphan = src.find("cleanup::ORPHAN_ALL_SQL").expect("the wipe must queue the library");
    let wipe = src.find("for table in WIPE_TABLES").unwrap();
    assert!(orphan < wipe, "queued before the table is emptied, or nothing is left to read");
}
