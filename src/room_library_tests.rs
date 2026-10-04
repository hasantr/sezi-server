//! Tests for the group library.
//!
//! A worker handler cannot run without workerd, so these come in two kinds, as in
//! `instrument_pack_tests.rs`: the pure helpers are called directly, and every statement the
//! handlers issue is a `const` exercised here with rusqlite against the REAL migration chain
//! (`crate::test_schema::full_schema`).

use super::*;
use crate::test_schema::full_schema;
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_780_000_000;

// ── The migration ───────────────────────────────────────────────────────────────

/// A migration missing from `self_provision.rs`'s hand-kept list is one a SELF-HOSTED relay never
/// runs: the table never exists there and every library route fails on it. That omission shipped
/// once (2026-08-25); `the_migrations_list_matches_the_folder` catches it too, this names the file.
#[test]
fn the_migration_is_wired_into_self_provision() {
    let src = include_str!("self_provision.rs");
    assert!(src.contains("include_str!(\"../migrations/0040_room_library.sql\")"));
    assert!(src.contains("\"0040_room_library\","));
}

/// The table exists with the shape the handlers rely on, and a fresh server has no library cap
/// and no library retention — keep until deleted, unlimited — until its owner says otherwise.
#[test]
fn a_fresh_server_keeps_the_library_and_caps_nothing() {
    let db = full_schema();
    let (retention, cap): (Option<i64>, Option<i64>) = db
        .query_row(
            "SELECT library_retention_days, max_room_library_bytes FROM server_settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(retention, None, "NULL = keep until deleted");
    assert_eq!(cap, None, "NULL = unlimited");

    let cols: Vec<String> = db
        .prepare("SELECT name FROM pragma_table_info('room_library_objects') ORDER BY cid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        cols,
        [
            "room_id",
            "object_id",
            "uploader_id",
            "kind",
            "size_bytes",
            "store_id",
            "created_at",
            "expires_at"
        ]
    );
}

/// The primary key is what makes a PUT idempotent: the same (room, id) is one object, while the
/// same id in another room is a different one — ids are only unique inside their room.
#[test]
fn an_object_is_keyed_by_room_and_id() {
    let db = full_schema();
    let insert = "INSERT INTO room_library_objects
                    (room_id, object_id, uploader_id, size_bytes, created_at)
                  VALUES (?, ?, 'u1', 10, ?)";
    db.execute(insert, params!["room-a", "obj-0123456789abcdef", NOW]).unwrap();
    assert!(
        db.execute(insert, params!["room-a", "obj-0123456789abcdef", NOW]).is_err(),
        "a second row for the same (room, id) must be refused"
    );
    db.execute(insert, params!["room-b", "obj-0123456789abcdef", NOW]).unwrap();

    // Defaults: a part on the primary store, kept until deleted.
    let (kind, store, expires): (String, String, Option<i64>) = db
        .query_row(
            "SELECT kind, store_id, expires_at FROM room_library_objects WHERE room_id = 'room-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((kind.as_str(), store.as_str(), expires), ("part", "r2-primary", None));
}

/// No foreign key onto `users`: a library belongs to its group, so the uploader's account going
/// away must neither take the rows with it nor — D1 enforces foreign keys — fail the deletion.
#[test]
fn an_uploader_leaving_the_server_does_not_touch_the_library() {
    let db = full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at)
         VALUES ('u1', 'u1@example.test', x'00', 1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO room_library_objects (room_id, object_id, uploader_id, size_bytes, created_at)
         VALUES ('room-a', 'obj-0123456789abcdef', 'u1', 10, ?)",
        params![NOW],
    )
    .unwrap();
    db.execute("DELETE FROM users WHERE id = 'u1'", []).unwrap();
    let left: Option<String> = db
        .query_row("SELECT uploader_id FROM room_library_objects", [], |r| r.get(0))
        .optional()
        .unwrap();
    assert_eq!(left.as_deref(), Some("u1"));
}

// ── The settings ────────────────────────────────────────────────────────────────

#[test]
fn a_library_setting_keeps_clears_sets_or_refuses() {
    let r = LIBRARY_RETENTION_RANGE;
    // Absent → the current value stays, whatever it is.
    assert_eq!(library_setting(None, Some(90), r.clone()), Ok(Some(90)));
    assert_eq!(library_setting(None, None, r.clone()), Ok(None));
    // 0 → cleared: keep until deleted.
    assert_eq!(library_setting(Some(0), Some(90), r.clone()), Ok(None));
    // Inside the range → set.
    assert_eq!(library_setting(Some(1), None, r.clone()), Ok(Some(1)));
    assert_eq!(library_setting(Some(3650), None, r.clone()), Ok(Some(3650)));
    // Outside it → refused, never clamped.
    assert_eq!(library_setting(Some(3651), None, r.clone()), Err(()));
    assert_eq!(library_setting(Some(-1), None, r), Err(()));

    let c = LIBRARY_CAP_RANGE;
    assert_eq!(library_setting(Some(0), Some(5), c.clone()), Ok(None));
    assert_eq!(library_setting(Some(1), None, c.clone()), Ok(Some(1)));
    assert_eq!(library_setting(Some(i64::MAX), None, c.clone()), Ok(Some(i64::MAX)));
    assert_eq!(library_setting(Some(-5), None, c), Err(()));
}

/// The settings upsert names both new columns and writes them where the handler's bind order
/// says — checked against the real table, so a column renamed in a later migration fails here.
#[test]
fn the_settings_upsert_writes_the_library_pair() {
    let db = full_schema();
    let write = |retention: Option<i64>, cap: Option<i64>| {
        db.execute(
            crate::admin::handlers::UPSERT_SERVER_SETTINGS_SQL,
            params![
                "Campus", "invite_only", "off", "members", 30, 30, None::<i64>, None::<i64>, 48,
                retention, cap, NOW
            ],
        )
        .unwrap();
    };
    let read = || -> (Option<i64>, Option<i64>, i64) {
        db.query_row(
            "SELECT library_retention_days, max_room_library_bytes, retention_days
               FROM server_settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    };
    write(Some(180), Some(50 * 1024 * 1024 * 1024));
    assert_eq!(read(), (Some(180), Some(50 * 1024 * 1024 * 1024), 30));
    // Back to "keep until deleted, unlimited".
    write(None, None);
    assert_eq!(read(), (None, None, 30));
}

// ── Pure helpers ────────────────────────────────────────────────────────────────

#[test]
fn an_object_id_is_long_random_and_needs_no_escaping() {
    assert!(valid_object_id("0123456789abcdef"), "16 characters is the floor");
    assert!(valid_object_id("6f1c1f0e-8a3b-4c5d-9e7f-0123456789ab"), "a UUID");
    assert!(valid_object_id("AbC_dEf-0123456789xyzQ"), "22 base64url characters");
    assert!(valid_object_id(&"a".repeat(128)));

    assert!(!valid_object_id("0123456789abcde"), "15 characters is too guessable to be an id");
    assert!(!valid_object_id(&"a".repeat(129)));
    assert!(!valid_object_id(""));
    // Anything a store key or a URL would have to escape.
    for bad in ["0123456789abcdef/x", "0123456789abcdef.", "0123456789 abcdef", "0123456789abcdeé"]
    {
        assert!(!valid_object_id(bad), "{bad:?} must be refused");
    }
}

#[test]
fn a_kind_is_a_short_lowercase_label_defaulting_to_part() {
    assert_eq!(parse_kind(None), Ok("part".to_string()));
    assert_eq!(parse_kind(Some("")), Ok("part".to_string()));
    assert_eq!(parse_kind(Some("  ")), Ok("part".to_string()));
    assert_eq!(parse_kind(Some("material")), Ok("material".to_string()));
    assert_eq!(parse_kind(Some("audio_part-2")), Ok("audio_part-2".to_string()));
    assert_eq!(parse_kind(Some(&"k".repeat(24))), Ok("k".repeat(24)));

    assert_eq!(parse_kind(Some(&"k".repeat(25))), Err(()));
    assert_eq!(parse_kind(Some("Part")), Err(()), "refused, not lowercased behind the client's back");
    assert_eq!(parse_kind(Some("lecture 3")), Err(()));
    assert_eq!(parse_kind(Some("a\r\nb")), Err(()));
}

#[test]
fn the_quota_charges_the_room_and_the_server_total() {
    // No caps: anything goes.
    assert_eq!(decide_library_upload(1 << 50, 1 << 50, 1 << 30, None, None), None);
    // The room cap, exact fit allowed.
    assert_eq!(decide_library_upload(0, 90, 10, None, Some(100)), None);
    assert_eq!(decide_library_upload(0, 91, 10, None, Some(100)), Some("room_library"));
    // The server total.
    assert_eq!(decide_library_upload(91, 0, 10, Some(100), None), Some("server_storage"));
    // Both exceeded: the server's answer, which no group admin can fix by deleting.
    assert_eq!(decide_library_upload(91, 91, 10, Some(100), Some(100)), Some("server_storage"));
    // Overflow cannot wrap a full room into an empty one.
    assert_eq!(decide_library_upload(0, i64::MAX, 10, None, Some(100)), Some("room_library"));
}

#[test]
fn retention_is_frozen_at_upload_and_null_keeps_forever() {
    assert_eq!(expires_at(NOW, None), None);
    assert_eq!(expires_at(NOW, Some(1)), Some(NOW + 86_400));
    assert_eq!(expires_at(NOW, Some(3650)), Some(NOW + 3650 * 86_400));

    assert!(!is_expired(None, i64::MAX), "kept until deleted means never expired");
    assert!(!is_expired(Some(NOW), NOW), "the second named is still served");
    assert!(is_expired(Some(NOW), NOW + 1));
}

#[test]
fn the_list_page_size_is_clamped() {
    assert_eq!(page_limit(None), 500);
    assert_eq!(page_limit(Some("20")), 20);
    assert_eq!(page_limit(Some("0")), 1);
    assert_eq!(page_limit(Some("100000")), 1000);
    assert_eq!(page_limit(Some("lots")), 500);
}

// ── SQL contracts ───────────────────────────────────────────────────────────────

pub(super) const ROOM: &str = "room-a";
pub(super) const OTHER_ROOM: &str = "room-b";

pub(super) fn obj(n: u32) -> String {
    format!("obj-{n:012}-part")
}

/// `full_schema` with an owner and the two rooms the library tests write into. A part is only
/// ever stored for a room whose group exists (`INSERT_OBJECT_SQL`), so the groups are part of
/// every fixture.
pub(super) fn library_db() -> Connection {
    let db = full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, created_at)
           VALUES ('owner', 'owner@example.test', x'00', 1);
         INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES
           ('room-a', 'Physics 101', 'owner', 1, 1),
           ('room-b', 'Chemistry 102', 'owner', 1, 1);",
    )
    .unwrap();
    db
}

/// The handler's INSERT, returning whether THIS call inserted the row.
pub(super) fn insert(
    db: &Connection,
    room: &str,
    id: &str,
    uploader: &str,
    size: i64,
    store: &str,
    expires: Option<i64>,
) -> bool {
    let mut stmt = db.prepare(INSERT_OBJECT_SQL).unwrap();
    let mut rows = stmt
        .query(params![room, id, uploader, "part", size, store, NOW, expires])
        .unwrap();
    rows.next().unwrap().is_some()
}

/// `PUT_POLICY_SQL` as the handler reads it: (retention, max_room, max_server, room_used,
/// server_used).
fn policy(db: &Connection, room: &str) -> (Option<i64>, Option<i64>, Option<i64>, i64, i64) {
    db.query_row(PUT_POLICY_SQL, params![room], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })
    .unwrap()
}

/// Of two PUTs racing the same id, exactly one inserts — the RETURNING row is what lets only
/// that one bump the counters.
#[test]
fn only_the_first_insert_of_an_id_reports_itself() {
    let db = library_db();
    assert!(insert(&db, ROOM, &obj(1), "u1", 100, "r2-primary", None));
    assert!(!insert(&db, ROOM, &obj(1), "u1", 100, "r2-primary", None));
    let row: (String, String, i64, String, i64, Option<i64>) = db
        .query_row(SELECT_OBJECT_SQL, params![ROOM, obj(1)], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })
        .unwrap();
    assert_eq!(row, ("u1".into(), "part".into(), 100, "r2-primary".into(), NOW, None));
}

/// A part arriving after its group was deleted is not written: the teardown batch has already
/// queued and dropped what the room held, and a row landing after it would be a blob nothing
/// ever deletes, charged to a room that no longer exists.
#[test]
fn no_part_is_stored_for_a_group_that_is_gone() {
    let db = library_db();
    assert!(!insert(&db, "room-deleted", &obj(1), "u1", 100, "r2-primary", None));
    db.execute("DELETE FROM groups WHERE id = ?", params![ROOM]).unwrap();
    assert!(!insert(&db, ROOM, &obj(2), "u1", 100, "r2-primary", None));
    let n: i64 = db
        .query_row("SELECT COUNT(*) FROM room_library_objects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

/// A server with no caps reads no usage at all — the CASE keeps the default install off both
/// sums — and its retention is "keep".
#[test]
fn the_policy_read_skips_both_sums_when_nothing_is_capped() {
    let db = library_db();
    insert(&db, ROOM, &obj(1), "u1", 700, "r2-primary", None);
    db.execute(
        "INSERT INTO server_stats (id, media_bytes, media_count, updated_at) VALUES (1, 5000, 3, 0)",
        [],
    )
    .unwrap();
    assert_eq!(policy(&db, ROOM), (None, None, None, 0, 0));
}

/// With caps set, the room's usage is THIS room's sum — a neighbour's library never counts
/// against it — and the server's is the `server_stats` total.
#[test]
fn the_policy_read_sums_this_room_and_the_server_total() {
    let db = library_db();
    db.execute(
        "UPDATE server_settings SET max_room_library_bytes = 1000, max_storage_bytes = 9000,
                library_retention_days = 90 WHERE id = 1",
        [],
    )
    .unwrap();
    insert(&db, ROOM, &obj(1), "u1", 300, "r2-primary", None);
    insert(&db, ROOM, &obj(2), "u2", 200, "r2-primary", None);
    insert(&db, OTHER_ROOM, &obj(3), "u1", 4000, "r2-primary", None);
    db.execute(
        "INSERT INTO server_stats (id, media_bytes, media_count, updated_at) VALUES (1, 4500, 3, 0)",
        [],
    )
    .unwrap();
    let (retention, max_room, max_server, room_used, server_used) = policy(&db, ROOM);
    assert_eq!((retention, max_room, max_server), (Some(90), Some(1000), Some(9000)));
    assert_eq!(room_used, 500, "two uploaders, one room: the room pays for both");
    assert_eq!(server_used, 4500);
    assert_eq!(decide_library_upload(server_used, room_used, 500, max_server, max_room), None);
    assert_eq!(
        decide_library_upload(server_used, room_used, 501, max_server, max_room),
        Some("room_library")
    );
}

/// DELETE's batch: the blob is queued under the exact key the store holds, the row goes, the
/// RETURNING row says this call did it, and a second DELETE finds nothing — so the counters move
/// once.
#[test]
fn a_delete_queues_the_blob_before_dropping_the_row() {
    let db = library_db();
    insert(&db, ROOM, &obj(1), "u1", 700, "s3-campus01", None);
    insert(&db, OTHER_ROOM, &obj(1), "u1", 50, "r2-primary", None);

    let delete = |db: &Connection| -> Option<i64> {
        db.execute(ORPHAN_OBJECT_SQL, params![NOW, ROOM, obj(1)]).unwrap();
        db.query_row(DELETE_OBJECT_SQL, params![ROOM, obj(1)], |r| r.get(0))
            .optional()
            .unwrap()
    };
    assert_eq!(delete(&db), Some(700));
    assert_eq!(delete(&db), None, "the second DELETE must not report a removal");

    let orphans: Vec<(String, String, i64)> = db
        .prepare("SELECT store_id, key, size_bytes FROM storage_orphans")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        orphans,
        [("s3-campus01".to_string(), crate::storage::library_key(ROOM, &obj(1)), 700)],
        "one tombstone, on the object's own store, under storage::library_key"
    );
    let left: i64 = db
        .query_row("SELECT COUNT(*) FROM room_library_objects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 1, "the same id in another room is another object");
}

/// The member list: id order, `after` continues where the last page stopped, expired rows are
/// not offered, and the room next door never appears.
#[test]
fn the_list_pages_in_id_order_and_hides_expired_parts() {
    let db = library_db();
    for n in [3, 1, 4, 2] {
        insert(&db, ROOM, &obj(n), "u1", 10 * n as i64, "r2-primary", None);
    }
    insert(&db, ROOM, &obj(5), "u1", 5, "r2-primary", Some(NOW - 1));
    insert(&db, ROOM, &obj(6), "u1", 6, "r2-primary", Some(NOW));
    insert(&db, OTHER_ROOM, &obj(0), "u9", 1, "r2-primary", None);

    let page = |after: &str, limit: i64| -> Vec<String> {
        db.prepare(LIST_PAGE_SQL)
            .unwrap()
            .query_map(params![ROOM, after, NOW, limit], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(page("", 2), [obj(1), obj(2)]);
    assert_eq!(page(&obj(2), 2), [obj(3), obj(4)]);
    assert_eq!(page(&obj(4), 10), [obj(6)], "expired at NOW-1 is gone, at NOW still served");

    // The header counts what is STORED — the expired part too, until the sweep takes it.
    db.execute("UPDATE server_settings SET max_room_library_bytes = 4096 WHERE id = 1", [])
        .unwrap();
    let (used, max): (i64, Option<i64>) = db
        .query_row(ROOM_USAGE_SQL, params![ROOM], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!((used, max), (10 + 20 + 30 + 40 + 5 + 6, Some(4096)));
}

/// The reconcile is where the "charged to the room" rule is enforced for good: library bytes
/// land in the server total and the per-store inventory, and NEVER in the uploader's
/// `user_storage` — the daily recompute would otherwise put a whole course on one teacher.
#[test]
fn the_reconcile_charges_library_bytes_to_the_server_and_the_store_not_the_uploader() {
    let db = library_db();
    // media_objects.uploader_id references users; the library's uploader_id does not.
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at)
         VALUES ('u1', 'u1@example.test', x'00', 1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO media_objects (blob_id, uploader_id, size_bytes, created_at, expires_at)
         VALUES ('m1', 'u1', 100, 1, 2)",
        [],
    )
    .unwrap();
    insert(&db, ROOM, &obj(1), "u1", 5000, "r2-primary", None);
    insert(&db, ROOM, &obj(2), "u1", 7000, "r2-primary", None);

    db.execute_batch("DELETE FROM user_storage; DELETE FROM server_stats WHERE id = 1;")
        .unwrap();
    db.execute(crate::usage::RECONCILE_USER_STORAGE_SQL, []).unwrap();
    db.execute(crate::usage::RECONCILE_SERVER_STATS_SQL, params![NOW]).unwrap();
    db.execute(crate::usage::RECONCILE_BACKENDS_SQL, params![NOW]).unwrap();

    let user: i64 = db
        .query_row("SELECT bytes FROM user_storage WHERE user_id = 'u1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(user, 100, "only the chat media is the uploader's");
    let (bytes, count): (i64, i64) = db
        .query_row("SELECT media_bytes, media_count FROM server_stats WHERE id = 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((bytes, count), (12_100, 3));
    let (used, objects): (i64, i64) = db
        .query_row(
            "SELECT used_bytes, object_count FROM storage_backends WHERE store_id = 'r2-primary'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (used, objects),
        (12_100, 3),
        "a store holding only library parts must not look empty — DELETE /admin/storage removes \
         empty stores"
    );
}

// ── Source-level guards (the choice inside a handler a behavioural test cannot reach) ──────

const SOURCE: &str = include_str!("room_library.rs");

/// The text of one handler, from its signature to the next `pub async fn`.
fn handler(name: &str) -> &'static str {
    let at = SOURCE
        .find(&format!("pub async fn {name}("))
        .unwrap_or_else(|| panic!("{name} must exist — if it was renamed, re-point this guard"));
    let rest = &SOURCE[at..];
    let end = rest[1..].find("pub async fn ").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

/// Every route proves the device is live AND the caller is an active member of the room before
/// anything else — the plugin channels' shared gate. The stateless JWT alone would leave a
/// revoked device ~15 minutes of access to a course's recordings.
#[test]
fn every_route_goes_through_the_membership_gate() {
    for name in ["put_object", "get_object", "delete_object"] {
        let body = handler(name);
        assert!(body.contains("match gate(&req, &ctx)"), "{name} must open with plugin_blob::gate");
    }
    assert!(handler("list_objects").contains("room_gate(&req, &ctx)"));
    assert!(!SOURCE.contains("require_auth("), "never the stateless JWT alone");
}

/// The GET streams. A 33 MiB part buffered through `Response::from_bytes` is held twice in a
/// 128 MB isolate — the shape `plugin_media` still has and this class was built not to repeat.
#[test]
fn the_download_is_streamed_never_buffered() {
    let body = handler("get_object");
    assert!(body.contains("get_stream("), "the GET must read through StorageRouter::get_stream");
    assert!(!SOURCE.contains("Response::from_bytes("), "no buffered body anywhere in the library");
    assert!(!body.contains("router\n        .get(") && !body.contains("router.get("));
}

/// Deleting is the uploader's or a group admin's — and never the server owner's by virtue of
/// running the box (AGENTS.md, "Who the server owner is").
#[test]
fn deletion_is_for_the_uploader_or_a_group_admin() {
    let body = handler("delete_object");
    assert!(body.contains("row.uploader_id != user_id && !is_group_admin(&role)"));
    assert!(!body.contains("require_owner(") && !body.contains("require_admin("));
}

/// The DELETE tombstones before it drops, inside one batch — the order is the argument.
#[test]
fn the_delete_batch_orphans_before_it_deletes() {
    let body = handler("delete_object");
    let batch = &body[body.find(".batch(vec![").expect("DELETE must be one batch")..];
    let orphan = batch.find("ORPHAN_OBJECT_SQL").expect("the tombstone left the batch");
    let delete = batch.find("DELETE_OBJECT_SQL").expect("the row delete left the batch");
    assert!(orphan < delete, "the tombstone must be written before the row it reads is dropped");
}

/// Library bytes are the ROOM's: the upload must charge the server total through
/// `library_added` and must not reach for the uploader's counter.
#[test]
fn an_upload_is_charged_to_the_room_not_the_uploader() {
    let body = handler("put_object");
    assert!(body.contains("crate::usage::library_added("));
    assert!(!body.contains("media_added(") && !body.contains("check_upload("));
}

/// `/capabilities` tells a client the library exists — only where a store does, like media —
/// and how long it keeps parts, from the setting the PUT freezes into each one.
#[test]
fn capabilities_announce_the_library_and_its_retention() {
    let src = include_str!("server/handlers.rs");
    let caps = &src[src.find("pub async fn capabilities").expect("capabilities moved")..];
    assert!(caps.contains("\"library\": media_ok"), "features.library must follow the store");
    assert!(caps.contains("\"library_days\": library_days"));
    assert!(caps.contains("fetch_library_retention_days(&ctx.env)"));
    assert!(caps.contains("\"max_object_bytes\": crate::room_library::MAX_OBJECT_BYTES"));
    assert!(src.contains("SELECT library_retention_days FROM server_settings"));
}
