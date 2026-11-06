//! The member budget of a room's plugin media (review 2026-11 H10): the decision, its SQL on the
//! real schema, and where `put_media` asks it.

use super::*;

const SRC: &str = include_str!("plugin_media.rs");

fn usage(db: &rusqlite::Connection, room: &str, uploader: &str) -> (i64, i64) {
    db.query_row(MEMBER_USAGE_SQL, [room, uploader], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
}

fn put(db: &rusqlite::Connection, room: &str, blob: &str, uploader: &str, size: i64) {
    db.execute(
        "INSERT INTO plugin_media_objects (room_id, blob_id, uploader_id, size_bytes, created_at) \
         VALUES (?1, ?2, ?3, ?4, 0)",
        rusqlite::params![room, blob, uploader, size],
    )
    .unwrap();
}

#[test]
fn the_usage_is_one_members_in_one_room() {
    let db = crate::test_schema::full_schema();
    assert_eq!(usage(&db, "r1", "alice"), (0, 0), "nothing kept is a row of zeros, not none");
    put(&db, "r1", "a", "alice", 10);
    put(&db, "r1", "b", "alice", 20);
    put(&db, "r1", "c", "bob", 40);
    put(&db, "r2", "d", "alice", 80);
    assert_eq!(usage(&db, "r1", "alice"), (30, 2));
    assert_eq!(usage(&db, "r1", "bob"), (40, 1));
}

#[test]
fn an_upload_past_the_member_budget_is_refused() {
    assert_eq!(media_refusal(0, 0, 50 * 1024 * 1024), None);
    let max = MAX_BYTES_PER_MEMBER_PER_ROOM;
    assert_eq!(media_refusal(max - 10, 1, 10), None, "exactly full fits");
    assert_eq!(media_refusal(max - 10, 1, 11), Some(("bytes", max)));
    let n = MAX_OBJECTS_PER_MEMBER_PER_ROOM;
    assert_eq!(media_refusal(0, n - 1, 1), None);
    assert_eq!(media_refusal(0, n, 1), Some(("objects", n)));
}

#[test]
fn the_refusal_is_a_400_with_a_typed_code() {
    assert_eq!(MEDIA_FULL_STATUS, 400, "apps since 2046 end an op at a 400 and retry nothing");
    assert_eq!(MEDIA_FULL_CODE, "plugin/media-full");
}

/// The budget is asked after the idempotent retry (a blob already stored costs nothing again)
/// and before the body is read — no point holding 50 MiB that will be refused.
#[test]
fn put_media_asks_the_budget_before_reading_the_body() {
    let start = SRC.find("\npub async fn put_media(").expect("put_media");
    let body = &SRC[start..];
    let body = &body[..body[1..].find("\npub async fn ").map(|i| i + 1).unwrap_or(body.len())];
    let retry = body.find("existing_size(").expect("the idempotent retry");
    let budget = body.find("member_usage(").expect("put_media must ask the member budget");
    assert!(SRC.contains(".prepare(MEMBER_USAGE_SQL)"), "member_usage runs the tested SQL");
    let read = body.find("req.bytes()").expect("the body read");
    assert!(retry < budget && budget < read);
    assert!(body.contains("MEDIA_FULL_CODE"));
}
