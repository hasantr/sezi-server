//! The owner's plugin-limits endpoints: the near list's SQL on the real schema, and the gates.

use super::*;

const SRC: &str = include_str!("plugin_limits.rs");

fn put(db: &rusqlite::Connection, room: &str, blob: &str, uploader: &str, size: i64) {
    db.execute(
        "INSERT INTO plugin_media_objects (room_id, blob_id, uploader_id, size_bytes, created_at) \
         VALUES (?1, ?2, ?3, ?4, 0)",
        rusqlite::params![room, blob, uploader, size],
    )
    .unwrap();
}

fn near(db: &rusqlite::Connection, l: &PluginLimits) -> Vec<serde_json::Value> {
    let m = l.media_limits();
    let mut st = db.prepare(NEAR_MEDIA_SQL).unwrap();
    let rows: Vec<NearMediaRow> = st
        .query_map(rusqlite::params![threshold(m.bytes), threshold(m.objects), NEAR_ROWS], |r| {
            Ok(NearMediaRow {
                room_id: r.get(0)?,
                user_id: r.get(1)?,
                display_name: r.get(2)?,
                bytes: r.get(3)?,
                objects: r.get(4)?,
            })
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    rows.iter().flat_map(|r| near_entries(r, l)).collect()
}

/// Who holds 80 % of a media limit in a room is listed, per room, by the limit they are near.
#[test]
fn the_near_list_is_who_holds_eighty_percent() {
    let db = crate::test_schema::full_schema();
    let l = PluginLimits::default()
        .with_write(&serde_json::json!({ "media_bytes": 1024 * 1024, "media_objects": 16 }))
        .unwrap();
    put(&db, "r1", "a", "alice", 900 * 1024); // 88 % of the bytes
    put(&db, "r2", "b", "alice", 100); // the same member, another room: not near
    for i in 0..13 {
        put(&db, "r1", &format!("o{i}"), "bob", 1); // 13 of 16 objects = 81 %
    }
    put(&db, "r1", "c", "carol", 1); // nowhere near
    let list = near(&db, &l);
    assert_eq!(list.len(), 2, "{list:?}");
    assert!(list.iter().any(|e| e["user_id"] == "alice" && e["room_id"] == "r1" && e["key"] == "media_bytes"));
    assert!(list.iter().any(|e| e["user_id"] == "bob" && e["key"] == "media_objects" && e["used"] == 13));
    // A higher limit: nobody is near.
    assert!(near(&db, &PluginLimits::default()).is_empty());
}

#[test]
fn the_threshold_rounds_up() {
    assert_eq!(threshold(100), 80);
    assert_eq!(threshold(16), 13);
    assert!(limits::is_near(threshold(4096), 4096));
    assert!(!limits::is_near(threshold(4096) - 1, 4096));
}

/// Any admin may read; only the owner may write (as every other server setting).
#[test]
fn the_gates_are_admin_to_read_and_owner_to_write() {
    let get = &SRC[SRC.find("pub async fn get_plugin_limits").unwrap()..];
    let get = &get[..get.find("pub async fn set_plugin_limits").unwrap()];
    assert!(get.contains("require_admin(&user_id"));
    let set = &SRC[SRC.find("pub async fn set_plugin_limits").unwrap()..];
    assert!(set.contains("require_owner(&user_id"));
    assert!(set.find(".with_write(&body)").unwrap() < set.find("limits::store(").unwrap(), "checked before stored");
    let lib = include_str!("../lib.rs");
    assert!(lib.contains(".get_async(\"/admin/plugin-limits\", admin::plugin_limits::get_plugin_limits)"));
    assert!(lib.contains(".patch_async(\"/admin/plugin-limits\", admin::plugin_limits::set_plugin_limits)"));
    let caps = include_str!("../server/handlers.rs");
    assert!(caps.contains("body[\"plugin_limits\"] = crate::plugin_limits::read(&db).await.announced();"));
}
