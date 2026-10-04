//! The shorten-retention preview and its apply, against the real schema: the preview counts what
//! the next sweep deletes, the apply only ever moves an expiry earlier, and both endpoints keep
//! their gates.

use super::*;
use rusqlite::{params, Connection};

const NOW: i64 = 1_780_000_000;

/// Physics: two old parts (400 and 200 days) and a new one; Chemistry: an old part, and a younger
/// one already promised a short life (expires in 10 days); Biology: one part already expired.
fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('t', 't@x', x'00', 1);
         INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES
           ('g-phys', 'Physics', 't', 1, 1), ('g-chem', 'Chemistry', 't', 1, 1),
           ('g-bio', 'Biology', 't', 1, 1);",
    )
    .unwrap();
    for (room, id, size, age_days, expires_in_days) in [
        ("g-phys", "p-old", 500, 400, None),
        ("g-phys", "p-mid", 300, 200, None),
        ("g-phys", "p-new", 100, 10, None),
        ("g-chem", "c-older", 800, 250, None),
        ("g-chem", "c-old", 40, 100, Some(10)),
        ("g-bio", "b-gone", 50, 300, Some(-1)),
    ] {
        db.execute(
            "INSERT INTO room_library_objects
               (room_id, object_id, uploader_id, size_bytes, created_at, expires_at)
             VALUES (?1, ?2, 't', ?3, ?4, ?5)",
            params![
                room,
                id,
                size,
                NOW - age_days * DAY,
                expires_in_days.map(|d: i64| NOW + d * DAY)
            ],
        )
        .unwrap();
    }
    db
}

fn totals(db: &Connection, days: i64) -> (i64, i64, i64) {
    db.query_row(PREVIEW_TOTALS_SQL, params![NOW - days * DAY, NOW], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })
    .unwrap()
}

#[test]
fn the_preview_counts_what_the_next_sweep_would_delete() {
    let db = db();
    // 180 days: Physics' two old parts and Chemistry's — not Biology's, which goes anyway.
    assert_eq!(totals(&db, 180), (3, 1600, 2));
    let top: Vec<(String, Option<String>, i64, i64)> = db
        .prepare(PREVIEW_TOP_SQL)
        .unwrap()
        .query_map(params![NOW - 180 * DAY, NOW, 3], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        top,
        [
            ("g-chem".into(), Some("Chemistry".into()), 800, 1),
            ("g-phys".into(), Some("Physics".into()), 800, 2),
        ]
    );
    // The new Physics part is not due, but its open-ended expiry moves to day 180.
    let later: i64 = db
        .query_row(
            PREVIEW_LATER_SQL,
            params![180 * DAY, NOW - 180 * DAY],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(later, 1);
}

/// Applying moves expiries earlier and never later: Chemistry's part was promised ten more days
/// and keeps exactly that, under a retention that would have given it more.
#[test]
fn applying_only_ever_shortens() {
    let db = db();
    let changed = db.execute(SHORTEN_EXPIRY_SQL, [180 * DAY]).unwrap();
    // The four open-ended parts, and Biology's expired one, which moves earlier still.
    assert_eq!(changed, 5);
    let exp = |id: &str| -> i64 {
        db.query_row(
            "SELECT expires_at FROM room_library_objects WHERE object_id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(exp("p-new"), NOW - 10 * DAY + 180 * DAY);
    assert!(
        exp("p-old") < NOW,
        "now due: unreadable at once, deleted at the sweep"
    );
    assert_eq!(exp("c-old"), NOW + 10 * DAY, "an earlier promise is kept");
    // The same retention again changes nothing.
    assert_eq!(db.execute(SHORTEN_EXPIRY_SQL, [180 * DAY]).unwrap(), 0);
}

#[test]
fn the_setting_is_written_whether_or_not_the_row_exists() {
    let db = db();
    db.execute("DELETE FROM server_settings", []).unwrap();
    db.execute(SET_RETENTION_SQL, params![Some(180), NOW])
        .unwrap();
    db.execute(SET_RETENTION_SQL, params![Option::<i64>::None, NOW])
        .unwrap();
    db.execute(SET_RETENTION_SQL, params![Some(90), NOW])
        .unwrap();
    let days: Option<i64> = db.query_row(CURRENT_SQL, [], |r| r.get(0)).unwrap();
    assert_eq!(days, Some(90));
}

#[test]
fn days_and_direction() {
    assert_eq!(preview_days(Some("180")), Some(180));
    assert_eq!(preview_days(Some("0")), None);
    assert_eq!(preview_days(Some("3651")), None);
    assert_eq!(preview_days(None), None);
    assert!(
        shortens(180, None),
        "anything is shorter than keep-until-deleted"
    );
    assert!(shortens(180, Some(365)));
    assert!(
        !shortens(365, Some(180)),
        "lengthening changes no existing row"
    );
}

/// The preview reads (admin), the apply writes policy (owner), and neither says anything the
/// server would need content to know.
#[test]
fn the_gates_are_admin_to_look_and_owner_to_change() {
    let src = include_str!("library_retention.rs");
    let preview =
        &src[src.find("pub async fn preview").unwrap()..src.find("struct ApplyBody").unwrap()];
    assert!(preview.contains("require_active_auth(") && preview.contains("require_admin("));
    let apply = &src[src.find("pub async fn apply").unwrap()..src.find("#[cfg(test)]").unwrap()];
    assert!(apply.contains("require_active_auth(") && apply.contains("require_owner("));
    assert!(!apply.contains("require_admin("));
    assert!(apply.contains("confirm_required"));
    for leak in ["uploader_id", "object_id", "kind"] {
        assert!(
            !preview.contains(leak),
            "the preview must not carry `{leak}`"
        );
    }
}
