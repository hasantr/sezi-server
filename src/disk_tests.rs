use super::*;

/// The sizes the relay announces for a disk item's parts must be the bytes the gateway sends —
/// `sezi_file::part::part_ciphertext_len` of each part's plaintext.
#[test]
fn part_sizes_follow_the_library_framing() {
    let part = 4 * 1024 * 1024;
    let size = part * 10 + 12_345;
    assert_eq!(part_count(size, part), 11);
    // A full part: 64 chunks of 64 KiB, one 16-byte tag each.
    assert_eq!(part_ciphertext_size(size, part, 0), Some(part + 64 * 16));
    // The tail: 12,345 bytes in one chunk.
    assert_eq!(part_ciphertext_size(size, part, 10), Some(12_345 + 16));
    assert_eq!(part_ciphertext_size(size, part, 11), None);
    // The gateway's live answer on 2026-11-23 for a 9,000,000-byte file: part 2 was 611,552.
    assert_eq!(part_ciphertext_size(9_000_000, part, 2), Some(611_552));
    assert_eq!(part_ciphertext_size(9_000_000, part, 1), Some(4_195_328));
}

#[test]
fn only_a_readable_layout_is_recorded() {
    let part = 4 * 1024 * 1024;
    assert!(valid_layout(9_000_000, part, 3));
    assert!(!valid_layout(9_000_000, part, 4));
    assert!(!valid_layout(0, part, 1));
    assert!(!valid_layout(9_000_000, 1024, part_count(9_000_000, 1024)));
    assert!(!valid_layout(65 * 1024 * 1024 * 1024, part, part_count(65 * 1024 * 1024 * 1024, part)));
}

#[test]
fn an_object_id_names_its_item_and_part() {
    assert_eq!(split_object_id("a-YUrMNWEl8nWAiQYjGCVA-2"), Some(("a-YUrMNWEl8nWAiQYjGCVA", 2)));
    assert_eq!(split_object_id("abc-"), None);
    assert_eq!(split_object_id("-3"), None);
    assert_eq!(split_object_id("abc-x1"), None);
    assert_eq!(split_object_id("abc"), None);
    assert!(valid_item_id("a-YUrMNWEl8nWAiQYjGCVA"));
    assert!(!valid_item_id("short"));
    assert!(!valid_item_id("has/slash-aaaaaaaaaaaaaaa"));
}

/// The table and every statement on it, against the real migrations.
#[test]
fn the_disk_table_holds_one_row_per_item_and_goes_with_its_group() {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('u1', 'a@x', 'k', 0);
         INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES ('g1', 'Sinema', 'u1', 0, 0);",
    )
    .unwrap();
    let insert = |room: &str| {
        db.execute(
            INSERT_ITEM_SQL,
            rusqlite::params![room, "item-aaaaaaaaaaaaaaaa", "u1", 9_000_000, 4_194_304, 3, 1],
        )
        .unwrap()
    };
    assert_eq!(insert("g1"), 1);
    assert_eq!(insert("g1"), 0, "the same item twice is one row");
    assert_eq!(insert("gone"), 0, "no group, no row");
    let (adder, parts): (String, i64) = db
        .query_row(SELECT_ITEM_SQL, rusqlite::params!["g1", "item-aaaaaaaaaaaaaaaa"], |r| {
            Ok((r.get(0)?, r.get(3)?))
        })
        .unwrap();
    assert_eq!((adder.as_str(), parts), ("u1", 3));
    assert_eq!(db.execute(DELETE_ITEM_SQL, rusqlite::params!["g1", "x"]).unwrap(), 0);
    db.execute("DELETE FROM groups WHERE id = 'g1'", []).unwrap();
    let left: i64 = db.query_row("SELECT COUNT(*) FROM room_library_disk", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0, "deleting the group takes its disk items");
}
