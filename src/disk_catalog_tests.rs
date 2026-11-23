use super::*;

#[test]
fn a_member_path_stays_inside_its_catalog() {
    assert_eq!(join("Kitaplar", "").as_deref(), Some("Kitaplar"));
    assert_eq!(join("Kitaplar", "Roman/a.epub").as_deref(), Some("Kitaplar/Roman/a.epub"));
    assert_eq!(join("", "a.epub").as_deref(), Some("a.epub"));
    for bad in ["../x", "Roman/../../x", "/etc", ".gizli", "a//b", "a\\b"] {
        assert_eq!(join("Kitaplar", bad), None, "{bad}");
    }
}

#[test]
fn answers_are_rebased_onto_the_catalog_and_nothing_outside_is_shown() {
    assert_eq!(strip("Kitaplar", "Kitaplar/Roman/a.epub").as_deref(), Some("Roman/a.epub"));
    assert_eq!(strip("Kitaplar", "Kitaplar").as_deref(), Some(""));
    assert_eq!(strip("Kitaplar", "Kitaplarim/a.epub"), None);
    assert_eq!(strip("Kitaplar", "Filmler/a.mkv"), None);
    let body = json!({
        "path": "Kitaplar/Roman",
        "entries": [
            {"name": "a.epub", "path": "Kitaplar/Roman/a.epub"},
            {"name": "x.mkv", "path": "Filmler/x.mkv"},
        ],
        "truncated": false,
    });
    let out = rebase("Kitaplar", body);
    assert_eq!(out["path"], "Roman");
    assert_eq!(out["entries"].as_array().unwrap().len(), 1);
    assert_eq!(out["entries"][0]["path"], "Roman/a.epub");
}

#[test]
fn names_are_trimmed_and_bounded() {
    assert_eq!(clean_name("  Kitaplık  ").as_deref(), Some("Kitaplık"));
    assert_eq!(clean_name("   "), None);
    assert_eq!(clean_name(&"a".repeat(81)), None);
    assert_eq!(clean_name("a\nb"), None);
}

#[test]
fn the_catalog_table_caps_a_group_and_goes_with_it() {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES ('u1', 'a@x', 'k', 0);
         INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES ('g1', 'Okuma', 'u1', 0, 0);",
    )
    .unwrap();
    let add = |id: &str, cap: i64| {
        db.execute(INSERT_SQL, rusqlite::params!["g1", id, "Kitaplar", "Kitaplık", "u1", 1, cap])
            .unwrap()
    };
    assert_eq!(add("c1", 2), 1);
    assert_eq!(add("c2", 2), 1);
    assert_eq!(add("c3", 2), 0, "the cap holds");
    let path: String = db
        .query_row(SELECT_SQL, rusqlite::params!["g1", "c1"], |r| r.get(0))
        .unwrap();
    assert_eq!(path, "Kitaplar");
    assert_eq!(db.execute(DELETE_SQL, rusqlite::params!["g1", "c2"]).unwrap(), 1);
    db.execute("DELETE FROM groups WHERE id = 'g1'", []).unwrap();
    let left: i64 = db.query_row("SELECT COUNT(*) FROM disk_catalogs", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0);
}
