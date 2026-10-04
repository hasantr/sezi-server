//! The real D1 schema for SQL contract tests: every migration in `migrations/`, applied in
//! file-name order — the order `self_provision.rs` applies them — to a fresh in-memory SQLite
//! database with foreign keys ON, as D1 has them.
//!
//! A fixture hand-written to look like the schema agrees with whatever the SQL under test
//! assumed; this one is the schema. Read from disk rather than from `self_provision`'s embedded
//! list, so a file missing from that list still reaches the tests (and
//! `the_migrations_list_matches_the_folder` catches the omission itself).

use rusqlite::Connection;

pub(crate) fn full_schema() -> Connection {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .expect("the migrations folder must be readable")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    for f in files {
        let sql = std::fs::read_to_string(&f).unwrap();
        db.execute_batch(&sql)
            .unwrap_or_else(|e| panic!("{} does not apply on SQLite: {e}", f.display()));
    }
    db
}
