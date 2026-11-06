//! The member budget of a room's plugin log, run on a real SQLite with the room DO's own tables
//! (`plugin_log.rs` `CREATE_*_SQL`) — the statements the DO runs, in the order it runs them.

use super::*;
use rusqlite::{params_from_iter, Connection};

/// The room DO's storage, as an in-memory SQLite.
struct Mem(Connection);

fn bind(args: &[Arg<'_>]) -> Vec<rusqlite::types::Value> {
    args.iter()
        .map(|a| match a {
            Arg::Text(s) => rusqlite::types::Value::Text((*s).to_string()),
            Arg::Int(i) => rusqlite::types::Value::Integer(*i),
        })
        .collect()
}

impl LogSql for Mem {
    fn exec(&self, sql: &str, args: &[Arg<'_>]) -> Result<(), String> {
        self.0
            .execute(sql, params_from_iter(bind(args)))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn behind(&self) -> Result<Vec<BehindRow>, String> {
        let mut st = self.0.prepare(BEHIND_SQL).map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| {
                Ok(BehindRow { plugin_id: r.get(0)?, through_seq: r.get(1)?, last_seq: r.get(2)? })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }
    fn usage(&self, plugin_id: &str, author_id: &str) -> Result<UsageRow, String> {
        self.0
            .query_row(USAGE_SQL, [plugin_id, author_id], |r| {
                Ok(UsageRow { app_bytes: r.get(0)?, room_bytes: r.get(1)? })
            })
            .map_err(|e| e.to_string())
    }
}

/// A room log as a build before this one left it: the two original tables only.
fn old_room() -> Mem {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(crate::plugin_log::CREATE_META_SQL).unwrap();
    db.execute_batch(crate::plugin_log::CREATE_ENTRIES_SQL).unwrap();
    Mem(db)
}

/// This build's room log: the DO creates the budget's tables beside the old ones.
fn room() -> Mem {
    let m = old_room();
    m.0.execute_batch(CREATE_USAGE_SQL).unwrap();
    m.0.execute_batch(CREATE_COUNTED_SQL).unwrap();
    m
}

/// Append as `do_append` does, with no budget: the seq, then the row. Returns the seq.
fn raw_append(m: &Mem, plugin: &str, author: &str, ciphertext: &str) -> i64 {
    m.0.execute(
        "INSERT OR IGNORE INTO plugin_log_meta (plugin_id, last_seq) VALUES (?1, 0)",
        [plugin],
    )
    .unwrap();
    let seq: i64 = m
        .0
        .query_row(
            "UPDATE plugin_log_meta SET last_seq = last_seq + 1 WHERE plugin_id = ?1 RETURNING last_seq",
            [plugin],
            |r| r.get(0),
        )
        .unwrap();
    m.0.execute(
        "INSERT INTO plugin_log_entries (plugin_id, seq, author_id, author_device_id, key_epoch, \
            author_counter, content_kind, ciphertext_b64, nonce_b64, aad_hash, uploaded_at_ms) \
         VALUES (?1, ?2, ?3, 'dev', 0, ?2, 'inline', ?4, 'nonce', 'aad', 0)",
        rusqlite::params![plugin, seq, author, ciphertext],
    )
    .unwrap();
    seq
}

fn cost_of(ciphertext: &str) -> i64 {
    entry_bytes(&EntryFields {
        ciphertext_b64: Some(ciphertext),
        nonce_b64: Some("nonce"),
        blob_id: None,
        blob_hash: None,
        aad_hash: "aad",
        prev_hash: None,
        entry_hash: None,
    })
}

/// The whole guarded append: admit, write, charge. `Some(full)` = refused.
fn append(m: &Mem, plugin: &str, author: &str, ciphertext: &str) -> Option<Full> {
    append_under(m, plugin, author, ciphertext, LogLimits::default())
}

/// [`append`] under a server's own limits.
fn append_under(m: &Mem, plugin: &str, author: &str, ciphertext: &str, limits: LogLimits) -> Option<Full> {
    let cost = cost_of(ciphertext);
    if let (Some(full), _) = admit(m, plugin, author, cost, limits).unwrap() {
        return Some(full);
    }
    let seq = raw_append(m, plugin, author, ciphertext);
    charge(m, plugin, author, cost, seq).unwrap();
    None
}

fn usage(m: &Mem, plugin: &str, author: &str) -> (i64, i64) {
    let u = m.usage(plugin, author).unwrap();
    (u.app_bytes, u.room_bytes)
}

#[test]
fn the_sql_cost_of_a_stored_row_is_the_rust_cost_of_the_entry() {
    let m = room();
    let text = "çok-baytlı-ğ".repeat(7); // multi-byte: length() alone would count characters
    raw_append(&m, "html:a", "alice", &text);
    let sql: i64 = m
        .0
        .query_row(&format!("SELECT {ENTRY_BYTES_EXPR} FROM plugin_log_entries"), [], |r| r.get(0))
        .unwrap();
    assert_eq!(sql, cost_of(&text));
}

#[test]
fn appends_are_charged_to_their_author_per_app_and_per_room() {
    let m = room();
    assert_eq!(append(&m, "html:a", "alice", "x"), None);
    assert_eq!(append(&m, "html:b", "alice", "yy"), None);
    assert_eq!(append(&m, "html:a", "bob", "z"), None);
    assert_eq!(usage(&m, "html:a", "alice"), (cost_of("x"), cost_of("x") + cost_of("yy")));
    assert_eq!(usage(&m, "html:a", "bob"), (cost_of("z"), cost_of("z")));
}

#[test]
fn an_app_log_past_the_member_budget_is_refused_for_that_member_only() {
    let m = room();
    // One stored entry that leaves 100 bytes of the app budget.
    let big = "a".repeat((MAX_BYTES_PER_MEMBER_PER_APP - cost_of("") - 100) as usize);
    assert_eq!(append(&m, "html:a", "alice", &big), None);
    assert_eq!(append(&m, "html:a", "alice", &"b".repeat(200)), Some(Full::App));
    // Small enough still fits; another member and another app are not touched.
    assert_eq!(append(&m, "html:a", "alice", "c"), None);
    assert_eq!(append(&m, "html:a", "bob", &"b".repeat(200)), None);
    assert_eq!(append(&m, "html:b", "alice", &"b".repeat(200)), None);
}

#[test]
fn inventing_app_ids_does_not_multiply_the_room_budget() {
    let m = room();
    let chunk = "a".repeat((MAX_BYTES_PER_MEMBER_PER_APP - cost_of("") - 1) as usize);
    let apps = MAX_BYTES_PER_MEMBER_PER_ROOM / MAX_BYTES_PER_MEMBER_PER_APP;
    for i in 0..apps {
        assert_eq!(append(&m, &format!("html:x{i}"), "alice", &chunk), None);
    }
    assert_eq!(append(&m, "html:fresh", "alice", &"b".repeat(1024)), Some(Full::Room));
    assert_eq!(append(&m, "html:fresh", "bob", &"b".repeat(1024)), None);
}

/// A room log written before this build: the first append counts what is already there.
#[test]
fn a_log_written_before_the_budget_is_counted_at_the_first_append() {
    let m = old_room();
    raw_append(&m, "html:a", "alice", "old-1");
    raw_append(&m, "html:a", "alice", "old-2");
    raw_append(&m, "draw", "alice", "old-3");
    // This build's DO starts: its tables are added beside the old ones.
    m.0.execute_batch(CREATE_USAGE_SQL).unwrap();
    m.0.execute_batch(CREATE_COUNTED_SQL).unwrap();
    assert_eq!(append(&m, "html:a", "alice", "new"), None);
    let app = cost_of("old-1") + cost_of("old-2") + cost_of("new");
    assert_eq!(usage(&m, "html:a", "alice"), (app, app + cost_of("old-3")));
}

/// A rollback: the previous build appends with no count; back on this build, nothing it wrote is
/// missed and nothing is counted twice.
#[test]
fn entries_written_by_a_previous_build_after_a_rollback_are_counted_once() {
    let m = room();
    assert_eq!(append(&m, "html:a", "alice", "one"), None);
    raw_append(&m, "html:a", "alice", "during-rollback");
    assert_eq!(append(&m, "html:a", "alice", "two"), None);
    assert_eq!(append(&m, "html:a", "alice", "three"), None);
    let expected = cost_of("one") + cost_of("during-rollback") + cost_of("two") + cost_of("three");
    assert_eq!(usage(&m, "html:a", "alice").0, expected);
}

#[test]
fn the_refusal_is_a_400_with_a_typed_code() {
    assert_eq!(LOG_FULL_STATUS, 400, "apps since 2046 end an op at a 400 and retry nothing");
    assert_eq!(LOG_FULL_CODE, "plugin/log-full");
    assert_eq!(Full::App.scope(), "app");
    assert_eq!(Full::Room.limit_bytes(LogLimits::default()), MAX_BYTES_PER_MEMBER_PER_ROOM);
    const { assert!(MAX_BYTES_PER_MEMBER_PER_APP <= MAX_BYTES_PER_MEMBER_PER_ROOM) };
}

/// The owner's limits (`plugin_limits.rs`) are the ones held, the refusal names them, and a member
/// past a LOWERED limit keeps everything and adds nothing (Hasan, 2026-11-06).
#[test]
fn the_owners_limits_are_the_ones_held() {
    let m = room();
    let small = LogLimits { app_bytes: 1_000, room_bytes: 1_500 };
    assert_eq!(append_under(&m, "html:a", "alice", &"a".repeat(800), small), None);
    assert_eq!(append_under(&m, "html:a", "alice", &"a".repeat(200), small), Some(Full::App));
    assert_eq!(Full::App.limit_bytes(small), 1_000);
    assert_eq!(append_under(&m, "html:b", "alice", &"a".repeat(700), small), Some(Full::Room));
    // The defaults would have taken it: the figure, not the code, decides.
    assert_eq!(append(&m, "html:a", "alice", &"a".repeat(200)), None);
    let held = usage(&m, "html:a", "alice");
    // Lowered below what alice holds: nothing she has is touched, the next entry is refused.
    let lowered = LogLimits { app_bytes: 500, room_bytes: 500 };
    assert_eq!(append_under(&m, "html:a", "alice", "x", lowered), Some(Full::App));
    assert_eq!(usage(&m, "html:a", "alice"), held);
}

/// The DO learns the limits from the handler's header; anything odd is the defaults.
#[test]
fn the_limits_header_round_trips_and_falls_back() {
    let l = LogLimits { app_bytes: 5, room_bytes: 9 };
    assert_eq!(LogLimits::from_header(Some(&l.to_header())), l);
    for odd in [None, Some(""), Some("5"), Some("a,b"), Some("0,9"), Some("-1,9")] {
        assert_eq!(LogLimits::from_header(odd), LogLimits::default(), "{odd:?}");
    }
    let before = UsageRow { app_bytes: 10, room_bytes: 30 };
    let u = usage_after(&before, 5, l);
    assert_eq!((u["app_bytes"].as_i64(), u["room_bytes"].as_i64()), (Some(15), Some(35)));
    assert_eq!((u["app_limit"].as_i64(), u["room_limit"].as_i64()), (Some(5), Some(9)));
}

/// The append handler hands the DO the owner's limits.
#[test]
fn the_handler_passes_the_owners_limits() {
    let src = include_str!("plugin_log.rs");
    assert!(src.contains("crate::plugin_limits::read(&db).await.log_limits()"));
    assert!(src.contains("headers.set(crate::plugin_log_budget::LIMITS_HEADER"));
    assert!(src.contains("budget::LogLimits::from_header("));
}
