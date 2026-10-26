//! "The program showed up" (`bots.program_seen_at`) against the real schema.

use super::PROGRAM_SEEN_SQL;
use rusqlite::{params, Connection};

const BOT: &str = "b0000000-0000-4000-8000-000000000001";

fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at, kind) VALUES (?1, 'b@bots.invalid', X'01', 1, 'bot')",
        [BOT],
    )
    .unwrap();
    db.execute("INSERT INTO bots (bot_id, name, created_at) VALUES (?1, 'Echo', 1)", [BOT]).unwrap();
    db
}

fn seen(db: &Connection) -> Option<i64> {
    db.query_row("SELECT program_seen_at FROM bots WHERE bot_id = ?1", [BOT], |r| r.get(0)).unwrap()
}

/// Every API call stamps it, and until 2026-10-26 every stamp was a D1 row written: a program
/// polling `getUpdates {timeout: 0}` in a loop wrote D1 as fast as it could call, spending the
/// daily write allowance the whole server shares. A stamp within a minute of the last now
/// writes nothing — the owner's "no word from it" line is measured in ten-minute steps.
#[test]
fn the_program_is_stamped_at_most_once_a_minute() {
    let db = db();
    let stamp = |now: i64| db.execute(PROGRAM_SEEN_SQL, params![BOT, now]).unwrap();
    assert_eq!(stamp(1_000), 1, "the first sight writes");
    assert_eq!(seen(&db), Some(1_000));
    for now in [1_000, 1_001, 1_030, 1_059] {
        assert_eq!(stamp(now), 0, "{now}: within the minute, no row is written");
    }
    assert_eq!(seen(&db), Some(1_000));
    assert_eq!(stamp(1_060), 1, "a minute on, it writes again");
    assert_eq!(seen(&db), Some(1_060));
    assert_eq!(db.execute(PROGRAM_SEEN_SQL, params!["another", 5_000]).unwrap(), 0);
}

/// `setWebhook` with the URL already set writes nothing (a program that registers on every
/// start, or in a loop); a change, or a clear, writes once.
#[test]
fn set_webhook_writes_only_a_change() {
    use crate::bots::api::SET_WEBHOOK_SQL;
    let db = db();
    let set = |url: Option<&str>| db.execute(SET_WEBHOOK_SQL, params![BOT, url]).unwrap();
    assert_eq!(set(Some("https://a.example/h")), 1);
    assert_eq!(set(Some("https://a.example/h")), 0, "the same URL again");
    assert_eq!(set(Some("https://b.example/h")), 1);
    assert_eq!(set(None), 1, "cleared");
    assert_eq!(set(None), 0, "cleared again");
}
