//! The bot key's shape and its lookup against the real schema.

use super::*;
use rusqlite::{params, Connection, OptionalExtension};

const BOT: &str = "b0000000-0000-4000-8000-000000000001";

#[test]
fn a_minted_token_names_its_bot_and_hides_the_rest() {
    let t = mint(BOT);
    assert!(t.starts_with("sezibot_b0000000-"));
    assert_eq!(t.len(), PREFIX.len() + 36 + 1 + 43);
    assert_eq!(parse(&t), Some(BOT));
    assert_ne!(mint(BOT), t, "every key is fresh");
    assert_eq!(hash(&t).len(), 64, "sha256 hex, as refresh_tokens");
    assert_eq!(hash(&t), hash(&t));
}

#[test]
fn a_secret_may_contain_underscores_and_the_id_ends_at_the_first() {
    let secret = format!("_{}", "a".repeat(42));
    let t = format!("{PREFIX}{BOT}_{secret}");
    assert_eq!(parse(&t), Some(BOT));
}

#[test]
fn malformed_tokens_name_no_bot() {
    let good_secret = "A".repeat(43);
    for bad in [
        String::new(),
        format!("{BOT}_{good_secret}"),                         // no prefix
        format!("sezibot-{BOT}_{good_secret}"),                 // wrong prefix
        format!("{PREFIX}{BOT}"),                                // no secret
        format!("{PREFIX}{BOT}_{}", "A".repeat(42)),            // short secret
        format!("{PREFIX}{BOT}_{}", "A".repeat(44)),            // long secret
        format!("{PREFIX}{BOT}_{}!", "A".repeat(42)),           // not b64url
        format!("{PREFIX}not-a-uuid_{good_secret}"),            // not an id
        format!("{PREFIX}{}_{good_secret}", BOT.replace('-', "x")),
    ] {
        assert_eq!(parse(&bad), None, "{bad}");
    }
}

fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at, kind) VALUES (?1, 'b@bots.invalid', X'01', 1, 'bot')",
        [BOT],
    )
    .unwrap();
    db.execute(
        "INSERT INTO bots (bot_id, name, about, created_at) VALUES (?1, 'Echo', NULL, 1)",
        [BOT],
    )
    .unwrap();
    db
}

fn lookup(db: &Connection, hash: &str, bot: &str) -> Option<(String, Option<i64>)> {
    db.query_row(TOKEN_LOOKUP_SQL, params![hash, bot], |r| Ok((r.get(1)?, r.get(3)?)))
        .optional()
        .unwrap()
}

#[test]
fn a_live_token_finds_its_bot_and_a_renewal_stops_the_old_one_at_once() {
    let db = db();
    db.execute(INSERT_TOKEN_SQL, params!["h1", BOT, 10]).unwrap();
    assert_eq!(lookup(&db, "h1", BOT), Some(("Echo".into(), None)));
    assert_eq!(lookup(&db, "h1", "b0000000-0000-4000-8000-000000000002"), None, "another bot's id");
    assert_eq!(lookup(&db, "h2", BOT), None);
    // Renewal: revoke all, insert the new one.
    db.execute(REVOKE_TOKENS_SQL, params![BOT, 20]).unwrap();
    db.execute(INSERT_TOKEN_SQL, params!["h2", BOT, 20]).unwrap();
    assert_eq!(lookup(&db, "h1", BOT), None, "the old key stops at once");
    assert!(lookup(&db, "h2", BOT).is_some());
}

#[test]
fn a_disabled_bot_is_found_and_a_deleted_one_is_not() {
    let db = db();
    db.execute(INSERT_TOKEN_SQL, params!["h1", BOT, 10]).unwrap();
    db.execute("UPDATE bots SET disabled_at = 30 WHERE bot_id = ?1", [BOT]).unwrap();
    assert_eq!(
        lookup(&db, "h1", BOT),
        Some(("Echo".into(), Some(30))),
        "found, so the API can answer bot/disabled rather than a wrong-key 401"
    );
    db.execute("UPDATE bots SET deleted_at = 40 WHERE bot_id = ?1", [BOT]).unwrap();
    assert_eq!(lookup(&db, "h1", BOT), None);
}
