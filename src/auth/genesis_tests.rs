//! Ownership comes from redeeming the genesis invite — the redeem → verify path end to end.
//!
//! The decision is split across two files on purpose: `invite_attribution::CLAIM_INVITE_SQL`
//! records at the claim whether the invite was the genesis one, and `verify` reads that record
//! back through `LOAD_INVITER_SQL` and hands it to `role_for_registration`. These tests drive both
//! halves over one in-memory ledger, so a change to either side that breaks the hand-off fails
//! here rather than on a server being claimed.

use super::invite_attribution::{CLAIM_INVITE_SQL, LOAD_INVITER_SQL};
use super::verify::role_for_registration;
use crate::auth::hashing::sha256_hex;
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_780_000_000;
const LEDGER: &str = include_str!("../../migrations/0031_invite_attributions.sql");
const GENESIS_COLUMN: &str = include_str!("../../migrations/0039_genesis_claim.sql");

/// The tables the claim and the loader touch, as they stand before 0031 — so the migrations under
/// test run against the shape they were written for. `role` is on `users` because the claim reads
/// it to decide whether the genesis door is still open.
fn base_db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE users (
           id TEXT PRIMARY KEY,
           identity_ed_pub BLOB,
           role TEXT NOT NULL DEFAULT 'member'
         );
         CREATE TABLE invite_tokens (
           token TEXT PRIMARY KEY,
           email_hint TEXT,
           used INTEGER NOT NULL DEFAULT 0,
           used_by TEXT REFERENCES users(id),
           owner_user_id TEXT REFERENCES users(id),
           expires_at INTEGER NOT NULL,
           created_at INTEGER NOT NULL
         );
         CREATE TABLE verification_codes (
           email TEXT PRIMARY KEY,
           invite_token TEXT,
           expires_at INTEGER NOT NULL
         );",
    )
    .unwrap();
    db.execute_batch(LEDGER).unwrap();
    db
}

fn ledger_db() -> Connection {
    let db = base_db();
    db.execute_batch(GENESIS_COLUMN).unwrap();
    db
}

/// An unused invite. `minter: None` is the genesis invite `auth::bootstrap` mints.
fn mint(db: &Connection, token: &str, minter: Option<&str>) {
    db.execute(
        "INSERT INTO invite_tokens
           (token, token_hash, email_hint, used, used_by, owner_user_id, expires_at, created_at)
         VALUES (?1, ?2, NULL, 0, NULL, ?3, ?4, ?5)",
        params![token, sha256_hex(token), minter, NOW + 3_600, NOW - 60],
    )
    .unwrap();
}

/// Redeem's claim, then its bridge row — what `auth::invite::redeem` writes for `email`. Returns
/// whether the claim was won.
fn redeem(db: &Connection, email: &str, token: &str) -> bool {
    redeem_with(db, email, token, true)
}

/// `redeem`, with the claim secret's verdict for this request (`auth::claim::claim_authorized`).
fn redeem_with(db: &Connection, email: &str, token: &str, genesis_allowed: bool) -> bool {
    let hash = sha256_hex(token);
    let won: Option<String> = db
        .query_row(
            CLAIM_INVITE_SQL,
            params![hash, NOW, token, NOW, hash, genesis_allowed as i64],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    if won.is_some() {
        db.execute(
            "INSERT INTO verification_codes (email, invite_token, invite_token_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![email, token, hash, NOW + 600],
        )
        .unwrap();
    }
    won.is_some()
}

/// The role verify would create `email`'s account with: the loader's `genesis` column, through
/// the same function verify calls. No ledger row (no claim reached this e-mail) reads as false.
fn role_at_verify(db: &Connection, email: &str) -> &'static str {
    let genesis: Option<i64> = db
        .query_row(LOAD_INVITER_SQL, [email], |r| r.get("genesis"))
        .optional()
        .unwrap();
    role_for_registration(genesis == Some(1))
}

#[test]
fn redeeming_the_genesis_invite_on_an_unowned_server_makes_the_owner() {
    let db = ledger_db();
    mint(&db, "genesis-secret", None);
    assert!(redeem(&db, "founder@sezgi.local", "genesis-secret"));
    assert_eq!(role_at_verify(&db, "founder@sezgi.local"), "owner");
}

/// The case the old rule got wrong: nobody on the server at all, and a registration that did not
/// come through the genesis invite. "Users is empty" said owner; the claim record says member.
#[test]
fn a_registration_without_the_genesis_invite_is_a_member_even_on_an_empty_server() {
    let db = ledger_db();
    db.execute(
        "INSERT INTO verification_codes (email, invite_token, expires_at)
         VALUES ('walk-in@sezgi.local', NULL, ?1)",
        [NOW + 600],
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0,
        "the server is empty"
    );
    assert_eq!(role_at_verify(&db, "walk-in@sezgi.local"), "member");
}

/// An invite somebody minted is never the genesis one, whether or not the server has an owner.
#[test]
fn a_minted_invite_registers_a_member_on_a_server_with_no_owner() {
    let db = ledger_db();
    db.execute("INSERT INTO users (id, role) VALUES ('adm', 'admin')", [])
        .unwrap();
    mint(&db, "admin-minted", Some("adm"));
    assert!(redeem(&db, "joiner@sezgi.local", "admin-minted"));
    assert_eq!(role_at_verify(&db, "joiner@sezgi.local"), "member");
}

/// Why `genesis` is a column of its own: removing the inviter clears `inviter_user_id` (the
/// explicit UPDATE in `membership.rs` and the foreign key's ON DELETE SET NULL both do), so an
/// ordinary invite whose minter left between redeem and verify must not start to read as genesis.
#[test]
fn the_genesis_fact_does_not_move_when_the_inviter_is_removed_mid_window() {
    let db = ledger_db();
    db.execute("INSERT INTO users (id, role) VALUES ('adm', 'admin')", [])
        .unwrap();
    mint(&db, "admin-minted", Some("adm"));
    assert!(redeem(&db, "joiner@sezgi.local", "admin-minted"));

    db.execute(
        "UPDATE invite_attributions SET inviter_user_id = NULL WHERE inviter_user_id = 'adm'",
        [],
    )
    .unwrap();
    assert_eq!(role_at_verify(&db, "joiner@sezgi.local"), "member");
}

/// A minter-less invite on an owned server is a leftover, not a way in: an admin removed before
/// 2026-10-04 left exactly these behind. The claim refuses it, which redeem reports as
/// `invalid_invite`, so it can neither admit anyone nor reach the one-owner index.
#[test]
fn a_minterless_invite_claims_nothing_once_the_server_has_an_owner() {
    let db = ledger_db();
    db.execute("INSERT INTO users (id, role) VALUES ('boss', 'owner')", [])
        .unwrap();
    mint(&db, "leftover", None);
    assert!(!redeem(&db, "someone@sezgi.local", "leftover"));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM invite_attributions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "a refused claim writes nothing to the ledger"
    );
}

/// The upgrade itself: a genesis claim redeemed before 0039 and verified after it must still make
/// the owner. Only an unverified, inviter-less claim with a live bridge row is marked.
#[test]
fn the_migration_marks_only_an_in_flight_genesis_claim() {
    let db = base_db();
    db.execute("INSERT INTO users (id, role) VALUES ('adm', 'admin')", [])
        .unwrap();
    let ledger_row = |hash: &str, inviter: Option<&str>, verified: Option<i64>| {
        db.execute(
            "INSERT INTO invite_attributions
               (invite_token_hash, inviter_user_id, created_at, expires_at, redeemed_at, verified_at)
             VALUES (?1, ?2, 1, 99, 2, ?3)",
            params![hash, inviter, verified],
        )
        .unwrap();
    };
    let in_flight = "a".repeat(64);
    let abandoned = "b".repeat(64);
    let finished = "c".repeat(64);
    let minted = "d".repeat(64);
    ledger_row(&in_flight, None, None);
    ledger_row(&abandoned, None, None);
    ledger_row(&finished, None, Some(3));
    ledger_row(&minted, Some("adm"), None);
    for (email, hash) in [
        ("founder@sezgi.local", &in_flight),
        ("done@sezgi.local", &finished),
        ("joiner@sezgi.local", &minted),
    ] {
        db.execute(
            "INSERT INTO verification_codes (email, invite_token_hash, expires_at)
             VALUES (?1, ?2, ?3)",
            params![email, hash, NOW + 600],
        )
        .unwrap();
    }

    db.execute_batch(GENESIS_COLUMN).unwrap();

    let marked: Vec<String> = db
        .prepare("SELECT invite_token_hash FROM invite_attributions WHERE genesis = 1")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(marked, vec![in_flight]);
    assert_eq!(role_at_verify(&db, "founder@sezgi.local"), "owner");
    assert_eq!(role_at_verify(&db, "joiner@sezgi.local"), "member");
}

/// Source-level guard on the half the SQL tests cannot reach: verify must take the role from the
/// claim record. The old rule is one innocent-looking SELECT away from coming back.
#[test]
fn verify_takes_the_role_from_the_claim_and_never_from_the_users_table() {
    const VERIFY: &str = include_str!("verify.rs");
    assert!(
        VERIFY.contains("role_for_registration(redeemed_genesis)"),
        "verify must decide the role from the genesis fact the claim recorded"
    );
    assert!(
        !VERIFY.contains("SELECT id FROM users LIMIT 1"),
        "\"the first account to register is the owner\" is the rule this replaced"
    );
}

/// A genesis invite minted before a claim secret was configured (the welcome page printed it)
/// must not claim the server for a request that lacks the secret — while an ordinary invite keeps
/// working regardless.
#[test]
fn without_the_claim_secret_the_genesis_invite_claims_nothing() {
    let db = ledger_db();
    mint(&db, "genesis-secret", None);
    assert!(!redeem_with(&db, "stranger@sezgi.local", "genesis-secret", false));
    assert!(redeem_with(&db, "founder@sezgi.local", "genesis-secret", true));
    assert_eq!(role_at_verify(&db, "founder@sezgi.local"), "owner");
}
