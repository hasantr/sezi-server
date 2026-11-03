//! The registration receipt on the real schema, and the registration's one batch.

use super::*;
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_800_000_000;
const EMAIL: &str = "joiner@example.org";

/// A code hash in the stored format with ONE iteration, so the test does not pay pbkdf2's 200,000.
fn cheap_hash(code: &str) -> String {
    use crate::utils::b64u_encode;
    let salt = [7u8; 16];
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(code.as_bytes(), &salt, 1, &mut out).unwrap();
    format!("pbk2$1${}${}", b64u_encode(&salt), b64u_encode(&out))
}

fn db_with_code(code: &str) -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute(
        "INSERT INTO verification_codes (email, code_hash, attempts, expires_at, created_at)
         VALUES (?1, ?2, 0, ?3, ?4)",
        params![EMAIL, cheap_hash(code), NOW + 600, NOW],
    )
    .unwrap();
    db
}

/// What the registration batch does to the code: the receipt first, then the code goes.
fn register(db: &Connection, user: &str) {
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, role, created_at) VALUES (?1, ?2, x'01', 'member', ?3)",
        params![user, EMAIL, NOW],
    )
    .unwrap();
    db.execute(
        WRITE_RECEIPT_SQL,
        params![EMAIL, user, "dev1", identity_hash(&[1, 2, 3]), None::<String>, None::<String>, NOW + RECEIPT_TTL_SECS],
    )
    .unwrap();
    db.execute("DELETE FROM verification_codes WHERE email = ?1", [EMAIL]).unwrap();
}

fn claim(db: &Connection, now: i64) -> Option<(String, String)> {
    db.query_row(CLAIM_RECEIPT_SQL, params![EMAIL, 5, now], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .unwrap()
}

#[test]
fn the_receipt_keeps_the_spent_codes_hash_and_answers_the_same_registration_only() {
    let db = db_with_code("482913");
    register(&db, "u1");
    let (code_hash, user) = claim(&db, NOW + 60).expect("a live receipt");
    assert_eq!(user, "u1");
    let r = Receipt {
        code_hash,
        user_id: user,
        device_id: "dev1".into(),
        identity_hash: identity_hash(&[1, 2, 3]),
        inviter_user_id: None,
        inviter_ed_pub: None,
    };
    assert!(same_registration(&r, "482913", &[1, 2, 3], "dev1"));
    assert!(!same_registration(&r, "482914", &[1, 2, 3], "dev1"), "another code");
    assert!(!same_registration(&r, "482913", &[9, 9, 9], "dev1"), "another identity");
    assert!(!same_registration(&r, "482913", &[1, 2, 3], "dev2"), "another device");
}

#[test]
fn a_receipt_is_charged_per_try_and_ends() {
    let db = db_with_code("482913");
    register(&db, "u1");
    for _ in 0..5 {
        assert!(claim(&db, NOW + 60).is_some());
    }
    assert!(claim(&db, NOW + 60).is_none(), "the code's own ceiling of five guesses");
    let db = db_with_code("482913");
    register(&db, "u1");
    assert!(claim(&db, NOW + RECEIPT_TTL_SECS + 1).is_none(), "half an hour, then nothing");
    db.execute(RECEIPT_CLEANUP_SQL, [NOW + RECEIPT_TTL_SECS + 1]).unwrap();
    let left: i64 = db.query_row("SELECT COUNT(*) FROM registration_receipts", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0);
}

#[test]
fn only_an_account_that_published_no_device_is_answered_again() {
    let db = db_with_code("482913");
    register(&db, "u1");
    let open = |db: &Connection, user: &str| -> i64 {
        db.query_row(UNPUBLISHED_ACCOUNT_SQL, [user], |r| r.get(0)).unwrap()
    };
    assert_eq!(open(&db, "u1"), 1);
    assert_eq!(open(&db, "nobody"), 0, "a deleted account is never answered");
    db.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    db.execute(
        "INSERT INTO devices (user_id, device_id, role, ed_pub, x_pub, added_at) VALUES ('u1', 'dev1', 'primary', x'01', x'02', 1)",
        [],
    )
    .unwrap();
    assert_eq!(open(&db, "u1"), 0, "the app had its answer: it published");
}

/// The registration is one batch: nothing between the user row and the refresh token is run on
/// its own, and the receipt is read from the code before the code is deleted.
#[test]
fn the_registration_is_one_batch_and_the_receipt_precedes_the_codes_delete() {
    let src = include_str!("verify.rs");
    let a = src.find("INSERT INTO users").unwrap();
    let b = src[a..].find("db.batch(stmts)").unwrap() + a;
    let span = &src[a..b];
    assert!(!span.contains(".run()") && !span.contains(".first("), "a write outside the batch");
    let receipt = span.find("verify_replay::receipt_statement").expect("the receipt");
    let delete = span.find("DELETE FROM verification_codes").expect("the code's delete");
    let refresh = span.find("INSERT INTO refresh_tokens").expect("the refresh token");
    assert!(receipt < delete && delete < refresh);
}
