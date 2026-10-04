//! The class claim against the real schema: seats are counted exactly, every redemption gets its
//! own ledger row, a retry does not cost a seat, an abandoned code gives its seat back, and the
//! single-use personal claim — genesis included — is never reached by a class token.

use super::*;
use crate::auth::hashing::sha256_hex;
use crate::auth::invite_attribution::{APPLY_INVITE_GRANT_SQL, CLAIM_INVITE_SQL};
use rusqlite::{params, Connection, OptionalExtension};

const NOW: i64 = 1_780_000_000;

fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, identity_ed_pub, role, created_at)
         VALUES ('adm', 'adm@sezgi.local', x'00', x'AA', 'admin', 1),
                ('boss', 'boss@sezgi.local', x'00', x'BB', 'owner', 1);",
    )
    .unwrap();
    db
}

fn mint_class(db: &Connection, token: &str, seats: i64) {
    db.execute(
        "INSERT INTO invite_tokens
           (token, token_hash, email_hint, used, owner_user_id, expires_at, created_at,
            kind, max_uses, uses, introduce, landing_room_id, landing_needs_approval)
         VALUES (?1, ?2, 'BIL203', 0, 'adm', ?3, ?4, 'class', ?5, 0, 0, 'g-course', 1)",
        params![token, sha256_hex(token), NOW + 3_600, NOW - 60, seats],
    )
    .unwrap();
}

/// Redeem's class path as one transaction, then its bridge row — what `class_invite::claim` and
/// `auth::invite::redeem` write for `email`. Returns the redemption's ledger key.
fn redeem(db: &mut Connection, token: &str, email: &str, now: i64) -> Option<String> {
    let hash = sha256_hex(token);
    let inflight: Option<String> = db
        .query_row(INFLIGHT_REDEMPTION_SQL, params![email, hash, now], |r| {
            r.get(0)
        })
        .optional()
        .unwrap();
    let key = match inflight {
        Some(key) => key,
        None => {
            let nonce = format!("nonce-{email}-{now}");
            let key = redemption_key(&hash, &nonce);
            let tx = db.transaction().unwrap();
            tx.execute(RELEASE_SEATS_SQL, params![hash, now]).unwrap();
            tx.execute(TAKE_SEAT_SQL, params![token, hash, nonce, now])
                .unwrap();
            let won: Option<String> = tx
                .query_row(RECORD_REDEMPTION_SQL, params![key, now, hash, nonce], |r| {
                    r.get(0)
                })
                .optional()
                .unwrap();
            tx.commit().unwrap();
            won?
        }
    };
    db.execute(
        "INSERT INTO verification_codes
           (email, code_hash, attempts, invite_token, invite_token_hash, expires_at, created_at)
         VALUES (?1, 'h', 0, NULL, ?2, ?3, ?4)
         ON CONFLICT(email) DO UPDATE SET invite_token_hash = excluded.invite_token_hash,
            expires_at = excluded.expires_at",
        params![email, key, now + 600, now],
    )
    .unwrap();
    Some(key)
}

fn uses(db: &Connection, token: &str) -> i64 {
    db.query_row(
        "SELECT uses FROM invite_tokens WHERE token = ?1",
        [token],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn a_class_invite_admits_exactly_its_seats_with_one_ledger_row_each() {
    let mut db = db();
    mint_class(&db, "class-secret-token", 3);
    let keys: Vec<Option<String>> = (0..5)
        .map(|i| {
            redeem(
                &mut db,
                "class-secret-token",
                &format!("s{i}@sezgi.local"),
                NOW,
            )
        })
        .collect();
    assert_eq!(
        keys.iter().filter(|k| k.is_some()).count(),
        3,
        "three seats, three students"
    );
    assert_eq!(
        uses(&db, "class-secret-token"),
        3,
        "a refused claim must not count"
    );

    let rows: Vec<(String, i64, String, i64, i64, Option<String>)> = db
        .prepare(
            "SELECT kind, genesis, source_hash, introduce, landing_needs_approval, landing_room_id
               FROM invite_attributions",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_eq!(
            row,
            (
                "class".into(),
                0,
                sha256_hex("class-secret-token"),
                0,
                1,
                Some("g-course".into())
            ),
            "every redemption snapshots the invite, is never genesis and never introduces"
        );
    }
}

#[test]
fn a_retry_from_the_same_device_reuses_its_seat() {
    let mut db = db();
    mint_class(&db, "class-secret-token", 2);
    let first = redeem(&mut db, "class-secret-token", "s1@sezgi.local", NOW);
    let again = redeem(&mut db, "class-secret-token", "s1@sezgi.local", NOW + 5);
    assert!(first.is_some());
    assert_eq!(first, again);
    assert_eq!(uses(&db, "class-secret-token"), 1);
}

/// A student who got a code and walked away holds a seat only while the code lives. Once the
/// invite looks full, the seat comes back — and only then, so a verified seat is never released.
#[test]
fn an_abandoned_code_gives_its_seat_back_when_the_invite_is_full() {
    let mut db = db();
    mint_class(&db, "class-secret-token", 2);
    redeem(
        &mut db,
        "class-secret-token",
        "walked-away@sezgi.local",
        NOW,
    )
    .unwrap();
    let joined = redeem(&mut db, "class-secret-token", "joined@sezgi.local", NOW).unwrap();
    db.execute(
        "UPDATE invite_attributions SET verified_at = ?1 WHERE invite_token_hash = ?2",
        params![NOW + 30, joined],
    )
    .unwrap();
    assert!(redeem(&mut db, "class-secret-token", "late@sezgi.local", NOW + 60).is_none());
    // Ten minutes on, the walked-away code is dead.
    assert!(redeem(&mut db, "class-secret-token", "late@sezgi.local", NOW + 700).is_some());
    assert_eq!(uses(&db, "class-secret-token"), 2);
    assert!(redeem(
        &mut db,
        "class-secret-token",
        "later@sezgi.local",
        NOW + 701
    )
    .is_none());
}

#[test]
fn a_revoked_or_expired_class_invite_admits_nobody() {
    let mut db = db();
    mint_class(&db, "revoked-class-token", 10);
    db.execute("UPDATE invite_tokens SET revoked_at = ?1", [NOW - 1])
        .unwrap();
    assert!(redeem(&mut db, "revoked-class-token", "s@sezgi.local", NOW).is_none());
    mint_class(&db, "expired-class-token", 10);
    assert!(redeem(&mut db, "expired-class-token", "s@sezgi.local", NOW + 7_200).is_none());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM invite_attributions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

/// Redeem routes by kind; this pins why it must. The class claim refuses a personal token, and
/// the kind read is what keeps a class token away from the single-use claim.
#[test]
fn the_two_claims_never_take_each_others_tokens() {
    let mut db = db();
    db.execute(
        "INSERT INTO invite_tokens
           (token, token_hash, used, owner_user_id, expires_at, created_at)
         VALUES ('personal-secret', ?1, 0, 'adm', ?2, ?3)",
        params![sha256_hex("personal-secret"), NOW + 3_600, NOW - 60],
    )
    .unwrap();
    assert!(redeem(&mut db, "personal-secret", "s@sezgi.local", NOW).is_none());
    let kind: String = db
        .query_row(KIND_SQL, ["personal-secret"], |r| r.get(0))
        .unwrap();
    assert_eq!(kind, "personal");
    mint_class(&db, "class-secret-token", 5);
    let kind: String = db
        .query_row(KIND_SQL, ["class-secret-token"], |r| r.get(0))
        .unwrap();
    assert_eq!(kind, "class");
    // The personal claim itself is untouched — genesis and all — and still works.
    let hash = sha256_hex("personal-secret");
    let won: Option<String> = db
        .query_row(
            CLAIM_INVITE_SQL,
            params![hash, NOW, "personal-secret", NOW, hash, 1],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(won, Some(hash));
}

/// The introduction is the snapshot's to decide: a class redemption verified by a student makes
/// no contact grant with the admin who minted it.
#[test]
fn a_class_redemption_introduces_nobody() {
    let mut db = db();
    db.execute_batch(
        "INSERT INTO users (id, email, identity_pubkey, created_at)
         VALUES ('stu', 's@sezgi.local', x'00', 2);",
    )
    .unwrap();
    mint_class(&db, "class-secret-token", 5);
    let key = redeem(&mut db, "class-secret-token", "s@sezgi.local", NOW).unwrap();
    db.execute(
        "UPDATE invite_attributions SET used_by = 'stu', verified_at = ?1
          WHERE invite_token_hash = ?2",
        params![NOW, key],
    )
    .unwrap();
    db.execute(APPLY_INVITE_GRANT_SQL, params!["s@sezgi.local", "stu", NOW])
        .unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM contact_grants", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

/// Verify's per-invite window keys a class redemption by its INVITE, so 120 students share one
/// window sized by 120 seats instead of each getting a fresh one.
#[test]
fn verify_finds_the_invite_behind_a_pending_code() {
    let mut db = db();
    mint_class(&db, "class-secret-token", 120);
    redeem(&mut db, "class-secret-token", "s@sezgi.local", NOW).unwrap();
    let door: (String, i64) = db
        .query_row(
            crate::auth::invite_attribution::DOOR_INVITE_OF_CODE_SQL,
            ["s@sezgi.local"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(door, (sha256_hex("class-secret-token"), 120));
}

#[test]
fn a_redemption_key_is_a_ledger_shaped_hash() {
    let key = redemption_key(&sha256_hex("t"), "n");
    assert_eq!(key.len(), 64);
    assert_ne!(key, redemption_key(&sha256_hex("t"), "m"));
}
