//! Durable attribution/grant ledger for invite redemption.
//!
//! `invite_tokens.token` is the bearer authorization secret and stays only in the
//! TTL-bounded source table. Both the ledger key and the verification-code bridge
//! carry `SHA-256(token)` instead, so even if the durable audit DB leaks, no reusable
//! invite secret is exposed.

/// Atomically claim an invite and snapshot the inviter metadata.
///
/// Uniqueness comes from the `invite_attributions.invite_token_hash` primary key: the
/// first INSERT wins, and a second redeem gets zero RETURNING rows even while
/// `invite_tokens.used` is still 0. Bind order: `token_hash, redeemed_at, raw_token,
/// now, token_hash`.
pub(crate) const CLAIM_INVITE_SQL: &str = "INSERT INTO invite_attributions
       (invite_token_hash, email_hint, inviter_user_id, inviter_ed_pub, used_by,
        created_at, expires_at, redeemed_at, verified_at)
     SELECT ?, it.email_hint, it.owner_user_id, u.identity_ed_pub, NULL,
            it.created_at, it.expires_at, ?, NULL
       FROM invite_tokens it
       LEFT JOIN users u ON u.id = it.owner_user_id
      WHERE it.token = ? AND it.used = 0 AND it.expires_at > ? AND it.token_hash = ?
     ON CONFLICT(invite_token_hash) DO NOTHING
     RETURNING invite_token_hash";

/// During verify, upgrade an in-flight record that was redeemed before the 0031
/// deploy — one whose verification_codes row carries only the raw legacy token — onto
/// the hash ledger. Bind order: `token_hash, redeemed_at, raw_token`.
pub(crate) const UPGRADE_LEGACY_CLAIM_SQL: &str = "INSERT INTO invite_attributions
       (invite_token_hash, email_hint, inviter_user_id, inviter_ed_pub, used_by,
        created_at, expires_at, redeemed_at, verified_at)
     SELECT ?, it.email_hint, it.owner_user_id, u.identity_ed_pub, it.used_by,
            it.created_at, it.expires_at, ?, NULL
       FROM invite_tokens it
       LEFT JOIN users u ON u.id = it.owner_user_id
      WHERE it.token = ? AND it.used = 1
     ON CONFLICT(invite_token_hash) DO UPDATE
       SET invite_token_hash = excluded.invite_token_hash
     RETURNING invite_token_hash";

/// Read the inviter identity for the verify response from the immutable snapshot,
/// which is independent of both the raw token secret and the source row's TTL.
pub(crate) const LOAD_INVITER_SQL: &str =
    "SELECT ia.inviter_user_id AS owner_user_id,
            CASE WHEN ia.inviter_ed_pub IS NULL THEN NULL ELSE hex(ia.inviter_ed_pub) END AS inviter_ed_pub
       FROM invite_attributions ia
      WHERE ia.invite_token_hash = (
        SELECT invite_token_hash FROM verification_codes WHERE email = ?
      )";

/// Bind the durable ledger to the user once verify completes. On a retry or a race the
/// COALESCE preserves the first successful attribution, so the same token is never
/// re-attributed to a different user.
pub(crate) const MARK_ATTRIBUTED_SQL: &str = "UPDATE invite_attributions
        SET used_by = COALESCE(used_by, ?),
            verified_at = COALESCE(verified_at, ?)
      WHERE invite_token_hash = (
        SELECT invite_token_hash FROM verification_codes WHERE email = ?
      )";

/// Materialize the account-level contact created by a successful invitation.
///
/// This statement intentionally has no conflict-update arm. The pair uniqueness
/// constraint therefore makes it both idempotent and fail-closed:
///
/// * an already-active grant keeps its stronger/original provenance;
/// * a revoked grant is never resurrected by a verify retry;
/// * either direction of an active block prevents creation;
/// * open registration, deleted inviters and self-attribution are no-ops.
///
/// It is executed immediately after [`MARK_ATTRIBUTED_SQL`] in the same ordered
/// D1 batch, so the SELECT observes the newly finalized `used_by` value. Bind
/// order: `email, used_by, created_at`.
pub(crate) const APPLY_INVITE_GRANT_SQL: &str = concat!(
    "INSERT OR IGNORE INTO contact_grants
       (grant_id, user_low, user_high, source, trust, accepted_request_id,
        created_at, revoked_at, revoked_by)
     SELECT 'invite:' || ia.invite_token_hash,
            ",
    crate::contact_grant::contact_pair_order_sql!("ia.inviter_user_id", "ia.used_by"),
    ",
            'invite', 'server_asserted', NULL, ?3, NULL, NULL
       FROM invite_attributions ia
       JOIN verification_codes vc ON vc.invite_token_hash = ia.invite_token_hash
      WHERE vc.email = ?1 AND ia.used_by = ?2
        AND ia.inviter_user_id IS NOT NULL
        AND ia.used_by IS NOT NULL
        AND ia.inviter_user_id != ia.used_by
        AND ",
    crate::contact_grant::contact_pair_block_guard_sql!("ia.inviter_user_id", "ia.used_by")
);

/// Emit exactly one account-scoped contact change for the inviter. The event id
/// is derived from the one-time token hash, so retries cannot advance the feed
/// twice. A revision is emitted only when this exact invite grant exists and is
/// active. Bind order: `email, used_by, created_at`.
pub(crate) const INSERT_INVITER_GRANT_REVISION_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id, account_id, peer_id, entity, entity_id, action, created_at)
     SELECT 'invite:' || ia.invite_token_hash || ':inviter',
            ia.inviter_user_id, ia.used_by, 'grant', g.grant_id, 'upsert', ?3
       FROM invite_attributions ia
       JOIN verification_codes vc ON vc.invite_token_hash = ia.invite_token_hash
       JOIN contact_grants g ON g.grant_id = 'invite:' || ia.invite_token_hash
      WHERE vc.email = ?1 AND ia.used_by = ?2 AND g.revoked_at IS NULL";

/// Joiner-side counterpart of [`INSERT_INVITER_GRANT_REVISION_SQL`]. Bind order:
/// `email, used_by, created_at`.
pub(crate) const INSERT_JOINER_GRANT_REVISION_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id, account_id, peer_id, entity, entity_id, action, created_at)
     SELECT 'invite:' || ia.invite_token_hash || ':joiner',
            ia.used_by, ia.inviter_user_id, 'grant', g.grant_id, 'upsert', ?3
       FROM invite_attributions ia
       JOIN verification_codes vc ON vc.invite_token_hash = ia.invite_token_hash
       JOIN contact_grants g ON g.grant_id = 'invite:' || ia.invite_token_hash
      WHERE vc.email = ?1 AND ia.used_by = ?2 AND g.revoked_at IS NULL";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::hashing::sha256_hex;
    use rusqlite::{params, Connection, OptionalExtension};

    const MIGRATION: &str = include_str!("../../migrations/0031_invite_attributions.sql");
    const CONTACTS_MIGRATION: &str =
        include_str!("../../migrations/0032_contacts_directory_v2.sql");

    fn pre_0031_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE users (
               id TEXT PRIMARY KEY,
               identity_ed_pub BLOB
             );
             CREATE TABLE server_settings (
               id INTEGER PRIMARY KEY CHECK(id = 1)
             );
             INSERT INTO server_settings(id) VALUES(1);
             CREATE TABLE group_members (
               group_id TEXT NOT NULL,
               user_id TEXT NOT NULL,
               status TEXT NOT NULL DEFAULT 'active',
               PRIMARY KEY(group_id, user_id)
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
        db
    }

    fn install_contacts(db: &Connection) {
        db.execute_batch(CONTACTS_MIGRATION).unwrap();
    }

    fn apply_invite_grant(db: &Connection, email: &str, used_by: &str, now: i64) {
        db.execute(APPLY_INVITE_GRANT_SQL, params![email, used_by, now])
            .unwrap();
        db.execute(
            INSERT_INVITER_GRANT_REVISION_SQL,
            params![email, used_by, now],
        )
        .unwrap();
        db.execute(
            INSERT_JOINER_GRANT_REVISION_SQL,
            params![email, used_by, now],
        )
        .unwrap();
    }

    fn claim(db: &Connection, token: &str, now: i64) -> Option<String> {
        let hash = sha256_hex(token);
        db.execute(
            "UPDATE invite_tokens SET token_hash=?1 WHERE token=?2",
            params![hash, token],
        )
        .unwrap();
        db.query_row(
            CLAIM_INVITE_SQL,
            params![hash, now, token, now, hash],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
    }

    #[test]
    fn claim_hash_pk_is_single_writer_and_ledger_has_no_bearer_token() {
        let db = pre_0031_db();
        db.execute_batch(MIGRATION).unwrap();
        db.execute(
            "INSERT INTO users (id, identity_ed_pub) VALUES (?1, ?2)",
            params!["owner", vec![0xAAu8; 32]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO invite_tokens
               (token, email_hint, used, used_by, owner_user_id, expires_at, created_at)
             VALUES (?1, 'Hasan', 0, NULL, 'owner', 200, 10)",
            ["invite-1-secret"],
        )
        .unwrap();

        let expected_hash = sha256_hex("invite-1-secret");
        assert_eq!(
            claim(&db, "invite-1-secret", 100),
            Some(expected_hash.clone())
        );
        // The legacy `used` flip has not happened yet; the hash-ledger primary key
        // still cuts the second redeem off.
        assert_eq!(claim(&db, "invite-1-secret", 100), None);

        let snapshot: (String, String, Vec<u8>, i64) = db
            .query_row(
                "SELECT invite_token_hash, inviter_user_id, inviter_ed_pub, redeemed_at
                   FROM invite_attributions WHERE invite_token_hash=?1",
                [expected_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(snapshot.1, "owner");
        assert_eq!(snapshot.2, vec![0xAAu8; 32]);
        assert_eq!(snapshot.3, 100);

        let columns: Vec<String> = db
            .prepare("PRAGMA table_info(invite_attributions)")
            .unwrap()
            .query_map([], |r| r.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!columns.iter().any(|c| c == "invite_token"));
        assert!(columns.iter().any(|c| c == "invite_token_hash"));
        assert!(!snapshot.0.contains("invite-1-secret"));
    }

    #[test]
    fn attribution_survives_source_token_expiry_and_completes_used_by() {
        let db = pre_0031_db();
        db.execute_batch(MIGRATION).unwrap();
        db.execute(
            "INSERT INTO users (id, identity_ed_pub) VALUES (?1, ?2)",
            params!["owner", vec![0x0Bu8; 32]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO invite_tokens
               (token, email_hint, used, used_by, owner_user_id, expires_at, created_at)
             VALUES ('invite-2-secret', 'B', 0, NULL, 'owner', 110, 10)",
            [],
        )
        .unwrap();
        let hash = claim(&db, "invite-2-secret", 100).unwrap();
        db.execute(
            "UPDATE invite_tokens SET used=1 WHERE token_hash=?1",
            [hash.as_str()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO verification_codes
               (email, invite_token, invite_token_hash, expires_at)
             VALUES ('joiner@sezgi.local', 'invite-2-secret', ?1, 700)",
            [hash.as_str()],
        )
        .unwrap();

        db.execute(crate::maintenance::INVITE_TOKEN_CLEANUP_SQL, [105])
            .unwrap();
        let inviter: (String, String) = db
            .query_row(LOAD_INVITER_SQL, ["joiner@sezgi.local"], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(inviter.0, "owner");
        assert_eq!(inviter.1, "0B".repeat(32));

        db.execute(
            "INSERT INTO users (id, identity_ed_pub) VALUES ('joiner', X'01')",
            [],
        )
        .unwrap();
        db.execute(
            MARK_ATTRIBUTED_SQL,
            params!["joiner", 106i64, "joiner@sezgi.local"],
        )
        .unwrap();

        db.execute(crate::maintenance::INVITE_TOKEN_CLEANUP_SQL, [111])
            .unwrap();
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM invite_tokens WHERE token_hash=?1",
                [hash.as_str()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        let audit: (String, String, i64) = db
            .query_row(
                "SELECT inviter_user_id, used_by, verified_at
                   FROM invite_attributions WHERE invite_token_hash=?1",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(audit, ("owner".into(), "joiner".into(), 106));
    }

    #[test]
    fn pre_0031_inflight_code_is_upgraded_to_hash_ledger() {
        let db = pre_0031_db();
        db.execute(
            "INSERT INTO users (id, identity_ed_pub) VALUES ('owner', X'A1B2')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO invite_tokens
               (token, used, used_by, owner_user_id, expires_at, created_at)
             VALUES ('legacy-secret', 1, NULL, 'owner', 999, 50)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO verification_codes (email, invite_token, expires_at)
             VALUES ('legacy@sezgi.local', 'legacy-secret', 800)",
            [],
        )
        .unwrap();
        db.execute_batch(MIGRATION).unwrap();

        // Without the hash-ledger backfill, maintenance does not delete the old used
        // secret.
        db.execute(crate::maintenance::INVITE_TOKEN_CLEANUP_SQL, [1_000])
            .unwrap();
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM invite_tokens WHERE token='legacy-secret'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );

        let hash = sha256_hex("legacy-secret");
        db.query_row(
            UPGRADE_LEGACY_CLAIM_SQL,
            params![hash, 100i64, "legacy-secret"],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
        db.execute(
            "UPDATE invite_tokens SET token_hash=?1 WHERE token='legacy-secret'",
            [hash.as_str()],
        )
        .unwrap();
        db.execute(
            "UPDATE verification_codes SET invite_token_hash=?1
              WHERE email='legacy@sezgi.local'",
            [hash.as_str()],
        )
        .unwrap();

        let inviter: (String, String) = db
            .query_row(LOAD_INVITER_SQL, ["legacy@sezgi.local"], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(inviter, ("owner".into(), "A1B2".into()));
        let stored: String = db
            .query_row(
                "SELECT invite_token_hash FROM invite_attributions",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, hash);
        assert_ne!(stored, "legacy-secret");
    }

    #[test]
    fn finalized_invite_creates_one_mutual_grant_and_two_revisions() {
        let db = pre_0031_db();
        db.execute_batch(MIGRATION).unwrap();
        install_contacts(&db);
        db.execute(
            "INSERT INTO users(id,identity_ed_pub) VALUES('inviter',X'01'),('joiner',X'02')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO invite_attributions
               (invite_token_hash,inviter_user_id,used_by,created_at,expires_at,redeemed_at,verified_at)
             VALUES(?1,'inviter','joiner',1,99,2,3)",
            ["a".repeat(64)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO verification_codes(email,invite_token_hash,expires_at)
             VALUES('joiner@sezgi.local',?1,99)",
            ["a".repeat(64)],
        )
        .unwrap();

        apply_invite_grant(&db, "joiner@sezgi.local", "joiner", 3);

        let grant: (String, String, String, String, String, Option<i64>) = db
            .query_row(
                "SELECT grant_id,user_low,user_high,source,trust,revoked_at FROM contact_grants",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(grant.0, format!("invite:{}", "a".repeat(64)));
        assert_eq!(
            (&grant.1, &grant.2),
            (&"inviter".to_string(), &"joiner".to_string())
        );
        assert_eq!(
            (&grant.3, &grant.4, grant.5),
            (&"invite".to_string(), &"server_asserted".to_string(), None)
        );

        let revisions: Vec<(String, String, String)> = db
            .prepare(
                "SELECT account_id,peer_id,entity_id FROM contact_revisions ORDER BY account_id",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(revisions.len(), 2);
        assert_eq!(
            (revisions[0].0.as_str(), revisions[0].1.as_str()),
            ("inviter", "joiner")
        );
        assert_eq!(
            (revisions[1].0.as_str(), revisions[1].1.as_str()),
            ("joiner", "inviter")
        );
        assert_eq!(revisions[0].2, grant.0);
        assert_eq!(revisions[1].2, grant.0);

        // contacts_only authorizes the pair immediately through this grant.
        db.execute("UPDATE server_settings SET dm_policy='contacts_only'", [])
            .unwrap();
        let authz: (i64, String, i64, i64) = db
            .query_row(
                crate::contacts::DIRECT_AUTHZ_SQL,
                params!["joiner", "inviter"],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(authz, (1, "contacts_only".into(), 0, 1));
    }

    #[test]
    fn invite_grant_is_idempotent_and_never_revives_revoked_pair() {
        let db = pre_0031_db();
        db.execute_batch(MIGRATION).unwrap();
        install_contacts(&db);
        db.execute("INSERT INTO users(id) VALUES('inviter'),('joiner')", [])
            .unwrap();
        let hash = "b".repeat(64);
        db.execute(
            "INSERT INTO invite_attributions
               (invite_token_hash,inviter_user_id,used_by,created_at,expires_at,redeemed_at,verified_at)
             VALUES(?1,'inviter','joiner',1,99,2,3)",
            [hash.as_str()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO verification_codes(email,invite_token_hash,expires_at)
             VALUES('joiner@sezgi.local',?1,99)",
            [hash.as_str()],
        )
        .unwrap();

        apply_invite_grant(&db, "joiner@sezgi.local", "joiner", 3);
        apply_invite_grant(&db, "joiner@sezgi.local", "joiner", 4);
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM contact_grants", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM contact_revisions", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );

        db.execute(
            "UPDATE contact_grants SET revoked_at=5,revoked_by='inviter'",
            [],
        )
        .unwrap();
        apply_invite_grant(&db, "joiner@sezgi.local", "joiner", 6);
        let state: (i64, Option<i64>) = db
            .query_row(
                "SELECT COUNT(*),MAX(revoked_at) FROM contact_grants",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, (1, Some(5)));
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM contact_revisions", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn block_null_and_self_attribution_fail_closed() {
        for case in ["blocked", "null", "self"] {
            let db = pre_0031_db();
            db.execute_batch(MIGRATION).unwrap();
            install_contacts(&db);
            db.execute("INSERT INTO users(id) VALUES('inviter'),('joiner')", [])
                .unwrap();
            let hash = match case {
                "blocked" => "c".repeat(64),
                "null" => "d".repeat(64),
                _ => "e".repeat(64),
            };
            let (inviter, used_by): (Option<&str>, &str) = match case {
                "null" => (None, "joiner"),
                "self" => (Some("joiner"), "joiner"),
                _ => (Some("inviter"), "joiner"),
            };
            db.execute(
                "INSERT INTO invite_attributions
                   (invite_token_hash,inviter_user_id,used_by,created_at,expires_at,redeemed_at,verified_at)
                 VALUES(?1,?2,?3,1,99,2,3)",
                params![hash, inviter, used_by],
            )
            .unwrap();
            db.execute(
                "INSERT INTO verification_codes(email,invite_token_hash,expires_at)
                 VALUES('joiner@sezgi.local',?1,99)",
                [hash.as_str()],
            )
            .unwrap();
            if case == "blocked" {
                db.execute(
                    "INSERT INTO contact_blocks(blocker_user_id,blocked_user_id,created_at)
                     VALUES('joiner','inviter',2)",
                    [],
                )
                .unwrap();
            }
            apply_invite_grant(&db, "joiner@sezgi.local", "joiner", 3);
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM contact_grants", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0,
                "case={case}"
            );
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM contact_revisions", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0,
                "case={case}"
            );
        }
    }
}
