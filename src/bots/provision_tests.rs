//! A bot's D1 rows against the real schema (`test_schema::full_schema`): what provisioning
//! writes is what every existing read path then serves — or hides.
//!
//! The statements run here are the very consts `creation_statements` / `deletion_statements`
//! batch, bound in the same order.

use super::*;
use crate::bots::api::SEND_TARGET_SQL;
use crate::bots::token::{INSERT_TOKEN_SQL, REVOKE_TOKENS_SQL};
use crate::bots::BOTS_AMONG_SQL;
use crate::contacts::DIRECT_AUTHZ_SQL;
use rusqlite::{params, Connection, OptionalExtension};

const BOT: &str = "b0000000-0000-4000-8000-000000000001";
const DEV: &str = "00aa11bb22cc33dd";
const NOW: i64 = 1_761_200_000;

fn human(db: &Connection, id: &str, name: &str) {
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, display_name, created_at, last_seen_at)
         VALUES (?1, ?1 || '@example.test', X'01', ?2, ?3, ?3)",
        params![id, name, NOW],
    )
    .unwrap();
}

fn block(db: &Connection, blocker: &str, blocked: &str) {
    db.execute(
        "INSERT INTO contact_blocks (blocker_user_id, blocked_user_id, created_at) VALUES (?1, ?2, ?3)",
        params![blocker, blocked, NOW],
    )
    .unwrap();
}

/// The creation batch, in `creation_statements`' order, with fixed key material.
fn provision(db: &Connection) {
    let doc = format!(
        r#"{{"v":1,"user_id":"{BOT}","rev":1,"devices":[{{"device_id":"{DEV}","role":"primary","ed_pub_b64":"ZWQ=","x_pub_b64":"eA==","added_at_ms":{}}}]}}"#,
        NOW * 1000
    );
    db.execute(
        INSERT_BOT_USER_SQL,
        params![BOT, bot_email(BOT), vec![0x78u8], vec![0x65u8], "Echo", 1, NOW],
    )
    .unwrap();
    db.execute(INSERT_BOT_SQL, params![BOT, "Echo", "repeats you", "alice", NOW]).unwrap();
    db.execute(INSERT_DEVICE_LIST_SQL, params![BOT, 1, doc, "c2ln", NOW]).unwrap();
    db.execute(
        INSERT_DEVICE_SQL,
        params![BOT, DEV, vec![0x65u8], vec![0x78u8], Option::<String>::None, NOW * 1000],
    )
    .unwrap();
    db.execute(INSERT_SPK_SQL, params![BOT, 7, vec![0x53u8], vec![0x5au8; 64], NOW, DEV]).unwrap();
    db.execute(
        &otk_insert_sql(3),
        params![BOT, 1, vec![1u8], DEV, BOT, 2, vec![2u8], DEV, BOT, 3, vec![3u8], DEV],
    )
    .unwrap();
    db.execute(INSERT_TOKEN_SQL, params!["hash-1", BOT, NOW]).unwrap();
    db.execute(GRANT_ALL_HUMANS_SQL, params![BOT, NOW]).unwrap();
    db.execute(GRANT_REVISIONS_FOR_BOT_SQL, params![BOT, NOW]).unwrap();
}

fn setup() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute("UPDATE server_settings SET dm_policy = 'contacts_only' WHERE id = 1", [])
        .unwrap();
    human(&db, "alice", "Alice");
    human(&db, "bob", "Bob");
    human(&db, "carol", "Carol");
    db
}

/// (granted, blocked, dm_policy) as `DIRECT_AUTHZ_SQL` answers `sender → target`.
fn authz(db: &Connection, sender: &str, target: &str) -> (i64, i64, String) {
    db.query_row(DIRECT_AUTHZ_SQL, params![target, sender], |r| {
        Ok((r.get("granted")?, r.get("blocked")?, r.get("dm_policy")?))
    })
    .unwrap()
}

#[test]
fn the_grant_lets_a_member_reach_the_bot_under_contacts_only() {
    let db = setup();
    provision(&db);
    let (granted, blocked, policy) = authz(&db, "alice", BOT);
    assert_eq!((granted, blocked, policy.as_str()), (1, 0, "contacts_only"));
    assert!(crate::contact_grant::direct_message_allowed(&policy, granted == 1, false));
    // The pair is unordered: the same grant answers the bot's direction too.
    assert_eq!(authz(&db, BOT, "bob").0, 1);
    // Blocking after the grant still wins.
    block(&db, "carol", BOT);
    let (granted, blocked, _) = authz(&db, "carol", BOT);
    assert_eq!((granted, blocked), (1, 1), "the grant exists, the block decides");
}

#[test]
fn a_block_already_in_place_gets_no_grant_and_only_humans_get_one() {
    let db = setup();
    // A pre-existing bot account (another bot) must not be granted to this one.
    db.execute(
        "INSERT INTO users (id, email, identity_pubkey, created_at, kind) VALUES ('otherbot', 'x@bots.invalid', X'01', 1, 'bot')",
        [],
    )
    .unwrap();
    // The block needs the bot's user row to exist; write it, block, then run the grants.
    db.execute(
        INSERT_BOT_USER_SQL,
        params![BOT, bot_email(BOT), vec![1u8], vec![2u8], "Echo", 1, NOW],
    )
    .unwrap();
    block(&db, "carol", BOT);
    db.execute(INSERT_BOT_SQL, params![BOT, "Echo", "", "alice", NOW]).unwrap();
    db.execute(GRANT_ALL_HUMANS_SQL, params![BOT, NOW]).unwrap();
    let peers: Vec<String> = {
        let mut s = db
            .prepare(
                "SELECT CASE WHEN user_low = ?1 THEN user_high ELSE user_low END FROM contact_grants
                  WHERE (user_low = ?1 OR user_high = ?1) ORDER BY 1",
            )
            .unwrap();
        s.query_map([BOT], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(peers, vec!["alice", "bob"], "carol blocked it; another bot is no human");
    let (source, trust): (String, String) = db
        .query_row("SELECT source, trust FROM contact_grants LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!((source.as_str(), trust.as_str()), ("manual", "server_asserted"));
}

#[test]
fn every_human_gets_one_revision_and_the_bot_none() {
    let db = setup();
    provision(&db);
    let rows: Vec<(String, String, String)> = {
        let mut s = db
            .prepare("SELECT account_id, peer_id, action FROM contact_revisions WHERE entity = 'grant' ORDER BY account_id")
            .unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let expect = |a: &str| (a.to_string(), BOT.to_string(), "upsert".to_string());
    assert_eq!(rows, vec![expect("alice"), expect("bob"), expect("carol")]);
    // Running the grant again (a retry) neither duplicates grants nor revisions.
    db.execute(GRANT_ALL_HUMANS_SQL, params![BOT, NOW + 5]).unwrap();
    db.execute(GRANT_REVISIONS_FOR_BOT_SQL, params![BOT, NOW + 5]).unwrap();
    let n: i64 = db.query_row("SELECT COUNT(*) FROM contact_revisions", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 3);
}

#[test]
fn the_bundle_sql_serves_the_bot_like_any_device() {
    let db = setup();
    provision(&db);
    let (prekey_id, spk): (i64, Vec<u8>) = db
        .query_row(crate::keys::handlers::DEVICE_SPK_SQL, params![BOT, DEV], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((prekey_id, spk), (7, vec![0x53]));
    let x: Vec<u8> = db
        .query_row(crate::keys::handlers::DEVICE_X_PUB_SQL, params![BOT, DEV], |r| r.get(0))
        .unwrap();
    assert_eq!(x, vec![0x78]);
    let claim = || -> Option<Vec<u8>> {
        db.query_row(crate::keys::handlers::CLAIM_DEVICE_OTK_SQL, params![BOT, DEV], |r| r.get(2))
            .optional()
            .unwrap()
    };
    assert_eq!(claim(), Some(vec![1]));
    assert_eq!(claim(), Some(vec![2]), "each claim takes a fresh key");
    let left: i64 = db.query_row(OTK_POOL_SQL, params![BOT, DEV], |r| r.get(0)).unwrap();
    assert_eq!(left, 1, "the pool count the tick tops up from");
    // The signed list is there for the members' kernels to verify.
    let rev: i64 = db
        .query_row("SELECT rev FROM device_lists WHERE user_id = ?1", [BOT], |r| r.get(0))
        .unwrap();
    let high: i64 = db
        .query_row("SELECT device_list_rev FROM users WHERE id = ?1", [BOT], |r| r.get(0))
        .unwrap();
    assert_eq!((rev, high), (1, 1));
}

#[test]
fn the_directory_member_list_and_counts_hide_the_bot() {
    let db = setup();
    provision(&db);
    // Even a bot row someone made visible stays out: the kind decides, not the visibility.
    db.execute("UPDATE users SET directory_visibility = 'visible' WHERE id = ?1", [BOT]).unwrap();
    for mode in ["all_members", "opt_in"] {
        let mut s = db.prepare(crate::contacts::DIRECTORY_PAGE_SQL).unwrap();
        let ids: Vec<String> = s
            .query_map(params!["alice", mode, mode, "alice", "alice", 0, "", "", "", 50], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!ids.contains(&BOT.to_string()), "{mode}: {ids:?}");
    }
    let mut s = db.prepare(crate::admin::handlers::USERS_PAGE_SQL).unwrap();
    let members: Vec<String> = s
        .query_map(params![Option::<i64>::None, "", 100], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(members, vec!["alice", "bob", "carol"]);
    let bots: i64 = db
        .query_row(BOTS_AMONG_SQL, [format!(r#"["alice","{BOT}"]"#)], |r| r.get(0))
        .unwrap();
    assert_eq!(bots, 1, "the group and remove-member refusals find it");
    let none: i64 = db.query_row(BOTS_AMONG_SQL, [r#"["alice","bob"]"#], |r| r.get(0)).unwrap();
    assert_eq!(none, 0);
}

#[test]
fn a_bot_writes_only_to_unblocked_humans() {
    let db = setup();
    provision(&db);
    block(&db, BOT, "bob"); // either direction counts
    let target = |to: &str| -> (i64, i64) {
        db.query_row(SEND_TARGET_SQL, params![to, BOT], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    };
    assert_eq!(target("alice"), (1, 0));
    assert_eq!(target("bob"), (1, 1));
    assert_eq!(target(BOT), (0, 0), "not to itself, not to another bot");
    assert_eq!(target("nobody"), (0, 0));
}

#[test]
fn a_joiner_gets_every_bot_not_deleted_with_a_revision() {
    let db = setup();
    provision(&db);
    db.execute("UPDATE bots SET disabled_at = ?2 WHERE bot_id = ?1", params![BOT, NOW]).unwrap();
    human(&db, "erin", "Erin");
    db.execute(GRANT_BOTS_TO_JOINER_SQL, params!["erin", NOW + 1]).unwrap();
    db.execute(GRANT_REVISIONS_FOR_JOINER_SQL, params!["erin", NOW + 1]).unwrap();
    assert_eq!(authz(&db, "erin", BOT).0, 1, "a disabled bot is still a contact");
    let rev: (String, String) = db
        .query_row(
            "SELECT peer_id, action FROM contact_revisions WHERE account_id = 'erin'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(rev, (BOT.to_string(), "upsert".to_string()));
}

#[test]
fn a_deleted_bot_loses_its_grants_keeps_its_name_and_reaches_no_joiner() {
    let db = setup();
    provision(&db);
    let delete = [MARK_DELETED_SQL, REVOKE_TOKENS_SQL, TOMBSTONE_REVISIONS_SQL, TOMBSTONES_SQL];
    for sql in delete {
        db.execute(sql, params![BOT, NOW + 10]).unwrap();
    }
    db.execute(REVOKE_GRANTS_SQL, params![BOT, NOW + 10, "alice"]).unwrap();
    assert_eq!(authz(&db, "alice", BOT).0, 0, "no grant: contacts_only refuses it now");
    let tomb: (String, String) = db
        .query_row(
            "SELECT r.action, t.peer_id FROM contact_revisions r
               JOIN contact_tombstones t ON t.account_id = r.account_id AND t.entity_id = r.entity_id
              WHERE r.account_id = 'alice' AND r.action = 'tombstone'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(tomb, ("tombstone".to_string(), BOT.to_string()));
    let tombstones: i64 = db.query_row("SELECT COUNT(*) FROM contact_tombstones", [], |r| r.get(0)).unwrap();
    assert_eq!(tombstones, 3, "one per member");
    let name: String = db
        .query_row("SELECT display_name FROM users WHERE id = ?1", [BOT], |r| r.get(0))
        .unwrap();
    assert_eq!(name, "Echo", "past messages keep their sender");
    let live: i64 = db
        .query_row("SELECT COUNT(*) FROM bot_tokens WHERE revoked_at IS NULL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(live, 0);
    human(&db, "erin", "Erin");
    db.execute(GRANT_BOTS_TO_JOINER_SQL, params!["erin", NOW + 11]).unwrap();
    assert_eq!(authz(&db, "erin", BOT).0, 0);
    // Deleting twice is a no-op, not a second set of tombstones.
    db.execute(TOMBSTONE_REVISIONS_SQL, params![BOT, NOW + 12]).unwrap();
    let n: i64 = db
        .query_row("SELECT COUNT(*) FROM contact_revisions WHERE action = 'tombstone'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 3);
}

#[test]
fn a_member_who_removed_the_bot_is_not_granted_it_again() {
    let db = setup();
    provision(&db);
    db.execute(
        "UPDATE contact_grants SET revoked_at = ?2, revoked_by = 'alice'
          WHERE grant_id = 'bot:' || ?1 || ':alice'",
        params![BOT, NOW + 1],
    )
    .unwrap();
    db.execute(GRANT_ALL_HUMANS_SQL, params![BOT, NOW + 2]).unwrap();
    assert_eq!(authz(&db, "alice", BOT).0, 0, "INSERT OR IGNORE never reopens a revoked pair");
}
