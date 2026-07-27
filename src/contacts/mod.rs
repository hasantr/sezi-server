//! Account contacts, virtual server directory and direct-message authorization.
//! Membership, discovery and authorization are deliberately independent.

use crate::auth::hashing::sha256_hex;
use crate::auth::middleware::{require_active_auth, ActiveAuth};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::{b64_decode, b64u_decode, b64u_encode, now_secs, random_b64u};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use worker::*;

const REQUEST_TTL_SEC: i64 = 7 * 24 * 60 * 60;
const MAX_PAGE: usize = 100;

pub(crate) const APPLY_ACCEPTED_GRANT_SQL: &str = concat!(
    "INSERT INTO contact_grants
       (grant_id, user_low, user_high, source, trust, accepted_request_id, created_at, revoked_at, revoked_by)
     SELECT 'request:' || request_id,
            ",
    crate::contact_grant::contact_pair_order_sql!("r.source_user_id", "r.target_user_id"),
    ",
            'request', 'server_asserted', request_id, ?, NULL, NULL
       FROM contact_requests r
      WHERE request_id = ? AND target_user_id = ? AND status = 'accepted'
        AND grant_applied = 0
        AND ",
    crate::contact_grant::contact_pair_block_guard_sql!("r.source_user_id", "r.target_user_id"),
    "
     ON CONFLICT(user_low, user_high) DO UPDATE SET
       source='request', trust='server_asserted', accepted_request_id=excluded.accepted_request_id,
       created_at=excluded.created_at, revoked_at=NULL, revoked_by=NULL"
);

const MARK_GRANT_APPLIED_SQL: &str = "UPDATE contact_requests SET grant_applied = 1
      WHERE request_id = ? AND target_user_id = ? AND status = 'accepted'
        AND grant_applied = 0
        AND EXISTS (SELECT 1 FROM contact_grants g
          WHERE g.accepted_request_id = contact_requests.request_id
            AND g.revoked_at IS NULL)";

/// Shared authorization query for `/messages/send`, key bundle and signed
/// device-list fetches. Block is checked first and wins over every other path.
/// `members` preserves the pre-0032 behavior. Strict policies accept an active
/// account-level grant or the explicitly advertised active-common-group
/// exception.
pub(crate) const DIRECT_AUTHZ_SQL: &str = "SELECT
       EXISTS(SELECT 1 FROM users WHERE id = ?1) AS target_exists,
       COALESCE((SELECT dm_policy FROM server_settings WHERE id = 1), 'members') AS dm_policy,
       EXISTS(
         SELECT 1 FROM contact_blocks
          WHERE (blocker_user_id = ?2 AND blocked_user_id = ?1)
             OR (blocker_user_id = ?1 AND blocked_user_id = ?2)
       ) AS blocked,
       EXISTS(
         SELECT 1 FROM contact_grants
          WHERE user_low = CASE WHEN ?2 < ?1 THEN ?2 ELSE ?1 END
            AND user_high = CASE WHEN ?2 < ?1 THEN ?1 ELSE ?2 END
            AND revoked_at IS NULL
       ) AS granted,
       EXISTS(
         SELECT 1
           FROM group_members a
           JOIN group_members b ON b.group_id = a.group_id
          WHERE a.user_id = ?2 AND b.user_id = ?1
            AND a.status = 'active' AND b.status = 'active'
       ) AS common_group";

#[derive(Deserialize)]
struct AuthzRow {
    target_exists: i64,
    dm_policy: String,
    blocked: i64,
    granted: i64,
    common_group: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectDecision {
    Allowed,
    NotFound,
    Denied,
}

pub(crate) async fn direct_decision(
    db: &D1Database,
    caller: &str,
    target: &str,
) -> Result<DirectDecision> {
    if caller == target {
        return Ok(DirectDecision::Allowed);
    }
    let row: Option<AuthzRow> = db
        .prepare(DIRECT_AUTHZ_SQL)
        .bind(&[d1_text(target), d1_text(caller)])?
        .first(None)
        .await?;
    let Some(row) = row else {
        // Missing settings row is equivalent to the backwards-compatible
        // `members` default, but a missing target still fails closed.
        return Ok(DirectDecision::NotFound);
    };
    if row.target_exists == 0 {
        return Ok(DirectDecision::NotFound);
    }
    if row.blocked != 0 {
        return Ok(DirectDecision::Denied);
    }
    let allowed = crate::contact_grant::direct_message_allowed(
        &row.dm_policy,
        row.granted != 0,
        row.common_group != 0,
    );
    Ok(if allowed {
        DirectDecision::Allowed
    } else {
        DirectDecision::Denied
    })
}

/// Map authorization to a response without exposing whether denial came from a
/// block, a missing grant or policy. Missing accounts keep the legacy 404.
pub(crate) async fn require_direct(
    db: &D1Database,
    caller: &str,
    target: &str,
) -> std::result::Result<(), Response> {
    match direct_decision(db, caller, target).await {
        Ok(DirectDecision::Allowed) => Ok(()),
        Ok(DirectDecision::NotFound) => Err(json_err(404, "not_found").unwrap()),
        Ok(DirectDecision::Denied) => Err(json_err(403, "contact_not_authorized").unwrap()),
        Err(_) => Err(json_err(503, "authorization_unavailable").unwrap()),
    }
}

async fn active(req: &Request, env: &Env) -> std::result::Result<ActiveAuth, Response> {
    require_active_auth(req, env).await
}

fn limit_param(req: &Request) -> usize {
    req.url()
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "limit")
                .and_then(|(_, v)| v.parse::<usize>().ok())
        })
        .unwrap_or(50)
        .clamp(1, MAX_PAGE)
}

fn query_param(req: &Request, name: &str) -> Option<String> {
    req.url().ok()?.query_pairs().find_map(|(k, v)| {
        if k == name {
            Some(v.into_owned())
        } else {
            None
        }
    })
}

#[derive(Serialize, Deserialize)]
struct NameCursor {
    name: String,
    id: String,
}

#[derive(Serialize, Deserialize)]
struct TimeCursor {
    created_at: i64,
    id: String,
}

fn encode_cursor<T: Serialize>(cursor: &T) -> Option<String> {
    serde_json::to_vec(cursor).ok().map(|v| b64u_encode(&v))
}

fn decode_cursor<T: for<'de> Deserialize<'de>>(raw: Option<String>) -> Option<T> {
    let raw = raw?;
    if raw.len() > 512 {
        return None;
    }
    let bytes = b64u_decode(&raw).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[derive(Deserialize)]
struct ProfileRow {
    user_id: String,
    display_name: Option<String>,
    role: String,
    profile_revision: i64,
    /// Exact SQLite ordering key. Never recompute with Rust Unicode casing:
    /// SQLite `lower()` is ASCII-oriented and a mismatch would skip/duplicate
    /// Turkish names across stable-cursor pages.
    sort_name: String,
}

fn profile_json(row: &ProfileRow) -> serde_json::Value {
    serde_json::json!({
        "user_id": row.user_id,
        "display_name": row.display_name,
        // No account avatar is currently persisted by the Worker. Keep the
        // privacy-safe wire field additive and explicitly null.
        "avatar_ref": serde_json::Value::Null,
        "role": row.role,
        "profile_revision": row.profile_revision,
    })
}

async fn directory_revision(db: &D1Database) -> Result<i64> {
    #[derive(Deserialize)]
    struct R {
        revision: i64,
    }
    Ok(db
        .prepare("SELECT COALESCE(MAX(revision), 0) AS revision FROM directory_revisions")
        .first::<R>(None)
        .await?
        .map(|r| r.revision)
        .unwrap_or(0))
}

async fn contact_revision(db: &D1Database, account: &str) -> Result<i64> {
    #[derive(Deserialize)]
    struct R {
        revision: i64,
    }
    Ok(db
        .prepare(
            "SELECT COALESCE(MAX(revision), 0) AS revision
               FROM contact_revisions WHERE account_id = ?",
        )
        .bind(&[d1_text(account)])?
        .first::<R>(None)
        .await?
        .map(|r| r.revision)
        .unwrap_or(0))
}

#[derive(Deserialize)]
struct PolicyRow {
    directory_mode: String,
    dm_policy: String,
}

async fn policy(db: &D1Database) -> Result<PolicyRow> {
    Ok(db
        .prepare("SELECT directory_mode, dm_policy FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await?
        .unwrap_or(PolicyRow {
            directory_mode: "off".into(),
            dm_policy: "members".into(),
        }))
}


mod directory;
mod grants;
mod requests;
mod state;
pub use directory::*;
pub use grants::*;
pub use requests::*;
pub use state::*;

/// One row of `contact_revisions` — the change log clients replay to converge.
///
/// Grouped into a struct on purpose. The previous positional signature had three
/// adjacent `&str` parameters (`entity`, `entity_id`, `action`); swapping any two
/// compiled without complaint and silently wrote a corrupt revision that every
/// client would then replay. Named fields make that class of mistake impossible.
pub(crate) struct ContactChange<'a> {
    pub event_id: &'a str,
    pub account: &'a str,
    pub peer: Option<&'a str>,
    pub entity: &'a str,
    pub entity_id: &'a str,
    pub action: &'a str,
    pub now: i64,
}

fn contact_change_stmt(db: &D1Database, c: ContactChange<'_>) -> Result<D1PreparedStatement> {
    db.prepare(
        "INSERT INTO contact_revisions
           (event_id, account_id, peer_id, entity, entity_id, action, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(c.event_id),
        d1_text(c.account),
        c.peer
            .map(d1_text)
            .unwrap_or_else(|| wasm_bindgen::JsValue::NULL),
        d1_text(c.entity),
        d1_text(c.entity_id),
        d1_text(c.action),
        d1_int(c.now),
    ])
}

#[cfg(test)]
mod tests {
    use super::requests::{request_transcript, CreateRequestBody};
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use rusqlite::{params, Connection};

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY,display_name TEXT,role TEXT NOT NULL DEFAULT 'member'); CREATE TABLE server_settings(id INTEGER PRIMARY KEY CHECK(id=1)); INSERT INTO server_settings(id) VALUES(1); CREATE TABLE groups(id TEXT PRIMARY KEY); CREATE TABLE group_members(group_id TEXT,user_id TEXT,role TEXT DEFAULT 'member',joined_at INTEGER DEFAULT 0,status TEXT DEFAULT 'active',PRIMARY KEY(group_id,user_id));").unwrap();
        c.execute_batch(include_str!(
            "../../migrations/0032_contacts_directory_v2.sql"
        ))
        .unwrap();
        for id in ["a", "b"] {
            c.execute("INSERT INTO users(id) VALUES(?)", params![id])
                .unwrap();
        }
        c
    }

    fn decision(c: &Connection) -> (String, i64, i64, i64) {
        c.query_row(DIRECT_AUTHZ_SQL, params!["b", "a"], |r| {
            Ok((r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
    }

    #[test]
    fn upgrade_defaults_preserve_messages_but_hide_directory() {
        let c = db();
        let p: (String, String) = c
            .query_row(
                "SELECT directory_mode,dm_policy FROM server_settings",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(p, ("off".into(), "members".into()));
        let d = decision(&c);
        assert_eq!(d.0, "members");
        assert_eq!(d.1, 0);
    }

    #[test]
    fn block_wins_over_members_and_grant() {
        let c = db();
        c.execute("INSERT INTO contact_grants(grant_id,user_low,user_high,source,trust,created_at) VALUES('g','a','b','request','server_asserted',1)",[]).unwrap();
        c.execute("INSERT INTO contact_blocks(blocker_user_id,blocked_user_id,created_at) VALUES('b','a',1)",[]).unwrap();
        let d = decision(&c);
        assert_eq!(d.1, 1);
        assert_eq!(d.2, 1);
    }

    #[test]
    fn strict_policy_accepts_grant_or_active_common_group() {
        let c = db();
        c.execute("UPDATE server_settings SET dm_policy='requests'", [])
            .unwrap();
        let d = decision(&c);
        assert_eq!((d.2, d.3), (0, 0));
        c.execute("INSERT INTO groups(id) VALUES('g')", []).unwrap();
        c.execute("INSERT INTO group_members(group_id,user_id,status) VALUES('g','a','active'),('g','b','active')",[]).unwrap();
        let d = decision(&c);
        assert_eq!(d.3, 1);
        c.execute(
            "UPDATE group_members SET status='pending' WHERE user_id='b'",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO contact_grants(grant_id,user_low,user_high,source,trust,created_at) VALUES('grant','a','b','request','server_asserted',1)",[]).unwrap();
        let d = decision(&c);
        assert_eq!((d.2, d.3), (1, 0));
    }

    #[test]
    fn accepted_request_retry_cannot_resurrect_revoked_grant() {
        let c = db();
        c.execute(
            "INSERT INTO contact_requests
               (request_id,source_user_id,target_user_id,source_device_id,
                server_fingerprint,issued_at,nonce_hash,signature_b64,status,trust,
                created_at,expires_at,responded_at,grant_applied)
             VALUES('r','a','b','d','fp',1,?,'sig','accepted','server_asserted',1,99,2,0)",
            params!["0".repeat(64)],
        )
        .unwrap();
        c.execute(APPLY_ACCEPTED_GRANT_SQL, params![2, "r", "b"])
            .unwrap();
        c.execute(MARK_GRANT_APPLIED_SQL, params!["r", "b"])
            .unwrap();
        let applied: i64 = c
            .query_row(
                "SELECT grant_applied FROM contact_requests WHERE request_id='r'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(applied, 1);
        c.execute(
            "UPDATE contact_grants SET revoked_at=3,revoked_by='a' WHERE grant_id='request:r'",
            [],
        )
        .unwrap();

        // Exact same accepted response retried after revocation.
        c.execute(APPLY_ACCEPTED_GRANT_SQL, params![4, "r", "b"])
            .unwrap();
        c.execute(MARK_GRANT_APPLIED_SQL, params!["r", "b"])
            .unwrap();
        let revoked: Option<i64> = c
            .query_row(
                "SELECT revoked_at FROM contact_grants WHERE grant_id='request:r'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(revoked, Some(3));
    }

    #[test]
    fn directory_cursor_uses_sqlite_sort_key_for_turkish_names() {
        let c = db();
        c.execute("UPDATE users SET display_name='Zulu' WHERE id='a'", [])
            .unwrap();
        c.execute("UPDATE users SET display_name='ipek' WHERE id='b'", [])
            .unwrap();
        c.execute(
            "INSERT INTO users(id,display_name) VALUES('c','İpek'),('d','Ada')",
            [],
        )
        .unwrap();
        let first: Vec<(String, String)> = {
            let mut q = c
                .prepare("SELECT id,lower(COALESCE(display_name,'')) AS sort_name FROM users ORDER BY sort_name,id LIMIT 2")
                .unwrap();
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let cursor = first.last().unwrap().clone();
        let second: Vec<(String, String)> = {
            let mut q = c.prepare("SELECT id,lower(COALESCE(display_name,'')) AS sort_name FROM users WHERE lower(COALESCE(display_name,''))>? OR (lower(COALESCE(display_name,''))=? AND id>?) ORDER BY sort_name,id").unwrap();
            q.query_map(params![cursor.1, cursor.1, cursor.0], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
        };
        let mut ids: Vec<String> = first.into_iter().chain(second).map(|r| r.0).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn directory_modes_hidden_and_blocks_are_symmetric() {
        let c = db();
        let visible = |c: &Connection, caller: &str, target: &str| -> i64 {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM users u,server_settings s
                  WHERE u.id=?2 AND s.id=1 AND u.id!=?1
                    AND ((s.directory_mode='all_members' AND u.directory_visibility!='hidden')
                      OR (s.directory_mode='opt_in' AND u.directory_visibility='visible'))
                    AND NOT EXISTS(SELECT 1 FROM contact_blocks b WHERE
                      (b.blocker_user_id=?1 AND b.blocked_user_id=u.id) OR
                      (b.blocker_user_id=u.id AND b.blocked_user_id=?1)))",
                params![caller, target],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(visible(&c, "a", "b"), 0, "upgrade default is off");
        c.execute("UPDATE server_settings SET directory_mode='opt_in'", [])
            .unwrap();
        assert_eq!(visible(&c, "a", "b"), 0);
        c.execute(
            "UPDATE users SET directory_visibility='visible' WHERE id='b'",
            [],
        )
        .unwrap();
        assert_eq!(visible(&c, "a", "b"), 1);
        c.execute(
            "UPDATE server_settings SET directory_mode='all_members'",
            [],
        )
        .unwrap();
        c.execute(
            "UPDATE users SET directory_visibility='hidden' WHERE id='b'",
            [],
        )
        .unwrap();
        assert_eq!(visible(&c, "a", "b"), 0, "hidden always wins");
        c.execute("UPDATE users SET directory_visibility='inherit'", [])
            .unwrap();
        c.execute(
            "INSERT INTO contact_blocks(blocker_user_id,blocked_user_id,created_at) VALUES('a','b',1)",
            [],
        )
        .unwrap();
        assert_eq!(visible(&c, "a", "b"), 0);
        assert_eq!(visible(&c, "b", "a"), 0, "block hides both directions");
    }

    #[test]
    fn request_signature_transcript_binds_server_accounts_device_and_nonce() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut body = CreateRequestBody {
            request_id: "00000000-0000-4000-8000-000000000001".into(),
            target_user_id: "00000000-0000-4000-8000-000000000002".into(),
            device_id: "device-a".into(),
            server_fingerprint: "server-one".into(),
            issued_at: 42,
            nonce: "0123456789abcdef".into(),
            signature_b64: String::new(),
        };
        let signed = request_transcript("source-a", &body);
        let sig = key.sign(signed.as_bytes());
        assert!(key.verifying_key().verify(signed.as_bytes(), &sig).is_ok());
        body.server_fingerprint = "server-two".into();
        assert!(key
            .verifying_key()
            .verify(request_transcript("source-a", &body).as_bytes(), &sig)
            .is_err());
    }
}
