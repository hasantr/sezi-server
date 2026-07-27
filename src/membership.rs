//! The single deletion primitive for server membership.
//!
//! One D1 batch commits membership, group ownership, the contact feed and the cross-DO purge
//! outbox together. The UserInbox purge is attempted after the commit; if it fails, the cron
//! idempotently retries the same outbox row.

use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

const PURGE_LEASE_SECS: i64 = 300;
const PURGE_BATCH: i64 = 20;
// Together with the purge and the D1 calls, the two live fan-outs must not push us towards
// the Worker subrequest ceiling, so their total stays at 24 DO calls. Every remaining or
// offline account converges via the authoritative revision and the group pull.
const LIVE_NUDGE_LIMIT: i64 = 12;
const GROUP_NUDGE_LIMIT: i64 = 12;

const SELF_MEMBERSHIP_GUARD_SQL: &str = "INSERT INTO membership_delete_guard(slot,target_id)
     VALUES(1,(SELECT id FROM users WHERE id=?1 AND role!='owner'))
     ON CONFLICT(slot) DO UPDATE SET target_id=excluded.target_id";

// The role reads in the admin handler exist only to produce a comprehensible error for the
// user. The real authorization decision is taken again inside the SAME D1 transaction as the
// delete: if either the caller's or the target's role changed in between, the scalar subquery
// returns NULL and the NOT NULL guard atomically rolls the whole batch back.
const ADMIN_MEMBERSHIP_GUARD_SQL: &str = "INSERT INTO membership_delete_guard(slot,target_id)
     VALUES(1,(SELECT target.id
       FROM users target JOIN users caller ON caller.id=?2
      WHERE target.id=?1 AND target.id!=caller.id
        AND ((caller.role='owner' AND target.role!='owner')
          OR (caller.role='admin' AND target.role='member'))
        AND (?3 IS NULL OR EXISTS(
          SELECT 1 FROM devices device
           WHERE device.user_id=caller.id AND device.device_id=?3
             AND device.revoked_at IS NULL))
      LIMIT 1))
     ON CONFLICT(slot) DO UPDATE SET target_id=excluded.target_id";

#[derive(Clone, Copy)]
pub(crate) enum RemovalReason {
    Left,
    Removed,
}

#[derive(Clone, Copy)]
pub(crate) enum RemovalAuthority<'a> {
    SelfLeave,
    Administrator {
        caller_id: &'a str,
        caller_device_id: Option<&'a str>,
    },
}

impl RemovalReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Removed => "removed",
        }
    }
}

#[derive(Debug)]
pub(crate) enum DeleteError {
    NotFound,
    OwnerTransferRequired,
    AuthorizationChanged,
    Worker(Error),
}

impl From<Error> for DeleteError {
    fn from(value: Error) -> Self {
        Self::Worker(value)
    }
}

pub(crate) struct RemovalOutcome {
    contact_nudges: Vec<ContactNudge>,
    group_nudges: Vec<GroupNudge>,
}

#[derive(Deserialize)]
struct TargetRow {
    role: String,
}

#[derive(Deserialize)]
struct ContactNudge {
    user_id: String,
    revision: i64,
}

#[derive(Deserialize)]
struct GroupNudge {
    user_id: String,
}

/// One deterministic event per counterpart account. Because UUID account ids are never
/// reused, a replay cannot advance the feed revision a second time.
const INSERT_COUNTERPART_REVISIONS_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id,account_id,peer_id,entity,entity_id,action,created_at)
     SELECT 'membership:' || ?1 || ':' || peer_id,
            peer_id,?1,'authorization','removed:' || ?1,'tombstone',?2
       FROM (
         SELECT CASE WHEN user_low=?1 THEN user_high ELSE user_low END AS peer_id
           FROM contact_grants WHERE user_low=?1 OR user_high=?1
         UNION
         SELECT CASE WHEN source_user_id=?1 THEN target_user_id ELSE source_user_id END
           FROM contact_requests WHERE source_user_id=?1 OR target_user_id=?1
         UNION
         SELECT CASE WHEN blocker_user_id=?1 THEN blocked_user_id ELSE blocker_user_id END
           FROM contact_blocks WHERE blocker_user_id=?1 OR blocked_user_id=?1
       )
      WHERE peer_id != ?1 AND EXISTS(SELECT 1 FROM users WHERE id=peer_id)";

const UPSERT_COUNTERPART_TOMBSTONES_SQL: &str = "INSERT INTO contact_tombstones
       (account_id,entity,entity_id,peer_id,revision,deleted_at)
     SELECT account_id,'authorization','removed:' || ?1,?1,revision,?2
       FROM contact_revisions
      WHERE event_id='membership:' || ?1 || ':' || account_id
     ON CONFLICT(account_id,entity,entity_id) DO UPDATE SET
       peer_id=excluded.peer_id,revision=excluded.revision,
       deleted_at=excluded.deleted_at";

const PROMOTE_GROUP_SUCCESSORS_SQL: &str = "UPDATE group_members AS gm SET role='owner'
      WHERE gm.user_id=(
        SELECT c.user_id FROM group_members c
         WHERE c.group_id=gm.group_id AND c.user_id!=?1 AND c.status='active'
         ORDER BY CASE c.role WHEN 'admin' THEN 0 ELSE 1 END,c.joined_at,c.user_id
         LIMIT 1)
        AND gm.group_id IN (SELECT id FROM groups WHERE created_by=?1)";

const TRANSFER_CREATED_GROUPS_SQL: &str = "UPDATE groups SET created_by=(
       SELECT gm.user_id FROM group_members gm
        WHERE gm.group_id=groups.id AND gm.user_id!=?1 AND gm.status='active'
        ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                 gm.joined_at,gm.user_id LIMIT 1)
     WHERE created_by=?1 AND EXISTS(
       SELECT 1 FROM group_members gm
        WHERE gm.group_id=groups.id AND gm.user_id!=?1 AND gm.status='active')";

/// Closes out D1 membership authority in a single transaction. The first-statement guard
/// rolls back any owner-role race that occurred between the handler's pre-check and the
/// transaction.
pub(crate) async fn delete_membership(
    env: &Env,
    target_id: &str,
    reason: RemovalReason,
    authority: RemovalAuthority<'_>,
) -> std::result::Result<RemovalOutcome, DeleteError> {
    let db = env.d1("DB")?;
    let target: Option<TargetRow> = db
        .prepare("SELECT role FROM users WHERE id=? LIMIT 1")
        .bind(&[d1_text(target_id)])?
        .first(None)
        .await?;
    let Some(target) = target else {
        return Err(DeleteError::NotFound);
    };
    if target.role == "owner" {
        return Err(DeleteError::OwnerTransferRequired);
    }

    // This list serves post-commit live convergence only; it carries no authority. The
    // transaction is what authoritatively closes group membership and the epoch floor. Devices
    // that lose the race, or are offline, converge through RefreshGroups on boot/resume.
    let group_nudges: Vec<GroupNudge> = match db
        .prepare(
            "SELECT DISTINCT peer.user_id
               FROM group_members removed
               JOIN group_members peer ON peer.group_id=removed.group_id
              WHERE removed.user_id=?1 AND removed.status='active'
                AND peer.user_id!=?1 AND peer.status='active'
              ORDER BY peer.user_id LIMIT ?2",
        )
        .bind(&[d1_text(target_id), d1_int(GROUP_NUDGE_LIMIT)])
    {
        Ok(stmt) => stmt
            .all()
            .await
            .and_then(|result| result.results())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    let now = now_secs() as i64;

    let guard = match authority {
        RemovalAuthority::SelfLeave => db
            .prepare(SELF_MEMBERSHIP_GUARD_SQL)
            .bind(&[d1_text(target_id)])?,
        RemovalAuthority::Administrator {
            caller_id,
            caller_device_id,
        } => db.prepare(ADMIN_MEMBERSHIP_GUARD_SQL).bind(&[
            d1_text(target_id),
            d1_text(caller_id),
            d1_opt_text(caller_device_id),
        ])?,
    };
    let stmts = vec![
        // First statement: if the target is gone by the start of the batch, or has been
        // promoted to owner — or, on the admin path, if the caller/target role matrix changed
        // at all — the scalar subquery returns NULL and the NOT NULL guard rolls the entire
        // transaction back.
        guard,
        // The cross-DO purge intent shares the SAME commit boundary as the D1 delete.
        db.prepare(
            "INSERT INTO account_purge_outbox
               (user_id,reason,created_at,attempts,next_at,last_error)
             VALUES(?,?,?,0,?,NULL)
             ON CONFLICT(user_id) DO UPDATE SET
               reason=excluded.reason,next_at=MIN(next_at,excluded.next_at)",
        )
        .bind(&[
            d1_text(target_id),
            d1_text(reason.as_str()),
            d1_int(now),
            d1_int(now),
        ])?,
        // Counterpart feed tombstones are produced before the relationship rows are deleted.
        db.prepare(INSERT_COUNTERPART_REVISIONS_SQL)
            .bind(&[d1_text(target_id), d1_int(now)])?,
        db.prepare(UPSERT_COUNTERPART_TOMBSTONES_SQL)
            .bind(&[d1_text(target_id), d1_int(now)])?,
        db.prepare(
            "INSERT OR IGNORE INTO directory_revisions
               (event_id,user_id,change_type,profile_revision,created_at)
             VALUES('membership:' || ?,?,'tombstone',NULL,?)",
        )
        .bind(&[d1_text(target_id), d1_text(target_id), d1_int(now)])?,
        db.prepare(
            "INSERT INTO directory_tombstones(user_id,revision,deleted_at)
             SELECT ?,revision,? FROM directory_revisions
              WHERE event_id='membership:' || ?
             ON CONFLICT(user_id) DO UPDATE SET
               revision=excluded.revision,deleted_at=excluded.deleted_at",
        )
        .bind(&[d1_text(target_id), d1_int(now), d1_text(target_id)])?,
        // Blobs due for deletion are first turned into durable storage-outbox rows.
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'media/' || blob_id,size_bytes,?,0
               FROM media_objects WHERE uploader_id=?",
        )
        .bind(&[d1_int(now), d1_text(target_id)])?,
        // Orphan the avatar blob too (0035: one slot per user; the key scheme matches
        // storage::avatar_key exactly, 'avatar/{user}/{object_id}').
        // avatar_objects.user_id REFERENCES users(id), so deleting `users` before this row
        // would violate the FK and roll the ENTIRE batch back — a member with an avatar could
        // not be removed at all.
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'avatar/' || user_id || '/' || object_id,size_bytes,?,0
               FROM avatar_objects WHERE user_id=?",
        )
        .bind(&[d1_int(now), d1_text(target_id)])?,
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'plugin-media/' || room_id || '/' || blob_id,size_bytes,?,0
               FROM plugin_media_objects
              WHERE uploader_id=? OR room_id IN (
                SELECT g.id FROM groups g WHERE g.created_by=? AND NOT EXISTS(
                  SELECT 1 FROM group_members gm
                   WHERE gm.group_id=g.id AND gm.user_id!=? AND gm.status='active'))",
        )
        .bind(&[
            d1_int(now),
            d1_text(target_id),
            d1_text(target_id),
            d1_text(target_id),
        ])?,
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'plugin-code/' || room_id || '/' || blob_id,size_bytes,?,0
               FROM plugin_code_objects
              WHERE uploader_id=? OR room_id IN (
                SELECT g.id FROM groups g WHERE g.created_by=? AND NOT EXISTS(
                  SELECT 1 FROM group_members gm
                   WHERE gm.group_id=g.id AND gm.user_id!=? AND gm.status='active'))",
        )
        .bind(&[
            d1_int(now),
            d1_text(target_id),
            d1_text(target_id),
            d1_text(target_id),
        ])?,
        // Every active group departure raises the epoch floor within the same transaction.
        db.prepare(
            "INSERT INTO plugin_epoch_floor(room_id,floor)
             SELECT group_id,1 FROM group_members
              WHERE user_id=? AND status='active'
             ON CONFLICT(room_id) DO UPDATE SET floor=floor+1",
        )
        .bind(&[d1_text(target_id)])?,
        // If the creator has an active successor, promote them to owner deterministically.
        db.prepare(PROMOTE_GROUP_SUCCESSORS_SQL)
            .bind(&[d1_text(target_id)])?,
        db.prepare(TRANSFER_CREATED_GROUPS_SQL)
            .bind(&[d1_text(target_id)])?,
        // A private group with no successor is closed down entirely, leaking no membership.
        db.prepare("DELETE FROM groups WHERE created_by=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("UPDATE group_members SET added_by=NULL WHERE added_by=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM group_members WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM plugin_epoch_floor WHERE room_id NOT IN (SELECT id FROM groups)"),
        // Short-lived credential and invite references.
        db.prepare("UPDATE invite_attributions SET used_by=NULL WHERE used_by=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("UPDATE invite_attributions SET inviter_user_id=NULL WHERE inviter_user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("UPDATE invite_tokens SET used_by=NULL WHERE used_by=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("UPDATE invite_tokens SET owner_user_id=NULL WHERE owner_user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare(
            "DELETE FROM verification_codes
              WHERE email=(SELECT email FROM users WHERE id=?)",
        )
        .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM link_requests WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        // Key, device, delivery and notification projections.
        db.prepare("DELETE FROM signed_prekeys WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM one_time_prekeys WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM pending_messages WHERE recipient_id=? OR sender_id=?")
            .bind(&[d1_text(target_id), d1_text(target_id)])?,
        db.prepare("DELETE FROM fanout_retry WHERE recipient_id=? OR sender_id=?")
            .bind(&[d1_text(target_id), d1_text(target_id)])?,
        db.prepare("DELETE FROM push_wake_debounce WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM refresh_tokens WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM push_tokens WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM devices WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM device_lists WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        // This account's own feed/cursor leftovers; the counterpart tombstones stay behind.
        db.prepare("DELETE FROM contact_tombstones WHERE account_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM contact_revisions WHERE account_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM contact_qr_claims WHERE claimant_user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM contact_qr_offers WHERE issuer_user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM contact_blocks WHERE blocker_user_id=? OR blocked_user_id=?")
            .bind(&[d1_text(target_id), d1_text(target_id)])?,
        db.prepare("DELETE FROM contact_grants WHERE user_low=? OR user_high=?")
            .bind(&[d1_text(target_id), d1_text(target_id)])?,
        db.prepare("DELETE FROM contact_requests WHERE source_user_id=? OR target_user_id=?")
            .bind(&[d1_text(target_id), d1_text(target_id)])?,
        // Once the blob metadata has moved to the outbox, drop it from the authoritative
        // inventory.
        db.prepare("DELETE FROM media_objects WHERE uploader_id=?")
            .bind(&[d1_text(target_id)])?,
        // FK ordering: avatar_objects references users, so it must be cleared BEFORE users is.
        db.prepare("DELETE FROM avatar_objects WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare(
            "DELETE FROM plugin_media_objects
              WHERE uploader_id=? OR room_id NOT IN (SELECT id FROM groups)",
        )
        .bind(&[d1_text(target_id)])?,
        db.prepare(
            "DELETE FROM plugin_code_objects
              WHERE uploader_id=? OR room_id NOT IN (SELECT id FROM groups)",
        )
        .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM user_storage WHERE user_id=?")
            .bind(&[d1_text(target_id)])?,
        // After the guard, the target is still a member as far as this transaction's snapshot
        // is concerned.
        db.prepare("DELETE FROM users WHERE id=?")
            .bind(&[d1_text(target_id)])?,
        db.prepare("DELETE FROM membership_delete_guard WHERE slot=1"),
    ];

    if let Err(error) = db.batch(stmts).await {
        // The guard abort has to be told apart from a concurrent owner promotion versus another
        // delete. If this diagnostic query fails too, return the original D1 error rather than
        // losing it.
        if let Ok(role) = db
            .prepare("SELECT role FROM users WHERE id=? LIMIT 1")
            .bind(&[d1_text(target_id)])
        {
            if let Ok(row) = role.first::<TargetRow>(None).await {
                match row {
                    Some(row) if row.role == "owner" => {
                        return Err(DeleteError::OwnerTransferRequired)
                    }
                    None => return Err(DeleteError::NotFound),
                    Some(row) => {
                        if let RemovalAuthority::Administrator {
                            caller_id,
                            caller_device_id,
                        } = authority
                        {
                            let caller_role = match db
                                .prepare("SELECT role FROM users WHERE id=? LIMIT 1")
                                .bind(&[d1_text(caller_id)])
                            {
                                Ok(stmt) => stmt
                                    .first::<TargetRow>(None)
                                    .await
                                    .ok()
                                    .flatten()
                                    .map(|value| value.role),
                                Err(_) => None,
                            };
                            let still_allowed = matches!(
                                (caller_role.as_deref(), row.role.as_str()),
                                (Some("owner"), role) if role != "owner"
                            ) || matches!(
                                (caller_role.as_deref(), row.role.as_str()),
                                (Some("admin"), "member")
                            );
                            let device_still_active = match caller_device_id {
                                Some(device_id) => crate::auth::middleware::account_device_active(
                                    env, caller_id, device_id,
                                )
                                .await
                                // If the diagnostic query fails, preserve the original D1
                                // batch error.
                                .unwrap_or(true),
                                None => true,
                            };
                            if !still_allowed || !device_still_active || caller_id == target_id {
                                return Err(DeleteError::AuthorizationChanged);
                            }
                        }
                    }
                }
            }
        }
        return Err(DeleteError::Worker(error));
    }
    // Fetch the revisions in ONE query and keep the live fan-out bounded. The DB feed holds
    // every counterpart, and accounts beyond the limit or currently offline converge via the
    // reconnect pull. We refuse to turn one HTTP request into hundreds of D1 + DO subrequests.
    let contact_nudges: Vec<ContactNudge> = match db
        .prepare(
            "SELECT account_id AS user_id,revision FROM contact_revisions
              WHERE entity='authorization' AND entity_id='removed:' || ?
                AND action='tombstone'
              ORDER BY revision DESC LIMIT ?",
        )
        .bind(&[d1_text(target_id), d1_int(LIVE_NUDGE_LIMIT)])
    {
        Ok(stmt) => match stmt.all().await.and_then(|result| result.results()) {
            Ok(rows) => rows,
            Err(error) => {
                console_warn!(
                    "membership committed; live nudge lookup skipped user={target_id}: {error:?}"
                );
                Vec::new()
            }
        },
        Err(error) => {
            console_warn!(
                "membership committed; live nudge bind skipped user={target_id}: {error:?}"
            );
            Vec::new()
        }
    };
    Ok(RemovalOutcome {
        contact_nudges,
        group_nudges,
    })
}

/// Post-commit live teardown. If the purge fails, the outbox row is retained.
pub(crate) async fn finish_removal(env: &Env, user_id: &str, outcome: &RemovalOutcome) {
    // Close the removed account's open channel first; the counterpart UI nudges follow. The D1
    // hot-path gate is already shut, but this drops the user immediately.
    match crate::realtime::purge_account_inbox(env, user_id).await {
        Ok(()) => {
            if let Ok(db) = env.d1("DB") {
                if let Ok(stmt) = db
                    .prepare("DELETE FROM account_purge_outbox WHERE user_id=?")
                    .bind(&[d1_text(user_id)])
                {
                    let _ = stmt.run().await;
                }
            }
        }
        Err(error) => console_warn!("account inbox purge queued user={user_id}: {error:?}"),
    }
    for nudge in &outcome.contact_nudges {
        if let Err(error) =
            crate::realtime::nudge_contact_update_at(env, &nudge.user_id, nudge.revision).await
        {
            console_warn!(
                "membership contact_update failed user={}: {error:?}",
                nudge.user_id
            );
        }
    }
    for nudge in &outcome.group_nudges {
        if let Err(error) = crate::realtime::nudge_group_update(env, &nudge.user_id).await {
            console_warn!(
                "membership group_update failed user={}: {error:?}",
                nudge.user_id
            );
        }
    }
}

/// POST /auth/leave — an owner must transfer ownership first.
pub async fn leave(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth,
        Err(resp) => return Ok(resp),
    };
    let outcome = match delete_membership(
        &ctx.env,
        &auth.user_id,
        RemovalReason::Left,
        RemovalAuthority::SelfLeave,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(DeleteError::NotFound) => return json_err(401, "inactive_account"),
        Err(DeleteError::OwnerTransferRequired) => return json_err(409, "owner_transfer_required"),
        Err(DeleteError::AuthorizationChanged) => return json_err(409, "membership_roles_changed"),
        Err(DeleteError::Worker(error)) => return Err(error),
    };
    finish_removal(&ctx.env, &auth.user_id, &outcome).await;
    Response::from_json(&serde_json::json!({"ok":true,"left":true}))
}

#[derive(Deserialize)]
struct PurgeRow {
    user_id: String,
    attempts: i64,
}

/// The 2-minute cron retry: claim a lease atomically, delete on a successful purge, and back
/// off exponentially (bounded) on failure. Because `/purge-account` is idempotent, losing a
/// response is safe.
pub(crate) async fn drain_purge_outbox(env: &Env) {
    let Ok(db) = env.d1("DB") else { return };
    let now = now_secs() as i64;
    let claimed: Vec<PurgeRow> = match db
        .prepare(
            "UPDATE account_purge_outbox SET next_at=?
              WHERE user_id IN (
                SELECT user_id FROM account_purge_outbox
                 WHERE next_at<=? ORDER BY next_at,created_at LIMIT ?)
             RETURNING user_id,attempts",
        )
        .bind(&[
            d1_int(now + PURGE_LEASE_SECS),
            d1_int(now),
            d1_int(PURGE_BATCH),
        ]) {
        Ok(stmt) => match stmt.all().await.and_then(|r| r.results()) {
            Ok(rows) => rows,
            Err(_) => return,
        },
        Err(_) => return,
    };
    for row in claimed {
        match crate::realtime::purge_account_inbox(env, &row.user_id).await {
            Ok(()) => {
                if let Ok(stmt) = db
                    .prepare("DELETE FROM account_purge_outbox WHERE user_id=?")
                    .bind(&[d1_text(&row.user_id)])
                {
                    let _ = stmt.run().await;
                }
            }
            Err(error) => {
                let attempts = row.attempts.saturating_add(1);
                let shift = attempts.clamp(0, 5) as u32;
                let backoff = (30_i64.saturating_mul(1_i64 << shift)).min(3600);
                let message: String = error.to_string().chars().take(120).collect();
                if let Ok(stmt) = db
                    .prepare(
                        "UPDATE account_purge_outbox
                            SET attempts=?,next_at=?,last_error=? WHERE user_id=?",
                    )
                    .bind(&[
                        d1_int(attempts),
                        d1_int(now + backoff),
                        d1_text(&message),
                        d1_text(&row.user_id),
                    ])
                {
                    let _ = stmt.run().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ADMIN_MEMBERSHIP_GUARD_SQL, INSERT_COUNTERPART_REVISIONS_SQL, PROMOTE_GROUP_SUCCESSORS_SQL,
        SELF_MEMBERSHIP_GUARD_SQL, TRANSFER_CREATED_GROUPS_SQL, UPSERT_COUNTERPART_TOMBSTONES_SQL,
    };
    use rusqlite::{params, Connection};

    #[test]
    fn transaction_guard_rejects_owner_or_missing_target() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE users(id TEXT PRIMARY KEY,role TEXT NOT NULL);
             INSERT INTO users VALUES('owner','owner'),('member','member');",
        )
        .unwrap();
        db.execute_batch(include_str!(
            "../migrations/0034_membership_cleanup_outbox.sql"
        ))
        .unwrap();

        for target in ["owner", "missing"] {
            let error = db
                .execute(SELF_MEMBERSHIP_GUARD_SQL, params![target])
                .unwrap_err();
            assert!(error.to_string().contains("NOT NULL"));
        }
        db.execute(SELF_MEMBERSHIP_GUARD_SQL, params!["member"])
            .unwrap();
        assert_eq!(
            db.query_row(
                "SELECT target_id FROM membership_delete_guard WHERE slot=1",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap(),
            "member"
        );
    }

    #[test]
    fn admin_guard_rechecks_both_roles_inside_the_delete_transaction() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE users(id TEXT PRIMARY KEY,role TEXT NOT NULL);
             CREATE TABLE devices(user_id TEXT,device_id TEXT,revoked_at INTEGER);
             INSERT INTO users VALUES
               ('owner','owner'),('admin','admin'),('other-admin','admin'),
               ('member','member'),('demoted','member');
             INSERT INTO devices VALUES
               ('owner','owner-device',NULL),('admin','admin-device',NULL),
               ('demoted','demoted-device',NULL);",
        )
        .unwrap();
        db.execute_batch(include_str!(
            "../migrations/0034_membership_cleanup_outbox.sql"
        ))
        .unwrap();

        for (target, caller) in [
            ("owner", "admin"),
            ("other-admin", "admin"),
            ("member", "demoted"),
            ("admin", "admin"),
        ] {
            let error = db
                .execute(
                    ADMIN_MEMBERSHIP_GUARD_SQL,
                    params![target, caller, format!("{caller}-device")],
                )
                .unwrap_err();
            assert!(error.to_string().contains("NOT NULL"));
        }

        db.execute(
            ADMIN_MEMBERSHIP_GUARD_SQL,
            params!["member", "admin", "admin-device"],
        )
        .unwrap();
        db.execute("DELETE FROM membership_delete_guard", [])
            .unwrap();
        db.execute(
            ADMIN_MEMBERSHIP_GUARD_SQL,
            params!["other-admin", "owner", "owner-device"],
        )
        .unwrap();

        db.execute("DELETE FROM membership_delete_guard", [])
            .unwrap();
        db.execute("UPDATE devices SET revoked_at=1 WHERE user_id='admin'", [])
            .unwrap();
        let error = db
            .execute(
                ADMIN_MEMBERSHIP_GUARD_SQL,
                params!["member", "admin", "admin-device"],
            )
            .unwrap_err();
        assert!(error.to_string().contains("NOT NULL"));
    }

    #[test]
    fn membership_contact_tombstones_are_set_based_and_replay_safe() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE users(id TEXT PRIMARY KEY);
             INSERT INTO users VALUES('gone'),('grant-peer'),('request-peer'),('block-peer');
             CREATE TABLE contact_grants(user_low TEXT,user_high TEXT);
             CREATE TABLE contact_requests(source_user_id TEXT,target_user_id TEXT);
             CREATE TABLE contact_blocks(blocker_user_id TEXT,blocked_user_id TEXT);
             CREATE TABLE contact_revisions(
               revision INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,
               account_id TEXT NOT NULL,peer_id TEXT,entity TEXT NOT NULL,
               entity_id TEXT NOT NULL,action TEXT NOT NULL,created_at INTEGER NOT NULL);
             CREATE TABLE contact_tombstones(
               account_id TEXT NOT NULL,entity TEXT NOT NULL,entity_id TEXT NOT NULL,
               peer_id TEXT,revision INTEGER NOT NULL,deleted_at INTEGER NOT NULL,
               PRIMARY KEY(account_id,entity,entity_id));
             INSERT INTO contact_grants VALUES('gone','grant-peer');
             INSERT INTO contact_requests VALUES('request-peer','gone');
             INSERT INTO contact_blocks VALUES('gone','block-peer');",
        )
        .unwrap();

        for _ in 0..2 {
            db.execute(INSERT_COUNTERPART_REVISIONS_SQL, params!["gone", 10])
                .unwrap();
            db.execute(UPSERT_COUNTERPART_TOMBSTONES_SQL, params!["gone", 10])
                .unwrap();
        }
        let revisions: i64 = db
            .query_row("SELECT COUNT(*) FROM contact_revisions", [], |r| r.get(0))
            .unwrap();
        let tombstones: i64 = db
            .query_row("SELECT COUNT(*) FROM contact_tombstones", [], |r| r.get(0))
            .unwrap();
        assert_eq!(revisions, 3, "replay revision çoğaltmamalı");
        assert_eq!(tombstones, 3);
        let wrong_peer: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM contact_tombstones WHERE peer_id!='gone'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(wrong_peer, 0);
    }

    #[test]
    fn group_owner_moves_to_active_admin_and_pending_only_group_closes() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE groups(id TEXT PRIMARY KEY,created_by TEXT NOT NULL);
             CREATE TABLE group_members(
               group_id TEXT,user_id TEXT,role TEXT,status TEXT,joined_at INTEGER,
               PRIMARY KEY(group_id,user_id));
             INSERT INTO groups VALUES('survives','gone'),('closes','gone');
             INSERT INTO group_members VALUES
               ('survives','gone','owner','active',1),
               ('survives','member','member','active',2),
               ('survives','admin','admin','active',3),
               ('closes','gone','owner','active',1),
               ('closes','pending','member','pending',2);",
        )
        .unwrap();
        db.execute(PROMOTE_GROUP_SUCCESSORS_SQL, params!["gone"])
            .unwrap();
        db.execute(TRANSFER_CREATED_GROUPS_SQL, params!["gone"])
            .unwrap();
        db.execute("DELETE FROM groups WHERE created_by=?", params!["gone"])
            .unwrap();

        let owner: (String, String) = db
            .query_row(
                "SELECT g.created_by,gm.role FROM groups g JOIN group_members gm
                   ON gm.group_id=g.id AND gm.user_id=g.created_by WHERE g.id='survives'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(owner, ("admin".into(), "owner".into()));
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM groups WHERE id='closes'", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }
}
