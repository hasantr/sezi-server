//! The single deletion primitive for server membership.
//!
//! One D1 batch commits membership, group ownership, the contact feed and the cross-DO purge
//! outbox together. The UserInbox purge is attempted after the commit; if it fails, the cron
//! idempotently retries the same outbox row.

use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_text};
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
        AND EXISTS(
          SELECT 1 FROM devices device
           WHERE device.user_id=caller.id AND device.device_id=?3
             AND device.revoked_at IS NULL)
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
        /// The admin's own device. Never optional: it comes from the caller's token, which
        /// always names one.
        caller_device_id: &'a str,
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

/// Group succession — the INVOLUNTARY twin of `groups_transfer.rs`'s `transfer_to`: both mint an
/// owner row for somebody who did not ask for one.
///
/// **The gates are an ORDER BY, never a filter.** This runs in the account-deletion transaction,
/// and two statements below `DELETE FROM groups WHERE created_by=?1` destroys every group left
/// unhanded. So the WHERE decides which groups SURVIVE and the ORDER BY only who INHERITS: one
/// more predicate up there (must be admin, must be under the cap) silently turns a group that
/// would have changed hands into a group that is destroyed.
///
/// The tiers: a sitting owner first — `group_members` has no partial UNIQUE index on
/// `role='owner'`, so a group whose `created_by` still names the departing user while somebody
/// else holds the owner row would gain a SECOND owner that no group handler can resolve; then an
/// admin over a plain member (a preference, not a gate); then fewest groups owned, which stands
/// in for `MAX_OWNED_GROUPS` because a threshold can empty the candidate set and this statement
/// must always name someone. The counting predicate matches `groups_transfer.rs`'s
/// `OWNED_GROUP_COUNT_SQL` exactly, so both paths measure a present holding, not a past act.
///
/// Residue: sort keys are computed from the table as found, so one deletion can push a person
/// past the cap by however many groups it hands over at once. And it is not consent — an account
/// that no longer exists cannot ask.
const PROMOTE_GROUP_SUCCESSORS_SQL: &str = "UPDATE group_members AS gm SET role='owner'
      WHERE gm.user_id=(
        SELECT c.user_id FROM group_members c
         WHERE c.group_id=gm.group_id AND c.user_id!=?1 AND c.status='active'
         ORDER BY CASE c.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                  (SELECT COUNT(*) FROM group_members o
                    WHERE o.user_id=c.user_id AND o.role='owner'),
                  c.joined_at,c.user_id
         LIMIT 1)
        AND gm.group_id IN (SELECT id FROM groups WHERE created_by=?1)";

/// Move `groups.created_by` onto the successor the statement above just promoted. It re-derives the
/// choice rather than being handed it, and the two agree because its first tier is `'owner'`: after
/// the promotion the successor is the only owner in the room, so this picks the same person. Its
/// lower tiers are the fallback for a group the promotion left alone.
const TRANSFER_CREATED_GROUPS_SQL: &str = "UPDATE groups SET created_by=(
       SELECT gm.user_id FROM group_members gm
        WHERE gm.group_id=groups.id AND gm.user_id!=?1 AND gm.status='active'
        ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                 gm.joined_at,gm.user_id LIMIT 1)
     WHERE created_by=?1 AND EXISTS(
       SELECT 1 FROM group_members gm
        WHERE gm.group_id=groups.id AND gm.user_id!=?1 AND gm.status='active')";

/// A departing member's invites that nobody has used go with the membership.
///
/// They used to be orphaned like every other reference to the account — `owner_user_id` set to
/// NULL — and an unused invite with no minter is exactly what the genesis invite looks like
/// (`auth::bootstrap`). Two faults followed. A removed admin's invites stayed redeemable for the
/// rest of their TTL, up to 30 days, so taking someone's role away left the doors they had handed
/// out open. And `idx_one_genesis_invite` (0018) admits ONE unused minter-less row, so removing an
/// admin who held two unused invites — or one, beside a leftover from an earlier removal — broke
/// the unique index and rolled the whole removal back.
///
/// "Unused" is `used = 0`, wider than revoke's test, which also spares a row the ledger has
/// claimed while its `used` flip has not landed. Detached, that row would be a minter-less
/// `used = 0` row too, and deleting it costs nothing: verify and the admin list read the claim's
/// snapshot in `invite_attributions`, never the source row. Runs BEFORE
/// [`DETACH_SPENT_INVITES_SQL`].
const DELETE_UNUSED_INVITES_SQL: &str =
    "DELETE FROM invite_tokens WHERE owner_user_id=?1 AND used=0";

/// What is left of the departing member's invites has been used. Its source row is detached,
/// because the foreign key needs that before `users` goes, and is swept with its TTL; the ledger
/// row in `invite_attributions` — who used it and when — stays. A `used = 1` row sits outside the
/// genesis index, which is the whole reason [`DELETE_UNUSED_INVITES_SQL`] runs first.
const DETACH_SPENT_INVITES_SQL: &str =
    "UPDATE invite_tokens SET owner_user_id=NULL WHERE owner_user_id=?1";

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
            d1_text(caller_device_id),
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
        // Delete-then-detach, in this order: see the two constants.
        db.prepare(DELETE_UNUSED_INVITES_SQL)
            .bind(&[d1_text(target_id)])?,
        db.prepare(DETACH_SPENT_INVITES_SQL)
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
                            let device_still_active =
                                crate::auth::middleware::account_device_active(
                                    env,
                                    caller_id,
                                    caller_device_id,
                                )
                                .await
                                // If the diagnostic query fails, preserve the original D1
                                // batch error.
                                .unwrap_or(true);
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

/// The rusqlite exercises over the SQL constants above. Split out because `membership.rs` sat
/// exactly ON the 800-line ceiling; `keys/handlers.rs` is the worked example of the move.
#[cfg(test)]
#[path = "membership_tests.rs"]
mod tests;
