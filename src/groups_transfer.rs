//! Group OWNERSHIP — the per-user cap that bounds it, and the transfer that moves it.
//!
//! The cap and the transfer live together because a transfer writes an owner row, making it the
//! second place `MAX_OWNED_GROUPS` has to hold; a cap enforced on one write path and forgotten on
//! the other is not a cap. The SQL and the argument for its ORDER are likewise one unit — separate
//! them and the ordering gets "tidied" by someone reading the statements without the argument.
//!
//! `groups.rs` carries the CALLER-side gates (who may create, transfer, or not transfer to
//! themselves). This module owns the RECIPIENT side.

use crate::d1util::{d1_int, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// How many groups a user owns RIGHT NOW.
///
/// It counts `group_members` rows with role='owner', NOT `groups.created_by`. `created_by` records
/// a historical act while ownership moves, so a cap counting it would let an account create
/// `MAX_OWNED_GROUPS` groups, transfer them all away and start again from zero, forever. The
/// membership row is what a transfer rewrites, so this stays correct through transfer untouched.
///
/// `status` is deliberately NOT filtered. Every owner row in the table is active anyway
/// (`TRANSFER_PROMOTE_TARGET_SQL` carries `status = 'active'` in its own WHERE), and omitting the
/// filter guarantees the count can never come in UNDER the number of groups actually held — the
/// direction that matters for a bound.
///
/// A `const` rather than an inline string so the rusqlite tests in `groups_tests.rs` exercise the
/// statement that actually ships.
pub(super) const OWNED_GROUP_COUNT_SQL: &str =
    "SELECT COUNT(*) AS c FROM group_members WHERE user_id = ? AND role = 'owner'";

/// Transfer 1/3 — demote the sitting owner (the caller). Binds: group_id, caller. The
/// `role = 'owner'` predicate makes the statement inert for anyone who is not the owner, so a
/// caller who slipped past the handler gate demotes nobody — and then statement 2 sees an owner
/// still in place and refuses to promote.
pub(super) const TRANSFER_DEMOTE_OWNER_SQL: &str = "UPDATE group_members SET role = 'admin'
     WHERE group_id = ? AND user_id = ? AND role = 'owner'";

/// Transfer 2/3 — promote the target. Binds: group_id, target, group_id.
/// The NOT EXISTS guard is what makes the batch fail SAFE instead of corrupt: a group can only
/// gain an owner while it has none. `group_members` carries no partial UNIQUE index on
/// role='owner' (0018's `idx_one_owner` is on `users`, the SERVER role — a different table and a
/// different question), so this guard is the only thing stopping a second owner row.
///
/// ⚠ The owned-groups cap is deliberately NOT one more `AND` in here — see `transfer_to`.
pub(super) const TRANSFER_PROMOTE_TARGET_SQL: &str = "UPDATE group_members SET role = 'owner'
     WHERE group_id = ? AND user_id = ? AND status = 'active'
       AND NOT EXISTS (SELECT 1 FROM group_members o
                        WHERE o.group_id = ? AND o.role = 'owner')";

/// Transfer 3/3 — move `groups.created_by` onto the new owner. Binds: target, now, group_id,
/// group_id, target. The EXISTS guard ties this to statement 2 having actually landed: if the
/// promotion was refused, the pointer does not move either.
pub(super) const TRANSFER_CREATED_BY_SQL: &str = "UPDATE groups SET created_by = ?, updated_at = ?
     WHERE id = ? AND EXISTS (SELECT 1 FROM group_members o
                               WHERE o.group_id = ? AND o.user_id = ? AND o.role = 'owner')";

/// The number of groups `user_id` currently owns. Shared by both write paths that can create an
/// owner row — `create_group` and `transfer_to` — because a cap counted two different ways is two
/// different caps.
///
/// Fails CLOSED: the `?` on a D1 error becomes a 500 rather than a write that skipped its bound.
/// That is the opposite choice from the fail-open storage quota in `quota.rs`, for the reason
/// recorded there in reverse — rejecting an upload that should have been allowed is a retry;
/// minting a group row that should not exist is durable and nobody goes back to clean it up.
pub(super) async fn owned_group_count(db: &D1Database, user_id: &str) -> Result<i64> {
    #[derive(Deserialize)]
    struct OwnedCountRow {
        c: i64,
    }
    let row: Option<OwnedCountRow> = db
        .prepare(OWNED_GROUP_COUNT_SQL)
        .bind(&[d1_text(user_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.c).unwrap_or(0))
}

/// Hand `group_id` to `target`, once `set_role` has established that the caller is the sitting
/// owner and that `target` is an ACTIVE member who is not already the owner. Returns 204, or the
/// refusal.
///
/// # THE TARGET MUST ALREADY BE AN ADMIN
///
/// This is the one write on the group surface that puts an OBLIGATION on somebody else: after the
/// batch the target IS the owner, `remove_member` refuses an owner's self-leave, and the previous
/// owner walks out as an ordinary admin. The transfer exists so nobody is structurally bound to a
/// room; with no rule here it re-creates that bind pointing the other way. The requirement is not
/// consent — an owner promotes unilaterally and gets there in two requests — but someone still
/// holding admin has declined the one exit this system offers, and it makes the voluntary
/// transfer agree with the involuntary one, where `PROMOTE_GROUP_SUCCESSORS_SQL` already answers
/// "who inherits a group" with "an admin". A pending offer the target accepts was rejected: it
/// re-binds the sender until they reply and invents durable state (offer row, expiry, a second
/// endpoint) nothing else on this surface has.
///
/// # The cap is checked before the batch, never inside it
///
/// A transfer writes an owner row, so `MAX_OWNED_GROUPS` binds here too. It must be a PRE-check:
/// folding it into `TRANSFER_PROMOTE_TARGET_SQL` as one more `AND` looks tidier, but statement 1
/// has already vacated the owner seat, so a refusal in there commits a batch leaving the group
/// with ZERO owners — unrecoverable, since `set_role`, `delete_group` and `update_settings` all
/// need one — while still answering 204. The residue is a TOCTOU window: two transfers
/// converging on one recipient can both promote. Tolerable, as in `create_group`: this bounds
/// bulk dumping and is not a security boundary.
pub(super) async fn transfer_to(
    env: &Env,
    db: &D1Database,
    group_id: &str,
    requester: &str,
    target: &str,
    target_role: &str,
) -> Result<Response> {
    if target_role != "admin" {
        return json_err(403, "target_not_admin");
    }
    if owned_group_count(db, target).await? as usize >= super::MAX_OWNED_GROUPS {
        return json_err(409, "target_too_many_groups");
    }
    transfer_group_owner(db, group_id, requester, target, now_secs() as i64).await?;
    // Two rows moved — the caller down to admin, the target up to owner — and both people's own
    // `GET /groups` row carries `gm.role`. Both are in the room, so the ordinary room fan-out
    // reaches them without naming either.
    super::notify::nudge_room(env, db, group_id, &[]).await;
    no_content()
}

/// The write itself: one batch, three ORDERED statements. The order is the correctness argument,
/// not a style choice.
///
/// ORDER: demote the caller (1 → 0 owners), THEN promote the target (0 → 1). The other way round
/// simply WRITES a second owner row — no index catches it at group scope, see
/// `TRANSFER_PROMOTE_TARGET_SQL` — and two owners is a state no handler here can resolve.
/// `admin/handlers.rs::transfer_ownership` hit the same mistake at server scope, where the partial
/// UNIQUE index turns it into an intermittent 500: loud there, silent here.
///
/// BATCH: D1 wraps a batch in an implicit transaction, so the group never rests at zero owners.
/// As three sequential `.run()` calls, a failure between statements 1 and 2 would leave it with NO
/// owner — unrecoverable through the API, since `set_role`, `delete_group` and `update_settings`
/// all require one.
///
/// NO epoch-floor bump, unlike leave/remove/delete: `bump_epoch_floor` fences someone who LEFT out
/// of the old plugin-log epoch, and a transfer changes nobody's membership or rights. Bumping
/// would force a pointless key rotation on every member.
async fn transfer_group_owner(
    db: &D1Database,
    group_id: &str,
    requester: &str,
    target: &str,
    now: i64,
) -> Result<()> {
    db.batch(vec![
        db.prepare(TRANSFER_DEMOTE_OWNER_SQL)
            .bind(&[d1_text(group_id), d1_text(requester)])?,
        db.prepare(TRANSFER_PROMOTE_TARGET_SQL).bind(&[
            d1_text(group_id),
            d1_text(target),
            d1_text(group_id),
        ])?,
        // STATEMENT 3 IS NOT BOOKKEEPING. Account deletion keys group succession on
        // `groups.created_by`, not on the owner row — `membership.rs`'s
        // PROMOTE_GROUP_SUCCESSORS_SQL, TRANSFER_CREATED_GROUPS_SQL and the `DELETE FROM groups`
        // beside them all select `WHERE created_by=?`. Leave created_by on the former owner and
        // the group stays in their deletion blast radius forever: when they delete their account
        // the succession UPDATE ranks 'admin' first and promotes one while the real owner is still
        // owner (two permanent owner rows), and with no other active member the DELETE destroys a
        // live group they do not own.
        db.prepare(TRANSFER_CREATED_BY_SQL).bind(&[
            d1_text(target),
            d1_int(now),
            d1_text(group_id),
            d1_text(group_id),
            d1_text(target),
        ])?,
    ])
    .await?;
    Ok(())
}
