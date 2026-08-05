//! Group OWNERSHIP — the per-user cap that bounds it, and the transfer that moves it.
//!
//! Split out of `groups.rs` for size, but the two halves belong together for a better reason: a
//! transfer writes an owner row, so it is the second place `MAX_OWNED_GROUPS` has to hold, and a
//! cap enforced on one write path and forgotten on the other is not a cap. Keeping the counting
//! query and the transfer batch in one file is how they stay one rule.
//!
//! The SQL and the argument for its ORDER are likewise one unit; separating them is how the
//! ordering gets "tidied" later by someone who reads the statements without the argument.
//!
//! `groups.rs` still carries the CALLER-side gates — who may create, who may transfer, who may not
//! transfer to themselves. This module owns the RECIPIENT side: whether the person about to hold a
//! group may hold it, and the write that puts them there.

use crate::d1util::{d1_int, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// How many groups a user owns RIGHT NOW.
///
/// Counting `group_members` rows with role='owner', NOT `groups.created_by`. The difference is not
/// cosmetic. `created_by` records a historical act; ownership moves. A cap counting `created_by`
/// would let one account create `MAX_OWNED_GROUPS` groups, transfer them all away and start again
/// from zero, forever — measuring a past act rather than a present holding. The membership row is
/// precisely what a transfer rewrites, so counting it stays correct through transfer without this
/// query being touched again.
///
/// `status` is deliberately NOT filtered, and the reason changed when transfer landed: it used to
/// be "`set_role` refuses to assign 'owner' at all, so every owner row is active". It now assigns
/// exactly one, and `TRANSFER_PROMOTE_TARGET_SQL` carries `status = 'active'` in its own WHERE, so
/// the property survives — every owner row in the table is an active one. Omitting the filter
/// guarantees the count can never come in UNDER the number of groups actually held, which is the
/// direction that matters for a bound.
///
/// A `const` rather than an inline string so the rusqlite tests in `groups_tests.rs` exercise the
/// statement that actually ships (the `membership.rs` pattern).
pub(super) const OWNED_GROUP_COUNT_SQL: &str =
    "SELECT COUNT(*) AS c FROM group_members WHERE user_id = ? AND role = 'owner'";

/// Transfer 1/3 — demote the sitting owner (the caller). Binds: group_id, caller. The
/// `role = 'owner'` predicate makes the statement inert for anyone who is not the owner, so a
/// caller who slipped past the handler gate demotes nobody — and then statement 2 sees an owner
/// still in place and refuses to promote. Constants rather than inline strings so the rusqlite
/// tests in `groups_tests.rs` exercise the SQL that actually ships (the `membership.rs` pattern).
pub(super) const TRANSFER_DEMOTE_OWNER_SQL: &str = "UPDATE group_members SET role = 'admin'
     WHERE group_id = ? AND user_id = ? AND role = 'owner'";

/// Transfer 2/3 — promote the target. Binds: group_id, target, group_id.
/// The NOT EXISTS guard is what makes the batch fail SAFE instead of corrupt: a group can only
/// gain an owner while it has none. `group_members` carries no partial UNIQUE index on
/// role='owner' (0018's `idx_one_owner` is on `users`, the SERVER role — a different table and a
/// different question), so nothing under this statement would stop a second owner row; the
/// guard is the only thing that does.
///
/// ⚠ The owned-groups cap is NOT one more `AND` in here, and the omission is deliberate — see
/// `transfer_to`, "The cap is checked before the batch, never inside it".
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
/// owner and that `target` is an ACTIVE member who is not already the owner. Returns the handler's
/// response: 204 on success, or the refusal.
///
/// # The recipient is never asked, so the shape of the ask is the whole design question
///
/// This is the one write on the group surface that puts an OBLIGATION on somebody else. After the
/// batch the target IS the owner, and `remove_member` answers `owner_cannot_leave` to an owner's
/// self-leave — so the previous owner can hand the group over and walk out as an ordinary admin a
/// second later, leaving the target holding a room they never agreed to run. `dc16d837` built the
/// transfer precisely because nobody should be structurally bound to a room; with no rule here it
/// re-creates that bind pointing the other way.
///
/// Three shapes were weighed. What ships is the third.
///
/// **A pending transfer the target accepts** is the only one that obtains real consent, and it was
/// rejected for what it costs the SENDER. An offer somebody else has to answer stops the owner's
/// exit being unilateral: until the target replies, or the offer expires, the owner is bound again
/// and their only remaining unilateral exit is DELETE — destroying a room other people are using.
/// Buying the recipient's consent by restoring the sender's bind trades one half of `dc16d837` for
/// the other. It also invents durable state nothing else on this surface has: an offer row, an
/// expiry, a second endpoint, its own nudge, and reconciliation for every way the world moves
/// underneath it (the target leaves, the owner leaves, the group is deleted, a second offer is
/// made, the target is demoted while an offer stands). Against CLAUDE.md's "Blocking is not a
/// moderation system" — a small circle of people who already know each other, where the stated
/// remedy for someone who becomes a problem is removal rather than a procedural gate everyone else
/// pays for — that is the wrong register.
///
/// **Nothing at all**, on the grounds that the recipient has the same exits the creator had, is
/// nearly true and not quite. The exits really are identical (transfer onward, or delete) but the
/// creator CHOSE the group into existence. "Your way out is to surprise somebody else the way you
/// were surprised, or to destroy a room other people are using" is not an exit anyone would defend
/// if it were written down, and in a group where the ex-owner has since left it is the only one.
///
/// **The target must already be an `admin`.** Be exact about what this is: it is NOT consent. The
/// owner promotes unilaterally, so a determined owner still gets there in two requests instead of
/// one and this buys nothing against them. What it buys is the ordinary case, which is the case
/// this product designs for:
///
/// - Consent to the ROOM already exists. `group_role` ignores 'pending' rows, so an invitee who has
///   not accepted cannot be handed the group at all (`not_member_target`). What is missing is
///   consent to the role, not to the room.
/// - Admin is the half of the job you can walk out of — `remove_member` refuses only the OWNER's
///   self-leave — so someone who is still an admin has, in the only way this system offers,
///   declined to leave the group's administration. Owner is the half you cannot walk out of.
///   Promoting from the reversible half is a far smaller step than handing the room to a member who
///   has never administered anything.
/// - It narrows the target set from "any of up to `MAX_GROUP_MEMBERS` active members" to "the
///   people this owner already elevated on purpose".
/// - And — the argument that stands with no consent reasoning at all — it makes the voluntary
///   transfer agree with the involuntary one. When an account is deleted,
///   `membership.rs::PROMOTE_GROUP_SUCCESSORS_SQL` chooses the successor with
///   `ORDER BY CASE role WHEN 'admin' THEN 0 ELSE 1 END`. The server already answers "who inherits
///   a group" with "an admin". Two different answers to one question in one codebase is the bug.
///
/// It costs a transfer nothing it cannot pay: an owner with no admin promotes one first, which is
/// two requests and never a dead end. A solo owner is unaffected — they had no eligible target
/// before either, and DELETE is still their exit.
///
/// # The cap is checked before the batch, never inside it
///
/// `create_group` bounds an account at `MAX_OWNED_GROUPS` groups owned. A transfer writes an owner
/// row too and used to write it with no cap at all, so an account sitting at the ceiling could push
/// all 64 groups onto one person and leave them unable to create a single group of their own — the
/// bound honoured on one path and given away on the other.
///
/// It has to be a PRE-check. Folding it into `TRANSFER_PROMOTE_TARGET_SQL` as one more `AND` looks
/// tidier and is the dangerous version: statement 1 has already vacated the owner seat by the time
/// statement 2 is evaluated, so a promotion refused in there commits a batch that leaves the group
/// with ZERO owners — the exact unrecoverable state the statement ORDER exists to prevent, since
/// `set_role`, `delete_group` and `update_settings` all need an owner to act. A guard inside the
/// batch also refuses silently and still answers 204, and the caller has to learn why.
///
/// The residue is a TOCTOU window: two transfers converging on one recipient can both read 63 and
/// both promote. `create_group` has the same race and it is tolerable for the same reason — this
/// bounds bulk dumping, it is not a security boundary, and an account one over the line can neither
/// create nor receive another group until it falls back under.
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
    // A transfer moves TWO rows — the caller down to admin, the target up to owner — and both
    // people's own `GET /groups` row carries `gm.role`. Both are in the room, so the ordinary room
    // fan-out reaches them without naming either.
    super::notify::nudge_room(env, db, group_id, &[]).await;
    no_content()
}

/// The write itself. The caller has already been checked to be the sitting owner, and the target to
/// be an active member who is under the cap; this runs the three statements.
///
/// ONE batch, THREE ORDERED statements — the order is the correctness argument, not a style
/// choice.
///
/// ORDER: demote the caller (owner count 1 → 0), THEN promote the target (0 → 1). Never the other
/// way round: at group scope a second owner row would simply be WRITTEN — see
/// `TRANSFER_PROMOTE_TARGET_SQL` on why no index catches it — and two owners is a state no handler
/// here can resolve. `admin/handlers.rs::transfer_ownership` learned this at server scope, where
/// the partial UNIQUE index turns the same mistake into a ~50% 500 depending on how SQLite happens
/// to order the scan. Loud there, silent here.
///
/// BATCH: D1 wraps a batch in an implicit transaction, so the group never rests at zero owners.
/// Written as three sequential `.run()` calls in `groups.rs`'s usual style, a failure between
/// statements 1 and 2 would leave the group with NO owner — unrecoverable through the API,
/// because `set_role`, `delete_group` and `update_settings` all require an owner to act. There
/// would be no way back in.
///
/// NO epoch-floor bump, unlike the leave/remove/delete paths. The asymmetry is deliberate and
/// would otherwise read as an omission: `bump_epoch_floor` fences someone who LEFT out of the old
/// plugin-log epoch. A transfer changes nobody's membership — the same people are in the group
/// before and after, and nobody loses read or append rights — so there is nothing to fence off,
/// and bumping would force a pointless key rotation on every member.
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
        // STATEMENT 3 IS NOT BOOKKEEPING — it is the load-bearing one, and the next person will
        // be tempted to drop it because "the owner ROW is the real thing". Two subsystems
        // disagree about that. Account deletion keys its group succession on `groups.created_by`,
        // not on the owner row: `membership.rs`'s PROMOTE_GROUP_SUCCESSORS_SQL,
        // TRANSFER_CREATED_GROUPS_SQL and the bare `DELETE FROM groups WHERE created_by=?` beside
        // them all select `WHERE created_by=?`. Leave created_by pointing at the former owner C
        // and this group stays inside C's deletion blast radius forever — a group C may no longer
        // even belong to. When C deletes their account, the succession UPDATE ranks 'admin' at 0
        // and drops 'owner' into the ELSE bucket, so it promotes an admin while the real owner B
        // is still owner → TWO permanent owner rows. And if the group happens to have no other
        // ACTIVE member at that moment, the DELETE destroys a live group C does not own.
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
