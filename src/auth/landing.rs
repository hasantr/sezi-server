//! Landing — putting a newly verified member into the group their invite named (campus plan Wave
//! F; migration 0044).
//!
//! Runs in `verify`, after the account exists. Two outcomes and a refusal:
//!
//! - **added** — an ordinary consent row in the landing group (`status = 'pending'`, `added_by` =
//!   the invite's minter). The joiner's client accepts it on its own (it asked to come in), which
//!   sends `GroupJoinAccepted` to the minter and the room key flows exactly as for any invitee.
//!   This is every personal invite with a landing group, and a class invite with auto-approval.
//! - **requested** — a join request (`group_join_requests`), which waits for a group admin. Every
//!   class invite with approval on, and — the safe direction — a class invite whose minter is no
//!   longer an admin of the group, or whose group is full: nobody is added on the authority of
//!   someone who no longer holds it.
//! - **unavailable** — a personal invite whose minter lost the group or whose group is full or
//!   gone. Hasan's rule is that a personally invited member is NEVER put into the request state,
//!   so the account is created and the landing is simply skipped.
//!
//! A landing never fails a registration: the account, keys and tokens are already committed, and a
//! person who could not be landed is one an admin can still add by hand.

use serde::Deserialize;
use worker::*;

use crate::d1util::{d1_int, d1_opt_text, d1_text};

/// Membership ceiling, the same number `groups.rs` enforces on `add_member` (fan-out width).
pub(crate) const LANDING_GROUP_CEILING: i64 = 256;

/// A personal invite's landing group, copied onto its ledger row right after the single-use claim
/// won. A separate statement rather than a change to `CLAIM_INVITE_SQL`, whose genesis decision is
/// pinned as it stands. A personal invite never needs approval, so only the room is copied. If the
/// source row is gone in the instant between the two (an admin revoke cannot delete a claimed row;
/// only the daily TTL sweep of an EXPIRED one could), the joiner is simply not landed. Binds:
/// `?1` token_hash.
pub(crate) const SNAPSHOT_PERSONAL_LANDING_SQL: &str = "UPDATE invite_attributions
        SET landing_room_id = (
          SELECT it.landing_room_id FROM invite_tokens it
           WHERE it.token_hash = ?1 AND it.kind = 'personal')
      WHERE invite_token_hash = ?1 AND verified_at IS NULL AND kind = 'personal'";

/// The direct landing: a consent row, only while the minter is still an ACTIVE owner/admin of the
/// group and the group has room. RETURNING says whether it happened. `OR IGNORE` makes a verify
/// retry a no-op. Binds: `?1` room, `?2` user, `?3` now, `?4` minter (NULL fails the EXISTS),
/// `?5` ceiling.
pub(crate) const LAND_DIRECT_SQL: &str = "INSERT OR IGNORE INTO group_members
       (group_id, user_id, role, joined_at, status, added_by)
     SELECT g.id, ?2, 'member', ?3, 'pending', ?4 FROM groups g
      WHERE g.id = ?1
        AND EXISTS (SELECT 1 FROM group_members a
                     WHERE a.group_id = g.id AND a.user_id = ?4 AND a.status = 'active'
                       AND a.role IN ('owner', 'admin'))
        AND (SELECT COUNT(*) FROM group_members c WHERE c.group_id = g.id) < ?5
     RETURNING user_id";

/// The join request. Binds: `?1` room, `?2` user, `?3` invite_hash, `?4` invite_label, `?5` now.
pub(crate) const LAND_REQUEST_SQL: &str = "INSERT INTO group_join_requests
       (group_id, user_id, invite_hash, invite_label, state, requested_at)
     SELECT g.id, ?2, ?3, ?4, 'pending', ?5 FROM groups g WHERE g.id = ?1
     ON CONFLICT(group_id, user_id) DO NOTHING
     RETURNING user_id";

/// What the redemption's snapshot says about landing (`LOAD_REDEMPTION_SQL`).
pub(crate) struct LandingPlan<'a> {
    pub(crate) class: bool,
    pub(crate) room_id: &'a str,
    pub(crate) needs_approval: bool,
    /// The invite's minter from the ledger snapshot — `None` once they have been removed.
    pub(crate) minter: Option<&'a str>,
    pub(crate) invite_hash: Option<&'a str>,
    pub(crate) invite_label: Option<&'a str>,
}

/// Which way a landing goes before the database is asked: approval first, and only then a direct
/// attempt. Pure, so the rule "personal never requests" is testable on its own.
#[derive(Debug, PartialEq)]
pub(crate) enum FirstStep {
    Direct,
    Request,
}

pub(crate) fn first_step(class: bool, needs_approval: bool) -> FirstStep {
    if class && needs_approval {
        FirstStep::Request
    } else {
        FirstStep::Direct
    }
}

#[derive(Deserialize)]
struct UserRow {
    #[allow(dead_code)] // read for its presence: RETURNING says the write happened
    user_id: String,
}

/// Land `user_id` per `plan`. Returns the state the verify response reports:
/// `added` | `requested` | `unavailable`.
pub(crate) async fn land(
    db: &D1Database,
    user_id: &str,
    plan: &LandingPlan<'_>,
    now: i64,
) -> Result<&'static str> {
    if first_step(plan.class, plan.needs_approval) == FirstStep::Direct {
        let added: Vec<UserRow> = db
            .prepare(LAND_DIRECT_SQL)
            .bind(&[
                d1_text(plan.room_id),
                d1_text(user_id),
                d1_int(now),
                d1_opt_text(plan.minter),
                d1_int(LANDING_GROUP_CEILING),
            ])?
            .all()
            .await?
            .results()?;
        if !added.is_empty() {
            return Ok("added");
        }
        // Personal: never a request. Class: fall back to the admins' judgement.
        if !plan.class {
            return Ok("unavailable");
        }
    }
    let requested: Vec<UserRow> = db
        .prepare(LAND_REQUEST_SQL)
        .bind(&[
            d1_text(plan.room_id),
            d1_text(user_id),
            d1_opt_text(plan.invite_hash),
            d1_opt_text(plan.invite_label),
            d1_int(now),
        ])?
        .all()
        .await?
        .results()?;
    Ok(if requested.is_empty() {
        "unavailable"
    } else {
        "requested"
    })
}

/// `LOAD_REDEMPTION_SQL`'s row: how this registration's invite treats the joiner.
#[derive(Deserialize)]
pub(crate) struct RedemptionRow {
    pub(crate) introduce: i64,
    pub(crate) kind: String,
    pub(crate) landing_room_id: Option<String>,
    pub(crate) landing_needs_approval: i64,
    pub(crate) source_hash: Option<String>,
    pub(crate) label: Option<String>,
    pub(crate) minter: Option<String>,
}

/// Verify's call: land the new account if its invite named a group, wake whoever has to know, and
/// say what happened in the shape the verify response carries —
/// `{"room_id", "name", "state": "added" | "requested" | "unavailable"}`, or `None` when the invite
/// named no group. Errors are swallowed into `unavailable`: see the module doc.
pub(crate) async fn land_after_verify(
    env: &Env,
    db: &D1Database,
    user_id: &str,
    row: &RedemptionRow,
    now: i64,
) -> Option<serde_json::Value> {
    let room_id = row.landing_room_id.as_deref()?;
    let plan = LandingPlan {
        class: row.kind == "class",
        room_id,
        needs_approval: row.landing_needs_approval == 1,
        minter: row.minter.as_deref(),
        invite_hash: row.source_hash.as_deref(),
        invite_label: row.label.as_deref(),
    };
    let state = match land(db, user_id, &plan, now).await {
        Ok(state) => state,
        Err(error) => {
            console_warn!("landing failed room={room_id} user={user_id}: {error:?}");
            "unavailable"
        }
    };
    if state != "unavailable" {
        crate::groups::nudge_landing(env, db, room_id, user_id, state == "requested").await;
    }
    #[derive(Deserialize)]
    struct NameRow {
        name: String,
    }
    // The group's name is shown to the joiner either way ("you will also join Data Structures"):
    // the invite's minter chose to name it to everyone holding the invite.
    let name = match db
        .prepare("SELECT name FROM groups WHERE id = ? LIMIT 1")
        .bind(&[d1_text(room_id)])
    {
        Ok(stmt) => stmt
            .first::<NameRow>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.name),
        Err(_) => None,
    };
    Some(serde_json::json!({ "room_id": room_id, "name": name, "state": state }))
}

#[cfg(test)]
#[path = "landing_tests.rs"]
mod tests;
