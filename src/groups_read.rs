//! The two READ projections of the group surface — what `GET /groups` and
//! `GET /groups/:id/members` hand back, and what they deliberately do not.
//!
//! Split out of `groups.rs` for size. They belong together because both are pure shaping of rows
//! into JSON with no authority of their own — every gate stays in the handler — and because the
//! two arguments worth keeping about this surface are both about the SHAPE of a response rather
//! than about who may ask for it: how a page admits it is a page, and which columns never leave
//! the server.

use crate::d1util::{d1_int, d1_text};
use serde::Deserialize;
use worker::*;

/// Ceiling on one `GET /groups` page.
///
/// The number is unchanged; what changed is that the response now SAYS when it hit it. Previously
/// this was a bare `LIMIT 200` with no cursor, no total and no flag, and joined groups and pending
/// INVITES share the one query — so past 200 rows a user silently lost the tail, invites included,
/// with no way to detect it. Since any member may create a group and add anyone to it, that was
/// also reachable on purpose: fill a target's list and their real groups fall off the end.
pub(super) const MAX_GROUPS_PAGE: i64 = 200;

/// Ceiling on one member list. A group cannot exceed `MAX_GROUP_MEMBERS` (256) rows, so unlike the
/// page above this limit is unreachable in practice and needs no signal — it is a backstop against
/// a corrupt table, not a paging boundary.
const MAX_MEMBERS_PAGE: i64 = 500;

#[derive(Deserialize)]
struct MyGroupRow {
    id: String,
    name: String,
    role: String,
    member_count: i64,
    created_at: i64,
    visibility: String,
    auto_join: i64,
    settings_json: Option<String>,
    status: String,
    added_by: Option<String>,
}

#[derive(Deserialize)]
struct CountRow {
    c: i64,
}

/// The groups I belong to, plus the invites I have received, with my own role and the ACTIVE
/// member count (a pending invitee is not counted until they accept). The client separates the two
/// kinds by `status`.
///
/// **ORDER: active memberships first, then invites, each by `updated_at DESC`.** The old ordering
/// was `updated_at DESC` across both kinds, which handed anyone a way to evict a target's real
/// groups from the page: a freshly created group carries `updated_at = now`, so a burst of unwanted
/// invites sorts straight to the top and pushes older, joined groups past the limit. Ranking by
/// kind first means an invite can now only ever displace another invite — a flood remains a
/// nuisance, but it can no longer hide a group you are actually in. Within each kind the recency
/// order the client already relies on is unchanged, and `g.id` breaks ties so the ordering is total
/// (two groups can easily share an `updated_at` second).
///
/// **THE SIGNAL IS `total` + `truncated`, NOT A CURSOR**, and that is a judgement call worth
/// stating. A cursor is the better answer in the abstract and it is the answer `contacts/` gives
/// for the directory and the request feed. It is the wrong answer here today for two concrete
/// reasons. First, nothing could consume it: the sole caller is `core`'s
/// `ApiClient::list_groups`, which returns `Vec<GroupRow>` from a single request and has no paging
/// concept, so a `next_cursor` would be server surface that is dead on arrival — and the file that
/// would have to learn to follow it is not in this change. Second, the reusable half of the house
/// cursor pattern (`encode_cursor`/`decode_cursor`/`query_param`) is private to `contacts/mod.rs`;
/// reaching for it would mean either widening that module's visibility or writing a second cursor
/// codec, and "one spelling per thing" is worth more than a page-two nobody requests. `total` and
/// `truncated` cost one extra `COUNT(*)` and make the loss VISIBLE, which is the part that cannot
/// be recovered afterwards. Wiring a real cursor is then a change to the client and this function
/// together, with the flag already in place to prove it is needed.
pub(super) async fn my_groups_page(db: &D1Database, user_id: &str) -> Result<serde_json::Value> {
    let rows: Vec<MyGroupRow> = db
        .prepare(
            "SELECT g.id, g.name, gm.role,
                    (SELECT COUNT(*) FROM group_members x
                       WHERE x.group_id = g.id AND x.status = 'active') AS member_count,
                    g.created_at, g.visibility, g.auto_join, g.settings_json,
                    gm.status, gm.added_by
             FROM groups g
             JOIN group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = ?
             ORDER BY CASE gm.status WHEN 'active' THEN 0 ELSE 1 END,
                      g.updated_at DESC, g.id
             LIMIT ?",
        )
        .bind(&[d1_text(user_id), d1_int(MAX_GROUPS_PAGE)])?
        .all()
        .await?
        .results()?;
    // Counted separately rather than derived from `rows.len()`: a full page is not proof of a
    // truncated one, and the client needs to know HOW MUCH it is missing, not merely that it is.
    let total = db
        .prepare("SELECT COUNT(*) AS c FROM group_members WHERE user_id = ?")
        .bind(&[d1_text(user_id)])?
        .first::<CountRow>(None)
        .await?
        .map(|row| row.c)
        .unwrap_or(rows.len() as i64);
    let groups: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "role": r.role,
                "member_count": r.member_count,
                "created_at": r.created_at,
                "visibility": r.visibility,
                "auto_join": r.auto_join != 0,
                "settings_json": r.settings_json,
                "status": r.status,
                "added_by": r.added_by,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "groups": groups,
        "total": total,
        "truncated": total > groups.len() as i64,
    }))
}

/// One row of `GET /groups/:id/members`.
///
/// **NO `email` COLUMN, and it is not an oversight to be helpfully restored.** This handler used to
/// `SELECT u.email` and return it verbatim to every member of the room, which contradicts the
/// directory design outright: the directory pages never expose an address and hard-code
/// `avatar_ref: null` rather than leak anything extra, so the member list was the one place on the
/// server where knowing a user id got you their e-mail. Nothing wanted it —
/// `core/src/client/api/mod.rs` declares the field `#[serde(default)] Option<String>` and no Rust
/// or Dart code reads it — so the leak bought nothing at all. `display_name` stays: it is the
/// self-chosen label the member list exists to show.
#[derive(Deserialize)]
struct MemberRow {
    user_id: String,
    display_name: Option<String>,
    role: String,
    joined_at: i64,
    status: String,
}

/// Every row of the group, pending invitees included — which is why a change to any row's
/// role or status is a change to what all the OTHER members see, and therefore why the
/// membership handlers nudge the whole room (see `groups_notify.rs`).
pub(super) async fn member_list(db: &D1Database, group_id: &str) -> Result<serde_json::Value> {
    let rows: Vec<MemberRow> = db
        .prepare(
            "SELECT gm.user_id, u.display_name, gm.role, gm.joined_at, gm.status
             FROM group_members gm
             JOIN users u ON u.id = gm.user_id
             WHERE gm.group_id = ?
             ORDER BY gm.joined_at ASC LIMIT ?",
        )
        .bind(&[d1_text(group_id), d1_int(MAX_MEMBERS_PAGE)])?
        .all()
        .await?
        .results()?;
    let members: Vec<_> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "user_id": r.user_id,
                "display_name": r.display_name,
                "role": r.role,
                "joined_at": r.joined_at,
                "status": r.status,
            })
        })
        .collect();
    Ok(serde_json::json!({ "members": members }))
}
