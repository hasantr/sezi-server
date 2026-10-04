//! Live `/group-update` nudges for the group surface — who gets woken, and what bounds it.
//!
//! **The nudge carries no authority.** D1 is the truth; this only wakes a pull. Losing one costs
//! nothing but latency, which is why every send here is best-effort with a `console_warn!` and
//! never touches the handler's response — the write already committed.
//!
//! **THE BUDGET IS THE DESIGN CONSTRAINT, and it has two sides.** Server side: a request gets
//! ~50 subrequests on the Workers free plan and one nudge is one Durable Object call, so
//! `GROUP_NUDGE_LIMIT` is the same 12 `membership.rs` uses and the worst-case handler stays
//! around 20 subrequests all-in. Client side, easy to miss: `handle_refresh_groups` answers a
//! nudge with `GET /groups` **plus one `GET /groups/:id/members` per active group** — an N+1
//! resync. A nudge is cheap to send and expensive to receive.
//!
//! **The rule the handlers apply.** `GET /groups/:id/members` returns every row of the room,
//! pending ones included, so any change to the room's row SET or to a row's role/status changes
//! what every member of that room sees: those handlers nudge the ROOM. On top of that they name
//! the affected party who is not in the room to be found — an invitee with no row yet
//! (`create_group`), a member who has just lost theirs (`remove_member`, `decline_invite`), or
//! everyone at once (`delete_group`, where the query has to run before the batch).
//!
//! Nobody is excluded, the caller included: their originating device does one redundant resync,
//! and in exchange their OTHER devices converge immediately.

use crate::d1util::{d1_int, d1_text};
use serde::Deserialize;
use worker::*;

/// Ceiling on Durable Object calls per handler. Deliberately the same 12 as
/// `membership.rs::GROUP_NUDGE_LIMIT` — two fan-outs converging on different numbers would mean
/// one was picked without reference to the subrequest ceiling.
///
/// Members past the limit are late, not abandoned: every device re-pulls the authoritative
/// snapshot on boot, on reconnect and on the next nudge that does reach it. With
/// `MAX_GROUP_MEMBERS` at 256, a large room converges mostly that way.
pub(super) const GROUP_NUDGE_LIMIT: usize = 12;

/// Deterministic so that a repeated operation wakes the same subset rather than a random one — the
/// ordering `membership.rs` uses for the same reason. Pending rows are included: an invitee's
/// `GET /groups` shows the group, so their view changes with the room's.
const ROOM_RECIPIENTS_SQL: &str =
    "SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id LIMIT ?";

#[derive(Deserialize)]
struct RecipientRow {
    user_id: String,
}

/// Up to `GROUP_NUDGE_LIMIT` members of the room, in id order. Exposed on its own because
/// `delete_group` has to take the snapshot BEFORE its batch — afterwards there is no row left to
/// ask — while every other caller reads it after the write and wants the state that resulted.
///
/// An unreadable list degrades to an empty one rather than failing the handler: the write it
/// follows has already committed, and a missing nudge is a slow client, not a wrong one.
pub(super) async fn room_recipients(db: &D1Database, group_id: &str) -> Vec<String> {
    let rows: Vec<RecipientRow> = match db
        .prepare(ROOM_RECIPIENTS_SQL)
        .bind(&[d1_text(group_id), d1_int(GROUP_NUDGE_LIMIT as i64)])
    {
        Ok(stmt) => match stmt.all().await.and_then(|result| result.results()) {
            Ok(rows) => rows,
            Err(error) => {
                console_warn!("group nudge lookup skipped group={group_id}: {error:?}");
                Vec::new()
            }
        },
        Err(error) => {
            console_warn!("group nudge bind skipped group={group_id}: {error:?}");
            Vec::new()
        }
    };
    rows.into_iter().map(|row| row.user_id).collect()
}

/// Everyone holding a `group_members` row for `group_id`, plus `also` — the parties the table can
/// no longer name (a member deleted a moment ago, an invitee whose row does not exist yet).
///
/// `also` goes FIRST and is therefore never the entry the limit drops. That ordering is the point:
/// on `remove_member` in a full room, truncating the other way would silently skip the one person
/// whose membership actually ended.
pub(super) async fn nudge_room(env: &Env, db: &D1Database, group_id: &str, also: &[&str]) {
    let mut ids: Vec<String> = also.iter().map(|id| (*id).to_string()).collect();
    ids.extend(room_recipients(db, group_id).await);
    nudge_users(env, group_id, ids).await;
}

/// Nudge an explicit list — used where the recipients are already in hand and a query would be a
/// wasted subrequest: `create_group` knows its invitees, and `delete_group` took its snapshot
/// before the batch.
///
/// Deduplicated, because the callers legitimately overlap (the removed member is also in the room
/// snapshot on a self-leave), and truncated to `GROUP_NUDGE_LIMIT`. A failed send still counts
/// against the budget: the subrequest was spent whether or not the DO answered.
pub(super) async fn nudge_users(env: &Env, group_id: &str, user_ids: Vec<String>) {
    let mut sent: Vec<String> = Vec::with_capacity(GROUP_NUDGE_LIMIT);
    for id in user_ids {
        if sent.len() >= GROUP_NUDGE_LIMIT {
            break;
        }
        if id.is_empty() || sent.contains(&id) {
            continue;
        }
        if let Err(error) = crate::realtime::nudge_group_update(env, &id).await {
            console_warn!("group_update nudge failed group={group_id} user={id}: {error:?}");
        }
        sent.push(id);
    }
}
