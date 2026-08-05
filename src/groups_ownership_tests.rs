//! Group OWNERSHIP, as tests: who may end up holding a group, and the ordered write that puts
//! them there. Split out of `groups_tests.rs` under the 800-line ceiling, along the same seam the
//! source took — this file is the twin of `groups_transfer.rs`, and `groups_tests.rs` keeps the
//! auth gates, the teardown, the nudges and the read surface.
//!
//! Declared as a child of `groups::tests` rather than a sibling, which is what makes the move free:
//! `SRC`, `TRANSFER_SRC` and `handler_body` stay private to the parent and are visible here anyway,
//! and the shipped SQL `const`s are `pub(in crate::groups)`, which reaches a descendant too.
//!
//! The three transfer statements are `const`s in `groups_transfer.rs`, so rusqlite runs the SQL that
//! actually ships rather than a copy of it (the `membership.rs` pattern). What it cannot reach is
//! the handler around them — every handler there needs D1, a Durable Object and a live worker
//! environment — so the authority gates and the recipient rules are asserted at source level, and
//! the SQL is asserted to be inert on its own when a caller who is not the owner reaches it anyway.

use super::{handler_body, SRC, TRANSFER_SRC};
use crate::groups::transfer::{
    OWNED_GROUP_COUNT_SQL, TRANSFER_CREATED_BY_SQL, TRANSFER_DEMOTE_OWNER_SQL,
    TRANSFER_PROMOTE_TARGET_SQL,
};
use rusqlite::{params, Connection};

/// `groups` + `group_members` as migrations 0006/0008 define them, narrowed to the columns the
/// transfer reads or writes. C owns group `g`, B is an admin, M a member, P a pending invitee.
fn transfer_fixture() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE users(id TEXT PRIMARY KEY);
         CREATE TABLE groups(
           id TEXT PRIMARY KEY, name TEXT NOT NULL,
           created_by TEXT NOT NULL REFERENCES users(id),
           created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
         CREATE TABLE group_members(
           group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
           user_id TEXT NOT NULL REFERENCES users(id),
           role TEXT NOT NULL DEFAULT 'member', joined_at INTEGER NOT NULL,
           status TEXT NOT NULL DEFAULT 'active', added_by TEXT,
           PRIMARY KEY(group_id, user_id));
         INSERT INTO users VALUES('c'),('b'),('m'),('p');
         INSERT INTO groups VALUES('g','G','c',100,100);
         INSERT INTO group_members VALUES
           ('g','c','owner',1,'active',NULL),
           ('g','b','admin',2,'active','c'),
           ('g','m','member',3,'active','c'),
           ('g','p','member',4,'pending','c');",
    )
    .unwrap();
    db
}

fn owner_rows(db: &Connection) -> Vec<String> {
    db.prepare("SELECT user_id FROM group_members WHERE group_id='g' AND role='owner' ORDER BY 1")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn role_of(db: &Connection, user: &str) -> Option<String> {
    db.query_row(
        "SELECT role FROM group_members WHERE group_id='g' AND user_id=?",
        params![user],
        |r| r.get(0),
    )
    .ok()
}

fn created_by(db: &Connection) -> Option<String> {
    db.query_row("SELECT created_by FROM groups WHERE id='g'", [], |r| {
        r.get(0)
    })
    .ok()
}

/// The whole batch, in the order `set_role` issues it.
fn run_transfer(db: &Connection, caller: &str, target: &str) {
    db.execute(TRANSFER_DEMOTE_OWNER_SQL, params!["g", caller])
        .unwrap();
    db.execute(TRANSFER_PROMOTE_TARGET_SQL, params!["g", target, "g"])
        .unwrap();
    db.execute(TRANSFER_CREATED_BY_SQL, params![target, 200, "g", "g", target])
        .unwrap();
}

/// The ordering property, checked BETWEEN the statements and not only at the end: demote first
/// (1 owner → 0), promote second (0 → 1). Two owner rows must never exist at any point — at group
/// scope nothing would stop them being written, since 0018's `idx_one_owner` is a partial UNIQUE
/// index on `users`, i.e. the SERVER role, not on `group_members`.
#[test]
fn the_ordered_transfer_never_yields_two_owners() {
    let db = transfer_fixture();
    assert_eq!(owner_rows(&db), ["c"]);
    db.execute(TRANSFER_DEMOTE_OWNER_SQL, params!["g", "c"])
        .unwrap();
    assert!(owner_rows(&db).is_empty(), "the demote must vacate the seat first");
    db.execute(TRANSFER_PROMOTE_TARGET_SQL, params!["g", "b", "g"])
        .unwrap();
    assert_eq!(owner_rows(&db), ["b"]);
    db.execute(TRANSFER_CREATED_BY_SQL, params!["b", 200, "g", "g", "b"])
        .unwrap();

    assert_eq!(role_of(&db, "c").as_deref(), Some("admin"), "the former owner keeps access");
    assert_eq!(created_by(&db).as_deref(), Some("b"), "created_by follows the owner row");
    assert_eq!(
        db.query_row("SELECT updated_at FROM groups WHERE id='g'", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        200
    );
}

/// Reverse the two statements — the mistake the batch order exists to prevent — and the guard
/// turns it into a NO-OP rather than corruption: the promotion is refused while an owner sits,
/// then the demotion leaves the group with its ORIGINAL owner. A refused transfer, not two owners.
#[test]
fn a_promotion_into_a_group_that_still_has_an_owner_is_a_no_op() {
    let db = transfer_fixture();
    db.execute(TRANSFER_PROMOTE_TARGET_SQL, params!["g", "b", "g"])
        .unwrap();
    assert_eq!(owner_rows(&db), ["c"], "no second owner row may be written");
    assert_eq!(role_of(&db, "b").as_deref(), Some("admin"));

    db.execute(TRANSFER_DEMOTE_OWNER_SQL, params!["g", "c"])
        .unwrap();
    db.execute(TRANSFER_CREATED_BY_SQL, params!["b", 200, "g", "g", "b"])
        .unwrap();
    assert_eq!(
        created_by(&db).as_deref(),
        Some("c"),
        "statement 3 must not move the pointer when the promotion was refused"
    );
}

/// Defence in depth beneath the `owner_required` gate: if a caller who is not the owner ever
/// reached the batch, statement 1 matches no row (`AND role='owner'`), so the sitting owner is
/// still there, so statement 2's NOT EXISTS refuses, so statement 3's EXISTS refuses. Nothing
/// moves. A pending invitee cannot be promoted either — `status='active'` is in the statement as
/// well as in `group_role`.
#[test]
fn the_batch_is_inert_for_a_caller_who_is_not_the_owner() {
    let db = transfer_fixture();
    run_transfer(&db, "b", "m");
    assert_eq!(owner_rows(&db), ["c"]);
    assert_eq!(role_of(&db, "b").as_deref(), Some("admin"));
    assert_eq!(role_of(&db, "m").as_deref(), Some("member"));
    assert_eq!(created_by(&db).as_deref(), Some("c"));

    let db = transfer_fixture();
    run_transfer(&db, "c", "p");
    assert!(owner_rows(&db).is_empty(), "the demote lands; the promote of a pending row must not");
    assert_eq!(role_of(&db, "p").as_deref(), Some("member"));
    assert_eq!(created_by(&db).as_deref(), Some("c"));
}

/// WHY STATEMENT 3 EXISTS, as a test rather than a comment. Account deletion keys its group
/// succession on `groups.created_by`, never on the owner row. With the pointer moved, deleting
/// the FORMER owner's account cannot see this group at all. With the pointer left behind — the
/// version where someone "tidies up" statement 3 — the same deletion promotes an admin while the
/// real owner is still owner, and the group ends up with TWO permanent owner rows.
///
/// The SQL below is a COPY of `membership.rs`'s PROMOTE_GROUP_SUCCESSORS_SQL, which is private to
/// that module. If it drifts, the property asserted here is still the one that matters. (The
/// second hazard named in `set_role`'s comment — `DELETE FROM groups WHERE created_by=?`
/// destroying the group — needs the additional condition that no active member other than the
/// deleted account remains, so it is not reproduced here.)
#[test]
fn a_stale_created_by_lets_account_deletion_mint_a_second_owner() {
    const PROMOTE_GROUP_SUCCESSORS_SQL: &str = "UPDATE group_members AS gm SET role='owner'
      WHERE gm.user_id=(
        SELECT c.user_id FROM group_members c
         WHERE c.group_id=gm.group_id AND c.user_id!=?1 AND c.status='active'
         ORDER BY CASE c.role WHEN 'admin' THEN 0 ELSE 1 END,c.joined_at,c.user_id
         LIMIT 1)
        AND gm.group_id IN (SELECT id FROM groups WHERE created_by=?1)";

    // The real transfer, all three statements: C hands the group to M, and C is demoted to admin.
    let db = transfer_fixture();
    run_transfer(&db, "c", "m");
    db.execute(PROMOTE_GROUP_SUCCESSORS_SQL, params!["c"]).unwrap();
    assert_eq!(
        owner_rows(&db),
        ["m"],
        "with created_by moved, deleting the former owner's account cannot reach this group"
    );

    // The same transfer with statement 3 dropped.
    let db = transfer_fixture();
    db.execute(TRANSFER_DEMOTE_OWNER_SQL, params!["g", "c"])
        .unwrap();
    db.execute(TRANSFER_PROMOTE_TARGET_SQL, params!["g", "m", "g"])
        .unwrap();
    assert_eq!(created_by(&db).as_deref(), Some("c"), "the pointer still names the ex-owner");
    db.execute(PROMOTE_GROUP_SUCCESSORS_SQL, params!["c"]).unwrap();
    assert_eq!(
        owner_rows(&db),
        ["b", "m"],
        "succession ranks 'admin' first and 'owner' in the ELSE bucket, so it promotes B \
         alongside the sitting owner M — two owners, and no handler in groups.rs can undo it"
    );
}

/// The order is the correctness argument, so pin it in the source too: the three statements must
/// be issued through ONE `db.batch` (sequential `.run()`s could strand the group at zero owners,
/// which no endpoint can recover from) and demote must precede promote inside it.
#[test]
fn the_transfer_statements_are_one_ordered_batch() {
    let batch = TRANSFER_SRC
        .find("db.batch(vec![")
        .map(|i| &TRANSFER_SRC[i..])
        .expect("the transfer must go through db.batch — see transfer_group_owner");
    let demote = batch.find("TRANSFER_DEMOTE_OWNER_SQL").expect("no demote statement in the batch");
    let promote =
        batch.find("TRANSFER_PROMOTE_TARGET_SQL").expect("no promote statement in the batch");
    let pointer = batch.find("TRANSFER_CREATED_BY_SQL").expect("no created_by statement in the batch");
    assert!(
        demote < promote && promote < pointer,
        "demote → promote → created_by is the ONLY safe order: promoting first writes a second \
         owner row (nothing at group scope stops it), and moving created_by before the promotion \
         lands would point the account-deletion succession at a group it does not own"
    );
}

/// Both authority gates on the transfer, asserted at source level because the handler cannot run
/// without a worker environment: only the sitting owner may transfer (`owner_required`), and the
/// sitting owner may not transfer to themselves (`already_owner`, the code
/// `admin/handlers.rs::transfer_ownership` uses for the same refusal at server scope).
#[test]
fn the_transfer_is_owner_gated_and_refuses_the_sitting_owner() {
    assert!(
        SRC.contains("owner_required"),
        "set_role dropped its owner gate — any member could hand the group to themselves"
    );
    assert!(
        SRC.contains("already_owner"),
        "set_role must refuse a transfer to the caller: it demotes and re-promotes the same row \
         while presenting itself as a change of ownership"
    );
}

/// The recipient rule. A transfer is the one write here that puts an OBLIGATION on somebody else —
/// after the batch the target is the owner, and `owner_cannot_leave` means the previous owner can
/// walk out a second later — so the target must already be an `admin`. The full argument, and the
/// two shapes rejected (a pending offer the target accepts; nothing at all), are on `transfer_to`.
///
/// A source guard because the check is Rust rather than SQL: every handler here needs D1, a
/// Durable Object and a live worker environment, so there is no level at which it can be run.
#[test]
fn the_group_can_only_be_handed_to_a_member_who_is_already_an_admin() {
    assert!(
        TRANSFER_SRC.contains(r#"target_role != "admin""#),
        "the transfer stopped requiring an admin recipient. Any active member could then be handed \
         a group they never administered and cannot leave, by an owner who leaves immediately \
         after — the bind dc16d837 removed, pointing the other way"
    );
    assert!(
        TRANSFER_SRC.contains("target_not_admin"),
        "the refusal must carry its own code: 'forbidden' does not tell an owner that the fix is \
         to promote the person first"
    );
    assert!(
        handler_body(SRC, "set_role").contains("&target_role"),
        "set_role must pass the target's CURRENT role down to the transfer. Resolving it a second \
         time inside groups_transfer.rs would be another round trip and another chance for the two \
         lookups to disagree across a concurrent role change"
    );
}

fn owned_count(db: &Connection, user: &str) -> i64 {
    db.query_row(OWNED_GROUP_COUNT_SQL, params![user], |r| r.get(0))
        .unwrap()
}

/// The owned-groups cap counts the OWNER ROW, and the third assertion is the one that earns the
/// test: under correct operation `groups.created_by` and the owner row move together — the transfer
/// batch moves both — so counting either would agree, and a test that only transfers cannot tell
/// the two apart. They come apart exactly where it matters. A group whose pointer was left behind
/// is a reachable state (`a_stale_created_by_lets_account_deletion_mint_a_second_owner` builds it
/// from a transfer with statement 3 dropped), and `created_by` records a historical act that would
/// otherwise let an account create up to the cap, hand everything away and start again from zero.
#[test]
fn the_owned_group_count_tracks_the_owner_row_and_not_created_by() {
    let db = transfer_fixture();
    db.execute_batch(
        "INSERT INTO users VALUES('x');
         INSERT INTO groups VALUES('x','X','c',1,1);
         INSERT INTO group_members VALUES('x','c','owner',1,'active',NULL);",
    )
    .unwrap();
    assert_eq!(owned_count(&db, "c"), 2);
    assert_eq!(owned_count(&db, "b"), 0, "an admin row is not an owned group");
    assert_eq!(owned_count(&db, "m"), 0, "nor is a member row");
    assert_eq!(owned_count(&db, "p"), 0, "nor is a pending one");

    run_transfer(&db, "c", "b");
    assert_eq!(owned_count(&db, "c"), 1, "the handed-over group stops counting against the sender");
    assert_eq!(owned_count(&db, "b"), 1, "and starts counting against the recipient");

    // Owner row and pointer disagreeing: B holds the group, C is merely named as its author.
    let db = transfer_fixture();
    db.execute(TRANSFER_DEMOTE_OWNER_SQL, params!["g", "c"]).unwrap();
    db.execute(TRANSFER_PROMOTE_TARGET_SQL, params!["g", "b", "g"]).unwrap();
    assert_eq!(created_by(&db).as_deref(), Some("c"));
    assert_eq!(
        owned_count(&db, "b"),
        1,
        "the cap must charge the group to whoever HOLDS it — counting created_by would let B \
         accumulate groups they own without any of them telling against their ceiling"
    );
    assert_eq!(
        owned_count(&db, "c"),
        0,
        "and must not go on charging a former owner, which is how a cap on a past act would keep \
         someone out of a group slot they no longer occupy"
    );
}

/// The cap has to be read BEFORE the batch, and the tidier-looking alternative is the reason this
/// test exists rather than a comment.
///
/// Second half below: fold the cap into `TRANSFER_PROMOTE_TARGET_SQL` as one more `AND` and the
/// refusal lands AFTER statement 1 has already vacated the owner seat — a committed batch that
/// leaves the group with ZERO owners, which `set_role`, `delete_group` and `update_settings` all
/// need an owner to undo. There is no way back in. (It also refuses silently and still answers 204,
/// so the caller never learns the recipient was full.)
#[test]
fn the_recipient_cap_is_read_before_the_batch_and_never_inside_it() {
    // B already holds two groups elsewhere; the literal 2 stands in for MAX_OWNED_GROUPS.
    let fixture = || {
        let db = transfer_fixture();
        db.execute_batch(
            "INSERT INTO users VALUES('x1'),('x2');
             INSERT INTO groups VALUES('x1','X1','b',1,1),('x2','X2','b',1,1);
             INSERT INTO group_members VALUES
               ('x1','b','owner',1,'active',NULL),('x2','b','owner',1,'active',NULL);",
        )
        .unwrap();
        db
    };

    // The shipped shape: the count is read first, the handler refuses, and nothing runs.
    let db = fixture();
    assert_eq!(
        db.query_row(OWNED_GROUP_COUNT_SQL, params!["b"], |r| r.get::<_, i64>(0))
            .unwrap(),
        2,
        "the pre-check sees the recipient at the ceiling and answers target_too_many_groups"
    );
    assert_eq!(owner_rows(&db), ["c"], "a refused transfer must write nothing at all");

    // The version where the cap is 'tidied' into statement 2.
    const PROMOTE_WITH_CAP_INLINE: &str = "UPDATE group_members SET role = 'owner'
     WHERE group_id = ? AND user_id = ? AND status = 'active'
       AND NOT EXISTS (SELECT 1 FROM group_members o
                        WHERE o.group_id = ? AND o.role = 'owner')
       AND (SELECT COUNT(*) FROM group_members WHERE user_id = ? AND role = 'owner') < 2";
    let db = fixture();
    db.execute(TRANSFER_DEMOTE_OWNER_SQL, params!["g", "c"]).unwrap();
    db.execute(PROMOTE_WITH_CAP_INLINE, params!["g", "b", "g", "b"]).unwrap();
    db.execute(TRANSFER_CREATED_BY_SQL, params!["b", 200, "g", "g", "b"]).unwrap();
    assert!(
        owner_rows(&db).is_empty(),
        "this is the state to avoid: the demote landed, the capped promote refused, and the group \
         now has no owner and no endpoint that can give it one"
    );
    assert_eq!(role_of(&db, "c").as_deref(), Some("admin"));
}

/// The source half of the same property: both recipient checks precede the write, and no COUNT
/// crept into the promote statement.
#[test]
fn the_recipient_checks_precede_the_write_in_transfer_to() {
    let start = TRANSFER_SRC
        .find("pub(super) async fn transfer_to")
        .expect("transfer_to left groups_transfer.rs — re-point this guard");
    let body = &TRANSFER_SRC[start..];
    let body = &body[..body
        .find("\nasync fn transfer_group_owner")
        .unwrap_or(body.len())];
    let admin = body.find("target_not_admin").expect("no admin check in transfer_to");
    let cap = body
        .find("target_too_many_groups")
        .expect("the transfer writes an owner row with no cap check — an account at the ceiling \
                 can push all its groups onto one person, who then cannot create any of their own");
    let write = body
        .find("transfer_group_owner(")
        .expect("transfer_to no longer performs the write — re-point this guard");
    assert!(
        admin < write && cap < write,
        "both recipient checks must run BEFORE the batch: once statement 1 has demoted the sitting \
         owner, a refusal commits a group with zero owners"
    );
    assert!(
        !TRANSFER_PROMOTE_TARGET_SQL.contains("COUNT("),
        "the cap must not be an AND inside the promote statement — see the behavioural half of \
         this property in the test above"
    );
}
