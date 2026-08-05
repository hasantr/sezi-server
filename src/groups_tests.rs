//! Guards the group surface against re-opening the device-revocation hole.
//!
//! This is the same shape as `admin/mod.rs`'s `auth_gate_guard`, and for the same reason: the bug
//! was never inside a function's logic, it was in WHICH middleware each handler happened to call,
//! and no behavioural test over one endpoint can see that the endpoint next to it chose
//! differently. The admin guard cannot be extended to cover this file — it enumerates
//! `admin/*.rs` — so the group surface carries its own. `devices/link_tests.rs` is the device-link
//! half of the same idea.
//!
//! A source-level assertion is also the only kind available here: every handler needs D1, a
//! Durable Object and a live worker environment.
//!
//! Not everything here is source-level, though: the teardown SQL is held in `const`s, so rusqlite
//! can run the statements that actually ship against an in-memory twin of the schema. That is the
//! `membership.rs` pattern, and it is what lets a property be checked BETWEEN two statements of a
//! batch rather than only at the end.
//!
//! The OWNERSHIP half — the transfer batch, the recipient rules, the owned-groups cap — is the
//! child module `ownership` (`groups_ownership_tests.rs`), split off under the 800-line ceiling.

/// `include_str!` binds at compile time and resolves relative to THIS file, so `groups.rs` must
/// sit beside it; renaming or moving either one breaks the build instead of silently emptying the
/// guard (the trick `auth/relogin.rs` uses on itself).
const SRC: &str = include_str!("groups.rs");
/// The transfer write lives in its own file, so the guard over its statement ORDER has to read
/// that file rather than `SRC`. Splitting the code and leaving the guard pointed at the old
/// location is how a source-level assertion turns into a test that passes by looking at nothing.
const TRANSFER_SRC: &str = include_str!("groups_transfer.rs");
/// Same reasoning, three more lifted blocks: the teardown batch, the live nudges and the two read
/// projections. Every source guard below must name the file the code actually lives in.
const DELETE_SRC: &str = include_str!("groups_delete.rs");
const NOTIFY_SRC: &str = include_str!("groups_notify.rs");
const READ_SRC: &str = include_str!("groups_read.rs");

/// One handler's source, from its `pub async fn` line to the next one. Several guards below are
/// about what a SPECIFIC handler does rather than what the file contains somewhere, and "the file
/// mentions it once" is exactly the assertion that keeps passing after the call is deleted from
/// the handler that needed it.
fn handler_body<'a>(src: &'a str, name: &str) -> &'a str {
    let needle = format!("\npub async fn {name}(");
    let start = src
        .find(&needle)
        .unwrap_or_else(|| panic!("no handler named {name} in groups.rs — re-point this guard"));
    let rest = &src[start + 1..];
    let end = rest.find("\npub async fn ").unwrap_or(rest.len());
    &rest[..end]
}

/// Every `pub async fn` in `groups.rs` is a route handler — `group_role` and `membership_status`
/// are `pub(crate)`/private and do not match — so the handler count and the gate count must be
/// equal. Counting rather than listing means a NEW handler is covered the day it is added, which
/// is exactly when this is easiest to forget.
#[test]
fn every_group_handler_gates_on_the_revocation_aware_check() {
    let handlers = SRC.matches("\npub async fn ").count();
    // Both needles below may be written WHOLE, and that is a consequence of the split: while this
    // guard lived at the bottom of `groups.rs`, `include_str!` pulled its own source in and a
    // needle spelled out here matched itself, so each one had to be assembled from `concat!`
    // fragments. `SRC` is now a file that does not contain this test, so the hazard is gone. Move
    // this module back inline and both assertions fail loudly rather than quietly.
    let gated = SRC.matches("require_live_device_auth(&req").count();
    assert_eq!(
        handlers, gated,
        "{handlers} route handlers but only {gated} calls to require_live_device_auth. Every \
         handler on the group surface must go through it: a revoked device's access token \
         stays valid for ~15 minutes and would keep DELETE /groups/:id, remove-member and \
         set-role working the whole time."
    );
    assert!(handlers >= 10, "the handler count collapsed to {handlers} — re-point this guard");
}

/// The negative half: nothing in `groups.rs` may fall back to the bare stateless JWT gate, which
/// verifies a signature and an expiry and nothing else.
#[test]
fn no_group_handler_gates_on_the_stateless_jwt_alone() {
    assert!(
        !SRC.contains("require_auth("),
        "a group handler reached for require_auth again — it proves neither that the account \
         still exists nor that the calling device is unrevoked"
    );
}

/// The creation route must NOT gate on the server-owner role. Group creation was owner-only
/// between 2026-07-03 and 2026-08-05, and the combination of that gate with `owner_cannot_leave`
/// made whoever administers the server a permanent member of every group on it. `owner` is a
/// SERVER-administration role and grants nothing inside a group; reading a group's messages must
/// require being in that group. Written as a source guard for the same reason as the two above —
/// the property is about which middleware a handler calls, and re-adding the gate is a one-line
/// edit that no behavioural test in this repo would notice.
#[test]
fn create_group_does_not_gate_on_the_server_owner_role() {
    assert!(
        !SRC.contains("require_owner"),
        "groups.rs reached for require_owner again. The server owner role is server \
         ADMINISTRATION only (invites, settings, storage, admin endpoints) and must carry no \
         in-group privilege — an owner-only create_group puts the server operator inside every \
         group, which is exactly what removing that gate was for. Bound creation with \
         MAX_OWNED_GROUPS and the rate limit, not with a role."
    );
}

/// The ownership half — the transfer batch, the recipient rules and the owned-groups cap — lifted
/// out under the 800-line ceiling, along the same seam the source took. A CHILD module rather than
/// a sibling, which is what makes the move free: `SRC`, `TRANSFER_SRC` and `handler_body` stay
/// private up here and are visible down there anyway.
#[cfg(test)]
#[path = "groups_ownership_tests.rs"]
mod ownership;

// ── Teardown (DELETE /groups/:id) ────────────────────────────────────────────────────────────
//
// The leak this closes was invisible from inside the handler: it deleted exactly the two tables it
// named and nothing complained, because nothing else has a foreign key onto `groups`. So the test
// has to be about the tables the handler did NOT name.

use super::delete::{ORPHAN_PLUGIN_CODE_SQL, ORPHAN_PLUGIN_MEDIA_SQL};
use rusqlite::{params, Connection};

/// The room-scoped tables as migrations 0019/0026/0028 define them, narrowed to the columns the
/// teardown touches. Room `g` is deleted, room `keep` is not; uploader `c` has blobs in both, which
/// is the case that turns a too-wide `WHERE` into someone else's data.
fn teardown_fixture() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE groups(id TEXT PRIMARY KEY, name TEXT NOT NULL,
           created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
         CREATE TABLE group_members(
           group_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL,
           joined_at INTEGER NOT NULL, status TEXT NOT NULL, added_by TEXT,
           PRIMARY KEY(group_id, user_id));
         CREATE TABLE plugin_media_objects(
           room_id TEXT NOT NULL, blob_id TEXT NOT NULL, uploader_id TEXT NOT NULL,
           size_bytes INTEGER NOT NULL, store_id TEXT NOT NULL DEFAULT 'r2-primary',
           created_at INTEGER NOT NULL, PRIMARY KEY(room_id, blob_id));
         CREATE TABLE plugin_code_objects(
           room_id TEXT NOT NULL, blob_id TEXT NOT NULL, uploader_id TEXT NOT NULL,
           size_bytes INTEGER NOT NULL, store_id TEXT NOT NULL DEFAULT 'r2-primary',
           created_at INTEGER NOT NULL, PRIMARY KEY(room_id, blob_id));
         CREATE TABLE plugin_epoch_floor(room_id TEXT PRIMARY KEY, floor INTEGER NOT NULL);
         CREATE TABLE storage_orphans(
           store_id TEXT NOT NULL, key TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0,
           created_at INTEGER NOT NULL, retry_count INTEGER NOT NULL DEFAULT 0,
           PRIMARY KEY(store_id, key));
         INSERT INTO groups VALUES('g','G','c',100,100),('keep','K','c',100,100);
         INSERT INTO group_members VALUES
           ('g','c','owner',1,'active',NULL),
           ('g','m','member',2,'active','c'),
           ('keep','c','owner',1,'active',NULL);
         INSERT INTO plugin_media_objects VALUES
           ('g','blob1','c',700,'r2-primary',1),
           ('g','blob2','m',300,'r2-primary',1),
           ('keep','blob3','c',50,'r2-primary',1);
         INSERT INTO plugin_code_objects VALUES
           ('g','code1','c',20,'r2-primary',1),
           ('keep','code2','c',5,'r2-primary',1);
         INSERT INTO plugin_epoch_floor VALUES('g',3),('keep',1);",
    )
    .unwrap();
    db
}

/// The batch as `delete_group_rows` issues it. The two orphan statements are the shipped `const`s;
/// the five DELETEs are copies, because they are inline in the batch — the property that they run
/// AFTER the orphans is pinned separately by the source guard below.
fn run_teardown(db: &Connection, room: &str, now: i64) {
    db.execute(ORPHAN_PLUGIN_MEDIA_SQL, params![now, room]).unwrap();
    db.execute(ORPHAN_PLUGIN_CODE_SQL, params![now, room]).unwrap();
    for sql in [
        "DELETE FROM plugin_media_objects WHERE room_id = ?",
        "DELETE FROM plugin_code_objects WHERE room_id = ?",
        "DELETE FROM group_members WHERE group_id = ?",
        "DELETE FROM plugin_epoch_floor WHERE room_id = ?",
    ] {
        db.execute(sql, params![room]).unwrap();
    }
    db.execute("DELETE FROM groups WHERE id = ?", params![room]).unwrap();
}

fn orphan_keys(db: &Connection) -> Vec<String> {
    db.prepare("SELECT key FROM storage_orphans ORDER BY 1")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

/// The whole of bug #1 in one assertion: every blob the room held is queued for deletion, the
/// metadata that charged it to somebody is gone, the epoch floor does not outlive its room, and the
/// room next door is untouched.
///
/// `quota` is the part that made this permanent rather than merely untidy — `usage.rs` derives
/// `user_storage` by summing `plugin_media_objects.size_bytes` per uploader, so while those rows
/// survived, a deleted group kept eating its uploader's allowance with nothing left in existence
/// that could ever release it.
#[test]
fn deleting_a_group_orphans_its_blobs_and_releases_the_quota() {
    let db = teardown_fixture();
    let quota = |db: &Connection, user: &str| -> i64 {
        db.query_row(
            "SELECT COALESCE(SUM(size_bytes),0) FROM plugin_media_objects WHERE uploader_id=?",
            params![user],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(quota(&db, "c"), 750);

    run_teardown(&db, "g", 500);

    assert_eq!(
        orphan_keys(&db),
        ["plugin-code/g/code1", "plugin-media/g/blob1", "plugin-media/g/blob2"],
        "every blob of the deleted room must be queued, code channel included, under the exact \
         key scheme storage::{{plugin_media_key, plugin_code_key}} writes"
    );
    assert_eq!(quota(&db, "c"), 50, "the deleted room must stop charging its uploader");
    assert_eq!(quota(&db, "m"), 0);
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM plugin_epoch_floor WHERE room_id='g'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0,
        "the floor row cannot outlive its room — no future append can ever name a v4 UUID again"
    );
    // The neighbouring room, which shares an uploader with the deleted one.
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM plugin_media_objects", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT floor FROM plugin_epoch_floor WHERE room_id='keep'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    // The size travels with the key: `retry_orphans` bills the store by it.
    assert_eq!(
        db.query_row(
            "SELECT size_bytes FROM storage_orphans WHERE key='plugin-media/g/blob1'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        700
    );
}

/// `storage_orphans` is keyed `(store_id, key)` and the inserts are `OR IGNORE`, so a retried
/// teardown — the same room deleted twice, or a batch replayed — cannot multiply the outbox.
#[test]
fn orphaning_the_same_room_twice_writes_one_row_per_blob() {
    let db = teardown_fixture();
    for _ in 0..2 {
        db.execute(ORPHAN_PLUGIN_MEDIA_SQL, params![500, "g"]).unwrap();
        db.execute(ORPHAN_PLUGIN_CODE_SQL, params![600, "g"]).unwrap();
    }
    assert_eq!(orphan_keys(&db).len(), 3);
}

/// The ordering argument, pinned in the source: one batch, and the blobs are queued BEFORE the
/// rows that name them are dropped.
///
/// Splitting the two halves across transactions is the failure worth naming — `storage_orphans`
/// rows committed while the metadata survives point the daily `retry_orphans` pass at blobs a LIVE
/// group is still using, which is data loss in the opposite direction from the leak being fixed.
#[test]
fn the_teardown_orphans_before_it_deletes_inside_one_batch() {
    let batch = DELETE_SRC
        .find("db.batch(vec![")
        .map(|i| &DELETE_SRC[i..])
        .expect("the teardown must go through db.batch — see delete_group_rows");
    for (orphan, drop) in [
        ("ORPHAN_PLUGIN_MEDIA_SQL", "DELETE FROM plugin_media_objects"),
        ("ORPHAN_PLUGIN_CODE_SQL", "DELETE FROM plugin_code_objects"),
    ] {
        let queued = batch.find(orphan).unwrap_or_else(|| panic!("{orphan} left the batch"));
        let dropped = batch.find(drop).unwrap_or_else(|| panic!("`{drop}` left the batch"));
        assert!(
            queued < dropped,
            "{orphan} must run before `{drop}`: the orphan statement SELECTs the very rows the \
             delete removes, so reversing them queues nothing and leaks every blob silently"
        );
    }
    for required in [
        "DELETE FROM group_members",
        "DELETE FROM groups WHERE id",
        "DELETE FROM plugin_epoch_floor",
    ] {
        assert!(batch.contains(required), "the teardown batch lost `{required}`");
    }
    assert!(
        !handler_body(SRC, "delete_group").contains("db.prepare"),
        "delete_group must issue no statement of its own — the teardown is one batch in \
         groups_delete.rs, and a stray sequential DELETE beside it reopens the half-deleted \
         group (members erased, group row surviving, nobody left who may delete it)"
    );
}

// ── Live nudges ──────────────────────────────────────────────────────────────────────────────

/// Every handler that changes what a member sees must wake the affected devices, and this is a
/// per-handler guard rather than a file-wide one on purpose: `nudge_group_update` and its client
/// half both already existed and were wired end to end, and the bug was simply that no group
/// handler called them. A guard that only asks "does the file mention it" would have been
/// satisfied by one call in one handler.
#[test]
fn every_membership_changing_handler_nudges_the_affected_devices() {
    for name in [
        "create_group",
        "add_member",
        "accept_invite",
        "decline_invite",
        "remove_member",
        "set_role",
        "update_settings",
        "delete_group",
    ] {
        assert!(
            handler_body(SRC, name).contains("notify::"),
            "{name} changes what a member's client would display but tells no live device about \
             it — the change then surfaces only at the next boot or reconnect, which is how an \
             invited user simply did not see the invite"
        );
    }
    // set_role has two exits (the plain UPDATE and the transfer's early return) and each needs its
    // own nudge; one call would leave whichever branch returns first silent. The transfer exit now
    // delegates to `groups_transfer.rs`, so the second half of the property is asserted THERE —
    // left counting two here it would have failed on a pure move, and simply relaxed to one it
    // would stop noticing if the transfer's nudge went missing.
    assert_eq!(
        handler_body(SRC, "set_role").matches("notify::").count(),
        1,
        "the plain role UPDATE in set_role must nudge the room"
    );
    assert!(
        TRANSFER_SRC.contains("notify::nudge_room"),
        "the transfer exit tells no live device that ownership moved. Two people's own \
         `GET /groups` row carries gm.role and both would keep showing the old one — including \
         the new owner, who would not know the group was theirs"
    );
    for name in ["list_my_groups", "group_members"] {
        assert!(
            !handler_body(SRC, name).contains("notify::"),
            "{name} is a read; nudging from it would let any client trigger a fan-out by polling"
        );
    }
}

/// The fan-out is bounded, and by the same number as the other one. Two group fan-outs in one
/// worker converging on different limits would mean at least one was picked without reference to
/// the Workers subrequest ceiling — the ceiling that produced the 2026-07-06 incident recorded in
/// `self_provision.rs`.
#[test]
fn the_group_nudge_fan_out_is_capped_at_the_house_limit() {
    assert_eq!(
        super::notify::GROUP_NUDGE_LIMIT,
        12,
        "membership.rs caps its group fan-out at 12 because a Workers request may make only ~50 \
         subrequests; a second, larger limit here spends a budget it does not own"
    );
    assert!(
        NOTIFY_SRC.contains("if sent.len() >= GROUP_NUDGE_LIMIT"),
        "the limit must be enforced in the send loop, not merely declared — and it is the SEND \
         count that must be capped, since a failed Durable Object call has already cost the \
         subrequest"
    );
    assert!(
        NOTIFY_SRC.contains("LIMIT ?"),
        "the recipient query must carry the limit too: reading 256 rows to send 12 is a wasted \
         D1 payload on every membership change in a large room"
    );
}

// ── What the read surface returns ────────────────────────────────────────────────────────────

/// No e-mail address may leave through the member list. The slice starts at the row struct so that
/// the doc comment above it — which has to keep saying what was removed, or the next person adds
/// the column back as a helpful improvement — is not itself the thing being searched.
#[test]
fn the_member_list_never_returns_an_email_address() {
    let projection = READ_SRC
        .find("struct MemberRow {")
        .map(|i| &READ_SRC[i..])
        .expect("MemberRow left groups_read.rs — re-point this guard");
    assert!(
        !projection.contains("email"),
        "the member list selected u.email and returned it verbatim to every member of the room. \
         The directory pages expose no address and hard-code avatar_ref: null rather than leak \
         anything extra; this was the one place a user id bought you someone's e-mail, and \
         nothing ever read the field"
    );
    assert!(!SRC.contains("email"), "no group handler may reach for an e-mail column either");
}

/// A page that hits its limit has to say so. Silently dropping the tail is what let a stranger
/// hide a target's groups by filling the list with invites — and pending invites are IN this same
/// query, so the tail that vanishes can be an invitation.
#[test]
fn the_group_list_admits_when_it_truncated() {
    assert!(
        READ_SRC.contains("\"truncated\":") && READ_SRC.contains("\"total\":"),
        "GET /groups must report both whether it truncated and how many rows exist — a bare \
         LIMIT with neither is undetectable from the client"
    );
    let page = READ_SRC
        .find("pub(super) async fn my_groups_page")
        .map(|i| &READ_SRC[i..])
        .expect("my_groups_page left groups_read.rs — re-point this guard");
    let order = page
        .find("ORDER BY")
        .map(|i| &page[i..])
        .expect("the page lost its ORDER BY");
    assert!(
        order.starts_with("ORDER BY CASE gm.status WHEN 'active' THEN 0 ELSE 1 END"),
        "active memberships must sort ahead of invites. A new group carries updated_at = now, so \
         under a plain recency order a burst of unwanted invites sorts to the top and pushes the \
         groups a user is actually IN off the end of the page"
    );
}

/// The opaque settings bag is capped on BOTH write paths. Capping only creation would leave the
/// unbounded write reachable one request later through the endpoint that is easier to reach — any
/// admin rather than only the creator, and as often as they like.
#[test]
fn the_settings_bag_is_capped_wherever_it_is_written() {
    for name in ["create_group", "update_settings"] {
        assert!(
            handler_body(SRC, name).contains("MAX_SETTINGS_JSON_BYTES"),
            "{name} writes settings_json without a size check. The column is opaque TEXT the \
             server never interprets and hands back to every member on every GET /groups, so \
             unbounded it is both a D1 filler and a response amplifier"
        );
    }
}
