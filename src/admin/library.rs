//! `GET /admin/library` — what the group LIBRARY costs, per group (campus plan R1: "the operator
//! sees sizes, never content").
//!
//! Admin or owner (`require_admin`), like the rest of the read-only admin surface
//! (`/admin/stats`, `GET /admin/storage`). Per group: its id, its name, how many active members
//! it has, the bytes and part count its library holds, and when the oldest and the newest part
//! arrived — `newest_at` IS the last upload. That is metadata the server keeps anyway. What is
//! NOT here, because the server does not have it: titles, lengths, who recorded or who appears.
//! The record naming a recording's parts travels end to end inside the group.
//!
//! Largest library first, because the question this answers is "where did the space go".
//! Paged by an opaque cursor over (bytes, room id) — a university has hundreds of courses.
//!
//! ```text
//! GET /admin/library?limit=50&cursor=<next>
//! 200 {
//!   "groups": [{ "room_id", "name", "members", "bytes", "objects", "oldest_at", "newest_at" }],
//!   "next": "<cursor>" | null,
//!   "totals": { "bytes", "objects", "groups" },
//!   "max_room_bytes": <per-group cap> | null,
//!   "retention_days": <library retention> | null,
//!   "stores": [{ "store_id", "label", "kind", "state", "library_pin", "healthy" | null,
//!                "used_bytes", "max_bytes" | null, "free_bytes" | null, "library_bytes" }]
//! }
//! ```
//!
//! `name` is null for a room whose group is gone — which the teardowns are built to make
//! impossible, so a null here is worth looking into rather than hiding.
//!
//! **`stores` answers "where is it, and how much room is left"** (board R4-Operator-Library,
//! "NEREDE" and the per-store free space), first page only. `used_bytes` is the server's own count
//! of what it put there, `library_bytes` the library's share of it. `free_bytes` is
//! `max_bytes - used_bytes` — the room under the cap the OWNER configured — and null when no cap is
//! set: neither R2 nor the S3 API reports a bucket's free space, and a self-hosted relay's local
//! store is reached through wrangler, not a filesystem the worker can `statvfs`. So "free" here is
//! never a measurement of the disk; the client words it as room under the configured limit.
//! `healthy` is the last probe's verdict, null when never probed. Shorten-retention lives in
//! `library_retention.rs`.

use serde::{Deserialize, Serialize};
use worker::*;

use crate::auth::middleware::{require_active_auth, require_admin};
use crate::d1util::{d1_int, d1_null, d1_text};
use crate::respond::json_err;
use crate::utils::{b64u_decode, b64u_encode};

const PAGE_DEFAULT: i64 = 50;
const PAGE_MAX: i64 = 200;

/// One page of groups, largest library first, ties by room id. Binds (numbered): cursor bytes
/// (NULL on the first page), cursor room id, limit. The HAVING clause is the keyset: strictly
/// after (bytes, room) in the ORDER BY's own order.
pub(crate) const USAGE_PAGE_SQL: &str = "SELECT l.room_id AS room_id, g.name AS name, \
       (SELECT COUNT(*) FROM group_members gm \
         WHERE gm.group_id = l.room_id AND gm.status = 'active') AS members, \
       SUM(l.size_bytes) AS bytes, COUNT(*) AS objects, \
       MIN(l.created_at) AS oldest_at, MAX(l.created_at) AS newest_at \
     FROM room_library_objects l LEFT JOIN groups g ON g.id = l.room_id \
     GROUP BY l.room_id \
     HAVING ?1 IS NULL OR SUM(l.size_bytes) < ?1 \
         OR (SUM(l.size_bytes) = ?1 AND l.room_id > ?2) \
     ORDER BY bytes DESC, l.room_id ASC \
     LIMIT ?3";

/// The whole library at a glance, beside the two settings that govern it. No binds.
pub(crate) const USAGE_TOTALS_SQL: &str = "SELECT \
       COALESCE((SELECT SUM(size_bytes) FROM room_library_objects), 0) AS bytes, \
       (SELECT COUNT(*) FROM room_library_objects) AS objects, \
       (SELECT COUNT(DISTINCT room_id) FROM room_library_objects) AS groups, \
       (SELECT max_room_library_bytes FROM server_settings WHERE id = 1) AS max_room_bytes, \
       (SELECT library_retention_days FROM server_settings WHERE id = 1) AS retention_days";

/// The keyset position after a page: the last group's bytes and room id.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct Cursor {
    b: i64,
    r: String,
}

/// Opaque on the wire — base64url of a tiny JSON — so the shape can change without a client
/// noticing.
pub(crate) fn encode_cursor(bytes: i64, room_id: &str) -> String {
    let json = serde_json::to_vec(&Cursor { b: bytes, r: room_id.to_string() })
        .unwrap_or_default();
    b64u_encode(&json)
}

/// `None` for anything that is not a cursor this endpoint issued — the caller answers 400
/// rather than silently restarting from the first page.
pub(crate) fn decode_cursor(raw: &str) -> Option<Cursor> {
    if raw.len() > 512 {
        return None;
    }
    serde_json::from_slice(&b64u_decode(raw).ok()?).ok()
}

fn page_limit(raw: Option<&str>) -> i64 {
    raw.and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(PAGE_DEFAULT)
        .clamp(1, PAGE_MAX)
}

fn query(req: &Request, name: &str) -> Option<String> {
    req.url()
        .ok()?
        .query_pairs()
        .find_map(|(k, v)| (k == name).then(|| v.into_owned()))
}

/// Every store with what the server counts on it and the library's share. No binds. (Above
/// `usage` on purpose: the guard at the bottom reads the handler's body for part metadata, and a
/// store's backend `kind` is not that.)
pub(crate) const STORES_SQL: &str = "SELECT b.store_id AS store_id, b.label AS label, \
       b.kind AS kind, b.state AS state, b.library_pin AS library_pin, \
       b.last_health_ok AS last_health_ok, b.used_bytes AS used_bytes, b.max_bytes AS max_bytes, \
       (SELECT COALESCE(SUM(l.size_bytes), 0) FROM room_library_objects l \
         WHERE l.store_id = b.store_id) AS library_bytes \
     FROM storage_backends b ORDER BY b.priority ASC, b.store_id ASC";

/// Room left under a store's configured cap; `None` without a cap (see the module doc: no backend
/// here can report its real free space). Never negative — a store over its cap has none left.
pub(crate) fn free_bytes(max_bytes: Option<i64>, used_bytes: i64) -> Option<i64> {
    max_bytes.map(|m| (m - used_bytes).max(0))
}

async fn stores(db: &D1Database) -> Result<Vec<serde_json::Value>> {
    #[derive(Deserialize)]
    struct StoreRow {
        store_id: String,
        label: String,
        kind: String,
        state: String,
        library_pin: i64,
        last_health_ok: Option<i64>,
        used_bytes: i64,
        max_bytes: Option<i64>,
        library_bytes: i64,
    }
    let rows: Vec<StoreRow> = db.prepare(STORES_SQL).all().await?.results()?;
    Ok(rows
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "store_id": s.store_id,
                "label": s.label,
                "kind": s.kind,
                "state": s.state,
                "library_pin": s.library_pin != 0,
                "healthy": s.last_health_ok.map(|v| v != 0),
                "used_bytes": s.used_bytes,
                "max_bytes": s.max_bytes,
                "free_bytes": free_bytes(s.max_bytes, s.used_bytes),
                "library_bytes": s.library_bytes,
            })
        })
        .collect())
}

pub async fn usage(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let cursor = match query(&req, "cursor").filter(|c| !c.is_empty()) {
        None => None,
        Some(raw) => match decode_cursor(&raw) {
            Some(c) => Some(c),
            None => return json_err(400, "bad_cursor"),
        },
    };
    let limit = page_limit(query(&req, "limit").as_deref());
    let db = ctx.env.d1("DB")?;

    #[derive(Deserialize)]
    struct GroupRow {
        room_id: String,
        name: Option<String>,
        members: i64,
        bytes: i64,
        objects: i64,
        oldest_at: i64,
        newest_at: i64,
    }
    let (after_bytes, after_room) = match &cursor {
        Some(c) => (d1_int(c.b), d1_text(&c.r)),
        None => (d1_null(), d1_text("")),
    };
    // One row past the page says whether another exists, without a COUNT over the groups.
    let mut rows: Vec<GroupRow> = db
        .prepare(USAGE_PAGE_SQL)
        .bind(&[after_bytes, after_room, d1_int(limit + 1)])?
        .all()
        .await?
        .results()?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().map(|r| encode_cursor(r.bytes, &r.room_id))
    } else {
        None
    };

    #[derive(Deserialize)]
    struct Totals {
        bytes: i64,
        objects: i64,
        groups: i64,
        max_room_bytes: Option<i64>,
        retention_days: Option<i64>,
    }
    let totals: Option<Totals> = db.prepare(USAGE_TOTALS_SQL).first(None).await?;
    let groups: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "room_id": r.room_id,
                "name": r.name,
                "members": r.members,
                "bytes": r.bytes,
                "objects": r.objects,
                "oldest_at": r.oldest_at,
                "newest_at": r.newest_at,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({
        "groups": groups,
        "next": next,
        "totals": {
            "bytes": totals.as_ref().map(|t| t.bytes).unwrap_or(0),
            "objects": totals.as_ref().map(|t| t.objects).unwrap_or(0),
            "groups": totals.as_ref().map(|t| t.groups).unwrap_or(0),
        },
        "max_room_bytes": totals.as_ref().and_then(|t| t.max_room_bytes),
        "retention_days": totals.and_then(|t| t.retention_days),
        "stores": if cursor.is_none() { stores(&db).await? } else { Vec::new() },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    #[test]
    fn a_cursor_round_trips_and_rubbish_is_refused() {
        let c = encode_cursor(123_456, "6f1c1f0e-8a3b-4c5d-9e7f-0123456789ab");
        assert_eq!(
            decode_cursor(&c),
            Some(Cursor { b: 123_456, r: "6f1c1f0e-8a3b-4c5d-9e7f-0123456789ab".into() })
        );
        assert_eq!(decode_cursor("not a cursor"), None);
        assert_eq!(decode_cursor(&b64u_encode(b"{\"x\":1}")), None);
        assert_eq!(decode_cursor(&"A".repeat(600)), None);
    }

    #[test]
    fn the_page_size_is_clamped() {
        assert_eq!(page_limit(None), 50);
        assert_eq!(page_limit(Some("0")), 1);
        assert_eq!(page_limit(Some("9999")), 200);
        assert_eq!(page_limit(Some("x")), 50);
    }

    /// Three courses and one room whose group is gone, against the real schema.
    fn db() -> Connection {
        let db = crate::test_schema::full_schema();
        db.execute_batch(
            "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES
               ('t', 't@example.test', x'00', 1), ('s1', 's1@example.test', x'00', 1),
               ('s2', 's2@example.test', x'00', 1);
             INSERT INTO groups (id, name, created_by, created_at, updated_at) VALUES
               ('g-phys', 'Physics', 't', 1, 1), ('g-chem', 'Chemistry', 't', 1, 1),
               ('g-bio', 'Biology', 't', 1, 1);
             INSERT INTO group_members (group_id, user_id, role, joined_at, status) VALUES
               ('g-phys', 't', 'owner', 1, 'active'), ('g-phys', 's1', 'member', 2, 'active'),
               ('g-phys', 's2', 'member', 3, 'pending'),
               ('g-chem', 't', 'owner', 1, 'active'),
               ('g-bio', 't', 'owner', 1, 'active');
             INSERT INTO room_library_objects
               (room_id, object_id, uploader_id, size_bytes, created_at) VALUES
               ('g-phys', 'p1', 't', 500, 100), ('g-phys', 'p2', 's1', 300, 400),
               ('g-chem', 'c1', 't', 800, 200),
               ('g-bio', 'b1', 't', 800, 300),
               ('g-gone', 'x1', 't', 10, 50);",
        )
        .unwrap();
        db
    }

    type Row = (String, Option<String>, i64, i64, i64, i64, i64);

    fn page(db: &Connection, after: Option<(i64, &str)>, limit: i64) -> Vec<Row> {
        let (b, r) = match after {
            Some((b, r)) => (Some(b), r.to_string()),
            None => (None, String::new()),
        };
        db.prepare(USAGE_PAGE_SQL)
            .unwrap()
            .query_map(params![b, r, limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// Largest first, a tie broken by room id, members counting only ACTIVE ones, oldest and
    /// newest per group — and a room with no group listed with no name rather than dropped.
    #[test]
    fn groups_are_listed_largest_first_with_what_the_server_knows() {
        let db = db();
        let all = page(&db, None, 10);
        assert_eq!(
            all,
            [
                ("g-bio".into(), Some("Biology".into()), 1, 800, 1, 300, 300),
                ("g-chem".into(), Some("Chemistry".into()), 1, 800, 1, 200, 200),
                ("g-phys".into(), Some("Physics".into()), 2, 800, 2, 100, 400),
                ("g-gone".into(), None, 0, 10, 1, 50, 50),
            ]
        );
    }

    /// The keyset walks the same order a page at a time, across a three-way tie, without
    /// skipping or repeating a group.
    #[test]
    fn the_cursor_continues_exactly_where_the_page_ended() {
        let db = db();
        let first = page(&db, None, 2);
        assert_eq!(first.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(), ["g-bio", "g-chem"]);
        let last = first.last().unwrap();
        let second = page(&db, Some((last.3, &last.0)), 2);
        assert_eq!(second.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(), ["g-phys", "g-gone"]);
        let last = second.last().unwrap();
        assert!(page(&db, Some((last.3, &last.0)), 2).is_empty());
    }

    #[test]
    fn the_totals_sum_the_whole_library_beside_its_settings() {
        let db = db();
        db.execute(
            "UPDATE server_settings SET max_room_library_bytes = 4096, library_retention_days = 180",
            [],
        )
        .unwrap();
        let totals: (i64, i64, i64, Option<i64>, Option<i64>) = db
            .query_row(USAGE_TOTALS_SQL, [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap();
        assert_eq!(totals, (2410, 5, 4, Some(4096), Some(180)));
    }

    /// Where the library lives and how much room is left under each store's configured cap.
    #[test]
    fn stores_report_the_library_share_and_the_room_under_the_cap() {
        let db = db();
        db.execute_batch(
            "INSERT INTO storage_backends
               (store_id, kind, label, state, priority, max_bytes, used_bytes, created_at,
                updated_at, library_pin)
             VALUES ('s3-campus', 's3', 'Campus MinIO', 'active', 10, 5000, 1200, 1, 1, 1);
             UPDATE room_library_objects SET store_id = 's3-campus' WHERE room_id = 'g-phys';",
        )
        .unwrap();
        let rows: Vec<(String, i64, Option<i64>, i64)> = db
            .prepare(STORES_SQL)
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get("store_id")?,
                    r.get("library_pin")?,
                    r.get("max_bytes")?,
                    r.get("library_bytes")?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rows,
            [
                ("r2-primary".into(), 0, None, 1610),
                ("s3-campus".into(), 1, Some(5000), 800),
            ]
        );
        assert_eq!(free_bytes(Some(5000), 1200), Some(3800));
        assert_eq!(free_bytes(Some(5000), 6000), Some(0), "over the cap is no room, not negative");
        assert_eq!(free_bytes(None, 1200), None, "no cap, no figure — the backend cannot say");
    }

    /// Admin or owner, through the revocation-aware gate — and nothing in the answer that the
    /// server would need content to know.
    #[test]
    fn the_endpoint_is_admin_level_and_metadata_only() {
        let src = include_str!("library.rs");
        let body = &src[src.find("pub async fn usage").unwrap()..];
        let body = &body[..body.find("#[cfg(test)]").unwrap()];
        assert!(body.contains("require_active_auth(") && body.contains("require_admin("));
        for leak in ["uploader_id", "object_id", "kind"] {
            assert!(!body.contains(leak), "the usage list must not carry `{leak}`");
        }
    }
}
