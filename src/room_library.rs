//! The group LIBRARY — a durable, per-group storage class for recordings and course materials
//! (docs/CAMPUS_PLAN.md: ruling R1, Wave D step 1).
//!
//! **What it is.** A group's recordings outlive the relay. Chat media is a TTL class
//! (`media_objects`, `retention_days`, 30 by default) and R1 leaves it exactly so; the library is
//! a separate, operator-visible class with its own retention and its own per-group cap. It names
//! an existing kind of exception rather than inventing one — plugin media, plugin code, avatars
//! and the instrument pack are already persistent.
//!
//! **What the server holds.** Encrypted parts it cannot read. A member's device cuts a recording
//! into ~32 MiB parts, encrypts each under a key derived from a per-recording key, and uploads
//! each part as one object; the record that names the parts and carries the key travels end to
//! end on the group channel. The operator sees sizes and dates — never titles, never content,
//! never who appears in a recording.
//!
//! **Who pays.** The ROOM, never the uploader: library bytes count against
//! `server_settings.max_room_library_bytes` (per group) and the server total
//! (`max_storage_bytes`, via `server_stats`), and stay out of `user_storage`. A teacher who
//! records a course must not pay for the course out of a personal allowance.
//!
//! **How long.** `server_settings.library_retention_days`, frozen into `expires_at` at upload
//! (NULL = keep until deleted, the default).
//!
//! # The HTTP contract
//!
//! Every route takes an access token from a live (not revoked) device of an ACTIVE member of
//! `:room` — `plugin_blob::gate`, shared with plugin code and plugin media. Error bodies are
//! `{"error": "<code>"}`.
//!
//! - `PUT /room-library/:room/:id` — body: the encrypted part, `Content-Length` required, at most
//!   [`MAX_OBJECT_BYTES`]. Optional `X-Sezi-Library-Kind` (`[a-z0-9_-]{1,24}`, default `part`).
//!   `200 {id, size, kind, created_at, expires_at}`, the same answer again for a retry by the same
//!   uploader with the same size (nothing is re-read or re-charged). `409 id_taken` when the id
//!   already names a different object. `429 {"error":"quota_exceeded","scope":"room_library" |
//!   "server_storage"}`.
//! - `GET /room-library/:room/:id` — the bytes, STREAMED from the store with `Content-Length`;
//!   `Range: bytes=N-` answers `206` with `Content-Range` (resume). `410 expired` once the object
//!   is past its `expires_at` and not yet swept, `404 not_found` otherwise.
//! - `DELETE /room-library/:room/:id` — the uploader, or a group admin/owner. `204`, also when
//!   the object is already gone.
//! - `GET /room-library/:room?after=<id>&limit=<n>` — metadata only:
//!   `{objects: [{id, kind, size, uploader_id, created_at, expires_at}], used_bytes, max_bytes,
//!   next}` in id order; `next` is the `after` for the following page, null on the last.
//!
//! Object ids are opaque to the server, unique only inside their room, and NEVER reused: a PUT
//! is idempotent by id, so an id two clients both picked would silently keep the first object.
//! Hence [`valid_object_id`] demands at least 16 characters — room for 96 random bits.

// The ways out — the daily retention sweep and the SQL the group, account and server teardowns
// share — kept beside the class that spells the store key, in a file of their own for size.
#[path = "room_library_cleanup.rs"]
pub(crate) mod cleanup;
pub(crate) use cleanup::sweep_expired;

use std::ops::RangeInclusive;

use crate::d1util::{d1_int, d1_opt_int, d1_text};
use crate::groups::is_group_admin;
use crate::instrument_pack::{parse_range, RangeAsk};
use crate::plugin_blob::gate;
use crate::respond::{json_err, json_err_msg, no_content};
use crate::storage::{library_key, placement_err_response, StorageClass, StorageRouter};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// Ceiling for one library object: a 32 MiB part plus 1 MiB of headroom.
///
/// The parts are 32 MiB of plaintext (the campus plan's board decision: small parts so playback
/// can start before the whole recording is down). `sezi-file`'s STREAM framing adds a 16-byte tag
/// per chunk — 8 KiB at 64 KiB chunks, 512 B at 1 MiB chunks — plus a short header, so 1 MiB of
/// headroom covers any chunk size and any header a keyed variant adds, by two orders of magnitude.
/// It also keeps the isolate comfortable: `put_new` holds the body twice for its store fallback,
/// 66 MiB of a 128 MB isolate, where chat media's 50 MiB already reaches 100.
pub(crate) const MAX_OBJECT_BYTES: u64 = 33 * 1024 * 1024;

/// Ids: `[A-Za-z0-9_-]`, 16..=128 characters — a UUID, 32 hex digits or 22 base64url characters
/// all fit, and nothing that needs escaping reaches a store key.
const OBJECT_ID_LEN: RangeInclusive<usize> = 16..=128;

/// The default `kind`, and the longest one a client may set.
const DEFAULT_KIND: &str = "part";
const MAX_KIND_CHARS: usize = 24;

/// Member list paging: the default and the ceiling. A semester of video for one course is a few
/// hundred parts, so one default page usually is the whole library.
const LIST_DEFAULT: i64 = 500;
const LIST_MAX: i64 = 1000;

/// Library retention, when one is set: the media window's own bounds (`admin/handlers.rs`
/// accepts `retention_days` in 1..=3650), so the two retention editors cannot disagree about
/// what a sane number of days is.
pub(crate) const LIBRARY_RETENTION_RANGE: RangeInclusive<i64> = 1..=3650;

/// A per-group cap, when one is set: any positive byte count.
pub(crate) const LIBRARY_CAP_RANGE: RangeInclusive<i64> = 1..=i64::MAX;

// ── SQL contracts (exercised against the real migrations in room_library_tests.rs) ────────

/// One object's row. Binds: room, id.
pub(crate) const SELECT_OBJECT_SQL: &str = "SELECT uploader_id, kind, size_bytes, store_id, \
     created_at, expires_at FROM room_library_objects WHERE room_id = ? AND object_id = ? LIMIT 1";

/// Everything a PUT needs to decide, in ONE round trip: the retention to freeze, both caps, and
/// the two usages — each usage read only when its cap is set, so a server with no caps (the
/// default) pays for neither sum. Binds: room. No row = a server_settings row that was never
/// seeded, which the handler reads as "no caps, keep until deleted".
pub(crate) const PUT_POLICY_SQL: &str = "SELECT s.library_retention_days AS retention_days, \
       s.max_room_library_bytes AS max_room, s.max_storage_bytes AS max_server, \
       CASE WHEN s.max_room_library_bytes IS NULL THEN 0 ELSE \
         (SELECT COALESCE(SUM(size_bytes), 0) FROM room_library_objects WHERE room_id = ?) \
       END AS room_used, \
       CASE WHEN s.max_storage_bytes IS NULL THEN 0 ELSE \
         COALESCE((SELECT media_bytes FROM server_stats WHERE id = 1), 0) \
       END AS server_used \
     FROM server_settings s WHERE s.id = 1 LIMIT 1";

/// The meta row. `DO NOTHING ... RETURNING` makes "did THIS request insert it" observable, so of
/// two concurrent PUTs only the one that inserted bumps the counters.
///
/// The row is written only while its GROUP still exists. The gate checked membership before the
/// body was read, and a group deleted in between would otherwise get a row after its teardown
/// batch had already queued and dropped everything it held — a part nothing would ever delete,
/// charged to a room that is gone. Inside one statement the two cannot interleave: either this
/// INSERT commits first and the teardown takes the row with the rest, or the teardown commits
/// first and this inserts nothing. Binds (numbered, room twice): room, id, uploader, kind, size,
/// store, created_at, expires_at.
pub(crate) const INSERT_OBJECT_SQL: &str = "INSERT INTO room_library_objects \
       (room_id, object_id, uploader_id, kind, size_bytes, store_id, created_at, expires_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 WHERE EXISTS (SELECT 1 FROM groups WHERE id = ?1) \
     ON CONFLICT(room_id, object_id) DO NOTHING RETURNING object_id";

/// DELETE, first half: queue the blob in `storage_orphans` under the exact key
/// `storage::library_key` writes. Binds: now, room, id.
pub(crate) const ORPHAN_OBJECT_SQL: &str =
    "INSERT OR IGNORE INTO storage_orphans(store_id, key, size_bytes, created_at, retry_count) \
     SELECT store_id, 'room-library/' || room_id || '/' || object_id, size_bytes, ?, 0 \
       FROM room_library_objects WHERE room_id = ? AND object_id = ?";

/// DELETE, second half: drop the row; RETURNING says whether this request was the one that did.
/// Binds: room, id.
pub(crate) const DELETE_OBJECT_SQL: &str = "DELETE FROM room_library_objects \
     WHERE room_id = ? AND object_id = ? RETURNING size_bytes";

/// One page of the member list, in id order — the primary key's own order, so a page is an index
/// range. Rows past their `expires_at` are left out: a GET would refuse them. Binds: room, after,
/// now, limit.
pub(crate) const LIST_PAGE_SQL: &str = "SELECT object_id, uploader_id, kind, size_bytes, \
       created_at, expires_at FROM room_library_objects \
     WHERE room_id = ? AND object_id > ? AND (expires_at IS NULL OR expires_at >= ?) \
     ORDER BY object_id LIMIT ?";

/// The room's usage and its cap, for the list header. `used_bytes` counts every row still
/// stored, expired-but-not-yet-swept included, because that is what the cap is measured against.
/// Binds: room.
pub(crate) const ROOM_USAGE_SQL: &str = "SELECT \
       COALESCE((SELECT SUM(size_bytes) FROM room_library_objects WHERE room_id = ?), 0) \
         AS used_bytes, \
       (SELECT max_room_library_bytes FROM server_settings WHERE id = 1) AS max_bytes";

// ── Pure helpers (the testable half) ──────────────────────────────────────────────────────

/// One library setting as `PATCH /admin/server-settings` receives it → the value to store.
///
/// The storage caps' convention, applied to both library fields: absent keeps `current`, `0`
/// CLEARS (NULL — unlimited for the cap, keep-until-deleted for the retention), a value inside
/// `valid` sets it, anything else is `Err` (→ 400). Clearing is spelled `0` rather than `null`
/// because serde cannot tell an explicit `null` from an absent field on an `Option`, and "keep
/// until deleted" is a setting an owner must be able to return to, not only start from.
pub(crate) fn library_setting(
    requested: Option<i64>,
    current: Option<i64>,
    valid: RangeInclusive<i64>,
) -> Result<Option<i64>, ()> {
    match requested {
        None => Ok(current),
        Some(0) => Ok(None),
        Some(v) if valid.contains(&v) => Ok(Some(v)),
        Some(_) => Err(()),
    }
}

/// Is this an id a library object may have? See [`OBJECT_ID_LEN`].
pub(crate) fn valid_object_id(id: &str) -> bool {
    OBJECT_ID_LEN.contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `X-Sezi-Library-Kind` → the stored kind. Absent or empty → `part`. Lowercase ASCII, digits,
/// `_` and `-`, at most 24 characters; anything else is refused rather than cleaned, because a
/// label the client did not send is worse than an error it can see.
pub(crate) fn parse_kind(raw: Option<&str>) -> Result<String, ()> {
    let k = raw.map(str::trim).unwrap_or("");
    if k.is_empty() {
        return Ok(DEFAULT_KIND.to_string());
    }
    let ok = k.len() <= MAX_KIND_CHARS
        && k
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok {
        Ok(k.to_string())
    } else {
        Err(())
    }
}

/// The library's quota decision. A `None` cap is unlimited; an exact fit is allowed (`>`, as in
/// `quota::decide_upload`). The server total is checked first: when both are exceeded, the
/// answer the client can do least about is the one it should be told.
pub(crate) fn decide_library_upload(
    server_used: i64,
    room_used: i64,
    size: i64,
    max_server: Option<i64>,
    max_room: Option<i64>,
) -> Option<&'static str> {
    if max_server.is_some_and(|cap| server_used.saturating_add(size) > cap) {
        return Some("server_storage");
    }
    if max_room.is_some_and(|cap| room_used.saturating_add(size) > cap) {
        return Some("room_library");
    }
    None
}

/// `expires_at` for an object uploaded at `now`: NULL when the server keeps the library until
/// deleted, otherwise frozen here and never recomputed.
pub(crate) fn expires_at(now: i64, retention_days: Option<i64>) -> Option<i64> {
    retention_days.map(|d| now.saturating_add(d.saturating_mul(86_400)))
}

/// Has this object passed its `expires_at`? Strictly after: the second named is still served,
/// the media rule (`media/handlers.rs` refuses `expires_at < now`).
pub(crate) fn is_expired(expires_at: Option<i64>, now: i64) -> bool {
    expires_at.is_some_and(|e| e < now)
}

/// The member list's `limit` → rows per page.
fn page_limit(raw: Option<&str>) -> i64 {
    raw.and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(LIST_DEFAULT)
        .clamp(1, LIST_MAX)
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name).ok().flatten()
}

fn query(req: &Request, name: &str) -> Option<String> {
    req.url()
        .ok()?
        .query_pairs()
        .find_map(|(k, v)| (k == name).then(|| v.into_owned()))
}

#[derive(Deserialize)]
struct ObjectRow {
    uploader_id: String,
    kind: String,
    size_bytes: i64,
    store_id: String,
    created_at: i64,
    expires_at: Option<i64>,
}

async fn load_object(db: &D1Database, room: &str, id: &str) -> Result<Option<ObjectRow>> {
    db.prepare(SELECT_OBJECT_SQL)
        .bind(&[d1_text(room), d1_text(id)])?
        .first(None)
        .await
}

fn object_json(id: &str, row: &ObjectRow) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "size": row.size_bytes,
        "kind": row.kind,
        "created_at": row.created_at,
        "expires_at": row.expires_at,
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────────────────────

/// `PUT /room-library/:room/:id` — store one encrypted part. Any active member may upload; the
/// bytes are charged to the room.
///
/// BLOB FIRST, row second — `plugin_media`'s order, for its reason: with no retention set nothing
/// ever sweeps these rows, so a row written before a failed store PUT would be a permanent
/// phantom, charging the room for bytes that do not exist. A failed row write after a good PUT
/// heals on the client's retry: the store overwrite is idempotent and the INSERT simply runs
/// again.
pub async fn put_object(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, object_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    if !valid_object_id(&object_id) {
        return json_err(400, "bad_id");
    }
    // No store at all → the same clean 503 as every other blob route; after authorization,
    // before anything is counted or buffered.
    let router = StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // The media upload limit (60 per 5 minutes). At 33 MiB a part that is ~2 GB per five
    // minutes per member; a client faster than that is paced by its own retry, not refused.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("library:put:{user_id}"),
        60,
        5 * 60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let size: u64 = match header(&req, "content-length").and_then(|s| s.parse().ok()) {
        Some(n) if n > 0 && n <= MAX_OBJECT_BYTES => n,
        Some(_) => return json_err_msg(413, "bad_size", &MAX_OBJECT_BYTES.to_string()),
        None => return json_err(411, "content_length_required"),
    };
    let Ok(kind) = parse_kind(header(&req, "x-sezi-library-kind").as_deref()) else {
        return json_err(400, "bad_kind");
    };
    let db = ctx.env.d1("DB")?;

    // Idempotent by id — but only for the SAME object. A retry comes from the same uploader with
    // the same bytes; anything else under an existing id is a collision, and answering it 200
    // would tell the second client its part is stored when it is not.
    if let Some(existing) = load_object(&db, &room_id, &object_id).await? {
        if existing.uploader_id == user_id && existing.size_bytes == size as i64 {
            return Response::from_json(&object_json(&object_id, &existing));
        }
        return json_err(409, "id_taken");
    }

    // Policy and quota. FAIL-CLOSED on a read error, unlike `quota::check_upload`: this read also
    // decides the retention, and an object stored without the expiry its server promised would
    // be kept forever with nothing to say so. The INSERT below needs the same database anyway.
    #[derive(Deserialize)]
    struct Policy {
        retention_days: Option<i64>,
        max_room: Option<i64>,
        max_server: Option<i64>,
        room_used: i64,
        server_used: i64,
    }
    let policy: Option<Policy> = match db
        .prepare(PUT_POLICY_SQL)
        .bind(&[d1_text(&room_id)])?
        .first(None)
        .await
    {
        Ok(p) => p,
        Err(_) => return json_err(503, "settings_unavailable"),
    };
    if let Some(p) = &policy {
        if let Some(scope) =
            decide_library_upload(p.server_used, p.room_used, size as i64, p.max_server, p.max_room)
        {
            let resp = Response::from_json(
                &serde_json::json!({ "error": "quota_exceeded", "scope": scope }),
            )?;
            return Ok(resp.with_status(429));
        }
    }

    let bytes = req.bytes().await?;
    // The declared length is what the idempotency check above compares and the quota charged;
    // a body that disagrees with it is refused rather than stored under the wrong size.
    if bytes.len() as u64 != size {
        return json_err_msg(400, "bad_size", "body length differs from Content-Length");
    }
    let store_id = match router
        .put_new(
            StorageClass::Library,
            &library_key(&room_id, &object_id),
            bytes,
            "application/octet-stream",
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => return placement_err_response(e),
    };

    let now = now_secs() as i64;
    let row = ObjectRow {
        uploader_id: user_id,
        kind,
        size_bytes: size as i64,
        store_id,
        created_at: now,
        expires_at: expires_at(now, policy.and_then(|p| p.retention_days)),
    };
    let inserted = db
        .prepare(INSERT_OBJECT_SQL)
        .bind(&[
            d1_text(&room_id),
            d1_text(&object_id),
            d1_text(&row.uploader_id),
            d1_text(&row.kind),
            d1_int(row.size_bytes),
            d1_text(&row.store_id),
            d1_int(row.created_at),
            d1_opt_int(row.expires_at),
        ])?
        .all()
        .await?
        .results::<serde_json::Value>()
        .map(|r| !r.is_empty())
        .unwrap_or(false);
    if !inserted {
        return match load_object(&db, &room_id, &object_id).await? {
            // A concurrent PUT of the same id inserted first: its row is the truth. The same
            // uploader with the same size is this request's own retry racing itself.
            Some(winner)
                if winner.uploader_id == row.uploader_id && winner.size_bytes == row.size_bytes =>
            {
                Response::from_json(&object_json(&object_id, &winner))
            }
            Some(_) => json_err(409, "id_taken"),
            // No row and none written: the group was deleted while the body was in flight. The
            // blob just stored has nothing to name it, so it goes straight to the tombstones.
            None => {
                crate::storage::maint::insert_orphans(
                    &db,
                    &[(row.store_id.clone(), library_key(&room_id, &object_id), row.size_bytes)],
                )
                .await;
                json_err(403, "not_member")
            }
        };
    }
    // Charged to the ROOM: the server total moves, `user_storage` does not. Best-effort; the
    // daily reconcile repairs any drift from the table itself.
    crate::usage::library_added(&db, row.size_bytes).await;
    crate::usage::count_bump(&db, "upload_bytes", row.size_bytes).await;
    crate::usage::count_bump(&db, "upload_count", 1).await;
    Response::from_json(&object_json(&object_id, &row))
}

/// `GET /room-library/:room/:id` — the part, streamed. Never `Response::from_bytes`: a 33 MiB
/// body buffered in a 128 MB isolate is held twice, and the instrument pack's streaming path
/// already exists for exactly this.
///
/// Only the open-ended `Range: bytes=N-` is honoured (the storage layer's one form); any other
/// range is answered whole with 200, which RFC 7233 allows. A player that wants the middle of a
/// part reads from N and closes the stream when it has enough.
pub async fn get_object(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, object_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    if !valid_object_id(&object_id) {
        return json_err(400, "bad_id");
    }
    let router = StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // The media download limit (600 per 5 minutes) — an egress guard, not authorization.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("library:get:{user_id}"),
        600,
        5 * 60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let db = ctx.env.d1("DB")?;
    let Some(row) = load_object(&db, &room_id, &object_id).await? else {
        return json_err(404, "not_found");
    };
    // The sweep runs daily; without this an expired part stays readable for up to a day past the
    // retention its group was promised.
    if is_expired(row.expires_at, now_secs() as i64) {
        return json_err(410, "expired");
    }
    let size = row.size_bytes.max(0) as u64;
    let offset = match parse_range(header(&req, "range").as_deref(), size) {
        RangeAsk::Whole => 0,
        RangeAsk::From(n) => n,
        RangeAsk::Unsatisfiable => {
            let headers = Headers::new();
            headers.set("content-range", &format!("bytes */{size}"))?;
            return Ok(Response::empty()?.with_status(416).with_headers(headers));
        }
    };
    let stream = match router
        .get_stream(&row.store_id, &library_key(&room_id, &object_id), offset)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return json_err(404, "not_found"),
        Err(_) => return json_err(503, "storage_backend_unavailable"),
    };
    let sent = (size - offset) as i64;
    crate::usage::count_bump(&db, "download_count", 1).await;
    crate::usage::count_bump(&db, "download_bytes", sent).await;

    // Content-Length from the row, not the store: the row is what the upload measured.
    let headers = Headers::new();
    headers.set("content-type", "application/octet-stream")?;
    headers.set("content-length", &sent.to_string())?;
    headers.set("accept-ranges", "bytes")?;
    headers.set("cache-control", "private, no-store")?;
    let status = if offset > 0 {
        headers.set(
            "content-range",
            &format!("bytes {offset}-{}/{size}", size - 1),
        )?;
        206
    } else {
        200
    };
    stream.into_response(status, headers)
}

/// `DELETE /room-library/:room/:id` — the uploader, or a group admin/owner. 204, and 204 again
/// when there is nothing left to delete: the state the caller asked for.
///
/// The row goes ATOMICALLY with its tombstone — `storage_orphans` row and row delete in one
/// batch, the `groups_delete.rs` argument. A row deleted first and its blob deleted second
/// leaks the blob forever if the worker dies between the two; a blob deleted first leaves a row
/// that charges the room for nothing. After the batch the blob is deleted right away, and the
/// tombstone dropped; if that fails, the daily `retry_orphans` finishes it.
pub async fn delete_object(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, object_id, role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    if !valid_object_id(&object_id) {
        return json_err(400, "bad_id");
    }
    let db = ctx.env.d1("DB")?;
    let Some(row) = load_object(&db, &room_id, &object_id).await? else {
        return no_content();
    };
    // A group admin removes what no longer belongs in the room; anyone else removes only their
    // own. The server OWNER has no say here — running the server is not a seat in the group.
    if row.uploader_id != user_id && !is_group_admin(&role) {
        return json_err(403, "not_uploader_or_admin");
    }
    let now = now_secs() as i64;
    let results = db
        .batch(vec![
            db.prepare(ORPHAN_OBJECT_SQL).bind(&[
                d1_int(now),
                d1_text(&room_id),
                d1_text(&object_id),
            ])?,
            db.prepare(DELETE_OBJECT_SQL)
                .bind(&[d1_text(&room_id), d1_text(&object_id)])?,
        ])
        .await?;
    let deleted = results
        .get(1)
        .and_then(|r| r.results::<serde_json::Value>().ok())
        .is_some_and(|rows| !rows.is_empty());
    if !deleted {
        // A concurrent DELETE won; it owns the counters and the store delete.
        return no_content();
    }
    crate::usage::library_removed(&db, row.size_bytes, 1).await;
    // Best-effort fast path; the tombstone already guarantees the blob goes.
    let key = library_key(&room_id, &object_id);
    if let Ok(router) = StorageRouter::from_env(&ctx.env).await {
        if router.delete(&row.store_id, &key).await.is_ok() {
            if let Ok(stmt) = db
                .prepare("DELETE FROM storage_orphans WHERE store_id = ? AND key = ?")
                .bind(&[d1_text(&row.store_id), d1_text(&key)])
            {
                let _ = stmt.run().await;
            }
        }
    }
    no_content()
}

/// `GET /room-library/:room` — what the room's library holds: ids, kinds, sizes, uploaders and
/// dates. Metadata only, and only what a member could already work out — the titles and keys
/// live in the end-to-end record, not here.
pub async fn list_objects(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (_user_id, room_id, _role) = match crate::plugin_blob::room_gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    let after = query(&req, "after").unwrap_or_default();
    if !after.is_empty() && !valid_object_id(&after) {
        return json_err(400, "bad_cursor");
    }
    let limit = page_limit(query(&req, "limit").as_deref());
    let db = ctx.env.d1("DB")?;

    #[derive(Deserialize)]
    struct ListRow {
        object_id: String,
        uploader_id: String,
        kind: String,
        size_bytes: i64,
        created_at: i64,
        expires_at: Option<i64>,
    }
    // One row past the page says whether another page exists, without a COUNT.
    let mut rows: Vec<ListRow> = db
        .prepare(LIST_PAGE_SQL)
        .bind(&[
            d1_text(&room_id),
            d1_text(&after),
            d1_int(now_secs() as i64),
            d1_int(limit + 1),
        ])?
        .all()
        .await?
        .results()?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = more.then(|| rows.last().map(|r| r.object_id.clone())).flatten();

    #[derive(Deserialize)]
    struct UsageRow {
        used_bytes: i64,
        max_bytes: Option<i64>,
    }
    let usage: Option<UsageRow> = db
        .prepare(ROOM_USAGE_SQL)
        .bind(&[d1_text(&room_id)])?
        .first(None)
        .await?;
    let objects: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.object_id,
                "kind": r.kind,
                "size": r.size_bytes,
                "uploader_id": r.uploader_id,
                "created_at": r.created_at,
                "expires_at": r.expires_at,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({
        "objects": objects,
        "used_bytes": usage.as_ref().map(|u| u.used_bytes).unwrap_or(0),
        "max_bytes": usage.and_then(|u| u.max_bytes),
        "next": next,
    }))
}

#[cfg(test)]
#[path = "room_library_tests.rs"]
mod tests;
