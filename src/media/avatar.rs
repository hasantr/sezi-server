//! Profile/group avatar blob upload + download (Profile Photo epic §2.3).
//!
//! The server is BLIND: blob contents are E2E-encrypted (XChaCha20 STREAM, the key never
//! leaves the E2E channel) and the worker holds only opaque bytes. Two things set this
//! apart from ephemeral media (`media/handlers.rs`):
//!   1. ONE LOGICAL SLOT PER USER — `avatar_objects.user_id` is the PK. On a successful
//!      new upload the previous object is pushed into `storage_orphans` (the existing
//!      daily `retry_orphans` deletes it from the store), so at most one live avatar blob
//!      per user survives.
//!   2. EXEMPT FROM RETENTION — `avatar_objects` has no `expires_at`, and the message
//!      retention sweep (`maintenance::cleanup_expired`) only touches `media_objects`, so
//!      an avatar is permanent.
//!
//! Storage goes through the existing `StorageRouter` (R2 / pluggable store) choke-point;
//! the key scheme is `storage::avatar_key` (`avatar/{user_id}/{object_id}`).

use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::json_err;
use crate::storage::{StorageClass, StorageRouter};
use crate::utils::now_secs;
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

/// Ceiling for an encrypted avatar (plan §6: 512px WebP q80 targets ~60-120KB, so the
/// encrypted ceiling is ≤400KB).
const MAX_AVATAR_SIZE: u64 = 400 * 1024;

// ── SQL contracts (unit-tested with rusqlite — the invite_attribution pattern) ───

/// Single slot: read the user's current avatar object, so the old one can be orphaned.
pub(crate) const SELECT_EXISTING_AVATAR_SQL: &str =
    "SELECT object_id, store_id, size_bytes FROM avatar_objects WHERE user_id = ? LIMIT 1";

/// Single-slot upsert: user_id is the PK, so one row per user — the new ref overwrites the old.
pub(crate) const UPSERT_AVATAR_SQL: &str = "INSERT INTO avatar_objects
       (user_id, object_id, store_id, size_bytes, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       object_id = excluded.object_id,
       store_id = excluded.store_id,
       size_bytes = excluded.size_bytes,
       updated_at = excluded.updated_at";

/// Download resolves by the opaque object_id (a single-segment ref). Because the upsert drops
/// the old object_id, a stale ref no longer matches any row → 404 (single-slot semantics).
pub(crate) const LOOKUP_AVATAR_SQL: &str =
    "SELECT user_id, store_id, size_bytes FROM avatar_objects WHERE object_id = ? LIMIT 1";

#[derive(Deserialize)]
struct ExistingAvatar {
    object_id: String,
    store_id: String,
    size_bytes: i64,
}

#[derive(Deserialize)]
struct AvatarMeta {
    user_id: String,
    store_id: String,
    size_bytes: i64,
}

/// POST /media/avatar — upload an E2E-encrypted avatar blob (the server stays blind).
///
/// Active members only; ≤400KB; rate-limited `avatar:up:{user}` at 10/day; one logical slot.
/// Response: `{ "avatar_ref": "<object_id>", "bytes": n }`. The `avatar_ref` travels in an
/// E2E control message (ProfileAvatar/RoomAvatar); the recipient fetches it with
/// GET /media/avatar/:id.
pub async fn upload(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };

    // Lite install (R2 is OPTIONAL): with no store the path is off — a clean 503 after auth
    // and before D1, symmetric with media/handlers.rs upload. The client treats it as
    // nonretryable.
    let router = StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }

    // Per-user upload rate-limit: `avatar:up:{user}` at 10 per 86400s (plan §6). The avatar
    // is single-slot — every upload replaces the previous one — so 10/day sits far above the
    // legitimate "set/change my profile photo" cadence while cutting off automated abuse.
    // The KV binding is OPTIONAL (template diet): with none, or on a KV get/put error, we
    // FAIL OPEN and allow — see ratelimit::check_rate_limit_env (lesson of 2026-06-28: the
    // rate-limiter must never wedge messaging, so the limit loosens temporarily instead).
    if !check_rate_limit_env(&ctx.env, &format!("avatar:up:{user_id}"), 10, 86400).await {
        return json_err(429, "rate_limited");
    }

    // Early gate: if content-length is present and over the ceiling, reject WITHOUT buffering
    // the body — no point holding a blob we are about to reject. The error class leaks
    // nothing: just "avatar_too_large", never the declared or actual size.
    if let Some(n) = req
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u64>().ok())
    {
        if n > MAX_AVATAR_SIZE {
            return json_err(413, "avatar_too_large");
        }
    }

    let bytes = req.bytes().await?;
    // Authoritative gate: content-length can lie, so check the ACTUAL buffered size too.
    if bytes.len() as u64 > MAX_AVATAR_SIZE {
        return json_err(413, "avatar_too_large");
    }
    if bytes.is_empty() {
        return json_err(400, "avatar_empty");
    }
    let size = bytes.len() as i64;

    // New object id: an unguessable UUID, i.e. an opaque capability carried over E2E. The key
    // is avatar/{user}/{object_id}; the content-type is opaque because the content is
    // encrypted (application/octet-stream).
    let object_id = Uuid::new_v4().to_string();
    let key = crate::storage::avatar_key(&user_id, &object_id);

    // Write the blob to the store FIRST, before D1. An avatar has no TTL, so a D1-first
    // ordering would turn a failed PUT into a PERMANENT ghost row: download locked at 404 and
    // cleanup would never sweep it. PUT-first means the row only moves to the new ref once
    // the blob really exists — consistent by construction.
    let store_id = match router
        .put_new(
            StorageClass::Media,
            &key,
            bytes,
            "application/octet-stream",
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => return crate::storage::placement_err_response(e),
    };

    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;

    // Single slot: read the current avatar object (so the old one can be orphaned), then point
    // at the new ref. The upsert on the user_id PK guarantees exactly one row. NOTE: the old
    // blob is orphaned only AFTER the upsert succeeds. The order matters — the pointer moves
    // to the new blob first, then the old one is dropped. The reverse order would delete a
    // live avatar whenever the upsert failed.
    let existing: Option<ExistingAvatar> = db
        .prepare(SELECT_EXISTING_AVATAR_SQL)
        .bind(&[d1_text(&user_id)])?
        .first(None)
        .await?;
    db.prepare(UPSERT_AVATAR_SQL)
        .bind(&[
            d1_text(&user_id),
            d1_text(&object_id),
            d1_text(&store_id),
            d1_int(size),
            d1_int(now),
        ])?
        .run()
        .await?;

    // Old object → `storage_orphans` (the existing daily `retry_orphans` deletes the blob from
    // the store). BEST-EFFORT: the upsert already points at the new blob, so a failed
    // orphan-insert only leaks the old blob — the avatar itself stays consistent. If the
    // object_id is unchanged (a theoretical retry) there is nothing to orphan.
    if let Some(old) = existing {
        if old.object_id != object_id {
            let old_key = crate::storage::avatar_key(&user_id, &old.object_id);
            crate::storage::maint::insert_orphans(&db, &[(old.store_id, old_key, old.size_bytes)])
                .await;
        }
    }

    Response::from_json(&serde_json::json!({ "avatar_ref": object_id, "bytes": size }))
}

/// GET /media/avatar/:id — download an E2E-encrypted avatar blob (opaque ciphertext).
///
/// Active members only. Member-level access is enough: without the key the content is
/// unreadable, and no contacts gate is needed because group members must be able to fetch a
/// RoomAvatar ref without being 1:1 contacts. The 404 leaks nothing about existence — a
/// missing blob and a ref superseded by the single-slot upsert are indistinguishable.
pub async fn download(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let uid = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // Lite install: with no store download is off too — a 503 symmetric with upload.
    let router = StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Egress-DoS guard (twin of media/download's 600/5min): unlimited fetching runs up the
    // R2 egress bill. 600/5min sits above a legitimate burst; a KV error FAILS OPEN (allow).
    if !check_rate_limit_env(&ctx.env, &format!("avatar:down:{uid}"), 600, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    let object_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let meta: Option<AvatarMeta> = db
        .prepare(LOOKUP_AVATAR_SQL)
        .bind(&[d1_text(&object_id)])?
        .first(None)
        .await?;
    let meta = match meta {
        Some(m) => m,
        None => return json_err(404, "not_found"),
    };
    let key = crate::storage::avatar_key(&meta.user_id, &object_id);
    // Read through the single choke-point (StorageRouter). Absent → 404; store unreachable →
    // 503, which is retryable.
    let obj = match router.get(&meta.store_id, &key).await {
        Ok(Some(o)) => o,
        Ok(None) => return json_err(404, "not_found_r2"),
        Err(_) => return json_err(503, "storage_backend_unavailable"),
    };

    let headers = Headers::new();
    headers.set("content-type", &obj.content_type)?;
    headers.set("content-length", &meta.size_bytes.to_string())?;
    headers.set("cache-control", "private, no-store")?;
    Ok(Response::from_bytes(obj.bytes)?.with_headers(headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::avatar_key;
    use rusqlite::{params, Connection, OptionalExtension};

    const MIGRATION: &str = include_str!("../../migrations/0035_avatar_objects.sql");

    /// Load the avatar_objects + storage_orphans schema (0035 plus a minimal orphan table).
    fn db_with_schema() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE users (id TEXT PRIMARY KEY);
             INSERT INTO users(id) VALUES ('u1'), ('u2');
             -- storage_orphans (migration 0028 ile bit-aynı sözleşme; tek-slot testi için).
             CREATE TABLE storage_orphans (
               store_id    TEXT NOT NULL,
               key         TEXT NOT NULL,
               size_bytes  INTEGER NOT NULL DEFAULT 0,
               created_at  INTEGER NOT NULL,
               retry_count INTEGER NOT NULL DEFAULT 0,
               PRIMARY KEY (store_id, key)
             );",
        )
        .unwrap();
        db.execute_batch(MIGRATION).unwrap();
        db
    }

    /// Orphan-insert SQL that is BIT-IDENTICAL to insert_orphans (storage::maint) — the
    /// rusqlite twin of the worker's D1 path, pinning upload's drop-the-old-object step
    /// as a contract.
    const ORPHAN_INSERT_SQL: &str =
        "INSERT INTO storage_orphans (store_id, key, size_bytes, created_at, retry_count) \
         VALUES (?, ?, ?, ?, 0) ON CONFLICT(store_id, key) DO NOTHING";

    fn upsert(db: &Connection, user: &str, object_id: &str, store: &str, size: i64, now: i64) {
        db.execute(
            UPSERT_AVATAR_SQL,
            params![user, object_id, store, size, now],
        )
        .unwrap();
    }

    fn lookup(db: &Connection, object_id: &str) -> Option<(String, String, i64)> {
        db.query_row(LOOKUP_AVATAR_SQL, params![object_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()
        .unwrap()
    }

    #[test]
    fn tek_slot_upsert_ve_lookup_by_ref() {
        let db = db_with_schema();
        upsert(&db, "u1", "obj-a", "r2-primary", 1000, 10);

        // First upload: the lookup resolves by ref, with the right store and size.
        assert_eq!(
            lookup(&db, "obj-a"),
            Some(("u1".into(), "r2-primary".into(), 1000))
        );

        // Second upload by the same user → still one row, and object_id becomes the new one.
        upsert(&db, "u1", "obj-b", "s3-xyz", 2000, 20);
        let n: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM avatar_objects WHERE user_id='u1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "user_id PK → kullanıcı başına tek satır");

        // The old ref no longer resolves (single-slot: the 404 class); the new one does.
        assert_eq!(lookup(&db, "obj-a"), None, "düşen eski ref satır bulmaz");
        assert_eq!(
            lookup(&db, "obj-b"),
            Some(("u1".into(), "s3-xyz".into(), 2000))
        );
    }

    #[test]
    fn object_id_benzersiz_kullanicilar_arasi() {
        let db = db_with_schema();
        upsert(&db, "u1", "shared-obj", "r2-primary", 100, 10);
        // A different user cannot take the SAME object_id — the unique index on object_id
        // guards this. The ref is an opaque capability, so a collision would bind one user's
        // ref to another user's blob.
        let err = db.execute(
            UPSERT_AVATAR_SQL,
            params!["u2", "shared-obj", "r2-primary", 100, 10],
        );
        assert!(err.is_err(), "object_id unique index çakışmayı reddetmeli");
    }

    #[test]
    fn replace_eski_objeyi_storage_orphans_a_duser() {
        let db = db_with_schema();
        // Starting avatar.
        upsert(&db, "u1", "obj-old", "r2-primary", 1500, 10);

        // The D1 half of the upload flow: read the old one, upsert the new one, orphan the old.
        let old: (String, String, i64) = db
            .query_row(
                SELECT_EXISTING_AVATAR_SQL,
                params!["u1"],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(old, ("obj-old".into(), "r2-primary".into(), 1500));

        upsert(&db, "u1", "obj-new", "r2-primary", 1800, 20);

        // Old object → orphan, with the full store key built by avatar_key.
        let old_key = avatar_key("u1", &old.0);
        assert_eq!(old_key, "avatar/u1/obj-old");
        db.execute(ORPHAN_INSERT_SQL, params![old.1, old_key, old.2, 20])
            .unwrap();

        // storage_orphans carries the old blob's key with the correct store and size.
        let orphan: (String, i64) = db
            .query_row(
                "SELECT store_id, size_bytes FROM storage_orphans WHERE key = ?",
                params!["avatar/u1/obj-old"],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(orphan, ("r2-primary".into(), 1500));

        // The live slot now points at the new blob; the old ref does not resolve.
        assert_eq!(
            lookup(&db, "obj-new"),
            Some(("u1".into(), "r2-primary".into(), 1800))
        );
        assert_eq!(lookup(&db, "obj-old"), None);
    }
}
