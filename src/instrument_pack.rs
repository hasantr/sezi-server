//! The operator-hosted instrument pack: ONE SoundFont per server, uploaded by the owner and
//! fetched by members (music studio, Phase A2).
//!
//! PLAINTEXT, BY DECLARED EXCEPTION — the one object this relay stores and serves unencrypted.
//! A SoundFont is public content the operator downloaded from the internet, not anyone's
//! message, and encrypting it under a key the server itself would hold is theatre: the same box
//! would keep the ciphertext and the key. So the pack is stored as it arrived. What does NOT
//! change is who may read it: `/instrument-pack` and `/instrument-pack/meta` both take an active
//! member token, exactly like every other blob route here.
//!
//! Shape:
//!   - `PUT /admin/instrument-pack` (owner) — the raw `.sf2` body, optional `X-Pack-Name`.
//!   - `DELETE /admin/instrument-pack` (owner) — drop the object and the row.
//!   - `GET /instrument-pack/meta` (member) — `{hash, name, size_bytes}` or 404 `no_pack`.
//!   - `GET /instrument-pack` (member) — the bytes, resumable.
//!
//! The hash is BLAKE3 of the file in hex and does three jobs: the storage key
//! (`packs/<hash>.sf2`), the HTTP `ETag`, and the pin the client keeps beside its copy. A member
//! who already holds the hash sends `If-None-Match` and gets a bodyless 304 — the pack is ~30 MB
//! and re-downloading it on every app start is the failure this endpoint exists to avoid.
//!
//! ⚠ THE ADMIN GUARD IN `admin/mod.rs` CANNOT SEE THIS FILE. It scans `admin/*.rs`, and this
//! module lives outside that directory because two of its four routes are member-facing. The
//! equivalent source-level gate assertions are in `instrument_pack_tests.rs`.

use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::{json_err, json_err_msg, no_content};
use crate::storage::{instrument_pack_key, placement_err_response, StorageClass, StorageRouter};
use crate::utils::now_ms;
use serde::Deserialize;
use worker::*;

/// Hard ceiling for an uploaded pack, in the `media/handlers.rs` style (a content-length gate
/// first, the buffered length second).
///
/// ⚠ 200 MiB is the WORKER's stop, not the platform's. Cloudflare refuses a request body over
/// the plan's limit (100 MB on Free/Pro) before the worker ever runs, and an isolate has 128 MB
/// of memory while the body must be buffered once to hash it. The packs this is built for are
/// ~30 MB (GeneralUser GS v2.0.3); anything near this ceiling will die on the platform's limit
/// or the isolate's memory, whichever comes first.
const MAX_PACK_SIZE: u64 = 200 * 1024 * 1024;

/// Display-name ceiling: "GeneralUser GS v2.0.3" is 21 characters, so 120 is generous.
const MAX_NAME_CHARS: usize = 120;

/// The pack is served opaquely — the contract says `application/octet-stream`, and no browser
/// should be invited to sniff a 30 MB binary.
const PACK_CONTENT_TYPE: &str = "application/octet-stream";

/// The bytes under one hash never change, but THIS URL always names the CURRENT pack, so a cache
/// must ask before reusing what it has. The ETag makes that a cheap round-trip (a 304 with no
/// body) instead of a re-download.
const PACK_CACHE_CONTROL: &str = "private, max-age=0, must-revalidate";

// ── SQL contracts (unit-tested with rusqlite — the avatar_objects pattern) ───────

/// The single row. `id = 1` is enforced by the schema's CHECK, so this cannot read a second pack.
pub(crate) const SELECT_PACK_SQL: &str =
    "SELECT hash, name, size_bytes, store_id FROM instrument_pack WHERE id = 1 LIMIT 1";

/// Replace the slot: one server, one pack. Every column is overwritten, so a re-upload under a
/// new name and a new hash leaves nothing of the old row behind.
pub(crate) const UPSERT_PACK_SQL: &str = "INSERT INTO instrument_pack
       (id, hash, name, size_bytes, store_id, uploaded_at_ms)
     VALUES (1, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       hash = excluded.hash,
       name = excluded.name,
       size_bytes = excluded.size_bytes,
       store_id = excluded.store_id,
       uploaded_at_ms = excluded.uploaded_at_ms";

pub(crate) const DELETE_PACK_SQL: &str = "DELETE FROM instrument_pack WHERE id = 1";

#[derive(Deserialize)]
struct PackRow {
    hash: String,
    name: String,
    size_bytes: i64,
    store_id: String,
}

async fn load_pack(db: &D1Database) -> Result<Option<PackRow>> {
    db.prepare(SELECT_PACK_SQL).first(None).await
}

// ── Pure helpers (the testable half) ────────────────────────────────────────────

/// The RIFF header of a SoundFont 2 file: `RIFF`, a 4-byte length, then `sfbk`.
///
/// A sanity check, NOT a security boundary — the bytes are parsed by rustysynth on the client,
/// never here. It exists so a mis-uploaded zip or mp3 cannot take the slot, because every member
/// on the server would then download tens of megabytes of the wrong thing before anything
/// noticed.
pub(crate) fn is_sf2(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"sfbk"
}

/// `X-Pack-Name` → a storable display name: control characters dropped (a header is
/// attacker-shaped input whoever sent it), trimmed, capped at `MAX_NAME_CHARS`. Absent or empty
/// → `""`, and the client shows its own wording. ASCII is the safe set: a header carries bytes,
/// and a non-ASCII name may not survive the trip — the name is cosmetic, the hash is the identity.
pub(crate) fn sanitize_name(raw: Option<String>) -> String {
    let cleaned: String = raw
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    cleaned
        .trim()
        .chars()
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// What a `Range` header asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RangeAsk {
    /// No range, or one this endpoint does not offer → send the whole object with 200. RFC 7233
    /// permits ignoring a range, and it is the honest answer: a 206 must describe what it
    /// actually returns, so answering a form we do not implement with a 206 would be a lie.
    Whole,
    /// `bytes=N-` — resume from N to the end. The only form a phone finishing an interrupted
    /// 30 MB download needs, and therefore the only one implemented.
    From(u64),
    /// The start byte is at or past the end of the object → 416.
    Unsatisfiable,
}

pub(crate) fn parse_range(raw: Option<&str>, size: u64) -> RangeAsk {
    let Some(raw) = raw else {
        return RangeAsk::Whole;
    };
    let lower = raw.trim().to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("bytes=") else {
        return RangeAsk::Whole;
    };
    // A multi-range ask would need a multipart body; serving the whole object is legal and far
    // simpler than getting that wrong.
    if rest.contains(',') {
        return RangeAsk::Whole;
    }
    let Some((start, end)) = rest.split_once('-') else {
        return RangeAsk::Whole;
    };
    // `bytes=N-M` and the suffix form `bytes=-N` both land here and are answered whole.
    if !end.trim().is_empty() {
        return RangeAsk::Whole;
    }
    let Ok(n) = start.trim().parse::<u64>() else {
        return RangeAsk::Whole;
    };
    if n >= size {
        return RangeAsk::Unsatisfiable;
    }
    RangeAsk::From(n)
}

/// The ETag as it goes on the wire: the hash in quotes (a strong validator).
pub(crate) fn etag_of(hash: &str) -> String {
    format!("\"{hash}\"")
}

/// Does an `If-None-Match` name the pack we hold? A comma-separated list is compared entry by
/// entry; `*` matches anything present; a weak validator (`W/"…"`) counts, because the comparison
/// a 304 uses is the weak one; and a bare unquoted hash is accepted too, since a hand-written
/// client will send one sooner or later.
pub(crate) fn if_none_match_hits(raw: &str, hash: &str) -> bool {
    raw.split(',').any(|entry| {
        let t = entry.trim();
        let t = t.strip_prefix("W/").unwrap_or(t);
        let t = t.trim_matches('"');
        t == "*" || t == hash
    })
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name).ok().flatten()
}

// ── Handlers ────────────────────────────────────────────────────────────────────

/// `PUT /admin/instrument-pack` — OWNER ONLY. Body: the raw `.sf2`. Header: `X-Pack-Name`
/// (optional display name). Answers `200 {hash, name, size_bytes}`.
///
/// Ordering is PUT-then-D1, the avatar rule: the pack has no TTL, so a row written before a
/// failed object write would be a permanent ghost — the download stuck at 404 with no sweep that
/// could ever clear it. The object goes in first, the row moves to it second, and only then is
/// the previous object removed.
///
/// The object is rewritten even when the hash is unchanged. It is an idempotent overwrite at the
/// same key, it costs one owner-initiated upload, and it REPAIRS the case where the object
/// vanished from the bucket while the row survived.
pub async fn put_pack(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // OWNER-ONLY, not require_admin: hosting a pack spends the server's storage and hands every
    // member a file to run through their synth. Same authority class as admin/storage.rs.
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    // Storage is OPTIONAL (no R2 binding on a Lite install): answer 503 after auth and before
    // anything is buffered, symmetric with media/avatar upload.
    let router = StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }

    // Early gate: a declared length over the ceiling is rejected WITHOUT reading the body.
    if let Some(n) = header(&req, "content-length").and_then(|s| s.parse::<u64>().ok()) {
        if n > MAX_PACK_SIZE {
            return json_err_msg(413, "bad_size", &MAX_PACK_SIZE.to_string());
        }
    }
    let name = sanitize_name(header(&req, "x-pack-name"));

    // ONE buffer: the bytes are read once, hashed in place, and MOVED into the store by
    // `put_once` (which, unlike `put_new`, does not clone them for a retry).
    let bytes = req.bytes().await?;
    // Authoritative gate: content-length can lie.
    if bytes.len() as u64 > MAX_PACK_SIZE {
        return json_err_msg(413, "bad_size", &MAX_PACK_SIZE.to_string());
    }
    if !is_sf2(&bytes) {
        return json_err(400, "not_a_soundfont");
    }
    let size = bytes.len() as i64;
    let hash = blake3::hash(&bytes).to_hex().to_string();

    let db = ctx.env.d1("DB")?;
    let existing = load_pack(&db).await?;

    let store_id = match router
        .put_once(
            StorageClass::Media,
            &instrument_pack_key(&hash),
            bytes,
            PACK_CONTENT_TYPE,
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => return placement_err_response(e),
    };

    db.prepare(UPSERT_PACK_SQL)
        .bind(&[
            d1_text(&hash),
            d1_text(&name),
            d1_int(size),
            d1_text(&store_id),
            d1_int(now_ms() as i64),
        ])?
        .run()
        .await?;

    // The previous object, now that the row points at the new one. A failed delete is handed to
    // `storage_orphans`, where the daily `retry_orphans` picks it up — a leaked 30 MB object is
    // worth a retry queue, and the pack itself is already consistent either way.
    if let Some(old) = existing {
        if old.hash != hash {
            drop_object(&router, &db, &old).await;
        }
    }

    Response::from_json(&serde_json::json!({
        "hash": hash,
        "name": name,
        "size_bytes": size,
    }))
}

/// `DELETE /admin/instrument-pack` — OWNER ONLY. 204, and 204 again when no pack is hosted
/// (delete is idempotent; "there is none" is the state the caller asked for).
///
/// The ROW goes first, deliberately. A row pointing at a missing object is a broken download
/// nothing can repair; an object with no row is an orphan the retry queue still reaches.
pub async fn delete_pack(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let Some(existing) = load_pack(&db).await? else {
        return no_content();
    };
    db.prepare(DELETE_PACK_SQL).run().await?;
    let router = StorageRouter::from_env(&ctx.env).await?;
    drop_object(&router, &db, &existing).await;
    no_content()
}

/// `GET /instrument-pack/meta` — any active member. `{hash, name, size_bytes}`, or 404
/// `{"error":"no_pack"}` when this server hosts none. Cheap by design: the client asks on every
/// open of a sampled instrument and only fetches the bytes when the hash differs from its copy.
pub async fn meta(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = require_active_auth(&req, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let Some(rec) = load_pack(&db).await? else {
        return json_err(404, "no_pack");
    };
    Response::from_json(&serde_json::json!({
        "hash": rec.hash,
        "name": rec.name,
        "size_bytes": rec.size_bytes,
    }))
}

/// `GET /instrument-pack` — any active member. Streams the object with `Content-Length`, an
/// `ETag`, `Accept-Ranges`, a 304 for `If-None-Match` and a 206 for `Range: bytes=N-`.
///
/// The body NEVER passes through a `Vec` here (`StorageRouter::get_stream`): 30 MB buffered in a
/// 128 MB isolate would be held twice over. `Content-Length` comes from the D1 row rather than
/// the backend, because the row is what the upload measured — if the two ever disagreed, the
/// stream would be cut to the declared length, which is why the row's size is written from the
/// buffered body and not from the client's content-length header.
pub async fn download(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let uid = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // Egress guard, tighter than media's 600/5min because one hit here is tens of megabytes. A
    // resume takes a handful of requests, so 20 per 5 minutes leaves honest use alone; a KV error
    // FAILS OPEN, as everywhere else.
    if !check_rate_limit_env(&ctx.env, &format!("pack:down:{uid}"), 20, 5 * 60).await {
        return json_err(429, "rate_limited");
    }

    let db = ctx.env.d1("DB")?;
    let Some(rec) = load_pack(&db).await? else {
        return json_err(404, "no_pack");
    };

    // 304 before any storage call: the member already holds this hash.
    if let Some(inm) = header(&req, "if-none-match") {
        if if_none_match_hits(&inm, &rec.hash) {
            let headers = Headers::new();
            headers.set("etag", &etag_of(&rec.hash))?;
            headers.set("cache-control", PACK_CACHE_CONTROL)?;
            return Ok(Response::empty()?.with_status(304).with_headers(headers));
        }
    }

    let size = rec.size_bytes.max(0) as u64;
    let offset = match parse_range(header(&req, "range").as_deref(), size) {
        RangeAsk::Whole => 0,
        RangeAsk::From(n) => n,
        RangeAsk::Unsatisfiable => {
            let headers = Headers::new();
            headers.set("content-range", &format!("bytes */{size}"))?;
            return Ok(Response::empty()?.with_status(416).with_headers(headers));
        }
    };

    let router = StorageRouter::from_env(&ctx.env).await?;
    let key = instrument_pack_key(&rec.hash);
    let stream = match router.get_stream(&rec.store_id, &key, offset).await {
        Ok(Some(s)) => s,
        // The row says there is a pack and the store says there is not: the operator emptied the
        // bucket by hand, or a backend was removed. Same answer as no pack at all — the client
        // falls back to its procedural synth either way.
        Ok(None) => return json_err(404, "no_pack"),
        Err(_) => return json_err(503, "storage_backend_unavailable"),
    };

    let headers = Headers::new();
    headers.set("content-type", PACK_CONTENT_TYPE)?;
    headers.set("etag", &etag_of(&rec.hash))?;
    headers.set("accept-ranges", "bytes")?;
    headers.set("cache-control", PACK_CACHE_CONTROL)?;
    headers.set("content-length", &(size - offset).to_string())?;
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

/// Remove a pack object, falling back to the orphan queue. Shared by replace (PUT) and DELETE so
/// the two cannot drift apart.
async fn drop_object(router: &StorageRouter, db: &D1Database, rec: &PackRow) {
    let key = instrument_pack_key(&rec.hash);
    if router.delete(&rec.store_id, &key).await.is_err() {
        crate::storage::maint::insert_orphans(db, &[(rec.store_id.clone(), key, rec.size_bytes)])
            .await;
    }
}

#[cfg(test)]
#[path = "instrument_pack_tests.rs"]
mod tests;
