//! Media blob storage — single choke-point + BACKEND ABSTRACTION.
//!
//! Two layers:
//!   - `BlobStore` (backend handle: KEY-based put/get/delete + probe) — `r2.rs`/`s3.rs`.
//!   - `StorageRouter` (placement/resolution; the ONLY thing handlers talk to) — `router.rs`.
//!
//! EVERY blob get/put/delete goes through here; no handler calls `env.bucket("MEDIA")`
//! directly. The router loads D1 `storage_backends` behind a 60s per-isolate cache; with only
//! the `r2-primary` row present reads/writes resolve to R2.
//!
//! Why an enum instead of `trait`+`dyn`: the workers-rs WASM world is `!Send`, which drags in
//! `async_trait(?Send)` / boxed-dyn friction. For a small fixed set of backends enum dispatch
//! is lighter.
//!
//! THE KEY SCHEME belongs to this module, not to the backends (`media_key`/`code_key`/
//! `plugin_media_key`): every backend uses the SAME key, so moving a blob between backends is
//! a plain copy with an unchanged key — the precondition for `drain.rs`.

pub mod drain;
mod health;
pub mod maint;
pub mod pin;
mod r2;
mod router;
mod s3;

pub use health::{probe_all, write_health};
pub use r2::R2Store;
pub use router::{invalidate_storage_cache, placement_err_response, StorageRouter};
pub use s3::{validate_config as validate_s3_config, S3Config, S3Store};

/// The default backend id. Meta rows (media_objects/plugin_media_objects/plugin_code_objects)
/// carry this store_id, and in single-backend mode ALL reads/writes resolve here. Additional
/// backends are 's3-<8hex>'.
pub const PRIMARY_STORE_ID: &str = "r2-primary";

/// A blob fetched from a backend: raw bytes + content-type.
pub struct BlobObject {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// A blob on its way to the client WITHOUT passing through a `Vec<u8>`.
///
/// Why this exists beside `BlobObject`: buffering is the right shape for a 400 KB avatar and the
/// wrong one for a 30 MB instrument pack. An isolate has 128 MB, and a buffered read holds the
/// object twice — once decoded here, once as the response body.
pub enum BlobStream {
    /// R2: `ObjectBody::response_body` hands the runtime the object's own stream, so the worker
    /// spends no CPU on the bytes at all.
    Passthrough(worker::ResponseBody),
    /// S3: workerd gives us a fetch body and we hand it on. Nothing is buffered either, but the
    /// chunks are pumped through this isolate.
    Pumped(worker::ByteStream),
}

impl BlobStream {
    /// Hand the body to the client with the caller's status and headers. The caller owns
    /// `content-length`/`content-range`: a streamed body carries no length of its own, and the
    /// authority for the size is the D1 meta row, not the backend's answer.
    pub fn into_response(
        self,
        status: u16,
        headers: worker::Headers,
    ) -> worker::Result<worker::Response> {
        let builder = worker::ResponseBuilder::new()
            .with_status(status)
            .with_headers(headers);
        match self {
            BlobStream::Passthrough(body) => Ok(builder.body(body)),
            BlobStream::Pumped(stream) => builder.from_stream(stream),
        }
    }
}

/// Placement class. Every class follows the same priority order with one exception: the group
/// library can be PINNED to chosen stores (`storage_backends.library_pin`, 0041; the rule is
/// `router.rs` `pinned_only`). The class is threaded through every PUT, so a further pin — e.g.
/// keep plugin-code on r2 — is again a change to the router alone.
pub enum StorageClass {
    Media,
    PluginMedia,
    PluginCode,
    /// A group's library part (`room_library.rs`) — the durable, room-charged class.
    Library,
}

/// A single backend handle. KEY-based (the key scheme lives in this module: `media_key` etc.).
pub enum BlobStore {
    R2(R2Store),
    S3(S3Store),
}

impl BlobStore {
    /// Write a blob (content-type goes into the backend's metadata). Idempotent overwrite.
    pub async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> worker::Result<()> {
        match self {
            BlobStore::R2(s) => s.put(key, bytes, content_type).await,
            BlobStore::S3(s) => s.put(key, bytes, content_type).await,
        }
    }

    /// Read a blob; `None` when it does not exist.
    pub async fn get(&self, key: &str) -> worker::Result<Option<BlobObject>> {
        match self {
            BlobStore::R2(s) => s.get(key).await,
            BlobStore::S3(s) => s.get(key).await,
        }
    }

    /// Read a blob as a STREAM, starting at `offset` bytes (0 = the whole object); `None` when
    /// the key does not exist. Only the open-ended form is offered because only `Range: bytes=N-`
    /// has a caller — a resuming download.
    pub async fn get_stream(&self, key: &str, offset: u64) -> worker::Result<Option<BlobStream>> {
        match self {
            BlobStore::R2(s) => s.get_stream(key, offset).await,
            BlobStore::S3(s) => s.get_stream(key, offset).await,
        }
    }

    /// Delete a blob. MUST be IDEMPOTENT (missing key → Ok); a genuine backend error is
    /// propagated so the caller keeps the D1 meta row, which is what prevents orphaned blobs
    /// (the established R2 discipline).
    pub async fn delete(&self, key: &str) -> worker::Result<()> {
        match self {
            BlobStore::R2(s) => s.delete(key).await,
            BlobStore::S3(s) => s.delete(key).await,
        }
    }

    /// Live verification: PUT→GET→(byte compare)→DELETE on a `probe/<uuid>` key. It goes through
    /// the same put/get/delete choke-point, so an R2 binding and a set of S3 credentials are
    /// exercised by one round-trip. The cleanup DELETE is best-effort — whatever the probe
    /// concluded, it should not leave a trace. A byte mismatch → Err.
    pub async fn probe(&self) -> worker::Result<()> {
        let key = format!("probe/{}", uuid::Uuid::new_v4());
        let payload = b"sezi-probe".to_vec();
        self.put(&key, payload.clone(), "application/octet-stream")
            .await?;
        let got = self.get(&key).await;
        let _ = self.delete(&key).await; // best-effort cleanup
        match got? {
            Some(o) if o.bytes == payload => Ok(()),
            Some(_) => Err(worker::Error::RustError("probe: bit mismatch".into())),
            None => Err(worker::Error::RustError("probe: could not read back the written blob".into())),
        }
    }
}

// ── Key scheme (backend-agnostic; every backend uses the SAME key) ────────────

/// Key for ephemeral user media (ack + TTL). Meta lives in `media_objects`.
pub fn media_key(blob_id: &str) -> String {
    format!("media/{blob_id}")
}

/// Key for plugin CODE blobs — PERSISTENT and room-scoped (anti-IDOR: the
/// `/plugin-blob/:room/:id` path is membership-checked, so even knowing another room's blob_id
/// gets you nowhere without its prefix).
pub fn code_key(room_id: &str, blob_id: &str) -> String {
    format!("plugin-code/{room_id}/{blob_id}")
}

/// Key for member-uploadable plugin MEDIA — PERSISTENT and room-scoped (a namespace separate
/// from code).
pub fn plugin_media_key(room_id: &str, blob_id: &str) -> String {
    format!("plugin-media/{room_id}/{blob_id}")
}

/// Key for a group LIBRARY part — durable (kept until deleted unless the server sets a library
/// retention) and room-scoped like plugin media, under a namespace of its own so a drain, a
/// teardown or an operator browsing the bucket can tell the classes apart. SQL in
/// `room_library.rs` and `room_library_cleanup.rs` spells this same shape
/// (`'room-library/' || room_id || '/' || object_id`), so it may never change.
pub fn library_key(room_id: &str, object_id: &str) -> String {
    format!("room-library/{room_id}/{object_id}")
}

/// Key for profile/group avatar blobs — PERSISTENT (no TTL) and user-scoped. `avatar_objects`
/// is single-slot meta (one object_id per user_id); on a new upload the old object is pushed
/// into `storage_orphans` under this key and the daily `retry_orphans` removes it from the
/// backend.
pub fn avatar_key(user_id: &str, object_id: &str) -> String {
    format!("avatar/{user_id}/{object_id}")
}

/// Key for the operator-hosted instrument pack — PERSISTENT, server-scoped, and the ONE object
/// this relay stores in PLAINTEXT (a SoundFont is public content, not a member's message; see
/// `instrument_pack.rs`). Content-addressed: the name IS the BLAKE3 hash, so re-uploading the
/// same file writes the same key and a member's hash pin stays valid.
pub fn instrument_pack_key(hash: &str) -> String {
    format!("packs/{hash}.sf2")
}

/// Build one backend's live `BlobStore` from `kind` + `config_json`. Shared by the router
/// (build_stores), the daily health probe (health::probe_all) and the manual probe endpoint
/// (admin/storage.rs) → backend construction cannot diverge between the three paths.
///   - `r2_binding` → the MEDIA binding (absent = Lite → `Err("binding_missing")` → the backend
///     is skipped).
///   - `s3` → parse `config_json` (malformed → `Err(short reason)`; a blob on that backend then
///     gets a 503).
///
/// The error TEXT is short and secret-free, so it can be stored in health `last_health_err`.
pub(crate) fn build_store(
    env: &worker::Env,
    kind: &str,
    config_json: &str,
) -> std::result::Result<BlobStore, String> {
    match kind {
        "r2_binding" => env
            .bucket("MEDIA")
            .map(|b| BlobStore::R2(R2Store::new(b)))
            .map_err(|_| "binding_missing".to_string()),
        "s3" => S3Store::from_config_json(config_json)
            .map(BlobStore::S3)
            .map_err(|e| e.to_string().chars().take(120).collect()),
        other => Err(format!("unsupported_kind:{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key scheme is frozen: a moved blob must be read and written under the same key, so
    /// these strings may never change shape.
    #[test]
    fn key_schema_is_bit_identical_to_the_existing_one() {
        assert_eq!(media_key("abc"), "media/abc");
        assert_eq!(code_key("room1", "blob1"), "plugin-code/room1/blob1");
        assert_eq!(plugin_media_key("room1", "blob1"), "plugin-media/room1/blob1");
        assert_eq!(library_key("room1", "obj1"), "room-library/room1/obj1");
        assert_eq!(avatar_key("user1", "obj1"), "avatar/user1/obj1");
        assert_eq!(instrument_pack_key("ab12"), "packs/ab12.sf2");
    }
}
