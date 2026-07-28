//! Media blob storage — single choke-point + BACKEND ABSTRACTION.
//!
//! Pluggable-Storage epic Faz 1-2 (2026-07-08): the single-file `storage.rs` enum
//! (`MediaStore`) became a two-layer module directory:
//!   - `BlobStore` (backend handle: KEY-based put/get/delete + probe) — `r2.rs`/`s3.rs`.
//!   - `StorageRouter` (placement/resolution; the ONLY thing handlers talk to) — `router.rs`.
//!   - `s3.rs` = the Faz 2 S3-compatible adapter (SigV4-signed workerd fetch;
//!     B2/MinIO/second R2).
//!
//! EVERY blob get/put/delete goes through here; no handler calls `env.bucket("MEDIA")`
//! directly. Single-backend behaviour (`r2-primary`, no S3 rows) is IDENTICAL to before: the
//! router loads D1 `storage_backends` behind a 60s per-isolate cache, and with only the
//! r2-primary row present reads/writes resolve to R2. Faz 2 = D1 config + multi-backend
//! resolution + the S3 adapter; Faz 3 = placement policy
//! (priority/overflow/max_bytes/fallback) + health; Faz 4 = the drain/move engine
//! (`drain.rs`: draining backend → the remaining ones, then auto-disabled).
//!
//! Why an enum instead of `trait`+`dyn`: the workers-rs WASM world is `!Send`, which drags in
//! `async_trait(?Send)` / boxed-dyn friction. For a small fixed set of backends enum dispatch
//! is lighter.
//!
//! THE KEY SCHEME now belongs to this module, not to the backends (`media_key`/`code_key`/
//! `plugin_media_key`): every backend uses the SAME key, so moving a blob between backends is
//! a plain copy with an unchanged key (the precondition for the Faz 4 drain).

pub mod drain;
mod health;
pub mod maint;
mod r2;
mod router;
mod s3;

pub use health::{probe_all, write_health};
pub use r2::R2Store;
pub use router::{invalidate_storage_cache, placement_err_response, StorageRouter};
pub use s3::{validate_config as validate_s3_config, S3Config, S3Store};

/// The Faz 1 single-backend id — migration 0028's default ('r2-primary'). Meta rows
/// (media_objects/plugin_media_objects/plugin_code_objects) carry this store_id, and in
/// single-backend mode ALL reads/writes resolve here. Faz 2+ multi-backend ids: 's3-<8hex>'.
pub const PRIMARY_STORE_ID: &str = "r2-primary";

/// A blob fetched from a backend: raw bytes + content-type.
pub struct BlobObject {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// Placement class — the v1 policy is class-agnostic (every class follows the same priority
/// order); it is threaded through the API so Faz 2+ can add class pinning (e.g. keep
/// plugin-code on r2).
pub enum StorageClass {
    Media,
    PluginMedia,
    PluginCode,
}

/// A single backend handle. KEY-based (the key scheme lives in this module: `media_key` etc.).
/// Faz 2 wired up the `S3(S3Store)` variant (`s3.rs` + `sigv4.rs`).
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

    /// Delete a blob. MUST be IDEMPOTENT (missing key → Ok); a genuine backend error is
    /// propagated so the caller keeps the D1 meta row, which is what prevents orphaned blobs
    /// (the established R2 discipline).
    pub async fn delete(&self, key: &str) -> worker::Result<()> {
        match self {
            BlobStore::R2(s) => s.delete(key).await,
            BlobStore::S3(s) => s.delete(key).await,
        }
    }

    /// Live verification (plan e): PUT→GET→(byte compare)→DELETE on a `probe/<uuid>` key.
    /// Backend-agnostic (it goes through the same put/get/delete choke-point), so an R2 binding
    /// and a set of S3 credentials are exercised by the same round-trip. The cleanup DELETE is
    /// best-effort (whatever the probe concluded, it should not leave a trace). A byte mismatch
    /// → Err.
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

/// Key for profile/group avatar blobs — PERSISTENT (no TTL) and user-scoped. `avatar_objects`
/// is single-slot meta (one object_id per user_id); on a new upload the old object is pushed
/// into `storage_orphans` under this key and the daily `retry_orphans` removes it from the
/// backend.
pub fn avatar_key(user_id: &str, object_id: &str) -> String {
    format!("avatar/{user_id}/{object_id}")
}

/// Build one backend's live `BlobStore` from `kind` + `config_json`. Shared by the router
/// (build_stores), the daily health probe (health::probe_all) and the manual probe endpoint
/// (admin/storage.rs) → backend construction cannot diverge between the three paths.
///   - `r2_binding` → the MEDIA binding (absent = Lite → `Err("binding_missing")` → the backend
///     is skipped).
///   - `s3` → parse `config_json` (malformed → `Err(short reason)`; a blob on that backend then
///     gets a 503, plan f#9).
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

    /// The key scheme must stay BIT-IDENTICAL to the pre-existing
    /// R2Store::key/code_key/plugin_media_key (behaviour invariance: a moved blob is read and
    /// written under the same key).
    #[test]
    fn key_schema_is_bit_identical_to_the_existing_one() {
        assert_eq!(media_key("abc"), "media/abc");
        assert_eq!(code_key("room1", "blob1"), "plugin-code/room1/blob1");
        assert_eq!(plugin_media_key("room1", "blob1"), "plugin-media/room1/blob1");
        assert_eq!(avatar_key("user1", "obj1"), "avatar/user1/obj1");
    }
}
