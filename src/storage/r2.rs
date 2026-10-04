//! Cloudflare R2 backend — the KEY-based form of `MediaStore::R2Store` (2026-07-06).
//!
//! Faz 1 was a pure move: the old `R2Store` had a method per channel (media/code/plugin-media)
//! and computed keys internally; the key scheme now lives in
//! `storage::{media_key,code_key,plugin_media_key}`, so this file exposes ONE put/get/delete and
//! the caller passes a ready-made key. Behaviour is unchanged (same R2 calls, same content-type
//! discipline).
//!
//! **The CF lock-in is confined to this file** — moving to a portable server (VPS/Pi) means
//! writing a new backend struct (like `s3.rs`) and adding a `BlobStore` variant; no handler
//! changes.

use worker::*;

use super::BlobObject;

pub struct R2Store {
    bucket: Bucket,
}

impl R2Store {
    /// Build from the MEDIA binding. The binding lookup is CHEAP (it never hits the network); if
    /// the binding is absent, router `from_env` does not add this backend at all
    /// (any_available=false → 503 media_not_configured).
    pub fn new(bucket: Bucket) -> Self {
        R2Store { bucket }
    }

    /// Write a blob — content-type goes into R2's http_metadata. Idempotent overwrite (a second
    /// PUT on the same key replaces it).
    pub async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<()> {
        self.bucket
            .put(key, bytes)
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_string()),
                ..Default::default()
            })
            .execute()
            .await?;
        Ok(())
    }

    /// Read a blob; `None` when absent. content-type comes from R2 metadata (else octet-stream).
    pub async fn get(&self, key: &str) -> Result<Option<BlobObject>> {
        let Some(obj) = self.bucket.get(key).execute().await? else {
            return Ok(None);
        };
        let Some(body) = obj.body() else {
            return Ok(None);
        };
        let bytes = body.bytes().await?;
        let content_type = obj
            .http_metadata()
            .content_type
            .unwrap_or_else(|| "application/octet-stream".into());
        Ok(Some(BlobObject { bytes, content_type }))
    }

    /// Read a blob as a STREAM (the big-object twin of `get`), starting at `offset` bytes;
    /// `None` when the key is absent. `response_body()` hands the object's own stream to the
    /// runtime, so a 30 MB instrument pack never enters worker memory and costs no CPU time.
    ///
    /// R2 answers an offset past the end of the object with a null body rather than an error, so
    /// that case arrives here as `None` — the caller refuses an unsatisfiable range before ever
    /// getting this far (it knows the size from D1).
    pub async fn get_stream(&self, key: &str, offset: u64) -> Result<Option<super::BlobStream>> {
        let mut builder = self.bucket.get(key);
        if offset > 0 {
            builder = builder.range(Range::OffsetToEnd { offset });
        }
        let Some(obj) = builder.execute().await? else {
            return Ok(None);
        };
        let Some(body) = obj.body() else {
            return Ok(None);
        };
        Ok(Some(super::BlobStream::Passthrough(body.response_body()?)))
    }

    /// Delete a blob. R2's delete is idempotent (a missing key is NOT an error), which makes ack
    /// and cleanup retries safe. A GENUINE R2 error (outage) is propagated so the caller keeps its
    /// D1 meta row — otherwise we would create an orphan: an R2 object with no D1 record, which
    /// cleanup can never see.
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.bucket.delete(key).await?;
        Ok(())
    }
}
