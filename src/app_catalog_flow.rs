//! What the catalog's four routes do (`admin/app_catalog.rs`), over two small ports — the media
//! store ([`CatalogBlobs`]) and the `app_catalog` table ([`CatalogRows`]) — so the whole of it runs
//! in the host tests against a store double and the real schema (`app_catalog_flow_tests.rs`). The
//! handlers only authorize, read the request and adapt the answer; the media store and D1 are their
//! adapters.
//!
//! No media store (a "Lite" relay) is a `None` store: every route answers `503
//! media_not_configured` before it reads anything else.

use crate::app_catalog::{self as catalog, judge_upload, object_key, Accepted, DbRow};
use sezi_plugin_fmt::allowlist::Allowlist;

/// The media store, as the catalog uses it.
pub(crate) trait CatalogBlobs {
    /// Why a write found no place (the store router's `PlacementError`).
    type PutErr;
    /// Write a new object; the id of the store it went to.
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<String, Self::PutErr>;
    /// An object's bytes; `Err` = the store did not answer.
    async fn get(&self, store_id: &str, key: &str) -> Result<Option<Vec<u8>>, ()>;
    /// Best effort.
    async fn delete(&self, store_id: &str, key: &str);
}

/// The `app_catalog` table.
pub(crate) trait CatalogRows {
    async fn list(&self) -> Vec<DbRow>;
    async fn count(&self) -> Result<i64, String>;
    async fn store_id_of(&self, id: &str) -> Option<String>;
    async fn insert(&self, a: &Accepted, size: i64, store_id: &str, by: &str, at_ms: i64) -> Result<(), String>;
    async fn delete(&self, id: &str) -> Result<(), String>;
}

/// What a route answers.
#[derive(Debug, PartialEq)]
pub(crate) enum Outcome<E> {
    /// `{"entries":[…]}`.
    List(Vec<DbRow>),
    /// A bundle's bytes, which hash to its id.
    Bytes(Vec<u8>),
    /// A refusal: status and code.
    Refused(u16, &'static str),
    /// The store found no place for the bytes.
    PutFailed(E),
    /// The table did not answer.
    Failed(String),
}

/// The refusal of a relay with no media store.
pub(crate) const NO_STORE: (u16, &str) = (503, "media_not_configured");

pub(crate) async fn list<B: CatalogBlobs, R: CatalogRows>(store: Option<&B>, rows: &R) -> Outcome<B::PutErr> {
    if store.is_none() {
        return Outcome::Refused(NO_STORE.0, NO_STORE.1);
    }
    Outcome::List(rows.list().await)
}

/// The bytes of entry `id` — only bytes whose BLAKE3 IS the id: an object that was replaced or
/// damaged in the store is no entry (the admin's core checks the same before it assigns).
pub(crate) async fn fetch<B: CatalogBlobs, R: CatalogRows>(
    store: Option<&B>,
    rows: &R,
    id: &str,
) -> Outcome<B::PutErr> {
    let Some(store) = store else { return Outcome::Refused(NO_STORE.0, NO_STORE.1) };
    if !catalog::is_entry_id(id) {
        return Outcome::Refused(404, catalog::NOT_FOUND);
    }
    let Some(store_id) = rows.store_id_of(id).await else {
        return Outcome::Refused(404, catalog::NOT_FOUND);
    };
    match store.get(&store_id, &object_key(id)).await {
        Ok(Some(bytes)) if blake3::hash(&bytes).to_hex().as_str() == id => Outcome::Bytes(bytes),
        Ok(_) => Outcome::Refused(404, catalog::NOT_FOUND),
        Err(()) => Outcome::Refused(503, "storage_backend_unavailable"),
    }
}

/// The owner's upload: judged (`judge_upload`), stored under its digest, its row written.
pub(crate) async fn add<B: CatalogBlobs, R: CatalogRows>(
    store: Option<&B>,
    rows: &R,
    bytes: Vec<u8>,
    list: &Allowlist,
    by: &str,
    at_ms: i64,
) -> Outcome<B::PutErr> {
    let Some(store) = store else { return Outcome::Refused(NO_STORE.0, NO_STORE.1) };
    let accepted = match judge_upload(&bytes, list) {
        Ok(a) => a,
        Err(code) => return Outcome::Refused(400, code),
    };
    let n = match rows.count().await {
        Ok(n) => n,
        Err(e) => return Outcome::Failed(e),
    };
    if n >= catalog::MAX_ENTRIES && rows.store_id_of(&accepted.id).await.is_none() {
        return Outcome::Refused(400, catalog::FULL);
    }
    let size = bytes.len() as i64;
    let store_id = match store.put(&object_key(&accepted.id), bytes).await {
        Ok(sid) => sid,
        Err(e) => return Outcome::PutFailed(e),
    };
    if let Err(e) = rows.insert(&accepted, size, &store_id, by, at_ms).await {
        return Outcome::Failed(e);
    }
    Outcome::List(rows.list().await)
}

/// The owner takes entry `id` off; its bytes go with the row.
pub(crate) async fn remove<B: CatalogBlobs, R: CatalogRows>(
    store: Option<&B>,
    rows: &R,
    id: &str,
) -> Outcome<B::PutErr> {
    let Some(store) = store else { return Outcome::Refused(NO_STORE.0, NO_STORE.1) };
    if !catalog::is_entry_id(id) {
        return Outcome::Refused(404, catalog::NOT_FOUND);
    }
    if let Some(store_id) = rows.store_id_of(id).await {
        if let Err(e) = rows.delete(id).await {
            return Outcome::Failed(e);
        }
        // Best effort: a row is gone either way, and an object left behind is never served — the
        // fetch reads the row first.
        store.delete(&store_id, &object_key(id)).await;
    }
    Outcome::List(rows.list().await)
}

#[cfg(test)]
#[path = "app_catalog_flow_tests.rs"]
mod tests;
