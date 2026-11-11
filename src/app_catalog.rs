//! The server's app catalog (`docs/PLUGINS_BOTS_REVIEW_2026_11.md` § 3.4, Wave C5; decision D3):
//! the signed web apps this server's OWNER put up, from which a group admin picks in the app's
//! "add app" sheet. The admin's app then installs the chosen bundle exactly as an imported one —
//! uploaded to the room encrypted (`plugin_blob.rs`) and fanned out by `plugin_code_dist` — so a
//! member's device fetches nothing but its own room's code, never from a third party.
//!
//! **Stored**: one `app_catalog` row per bundle (migration 0060, expand-only) and the bundle's bytes
//! in the media store under [`object_key`]. No media store (a "Lite" relay) = no catalog: the list
//! answers `503 media_not_configured`, which the app words, and `/capabilities` says
//! `app_catalog: false`.
//!
//! **Plaintext, deliberately.** Unlike a room's plugin code, a catalog bundle is kept as the bytes
//! the publisher shipped. It is public code: the owner chose to offer it to every group admin of
//! the server, and the relay has to read it to check it (below). Encrypting it under a key the
//! relay itself holds would hide nothing from the relay and nothing from anyone it serves. What a
//! member must be able to trust is not secrecy but integrity, and that does not rest on the relay:
//! the publisher's Ed25519 signature over every file is verified on the admin's device before the
//! assign and on every member's device before the code is cached, against the publisher pinned for
//! that app id. The object's name is the BLAKE3 of its bytes, which the admin's core checks too.
//! What a room's members write with the app stays end to end as before; the catalog never sees it.
//!
//! **What an owner's upload must be**: a bundle `sezi_plugin_fmt` opens, signed (manifest v2 —
//! an unsigned page belongs to a group admin's own import, not a server-wide offer), and — when the
//! server keeps an allowlist (`plugin_allowlist.rs`) — one the list approves with what it grants.

use std::collections::BTreeSet;

use base64::Engine as _;
use sezi_plugin_fmt::allowlist::{self as rule, Allowlist, Candidate};
use sezi_plugin_fmt::plugin_bundle::unpack_bundle;

/// The bundle is not one `sezi_plugin_fmt` opens (a bad tar, a file that fails its hash, too big).
pub(crate) const BAD_BUNDLE: &str = "app-catalog/bad-bundle";
/// The bundle carries no publisher signature (manifest v2).
pub(crate) const NOT_SIGNED: &str = "app-catalog/not-signed";
/// The catalog holds [`MAX_ENTRIES`] bundles.
pub(crate) const FULL: &str = "app-catalog/full";
/// No such entry.
pub(crate) const NOT_FOUND: &str = "app-catalog/not-found";

/// How many bundles one server offers at most — a screen's worth, and a bound on the store.
pub(crate) const MAX_ENTRIES: i64 = 200;
/// The largest bundle, as the format allows it.
pub(crate) const MAX_BYTES: usize = sezi_plugin_fmt::plugin_bundle::MAX_BUNDLE_BYTES;

pub(crate) const LIST_SQL: &str = "SELECT id, code_hash, app_id, name, version, publisher_key, \
     publisher_name, manifest, size_bytes, added_at FROM app_catalog ORDER BY name COLLATE NOCASE, \
     version DESC";
pub(crate) const COUNT_SQL: &str = "SELECT COUNT(*) AS n FROM app_catalog";
pub(crate) const STORE_SQL: &str = "SELECT store_id FROM app_catalog WHERE id = ?1";
/// Binds: id, code_hash, app_id, name, version, publisher_key, publisher_name, manifest,
/// size_bytes, store_id, added_by, added_at. The same bundle again only refreshes who added it.
pub(crate) const INSERT_SQL: &str = "INSERT INTO app_catalog (id, code_hash, app_id, name, \
     version, publisher_key, publisher_name, manifest, size_bytes, store_id, added_by, added_at) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
     ON CONFLICT (id) DO UPDATE SET added_by = excluded.added_by, added_at = excluded.added_at";
pub(crate) const DELETE_SQL: &str = "DELETE FROM app_catalog WHERE id = ?1";

/// Where a bundle's bytes live in the store.
pub(crate) fn object_key(id: &str) -> String {
    format!("apps/{id}.tar")
}

/// An entry id as a path names it: 64 lowercase hex characters.
pub(crate) fn is_entry_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One stored row as D1 answers it.
#[derive(serde::Deserialize, Debug, Clone, PartialEq)]
pub(crate) struct DbRow {
    pub id: String,
    pub code_hash: String,
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub publisher_key: String,
    pub publisher_name: String,
    pub manifest: String,
    pub size_bytes: i64,
    pub added_at: i64,
}

/// A bundle the owner may add, as it will be stored.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Accepted {
    pub id: String,
    pub code_hash: String,
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub publisher_key: String,
    pub publisher_name: String,
    pub manifest: String,
}

/// Open and judge an owner's upload. Pure.
pub(crate) fn judge_upload(bytes: &[u8], list: &Allowlist) -> Result<Accepted, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(BAD_BUNDLE);
    }
    let bundle = unpack_bundle(bytes).map_err(|_| BAD_BUNDLE)?;
    let app = bundle.app.ok_or(NOT_SIGNED)?;
    let digest = blake3::hash(bytes);
    let code_hash = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest.as_bytes());
    let m = &app.manifest;
    let granted: BTreeSet<String> = m.capabilities.granted();
    let candidate = Candidate {
        plugin_id: &m.id,
        publisher_key_id: Some(&m.publisher.key_id),
        code_hash: Some(&code_hash),
        granted: &granted,
    };
    if !list.approves(&candidate) {
        return Err(rule::NOT_APPROVED);
    }
    Ok(Accepted {
        id: digest.to_hex().to_string(),
        code_hash,
        app_id: m.id.clone(),
        name: m.name.clone(),
        version: m.version.to_string(),
        publisher_key: m.publisher.key_id.clone(),
        publisher_name: m.publisher.name.clone(),
        manifest: String::from_utf8_lossy(&app.manifest_json).into_owned(),
    })
}

/// The catalog as every answer gives it: `{"entries":[…]}`, each entry its id, the app's id, name,
/// version, publisher, size, when it was added, and the manifest the publisher signed (as JSON, so
/// the app can show what it asks for before it is picked).
pub(crate) fn view(rows: &[DbRow]) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "code_hash": r.code_hash,
                "app_id": r.app_id,
                "name": r.name,
                "version": r.version,
                "publisher_key": r.publisher_key,
                "publisher_name": r.publisher_name,
                "manifest": serde_json::from_str::<serde_json::Value>(&r.manifest)
                    .unwrap_or(serde_json::Value::Null),
                "size_bytes": r.size_bytes,
                "added_at": r.added_at,
            })
        })
        .collect();
    serde_json::json!({ "entries": entries })
}

#[cfg(test)]
#[path = "app_catalog_tests.rs"]
mod tests;
