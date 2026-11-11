//! The SIGNED bundle, manifest `v:2` (review 2026-11 § 3.3, Wave C1): a v1 bundle's files plus
//! the app's `sezi-app.json` and its publisher's signature, in the same deterministic tar.
//!
//! **Layout.** `sezgi-manifest.json` first (`v:2`, the entry, every file's path, size and BLAKE3,
//! and `app`: the BLAKE3 and size of `sezi-app.json`), then `sezi-app.json`, then `sezi-app.sig`,
//! then the files sorted by path. The two app entries are RESERVED: they are not in `files`, are
//! never served to the WebView, and no file may take their names.
//!
//! **What is signed.** `DOMAIN ‖ BLAKE3(sezgi-manifest.json) ‖ sezi-app.json`, with the
//! publisher's Ed25519 key named in the app manifest. The bundle manifest commits to every file
//! and to the app manifest, so its hash is the bundle's content digest — the tar's own hash cannot
//! be signed from inside the tar. The app manifest is appended whole as well, so a party that
//! holds only the digest and the manifest (an owner's approval row, a catalog's index) can check
//! the publisher's claim without the files ([`verify_detached`]). `sezi-app.sig` is one line,
//! `<key id> <signature in unpadded base64url>`, and its key id must be the manifest's.
//!
//! **Deterministic.** The same files, manifest and signature make the same tar, so a publisher
//! can ship a zip of them and any packer reproduces the bytes that were signed
//! ([`signing_message`] is what the publisher's tool signs). Nothing here holds a private key.
//!
//! v1 bundles are untouched: `pack_bundle` still writes them byte for byte as before, and
//! `unpack_bundle` reads them as before (`app: None`).

use std::collections::BTreeMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};

use sezi_error::{Error, Result};

use crate::app_manifest::{self, AppManifest, APP_MANIFEST_NAME, MAX_APP_MANIFEST_BYTES};
use crate::plugin_bundle::{
    blake3_b64, content_type_for_path, validate_path, write_tar_entry, BundleAppMeta,
    BundleFileMeta, BundleManifest, MANIFEST_NAME, MAX_BUNDLE_BYTES, MAX_BUNDLE_ENTRIES, TAR_BLOCK,
};

/// The signature's name inside a bundle.
pub const APP_SIGNATURE_NAME: &str = "sezi-app.sig";
/// Domain separation for what a publisher signs: no other Sezi signature can be replayed as one.
pub const SIGNATURE_DOMAIN: &[u8] = b"sezi-app-bundle/1\0";

/// The bundle has no `sezi-app.json`, or its hash or size is not the one the manifest pins.
pub const APP_MANIFEST_MISSING: &str = "plugin/bundle-app-manifest";
/// The bundle has no `sezi-app.sig`, or it is not one `<key id> <signature>` line.
pub const SIGNATURE_MISSING: &str = "plugin/signature-missing";
/// The signature names a key other than the manifest's publisher.
pub const SIGNATURE_KEY_MISMATCH: &str = "plugin/signature-key-mismatch";
/// The signature does not verify.
pub const BAD_SIGNATURE: &str = "plugin/bad-signature";
/// The bundle's entry is not the manifest's, or its icon is not in the bundle.
pub const ENTRY_MISMATCH: &str = "plugin/bundle-entry-mismatch";
/// A file takes a reserved name (`sezi-app.json`, `sezi-app.sig`).
pub const RESERVED_NAME: &str = "plugin/bundle-reserved-name";

/// A v2 bundle's app manifest whose signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApp {
    pub manifest: AppManifest,
    /// `sezi-app.json` exactly as signed.
    pub manifest_json: Vec<u8>,
    /// BLAKE3 of the bundle manifest — the content digest the signature covers.
    pub bundle_digest: [u8; 32],
    /// `sezi-app.sig` as signed (`<key id> <signature>`), trimmed — what an upload presents to an
    /// allowlist relay beside the manifest and the digest (`allowlist`).
    pub signature: String,
}

fn is_reserved(path: &str) -> bool {
    path == APP_MANIFEST_NAME || path == APP_SIGNATURE_NAME
}

/// The message a publisher signs: [`SIGNATURE_DOMAIN`] ‖ `bundle_digest` ‖ `app_json`.
pub fn message(bundle_digest: &[u8; 32], app_json: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + app_json.len());
    m.extend_from_slice(SIGNATURE_DOMAIN);
    m.extend_from_slice(bundle_digest);
    m.extend_from_slice(app_json);
    m
}

/// The bundle manifest a v2 pack writes for these files and this app manifest, and its entry.
/// Validates the paths and the app manifest the way unpack will.
fn v2_manifest(
    files: &BTreeMap<String, Vec<u8>>,
    app_json: &[u8],
) -> Result<(Vec<u8>, AppManifest)> {
    if app_json.len() > MAX_APP_MANIFEST_BYTES {
        return Err(Error::Malformed(app_manifest::BAD_JSON));
    }
    let app = app_manifest::parse_app_manifest(app_json).map_err(Error::Malformed)?;
    if files.is_empty() {
        return Err(Error::Malformed("bundle is empty (no files)"));
    }
    for path in files.keys() {
        validate_path(path)?;
        if is_reserved(path) {
            return Err(Error::Malformed(RESERVED_NAME));
        }
    }
    // The manifest and the two app entries are entries too.
    if files.len() + 3 > MAX_BUNDLE_ENTRIES {
        return Err(Error::Malformed("bundle has more files than the entry ceiling"));
    }
    if !files.contains_key(&app.entry) || app.icon.as_ref().is_some_and(|i| !files.contains_key(i)) {
        return Err(Error::Malformed(ENTRY_MISMATCH));
    }
    let manifest = BundleManifest {
        v: 2,
        entrypoint: app.entry.clone(),
        files: files
            .iter()
            .map(|(path, content)| BundleFileMeta {
                path: path.clone(),
                blake3_b64: blake3_b64(content),
                size: content.len() as u64,
                content_type: content_type_for_path(path).to_string(),
            })
            .collect(),
        app: Some(BundleAppMeta { blake3_b64: blake3_b64(app_json), size: app_json.len() as u64 }),
    };
    let json =
        serde_json::to_vec(&manifest).map_err(|e| Error::Crypto(format!("manifest json: {e}")))?;
    Ok((json, app))
}

fn sorted(files: Vec<(String, Vec<u8>)>) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for (path, content) in files {
        if out.insert(path, content).is_some() {
            return Err(Error::Malformed("duplicate path in the bundle"));
        }
    }
    Ok(out)
}

/// What the publisher signs for these files and this `sezi-app.json` — the same bytes
/// [`unpack_bundle`](crate::plugin_bundle::unpack_bundle) will verify the signature over.
pub fn signing_message(files: Vec<(String, Vec<u8>)>, app_json: &[u8]) -> Result<Vec<u8>> {
    let (manifest_json, _) = v2_manifest(&sorted(files)?, app_json)?;
    Ok(message(blake3::hash(&manifest_json).as_bytes(), app_json))
}

/// The `sezi-app.sig` line for a key and a 64-byte signature.
pub fn signature_line(key_id: &str, signature: &[u8; 64]) -> String {
    format!(
        "{key_id} {}\n",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    )
}

/// Files + `sezi-app.json` + its `sezi-app.sig` → the deterministic v2 tar. The signature is
/// checked before anything is written: a bundle that would not unpack is never made.
pub fn pack_bundle_v2(
    files: Vec<(String, Vec<u8>)>,
    app_json: &[u8],
    signature: &str,
) -> Result<Vec<u8>> {
    let files = sorted(files)?;
    let (manifest_json, app) = v2_manifest(&files, app_json)?;
    let digest = *blake3::hash(&manifest_json).as_bytes();
    verify_detached(&digest, app_json, signature, &app)?;

    let mut out = Vec::new();
    write_tar_entry(&mut out, MANIFEST_NAME, &manifest_json)?;
    write_tar_entry(&mut out, APP_MANIFEST_NAME, app_json)?;
    write_tar_entry(&mut out, APP_SIGNATURE_NAME, signature.as_bytes())?;
    for (path, content) in &files {
        write_tar_entry(&mut out, path, content)?;
    }
    out.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));
    if out.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Malformed("bundle exceeds the 8MB ceiling"));
    }
    Ok(out)
}

/// A file set from an imported zip: v2 when it carries `sezi-app.json` (its `sezi-app.sig` beside
/// it, both taken out of the files), else v1 with `entrypoint` as before. The name is reserved
/// from here on, so a zip that holds one without a signature is refused, not packed as v1.
pub fn pack_any(files: Vec<(String, Vec<u8>)>, entrypoint: &str) -> Result<Vec<u8>> {
    if !files.iter().any(|(p, _)| p == APP_MANIFEST_NAME) {
        return crate::plugin_bundle::pack_bundle(files, entrypoint);
    }
    let mut app_json = None;
    let mut signature = None;
    let mut rest = Vec::with_capacity(files.len());
    for (path, content) in files {
        match path.as_str() {
            APP_MANIFEST_NAME if app_json.is_none() => app_json = Some(content),
            APP_SIGNATURE_NAME if signature.is_none() => signature = Some(content),
            APP_MANIFEST_NAME | APP_SIGNATURE_NAME => {
                return Err(Error::Malformed("duplicate path in the bundle"))
            }
            _ => rest.push((path, content)),
        }
    }
    let signature = signature
        .and_then(|s| String::from_utf8(s).ok())
        .ok_or(Error::Malformed(SIGNATURE_MISSING))?;
    pack_bundle_v2(rest, &app_json.unwrap_or_default(), &signature)
}

/// Check a signature line against a content digest and an app manifest, without the files —
/// what an approval list or a catalog can check from a row. `app` is `app_json` parsed.
pub fn verify_detached(
    bundle_digest: &[u8; 32],
    app_json: &[u8],
    signature: &str,
    app: &AppManifest,
) -> Result<()> {
    let line = signature.trim();
    let (key_id, sig_b64) = line.split_once(' ').ok_or(Error::Malformed(SIGNATURE_MISSING))?;
    if key_id != app.publisher.key_id {
        return Err(Error::Malformed(SIGNATURE_KEY_MISMATCH));
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| Error::Malformed(SIGNATURE_MISSING))?;
    let raw: [u8; 64] = raw.try_into().map_err(|_| Error::Malformed(SIGNATURE_MISSING))?;
    let key =
        VerifyingKey::from_bytes(&app.publisher.key).map_err(|_| Error::Malformed(BAD_SIGNATURE))?;
    key.verify_strict(&message(bundle_digest, app_json), &Signature::from_bytes(&raw))
        .map_err(|_| Error::Malformed(BAD_SIGNATURE))
}

/// Unpack's v2 half, before the file-set check: take the two reserved entries out of `raw`,
/// check the app manifest against the bundle manifest's pin, parse it and verify the signature.
pub(crate) fn take_and_verify(
    raw: &mut BTreeMap<String, Vec<u8>>,
    manifest: &BundleManifest,
    manifest_json: &[u8],
) -> Result<VerifiedApp> {
    if manifest.files.iter().any(|f| is_reserved(&f.path)) {
        return Err(Error::Malformed(RESERVED_NAME));
    }
    let app_json = raw.remove(APP_MANIFEST_NAME).ok_or(Error::Malformed(APP_MANIFEST_MISSING))?;
    let signature = raw.remove(APP_SIGNATURE_NAME).ok_or(Error::Malformed(SIGNATURE_MISSING))?;
    let pin = manifest.app.as_ref().ok_or(Error::Malformed(APP_MANIFEST_MISSING))?;
    if pin.size != app_json.len() as u64 || pin.blake3_b64 != blake3_b64(&app_json) {
        return Err(Error::Malformed(APP_MANIFEST_MISSING));
    }
    let app = app_manifest::parse_app_manifest(&app_json).map_err(Error::Malformed)?;
    let signature = String::from_utf8(signature).map_err(|_| Error::Malformed(SIGNATURE_MISSING))?;
    let bundle_digest = *blake3::hash(manifest_json).as_bytes();
    verify_detached(&bundle_digest, &app_json, &signature, &app)?;
    let signature = signature.trim().to_string();
    Ok(VerifiedApp { manifest: app, manifest_json: app_json, bundle_digest, signature })
}

/// Unpack's v2 half, after the files verified: the entry the bundle opens on is the manifest's,
/// and the icon it names is in the bundle.
pub(crate) fn check_against_files(
    app: &VerifiedApp,
    manifest: &BundleManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let m = &app.manifest;
    if manifest.entrypoint != m.entry || m.icon.as_ref().is_some_and(|i| !files.contains_key(i)) {
        return Err(Error::Malformed(ENTRY_MISMATCH));
    }
    Ok(())
}

#[cfg(test)]
#[path = "plugin_bundle_v2_tests.rs"]
mod tests;
