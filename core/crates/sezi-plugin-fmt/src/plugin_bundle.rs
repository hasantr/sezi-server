//! Packs a multi-file web app into a SINGLE deterministic tar blob; the crypto path
//! (`plugin_code.rs` → `encrypt_in_memory`) takes plaintext = the tar bytes.
//!
//! WHY DETERMINISTIC: `code_hash = BLAKE3(plaintext)` is what triggers re-consent, so the
//! same file set must produce the same hash. Hence fixed headers (mtime/uid/gid = 0, mode
//! 0o644, empty owner names), paths sorted by bytes, and NO compression — zip-deflate is
//! non-deterministic and would re-prompt for consent on unchanged code.
//!
//! INTEGRITY: `sezgi-manifest.json` carries each file's BLAKE3 + size + content type, and
//! `unpack_bundle` verifies every file against it — that is what catches a malicious
//! server or a corrupt blob.
//!
//! SECURITY: path traversal (`..`, absolute, Windows drive, empty segment, NUL) is
//! rejected on BOTH sides; a poisoned path is never normalized away, even though
//! extraction goes to a RAM map. Content types come from a static-web whitelist, unknown →
//! `application/octet-stream`, so an executable MIME the WebView would act on is never
//! produced.

use std::collections::BTreeMap;
use std::io::Read as _;

use serde::{Deserialize, Serialize};

use sezi_error::{Error, Result};

/// Ceiling for the bundle's total plaintext (tar) size. Must stay equal to
/// `MAX_PLUGIN_CODE_BYTES` in `plugin_code.rs` and `plugin_install.rs` — a huge web app
/// fits, a malicious admin cannot inflate it.
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// Ceiling for the number of tar entries, the manifest included. The byte ceiling already
/// bounds it (one 512-byte header each), so this only says how many a web app may need.
pub const MAX_BUNDLE_ENTRIES: usize = 4096;

/// Manifest file name, at the bundle root. Plugin files cannot use this name (pack
/// rejects it) so it can never be shadowed.
pub const MANIFEST_NAME: &str = "sezgi-manifest.json";

/// USTAR block size: a 512B header + content rounded up to 512 + a 2×512 end block.
pub(crate) const TAR_BLOCK: usize = 512;

/// A single file record inside the manifest — path + integrity + presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFileMeta {
    /// Relative path inside the bundle (POSIX `/`; traversal-clean, validated).
    pub path: String,
    /// BLAKE3(file content), vodozemac base64 — the same encoding as `PluginCodeRefV1`.
    pub blake3_b64: String,
    /// File size in bytes.
    pub size: u64,
    /// Content type used when serving (whitelisted; unknown → `application/octet-stream`).
    pub content_type: String,
}

/// Body of `sezgi-manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Manifest schema version (forward compatibility).
    pub v: u8,
    /// Entry file the WebView loads; it MUST be present in `files`.
    pub entrypoint: String,
    /// File records, SORTED by path bytes.
    pub files: Vec<BundleFileMeta>,
    /// `v:2` only: the app manifest (`sezi-app.json`) the bundle carries beside its files —
    /// its BLAKE3 and size, so that the signed digest of this manifest commits to it
    /// (`plugin_bundle_v2.rs`). Absent from a v1 manifest, whose bytes are unchanged by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<BundleAppMeta>,
}

/// Where a v2 bundle's app manifest is pinned: its hash and size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleAppMeta {
    /// BLAKE3(`sezi-app.json` bytes), vodozemac base64.
    pub blake3_b64: String,
    pub size: u64,
}

/// Output of `unpack_bundle`.
#[derive(Debug, Clone)]
pub struct BundleFiles {
    /// path → content bytes, BLAKE3-verified against the manifest. RAM only, no disk.
    pub files: BTreeMap<String, Vec<u8>>,
    pub manifest: BundleManifest,
    /// A v2 bundle's app manifest, its signature checked against the publisher key it names;
    /// `None` for a v1 bundle.
    pub app: Option<crate::plugin_bundle_v2::VerifiedApp>,
}

impl BundleFiles {
    /// The content type of a path; octet-stream if the manifest has no record for it.
    pub fn content_type_for(&self, path: &str) -> &str {
        self.manifest
            .files
            .iter()
            .find(|f| f.path == path)
            .map(|f| f.content_type.as_str())
            .unwrap_or("application/octet-stream")
    }
}

/// Extension → content-type whitelist. Static-web MIME types only; unknown →
/// `application/octet-stream`, never an executable MIME the WebView would act on.
pub(crate) fn content_type_for_path(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "json" | "map" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// `blake3(bytes)` → base64, the same encoding as the `PluginCodeRefV1` hash fields.
pub(crate) fn blake3_b64(bytes: &[u8]) -> String {
    vodozemac::base64_encode(blake3::hash(bytes).as_bytes())
}

/// Path-traversal validation, called on BOTH sides (pack AND unpack). Nothing is
/// normalized — a suspicious path is rejected rather than rewritten.
pub(crate) fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::Malformed("bundle path is empty"));
    }
    if path.len() > 255 {
        return Err(Error::Malformed("bundle path >255 (tar USTAR limit)"));
    }
    if path.contains('\0') {
        return Err(Error::Malformed("bundle path contains NUL"));
    }
    // A backslash is a Windows-path escape; POSIX `/` is mandatory.
    if path.contains('\\') {
        return Err(Error::Malformed("bundle path contains a backslash"));
    }
    if path.starts_with('/') {
        return Err(Error::Malformed("bundle path is absolute (/)"));
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(Error::Malformed("bundle path Windows drive (X:)"));
    }
    for seg in path.split('/') {
        if seg.is_empty() {
            return Err(Error::Malformed("bundle path has an empty segment (//)"));
        }
        if seg == ".." {
            return Err(Error::Malformed("bundle path .. (traversal)"));
        }
        if seg == "." {
            return Err(Error::Malformed("bundle path . segment"));
        }
    }
    if path == MANIFEST_NAME {
        return Err(Error::Malformed("bundle path collides with the manifest name"));
    }
    Ok(())
}

/// A 512B USTAR (POSIX) header, deterministic: mtime/uid/gid = 0, mode = 0o644.
fn write_tar_header(out: &mut Vec<u8>, path: &str, size: u64) -> Result<()> {
    let mut header = [0u8; TAR_BLOCK];

    // USTAR splits a long path as name(100) + prefix(155); validate_path guarantees ≤255.
    let pbytes = path.as_bytes();
    let (prefix, name): (&[u8], &[u8]) = if pbytes.len() <= 100 {
        (&[], pbytes)
    } else {
        // Split at the last '/' that leaves prefix ≤155 and name ≤100.
        let split = pbytes
            .iter()
            .enumerate()
            .filter(|(i, &b)| b == b'/' && *i <= 155 && pbytes.len() - i - 1 <= 100)
            .map(|(i, _)| i)
            .next_back();
        match split {
            Some(i) => (&pbytes[..i], &pbytes[i + 1..]),
            None => return Err(Error::Malformed("bundle path could not be split for USTAR")),
        }
    };
    if name.len() > 100 || prefix.len() > 155 {
        return Err(Error::Malformed("bundle path overflowed the USTAR name/prefix"));
    }
    header[0..name.len()].copy_from_slice(name);

    // USTAR field offsets: mode 100, uid 108, gid 116, size 124, mtime 136, typeflag 156,
    // magic 257, version 263, prefix 345. uname/gname and devmajor/devminor stay zeroed —
    // that is what keeps the output deterministic.
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], 0);
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[345..345 + prefix.len()].copy_from_slice(prefix);

    // Checksum @148 is computed with its own field filled with spaces, then written back
    // as 6 octal digits + NUL + space — the classic tar format.
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    let cksum = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(cksum.as_bytes());

    out.extend_from_slice(&header);
    Ok(())
}

/// A tar numeric field: `field.len()-1` zero-padded octal digits + NUL.
fn write_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let s = format!("{value:0width$o}", width = digits);
    // A ≤8MB bundle fits 11 octal digits (0o77777777777 ≈ 8GB); truncate defensively anyway.
    let bytes = s.as_bytes();
    let start = bytes.len().saturating_sub(digits);
    field[..digits].copy_from_slice(&bytes[start..]);
    field[digits] = 0;
}

/// One tar entry: header + content + padding to a 512 boundary.
pub(crate) fn write_tar_entry(out: &mut Vec<u8>, path: &str, content: &[u8]) -> Result<()> {
    write_tar_header(out, path, content.len() as u64)?;
    out.extend_from_slice(content);
    let rem = content.len() % TAR_BLOCK;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, TAR_BLOCK - rem));
    }
    Ok(())
}

/// Multi-file web app → a deterministic uncompressed tar: the manifest first, then the
/// files sorted by path bytes.
///
/// The output is bit-deterministic — the same (files, entrypoint) yields the same
/// `BLAKE3(tar)`, so re-consent is triggered only when the content actually changes.
pub fn pack_bundle(files: Vec<(String, Vec<u8>)>, entrypoint: &str) -> Result<Vec<u8>> {
    if files.is_empty() {
        return Err(Error::Malformed("bundle is empty (no files)"));
    }
    if entrypoint.is_empty() {
        return Err(Error::Malformed("bundle entrypoint is empty"));
    }
    // BTreeMap gives the sort by path bytes, and an overwriting insert is a duplicate path.
    let mut sorted: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (path, content) in files {
        validate_path(&path)?;
        if sorted.insert(path.clone(), content).is_some() {
            return Err(Error::Malformed("duplicate path in the bundle"));
        }
    }
    validate_path(entrypoint)?;
    // The manifest is one entry too; unpack refuses more than the ceiling.
    if sorted.len() >= MAX_BUNDLE_ENTRIES {
        return Err(Error::Malformed("bundle has more files than the entry ceiling"));
    }
    if !sorted.contains_key(entrypoint) {
        return Err(Error::Malformed("bundle entrypoint is not in files"));
    }

    let metas: Vec<BundleFileMeta> = sorted
        .iter()
        .map(|(path, content)| BundleFileMeta {
            path: path.clone(),
            blake3_b64: blake3_b64(content),
            size: content.len() as u64,
            content_type: content_type_for_path(path).to_string(),
        })
        .collect();
    let manifest = BundleManifest {
        v: 1,
        entrypoint: entrypoint.to_string(),
        files: metas,
        app: None,
    };
    let manifest_json =
        serde_json::to_vec(&manifest).map_err(|e| Error::Crypto(format!("manifest json: {e}")))?;

    let mut out = Vec::new();
    write_tar_entry(&mut out, MANIFEST_NAME, &manifest_json)?;
    for (path, content) in &sorted {
        write_tar_entry(&mut out, path, content)?;
    }
    // tar EOF: two all-NUL blocks.
    out.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));

    if out.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Malformed("bundle exceeds the 8MB ceiling"));
    }
    Ok(out)
}

/// Deterministic tar → a verified RAM file map (no disk).
///
/// Everything here is a decode-side integrity check and none of it is optional: a hostile
/// blob is assumed. Paths are re-validated for traversal, every file must match the
/// manifest's BLAKE3 and size with no missing or extra entries, and content types are
/// RE-DERIVED from the path whitelist so a manifest cannot inject an executable MIME.
/// This sits behind the `code_hash`(tar) check `plugin_code.rs` already did — defence in
/// depth, deliberately duplicated.
pub fn unpack_bundle(tar: &[u8]) -> Result<BundleFiles> {
    if tar.len() > MAX_BUNDLE_BYTES {
        return Err(Error::Malformed("bundle exceeds the 8MB ceiling (unpack)"));
    }
    let mut archive = tar::Archive::new(tar);
    let mut raw: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let entries = archive
        .entries()
        .map_err(|e| Error::Crypto(format!("tar entries: {e}")))?;
    // Bytes read so far, over every entry. A slice cannot hold more than MAX_BUNDLE_BYTES of
    // regular data, but tar can PRODUCE more than it holds (a sparse entry's holes), so the
    // budget is counted on what is read, not on what came in.
    let mut unpacked: u64 = 0;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::Crypto(format!("tar entry: {e}")))?;
        if raw.len() >= MAX_BUNDLE_ENTRIES {
            return Err(Error::Malformed("bundle has more tar entries than the ceiling"));
        }
        // Only what pack writes: a regular file. tar's `entries()` expands a GNU sparse entry
        // into zeros it pads in itself — a 512-byte header can name terabytes (crates review
        // PLG-1) — and nothing else (a directory, a link, a device) belongs in a RAM file map.
        // The extended headers tar consumes on its own (GNU long name, PAX) never reach here.
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(Error::Malformed("bundle tar entry type is not a regular file"));
        }
        // Raw bytes, not the tar crate's `path()` — its normalization must not be trusted.
        let path_bytes = entry
            .path_bytes()
            .into_owned();
        let path = String::from_utf8(path_bytes)
            .map_err(|_| Error::Malformed("tar path is not utf8"))?;
        // The manifest is the one allowed name that `validate_path` rejects.
        if path != MANIFEST_NAME {
            validate_path(&path)?;
        }
        // Read at most one byte past what the whole bundle may still hold, so an entry that
        // would go over is caught after a bounded read rather than after its whole claim.
        let budget = MAX_BUNDLE_BYTES as u64 - unpacked;
        let mut content = Vec::new();
        (&mut entry)
            .take(budget + 1)
            .read_to_end(&mut content)
            .map_err(|e| Error::Crypto(format!("tar read: {e}")))?;
        unpacked += content.len() as u64;
        if unpacked > MAX_BUNDLE_BYTES as u64 {
            return Err(Error::Malformed("bundle unpacks past the 8MB ceiling"));
        }
        if raw.insert(path, content).is_some() {
            return Err(Error::Malformed("duplicate path in the tar"));
        }
    }

    let manifest_json = raw
        .remove(MANIFEST_NAME)
        .ok_or(Error::Malformed("bundle has no manifest"))?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_json)
        .map_err(|e| Error::Crypto(format!("manifest parse: {e}")))?;
    // v1 is read exactly as before; v2 first takes out its app manifest and signature, which
    // are reserved entries beside the files, and checks them (`plugin_bundle_v2.rs`).
    let app = match manifest.v {
        1 if manifest.app.is_none() => None,
        2 => Some(crate::plugin_bundle_v2::take_and_verify(&mut raw, &manifest, &manifest_json)?),
        _ => return Err(Error::Malformed("bundle manifest version")),
    };

    // The tar file set must EQUAL the manifest's — an extra entry is as fatal as a missing one.
    // Counting is equality only while the manifest names each path once: a path listed twice
    // would let one unlisted tar entry through on the count (crates review PLG-2).
    let mut listed = std::collections::BTreeSet::new();
    if !manifest.files.iter().all(|m| listed.insert(m.path.as_str())) {
        return Err(Error::Malformed("bundle manifest lists a path twice (duplicate)"));
    }
    if raw.len() != manifest.files.len() {
        return Err(Error::Malformed("bundle file count does not match the manifest"));
    }
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for meta in &manifest.files {
        validate_path(&meta.path)?;
        let content = raw
            .get(&meta.path)
            .ok_or(Error::Malformed("a manifest file is missing from the tar"))?;
        if content.len() as u64 != meta.size {
            return Err(Error::Malformed("bundle file size does not match the manifest"));
        }
        if blake3_b64(content) != meta.blake3_b64 {
            return Err(Error::Malformed("bundle file BLAKE3 does not match"));
        }
        files.insert(meta.path.clone(), content.clone());
    }

    if manifest.entrypoint.is_empty() {
        return Err(Error::Malformed("bundle manifest entrypoint is empty"));
    }
    validate_path(&manifest.entrypoint)?;
    if !files.contains_key(&manifest.entrypoint) {
        return Err(Error::Malformed("bundle entrypoint is not in the file map"));
    }

    // The manifest's own content_type is IGNORED and re-derived from the path.
    let safe_files: Vec<BundleFileMeta> = manifest
        .files
        .iter()
        .map(|m| BundleFileMeta {
            path: m.path.clone(),
            blake3_b64: m.blake3_b64.clone(),
            size: m.size,
            content_type: content_type_for_path(&m.path).to_string(),
        })
        .collect();
    let safe_manifest = BundleManifest {
        v: manifest.v,
        entrypoint: manifest.entrypoint,
        files: safe_files,
        app: manifest.app,
    };
    if let Some(app) = &app {
        crate::plugin_bundle_v2::check_against_files(app, &safe_manifest, &files)?;
    }

    Ok(BundleFiles {
        files,
        manifest: safe_manifest,
        app,
    })
}

#[cfg(test)]
#[path = "plugin_bundle_tests.rs"]
mod tests;
