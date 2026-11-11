//! Tests for `plugin_bundle.rs` (PHASE C, C1 — sibling file, 600/800 budget).
//! Roundtrip + path-traversal rejection (both directions) + per-file BLAKE3 +
//! corrupt-file handling + code_hash determinism (independent of mtime).

use super::*;

fn files() -> Vec<(String, Vec<u8>)> {
    vec![
        ("index.html".into(), b"<html><script src=app.js></script></html>".to_vec()),
        ("app.js".into(), b"console.log('hi')".to_vec()),
        ("css/style.css".into(), b"body{margin:0}".to_vec()),
        ("img/logo.png".into(), vec![0x89, 0x50, 0x4e, 0x47, 1, 2, 3]),
    ]
}

/// pack → unpack roundtrip (multi-file): every file comes back bit-identical, the
/// entrypoint is preserved, and the content type is derived correctly.
#[test]
fn roundtrip_multi_file() {
    let tar = pack_bundle(files(), "index.html").unwrap();
    let out = unpack_bundle(&tar).unwrap();
    assert_eq!(out.manifest.entrypoint, "index.html");
    assert_eq!(out.files.len(), 4);
    assert_eq!(
        out.files.get("index.html").unwrap(),
        b"<html><script src=app.js></script></html>"
    );
    assert_eq!(out.files.get("app.js").unwrap(), b"console.log('hi')");
    assert_eq!(out.files.get("css/style.css").unwrap(), b"body{margin:0}");
    assert_eq!(out.files.get("img/logo.png").unwrap(), &[0x89, 0x50, 0x4e, 0x47, 1, 2, 3]);
    // content-type derivation (whitelist).
    assert_eq!(out.content_type_for("index.html"), "text/html");
    assert_eq!(out.content_type_for("app.js"), "text/javascript");
    assert_eq!(out.content_type_for("css/style.css"), "text/css");
    assert_eq!(out.content_type_for("img/logo.png"), "image/png");
}

/// code_hash is DETERMINISTIC: the same (files, entrypoint) → a BIT-IDENTICAL tar → the
/// same BLAKE3. Even packed in a different insertion order (a BTreeMap sorts by path) →
/// the same hash. With mtime/uid/gid=0 two calls agree even across time, which is what
/// makes re-consent correct.
#[test]
fn code_hash_deterministic() {
    let tar1 = pack_bundle(files(), "index.html").unwrap();
    // The same files in REVERSE order → pack sorts by path again → the same tar.
    let mut shuffled = files();
    shuffled.reverse();
    let tar2 = pack_bundle(shuffled, "index.html").unwrap();
    assert_eq!(tar1, tar2, "independent of insert order → a deterministic tar");
    assert_eq!(
        blake3::hash(&tar1),
        blake3::hash(&tar2),
        "the same content → the same code_hash (re-consent only when the content changes)"
    );
}

/// A content change CHANGES the hash (which triggers re-consent).
#[test]
fn code_hash_changes_on_content_change() {
    let tar1 = pack_bundle(files(), "index.html").unwrap();
    let mut f2 = files();
    f2[1].1 = b"console.log('changed')".to_vec();
    let tar2 = pack_bundle(f2, "index.html").unwrap();
    assert_ne!(tar1, tar2, "the content changed → the tar changed → re-consent");
}

/// PATH TRAVERSAL rejected at pack time: `..`, absolute, backslash, drive, NUL, empty segment.
#[test]
fn pack_rejects_traversal() {
    let bad = [
        "../escape.html",
        "/etc/passwd",
        "a/../../b",
        "C:\\win.html",
        "back\\slash.js",
        "a//b.css",
        "/abs.js",
    ];
    for p in bad {
        let f = vec![(p.to_string(), b"x".to_vec())];
        assert!(
            pack_bundle(f, p).is_err(),
            "pack accepted a traversal path: {p}"
        );
    }
    // NUL separately (inside a string literal).
    let f = vec![("a\0b.html".to_string(), b"x".to_vec())];
    assert!(pack_bundle(f, "a\0b.html").is_err(), "a NUL path was accepted");
}

/// An entrypoint that is NOT among the files is rejected at pack time.
#[test]
fn pack_rejects_missing_entrypoint() {
    let f = vec![("index.html".to_string(), b"x".to_vec())];
    assert!(pack_bundle(f, "main.html").is_err(), "a missing entrypoint was accepted");
}

/// An empty bundle / an empty entrypoint is rejected.
#[test]
fn pack_rejects_empty() {
    assert!(pack_bundle(vec![], "index.html").is_err());
    let f = vec![("index.html".to_string(), b"x".to_vec())];
    assert!(pack_bundle(f, "").is_err());
}

/// A duplicate path is rejected at pack time.
#[test]
fn pack_rejects_duplicate_path() {
    let f = vec![
        ("a.html".to_string(), b"1".to_vec()),
        ("a.html".to_string(), b"2".to_vec()),
    ];
    assert!(pack_bundle(f, "a.html").is_err(), "a duplicate path was accepted");
}

/// A manifest-name collision is rejected at pack time (no file may be `sezgi-manifest.json`).
#[test]
fn pack_rejects_manifest_name_collision() {
    let f = vec![(MANIFEST_NAME.to_string(), b"fake".to_vec())];
    assert!(pack_bundle(f, MANIFEST_NAME).is_err());
}

/// per-file BLAKE3: corrupting the tar contents by hand makes unpack fail (the manifest
/// hash no longer matches).
#[test]
fn unpack_rejects_corrupted_file() {
    let mut tar = pack_bundle(files(), "index.html").unwrap();
    // Flip one byte inside app.js. The content is plainly visible in the tar ("console.log").
    let needle = b"console.log('hi')";
    let pos = tar
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the app.js content must be present in the tar");
    tar[pos] ^= 0xff; // corrupt it
    let res = unpack_bundle(&tar);
    assert!(res.is_err(), "unpack accepted a corrupted file (BLAKE3 was skipped)");
}

/// A missing manifest or a corrupt tar → Err.
#[test]
fn unpack_rejects_garbage() {
    assert!(unpack_bundle(b"not a tar at all").is_err());
    assert!(unpack_bundle(&[0u8; 1024]).is_err(), "empty blocks with no manifest → Err");
}

/// > 8MB tar → unpack RED (DoS guard).
#[test]
fn unpack_rejects_oversize() {
    let huge = vec![0u8; MAX_BUNDLE_BYTES + 1];
    assert!(unpack_bundle(&huge).is_err());
}

/// pack > 8MB → rejected. A single file exceeds 8MB, so with the tar header and padding
/// it goes over the ceiling.
#[test]
fn pack_rejects_oversize() {
    let big = vec![b'a'; MAX_BUNDLE_BYTES];
    let f = vec![("big.bin".to_string(), big)];
    assert!(pack_bundle(f, "big.bin").is_err(), "a bundle over 8MB was accepted");
}

/// The content type is RE-derived from the whitelist during unpack → a malicious manifest
/// cannot inject an executable mime. (Here we pack normally, so it is safe anyway; the
/// octet-stream fallback of the derivation is verified as well.)
#[test]
fn unknown_extension_is_octet_stream() {
    let f = vec![
        ("index.html".to_string(), b"<html></html>".to_vec()),
        ("data.weird".to_string(), b"binary".to_vec()),
    ];
    let tar = pack_bundle(f, "index.html").unwrap();
    let out = unpack_bundle(&tar).unwrap();
    assert_eq!(
        out.content_type_for("data.weird"),
        "application/octet-stream",
        "an unknown extension → octet-stream (NEVER an executable mime)"
    );
}

/// USTAR long path (name > 100B): the name/prefix split survives a roundtrip.
#[test]
fn roundtrip_long_path() {
    let long = format!("{}/deep/index.html", "a".repeat(110));
    let f = vec![(long.clone(), b"<html></html>".to_vec())];
    let tar = pack_bundle(f, &long).unwrap();
    let out = unpack_bundle(&tar).unwrap();
    assert!(out.files.contains_key(&long), "the long path was lost in the roundtrip");
}

// --- Hostile tars (crates review PLG-1, PLG-2) -------------------------------------------

/// A tar built by hand: the given manifest first, then each raw entry as `pack` writes one.
/// Lets a test say what `pack_bundle` itself refuses to produce. No end blocks.
fn tar_with(manifest: &BundleManifest, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    write_tar_entry(&mut out, MANIFEST_NAME, &serde_json::to_vec(manifest).unwrap()).unwrap();
    for (path, content) in entries {
        write_tar_entry(&mut out, path, content).unwrap();
    }
    out
}

fn meta(path: &str, content: &[u8]) -> BundleFileMeta {
    BundleFileMeta {
        path: path.into(),
        blake3_b64: blake3_b64(content),
        size: content.len() as u64,
        content_type: content_type_for_path(path).into(),
    }
}

/// A GNU sparse header for `path` whose one hole runs to `real_size`: no data blocks at
/// all, so the whole entry is a single 512-byte header that tar expands to zeros.
fn sparse_entry(path: &str, real_size: u64) -> Vec<u8> {
    let mut h = tar::Header::new_gnu();
    h.set_path(path).unwrap();
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::GNUSparse);
    h.set_size(0);
    let gnu = h.as_gnu_mut().unwrap();
    gnu.set_real_size(real_size);
    gnu.sparse[0].set_offset(real_size);
    gnu.sparse[0].set_length(0);
    h.set_cksum();
    h.as_bytes().to_vec()
}

/// PLG-1: one sparse entry (a 512-byte header) must not expand at all — a manifest naming
/// the expanded zeros with their real hash would otherwise be accepted after allocating
/// them. 64 MiB here keeps the pre-fix run survivable; the real attack names terabytes.
#[test]
fn unpack_refuses_a_sparse_entry() {
    let real = 64 * 1024 * 1024u64;
    let zeros = vec![0u8; real as usize];
    let manifest = BundleManifest {
        v: 1,
        entrypoint: "index.html".into(),
        files: vec![meta("index.html", &zeros)],
        app: None,
    };
    let mut tar = tar_with(&manifest, &[]);
    tar.extend(sparse_entry("index.html", real));
    tar.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));
    assert!(tar.len() < 4 * 1024, "the hostile bundle is a few KB");
    match unpack_bundle(&tar) {
        Err(Error::Malformed(m)) => assert!(m.contains("entry type"), "refused as: {m}"),
        other => panic!("a sparse entry was not refused by type: {:?}", other.map(|b| b.files.len())),
    }
}

/// PLG-1, the size of the real attack: a hole of 1 TiB (base-256 offset) is refused at
/// its header, before a byte of it is produced.
#[test]
fn unpack_refuses_a_terabyte_sparse_entry() {
    let manifest = BundleManifest { v: 1, entrypoint: "a.html".into(), files: vec![], app: None };
    let mut tar = tar_with(&manifest, &[]);
    tar.extend(sparse_entry("a.html", 1u64 << 40));
    tar.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));
    assert!(matches!(unpack_bundle(&tar), Err(Error::Malformed(_))));
}

/// PLG-1: every type pack never writes — a directory, a symlink, a FIFO — is refused too.
#[test]
fn unpack_refuses_non_regular_entries() {
    for ty in [tar::EntryType::Directory, tar::EntryType::Symlink, tar::EntryType::Fifo] {
        let page = b"<html></html>";
        let manifest = BundleManifest {
            v: 1,
            entrypoint: "index.html".into(),
            files: vec![meta("index.html", page), meta("x", b"")],
            app: None,
        };
        let mut tar = tar_with(&manifest, &[("index.html", page)]);
        let mut h = tar::Header::new_ustar();
        h.set_path("x").unwrap();
        h.set_entry_type(ty);
        h.set_size(0);
        h.set_cksum();
        tar.extend_from_slice(h.as_bytes());
        tar.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));
        match unpack_bundle(&tar) {
            Err(Error::Malformed(m)) => assert!(m.contains("entry type"), "refused as: {m}"),
            other => panic!("entry type {ty:?} was not refused by type: {:?}", other.map(|b| b.files.len())),
        }
    }
}

/// PLG-1: more entries than any bundle may hold is refused, on both sides.
#[test]
fn entry_count_is_capped() {
    let many: Vec<(String, Vec<u8>)> =
        (0..MAX_BUNDLE_ENTRIES).map(|i| (format!("f{i}.txt"), Vec::new())).collect();
    assert!(pack_bundle(many.clone(), "f0.txt").is_err(), "pack wrote too many entries");

    let manifest = BundleManifest {
        v: 1,
        entrypoint: "f0.txt".into(),
        files: many.iter().map(|(p, c)| meta(p, c)).collect(),
        app: None,
    };
    let entries: Vec<(&str, &[u8])> = many.iter().map(|(p, c)| (p.as_str(), &c[..])).collect();
    let tar = tar_with(&manifest, &entries);
    assert!(tar.len() <= MAX_BUNDLE_BYTES, "the tar itself is within the byte ceiling");
    match unpack_bundle(&tar) {
        Err(Error::Malformed(m)) => assert!(m.contains("entries"), "refused as: {m}"),
        other => panic!("{} tar entries were accepted: {:?}", MAX_BUNDLE_ENTRIES + 1, other.map(|b| b.files.len())),
    }

    // One fewer file (the manifest is the other entry) is still a bundle.
    let fit = many[..MAX_BUNDLE_ENTRIES - 1].to_vec();
    let tar = pack_bundle(fit, "f0.txt").expect("a bundle at the entry cap packs");
    assert!(unpack_bundle(&tar).is_ok(), "a bundle at the entry cap unpacks");
}

/// PLG-2: a manifest that lists one path twice must not admit an unlisted tar entry by
/// keeping the counts equal.
#[test]
fn unpack_refuses_a_duplicate_manifest_path() {
    let page = b"<html></html>";
    let manifest = BundleManifest {
        v: 1,
        entrypoint: "index.html".into(),
        files: vec![meta("index.html", page), meta("index.html", page)],
        app: None,
    };
    let mut tar = tar_with(&manifest, &[("index.html", page), ("extra.js", b"evil()")]);
    tar.extend(std::iter::repeat_n(0u8, 2 * TAR_BLOCK));
    match unpack_bundle(&tar) {
        Err(Error::Malformed(m)) => assert!(m.contains("duplicate"), "refused as: {m}"),
        other => panic!("a duplicated manifest path admitted an unlisted file: {:?}", other.map(|b| b.files.len())),
    }
}
