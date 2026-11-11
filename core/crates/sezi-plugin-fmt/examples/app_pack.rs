//! Pack a publisher's web app into a signed `.sezi` bundle (`plugin_bundle_v2`). The library stays
//! I/O-free and never signs: `scripts/app-sign.sh` runs this for the bytes to sign, signs them with
//! `openssl pkeyutl` (the key's passphrase from KeePassXC), then runs it again to pack.
//!
//! ```text
//! cargo run -q -p sezi-plugin-fmt --example app_pack -- key-id <pub.pem>
//! cargo run -q -p sezi-plugin-fmt --example app_pack -- message <app-dir> <message.bin>
//! cargo run -q -p sezi-plugin-fmt --example app_pack -- pack <app-dir> <signature.bin> <out.sezi>
//! ```
//!
//! - `key-id`: the `key_id` a manifest signed with that Ed25519 public key names (`publisher.key_id`).
//! - `message`: every file under `<app-dir>` but `sezi-app.json` and `sezi-app.sig`, plus
//!   `<app-dir>/sezi-app.json`, to the exact bytes the publisher signs.
//! - `pack`: the same files, `sezi-app.json` and the 64-byte raw signature → the bundle. The
//!   signature is checked against the manifest's `publisher.key_id` before anything is written.
//!
//! Exits 0 on success; prints the refusal on stderr and exits 1 (2 = usage).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sezi_plugin_fmt::app_manifest::{key_id_of, parse_app_manifest, APP_MANIFEST_NAME};
use sezi_plugin_fmt::plugin_bundle_v2::{pack_bundle_v2, signature_line, signing_message, APP_SIGNATURE_NAME};

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 key bytes follow it.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

fn usage() -> ExitCode {
    eprintln!("usage: app_pack key-id <pub.pem> | message <app-dir> <message.bin> | pack <app-dir> <signature.bin> <out.sezi>");
    ExitCode::from(2)
}

fn fail(why: impl std::fmt::Display) -> ExitCode {
    eprintln!("app_pack: {why}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["key-id", pem] => match public_key(Path::new(pem)) {
            Ok(key) => {
                println!("{}", key_id_of(&key));
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        ["message", dir, out] => {
            let run = || -> Result<(), String> {
                let (files, app_json) = read_app(Path::new(dir))?;
                let message = signing_message(files, &app_json).map_err(|e| e.to_string())?;
                std::fs::write(out, message).map_err(|e| format!("{out}: {e}"))
            };
            run().map_or_else(fail, |()| ExitCode::SUCCESS)
        }
        ["pack", dir, sig, out] => {
            let run = || -> Result<usize, String> {
                let (files, app_json) = read_app(Path::new(dir))?;
                let app = parse_app_manifest(&app_json).map_err(str::to_string)?;
                let raw = std::fs::read(sig).map_err(|e| format!("{sig}: {e}"))?;
                let raw: [u8; 64] = raw.try_into().map_err(|_| "the signature is not 64 bytes".to_string())?;
                let line = signature_line(&app.publisher.key_id, &raw);
                let bundle = pack_bundle_v2(files, &app_json, &line).map_err(|e| e.to_string())?;
                std::fs::write(out, &bundle).map_err(|e| format!("{out}: {e}"))?;
                Ok(bundle.len())
            };
            match run() {
                Ok(n) => {
                    println!("ok {out} {n} bytes");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }
        _ => usage(),
    }
}

/// An Ed25519 public key from its PEM (`openssl pkey -pubout`).
fn public_key(pem: &Path) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let text = std::fs::read_to_string(pem).map_err(|e| format!("{}: {e}", pem.display()))?;
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| "not a PEM public key".to_string())?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return Err("not an Ed25519 public key".into());
    }
    der[12..].try_into().map_err(|_| "not an Ed25519 public key".into())
}

/// The app's files (relative paths with `/`, the two app entries left out) and its `sezi-app.json`.
#[allow(clippy::type_complexity)]
fn read_app(dir: &Path) -> Result<(Vec<(String, Vec<u8>)>, Vec<u8>), String> {
    let app_json = std::fs::read(dir.join(APP_MANIFEST_NAME))
        .map_err(|e| format!("{}/{APP_MANIFEST_NAME}: {e}", dir.display()))?;
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(dir)
                .map_err(|e| e.to_string())?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if rel == APP_MANIFEST_NAME || rel == APP_SIGNATURE_NAME {
                continue;
            }
            files.push((rel, std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?));
        }
    }
    Ok((files, app_json))
}
