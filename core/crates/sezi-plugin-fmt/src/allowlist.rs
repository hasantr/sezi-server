//! The server owner's plugin allowlist (review 2026-11 § 3.5, Wave C3; decision D1) — the ONE
//! rule both halves apply: the relay at `put_code` (`worker-rs/src/plugin_allowlist.rs`) and every
//! member's core on assign and on receipt (`core/src/kernel/plugin_policy.rs`). Pure: no I/O, no
//! clock, builds for wasm.
//!
//! A server's plugin policy has a [`Mode`]: `open` — today's behaviour, every app an admin of a
//! room installs runs — or `allowlist`, where only an app a row of the owner's list approves does.
//! A row approves either
//!
//! - **a publisher** ([`AllowRule::Publisher`]): every app signed by that Ed25519 key, or only one
//!   app id of it, each up to the row's `max_caps` — a capability the app would be granted
//!   (`Capabilities::granted`) that the row does not name is refused, so a grant never exceeds the
//!   row. `network` in `max_caps` covers every origin; `network:<origin>` that origin only; or
//! - **one exact bundle** ([`AllowRule::Hash`]): the BLAKE3 of the plaintext code
//!   (`PluginCodeRefV1.code_hash_b64`, the vodozemac base64 of the 32 bytes), for an app with no
//!   publisher — an `html:` app — or a pinned build of a signed one. Its `max_caps` holds too.
//!
//! Built-ins and first-party web apps are this build's own code, not ruled here: they keep their
//! switches (the disabled list), as decision D1 says.
//!
//! **Extensible by rule** (Hasan, 2026-11-06): a mode this reader does not know is read as
//! `allowlist` — a later mode is a narrowing or a catalog, never a reason to run unapproved code —
//! and a capability name in a row this reader does not know is kept (a later host may grant it),
//! which costs nothing: a capability this host does not know is never granted
//! (`app_manifest` module doc), so it is never checked against a row either.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::app_manifest::{capability_name_ok, is_app_id, is_origin, parse_key_id};

/// The refusal: the owner's list does not approve this app (or this grant of it).
pub const NOT_APPROVED: &str = "plugin/not-approved";
/// A row a write may not hold (no key and no hash, both, a bad key, hash, id or capability).
pub const BAD_ROW: &str = "plugin/allowlist-bad-row";
/// The list is full.
pub const LIST_FULL: &str = "plugin/allowlist-full";
/// A mode a write may not set.
pub const BAD_MODE: &str = "plugin/policy-bad-mode";

/// The most rows a server keeps.
pub const MAX_ROWS: usize = 256;
/// The most capability names in one row.
pub const MAX_CAPS: usize = 32;
/// The longest label, in characters.
pub const MAX_LABEL_CHARS: usize = 80;

/// The capability name that, in `max_caps`, covers every origin.
pub const ANY_ORIGIN: &str = "network";

/// What a server's plugin policy lets run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Every app an admin of a room installs (the behaviour before C3, and every old relay's).
    #[default]
    Open,
    /// Only what a row of the owner's list approves.
    Allowlist,
}

impl Mode {
    /// The wire word.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Open => "open",
            Mode::Allowlist => "allowlist",
        }
    }

    /// Read a relay's word leniently: absent = `open` (a relay from before C3), `open` = open,
    /// anything else = allowlist (module doc).
    pub fn read(word: Option<&str>) -> Mode {
        match word {
            None | Some("open") => Mode::Open,
            Some(_) => Mode::Allowlist,
        }
    }

    /// Read an owner's WRITE strictly: only the two words this build knows.
    pub fn parse_write(word: &str) -> Result<Mode, &'static str> {
        match word {
            "open" => Ok(Mode::Open),
            "allowlist" => Ok(Mode::Allowlist),
            _ => Err(BAD_MODE),
        }
    }
}

/// What one row approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowRule {
    /// Apps signed by `key_id` (`ed25519:` + base64url) — every one, or `app_id` only.
    Publisher { key_id: String, app_id: Option<String> },
    /// The one bundle whose plaintext BLAKE3 is `code_hash` (vodozemac base64).
    Hash { code_hash: String },
}

/// One row of the owner's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRow {
    /// The relay's row id (0 for a row not stored yet).
    pub id: i64,
    pub rule: AllowRule,
    /// The capability names an approved app may be granted at most.
    pub max_caps: BTreeSet<String>,
    /// What the owner called it.
    pub label: String,
    /// When it was added, ms.
    pub added_at: i64,
}

/// A server's whole policy as far as this file is concerned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    pub mode: Mode,
    pub rows: Vec<AllowRow>,
}

/// What is known of an app when it is judged.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// The id it runs under (`ext:<publisher>/<name>`, `html:…`).
    pub plugin_id: &'a str,
    /// The key that signed it, when a signature verified.
    pub publisher_key_id: Option<&'a str>,
    /// BLAKE3 of the plaintext code, vodozemac base64, when known.
    pub code_hash: Option<&'a str>,
    /// What it would be granted (`Capabilities::granted`; an `html:` app: `network` when it is
    /// networked, else nothing).
    pub granted: &'a BTreeSet<String>,
}

/// Is every grant named by `max`? In `max`, `network` covers every `network:<origin>`; a
/// networked app is granted `network` beside each of its origins, which a row naming only origins
/// covers too — the origins are then what it holds to.
pub fn caps_within(granted: &BTreeSet<String>, max: &BTreeSet<String>) -> bool {
    granted.iter().all(|g| {
        max.contains(g)
            || (g.starts_with("network:") && max.contains(ANY_ORIGIN))
            || (g == ANY_ORIGIN && max.iter().any(|m| m.starts_with("network:")))
    })
}

impl AllowRow {
    /// Does this row approve `c`?
    pub fn approves(&self, c: &Candidate<'_>) -> bool {
        let matched = match &self.rule {
            AllowRule::Publisher { key_id, app_id } => {
                c.publisher_key_id == Some(key_id.as_str())
                    && app_id.as_deref().is_none_or(|id| id == c.plugin_id)
            }
            AllowRule::Hash { code_hash } => c.code_hash == Some(code_hash.as_str()),
        };
        matched && caps_within(c.granted, &self.max_caps)
    }

    /// Could this row approve a SIGNED app under `plugin_id` whose bundle has not verified yet
    /// (a member holding only the install's `code_ref`)? A hash row that names `code_hash`, or a
    /// publisher row for every app or for this id. The full check follows at the download.
    pub fn may_approve_unverified(&self, plugin_id: &str, code_hash: Option<&str>) -> bool {
        match &self.rule {
            AllowRule::Publisher { app_id, .. } => app_id.as_deref().is_none_or(|id| id == plugin_id),
            AllowRule::Hash { code_hash: h } => code_hash == Some(h.as_str()),
        }
    }
}

impl Allowlist {
    /// May `c` run? Always in `open` mode.
    pub fn approves(&self, c: &Candidate<'_>) -> bool {
        self.mode == Mode::Open || self.rows.iter().any(|r| r.approves(c))
    }

    /// [`AllowRow::may_approve_unverified`] over the list; always in `open` mode.
    pub fn may_approve_unverified(&self, plugin_id: &str, code_hash: Option<&str>) -> bool {
        self.mode == Mode::Open
            || self.rows.iter().any(|r| r.may_approve_unverified(plugin_id, code_hash))
    }
}

/// A code hash as the install wire carries it: 32 bytes in standard base64 without padding.
pub fn is_code_hash(h: &str) -> bool {
    h.len() == 43
        && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        && h.as_bytes()[42].is_ascii_alphanumeric()
}

/// A capability name a row may hold: a name a host could give a meaning to, or
/// `network:<origin>`.
pub fn is_cap_name(n: &str) -> bool {
    match n.strip_prefix("network:") {
        Some(origin) => is_origin(origin),
        None => capability_name_ok(n),
    }
}

/// Read one row from the relay's JSON leniently: `None` for a row this reader cannot hold (no
/// key and no hash, a field of the wrong type). Never errs on an unknown field.
pub fn row_from_json(v: &Value) -> Option<AllowRow> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let rule = match (s("publisher_key"), s("code_hash")) {
        (Some(key), None) => AllowRule::Publisher {
            key_id: key.to_string(),
            app_id: s("app_id").map(str::to_string),
        },
        (None, Some(hash)) => AllowRule::Hash { code_hash: hash.to_string() },
        _ => return None,
    };
    let max_caps = v
        .get("max_caps")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    Some(AllowRow {
        id: v.get("id").and_then(Value::as_i64).unwrap_or(0),
        rule,
        max_caps,
        label: s("label").unwrap_or_default().to_string(),
        added_at: v.get("added_at").and_then(Value::as_i64).unwrap_or(0),
    })
}

/// A row as the relay serves it.
pub fn row_to_json(r: &AllowRow) -> Value {
    let (key, app, hash) = match &r.rule {
        AllowRule::Publisher { key_id, app_id } => (Some(key_id.clone()), app_id.clone(), None),
        AllowRule::Hash { code_hash } => (None, None, Some(code_hash.clone())),
    };
    json!({
        "id": r.id,
        "publisher_key": key,
        "app_id": app,
        "code_hash": hash,
        "max_caps": r.max_caps.iter().collect::<Vec<_>>(),
        "label": r.label,
        "added_at": r.added_at,
    })
}

/// Read the policy part of a relay's `GET /plugin-policy` answer leniently: no `mode` = `open`
/// (an old relay), rows this reader cannot hold are skipped.
pub fn allowlist_from_json(v: &Value) -> Allowlist {
    Allowlist {
        mode: Mode::read(v.get("mode").and_then(Value::as_str)),
        rows: v
            .get("allowed")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(row_from_json).collect())
            .unwrap_or_default(),
    }
}

/// Check an owner's WRITE of a row strictly: exactly one of a publisher key and a code hash, each
/// of its shape, an app id only beside a key and of the signed-app shape, capability names of
/// their shape, a label within bounds.
pub fn check_new_row(v: &Value) -> Result<AllowRow, &'static str> {
    let row = row_from_json(v).ok_or(BAD_ROW)?;
    match &row.rule {
        AllowRule::Publisher { key_id, app_id } => {
            if parse_key_id(key_id).is_none() || app_id.as_deref().is_some_and(|id| !is_app_id(id)) {
                return Err(BAD_ROW);
            }
        }
        AllowRule::Hash { code_hash } => {
            if !is_code_hash(code_hash) || v.get("app_id").is_some_and(|a| !a.is_null()) {
                return Err(BAD_ROW);
            }
        }
    }
    let caps = v.get("max_caps").map(|c| c.as_array().ok_or(BAD_ROW)).transpose()?;
    if let Some(caps) = caps {
        if caps.len() > MAX_CAPS || !caps.iter().all(|c| c.as_str().is_some_and(is_cap_name)) {
            return Err(BAD_ROW);
        }
    }
    let label = v.get("label").map(|l| l.as_str().ok_or(BAD_ROW)).transpose()?.unwrap_or("");
    if label.chars().count() > MAX_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err(BAD_ROW);
    }
    Ok(row)
}

// ── What an admin's app presents with a code upload ────────────────────────────────────────────
//
// The relay stores a plugin's code as ciphertext under a key it never sees, so it cannot look
// inside the bundle. What it CAN check is a claim the uploading app makes beside the bytes: the
// code hash, and for a signed app the publisher's signed manifest and the bundle digest, whose
// signature it verifies (`plugin_bundle_v2::verify_detached`). It cannot check that the claim is
// about the bytes uploaded; every member's core checks that when it opens them (module doc of
// `worker-rs/src/plugin_allowlist.rs` says what this does and does not stop).

/// The plaintext code hash (vodozemac base64), sent with every upload by an app of C3 or later.
pub const HEADER_CODE_HASH: &str = "x-sezi-code-hash";
/// A signed app's `sezi-app.json`, base64url without padding.
pub const HEADER_APP: &str = "x-sezi-app";
/// The publisher's signature line (`<key id> <signature>`), as in `sezi-app.sig`.
pub const HEADER_APP_SIG: &str = "x-sezi-app-sig";
/// The bundle digest the signature covers, base64url without padding.
pub const HEADER_APP_DIGEST: &str = "x-sezi-app-digest";
/// A FIRST-PARTY web app's id (one of [`FIRST_PARTY_APP_IDS`]), presented with the upload of its
/// code. Such an app is exempt from the list (decision D1: a fresh `allowlist` server must work out
/// of the box): every client runs the code compiled into its own binary for these ids and never the
/// bytes an install carried, so whatever is uploaded under one is never run.
pub const HEADER_FIRST_PARTY: &str = "x-sezi-first-party";
/// The first-party web apps (the Web Suite). ⚠ A hand-kept mirror of the app's `kWebSuitePlugins`
/// first-party set (`mobile/lib/src/plugins/web/web_app_catalog.dart`); the core's
/// `plugin_builtin::FIRST_PARTY_WEB_APP_IDS` is this list.
pub const FIRST_PARTY_APP_IDS: &[&str] = &["html:echo", "html:iris", "html:loop", "html:scene"];

/// Is `id` one of the first-party web apps, exempt from the list?
pub fn is_first_party(id: &str) -> bool {
    FIRST_PARTY_APP_IDS.contains(&id)
}

/// The largest `sezi-app.json` an upload presents. Request headers are bounded (a Worker's and
/// workerd's both); a larger manifest is not presented, and an allowlist relay then approves the
/// upload only by its hash.
pub const MAX_PRESENTED_APP_BYTES: usize = 6 * 1024;

/// A signed app as an upload presented it, its signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedApp {
    /// The manifest's id (`ext:<publisher>/<name>`).
    pub app_id: String,
    pub publisher_key_id: String,
    /// What the manifest would be granted.
    pub granted: BTreeSet<String>,
}

/// Open what an upload presents for a signed app: decode the manifest and the digest, parse the
/// manifest and verify the publisher's signature over them. `Err` = nothing usable was presented.
pub fn open_presented(app_b64: &str, signature: &str, digest_b64: &str) -> Result<PresentedApp, &'static str> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    if app_b64.len() > MAX_PRESENTED_APP_BYTES.div_ceil(3) * 4 {
        return Err(NOT_APPROVED);
    }
    let app_json = b64.decode(app_b64.trim()).map_err(|_| NOT_APPROVED)?;
    let digest: [u8; 32] = b64
        .decode(digest_b64.trim())
        .ok()
        .and_then(|d| d.try_into().ok())
        .ok_or(NOT_APPROVED)?;
    let app = crate::app_manifest::parse_app_manifest(&app_json).map_err(|_| NOT_APPROVED)?;
    crate::plugin_bundle_v2::verify_detached(&digest, &app_json, signature, &app)
        .map_err(|_| NOT_APPROVED)?;
    Ok(PresentedApp {
        app_id: app.id.clone(),
        publisher_key_id: app.publisher.key_id.clone(),
        granted: app.capabilities.granted(),
    })
}

#[cfg(test)]
#[path = "allowlist_tests.rs"]
mod tests;
