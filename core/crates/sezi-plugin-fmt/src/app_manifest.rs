//! `sezi-app.json` — what a web app declares about itself (review 2026-11 § 3.2, Wave C1): who
//! publishes it, the contract it is written for, and what it may do. The schema a publisher
//! writes against is `docs/platform/sezi-app.schema.json`; this is the HOST's reader of it.
//!
//! **The reader is lenient where leniency only adds, strict where a field grants.** A format-1
//! field an older host does not know is ignored (a field added to format 1 is optional by the
//! contract's rule, so a newer app still opens on an older host). A CAPABILITY it does not know is
//! parsed, kept by name and never granted ([`Capabilities::unknown`]): the old host has no bridge
//! call that could honour it, so leaving it out is fail-closed, and the host can show it as asked
//! for and not given. When a later host learns that capability it is no longer "unknown"
//! but granted — and since what a member consented to is kept as the GRANTED names
//! ([`Capabilities::granted`]), never re-derived from the manifest, that later grant is a widening
//! and is asked again. Refusing the whole manifest instead would make every new capability a
//! breaking change for every app that declares it, which closes a door for no gain in safety.
//!
//! Everything that grants is checked to its shape: the id is `ext:<publisher>/<name>` (built-in
//! and `html:` ids are unreachable from a manifest), origins are `https:`/`wss:` hosts with no
//! wildcard, no path and no blanket scheme (D11), the publisher key is an Ed25519 key. Errors are
//! typed `plugin/manifest-…` codes, never sentences.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde_json::{Map, Value};

use crate::semver::Semver;

/// The manifest's name inside a bundle, at its root.
pub const APP_MANIFEST_NAME: &str = "sezi-app.json";
/// The manifest format this reader knows (`sezi_app`). A change an older reader could not survive
/// is a new number, which this reader refuses.
pub const APP_MANIFEST_FORMAT: u64 = 1;
/// The largest manifest read, in bytes.
pub const MAX_APP_MANIFEST_BYTES: usize = 64 * 1024;
/// The most origins a manifest may name (the schema's `maxItems`).
pub const MAX_ORIGINS: usize = 16;
/// The most collections a manifest may name (the schema's `maxProperties`).
pub const MAX_COLLECTIONS: usize = 64;

/// Not JSON, not an object, or past [`MAX_APP_MANIFEST_BYTES`].
pub const BAD_JSON: &str = "plugin/manifest-not-json";
/// `sezi_app` is missing or names a format this reader does not know.
pub const BAD_FORMAT: &str = "plugin/manifest-format";
/// The id is not `ext:<publisher>/<name>`.
pub const BAD_ID: &str = "plugin/manifest-bad-id";
/// `version` is not a semantic version.
pub const BAD_VERSION: &str = "plugin/manifest-bad-version";
/// `contract` is missing, below 2, or its `max` is below its `min`.
pub const BAD_CONTRACT: &str = "plugin/manifest-bad-contract";
/// `publisher` is missing, or its key is not `ed25519:` and 32 bytes of unpadded base64url.
pub const BAD_PUBLISHER: &str = "plugin/manifest-bad-publisher";
/// A capability is present with the wrong shape (a known one), or its name is not a name.
pub const BAD_CAPABILITY: &str = "plugin/manifest-bad-capability";
/// An origin is not an `https:`/`wss:` host (a wildcard, a path, `http:`, a bare scheme).
pub const BAD_ORIGIN: &str = "plugin/manifest-bad-origin";
/// A collection's name or rule is not one this reader takes.
pub const BAD_COLLECTION: &str = "plugin/manifest-bad-collection";
/// Any other field of the wrong type or past its length (`name`, `mode`, `entry`, `icon`,
/// `requires`, `budgets`).
pub const BAD_FIELD: &str = "plugin/manifest-bad-field";

/// A parsed, checked `sezi-app.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppManifest {
    /// `ext:<publisher>/<name>`, stable across versions.
    pub id: String,
    /// The name Sezi shows when no entry of [`AppManifest::names`] matches.
    pub name: String,
    /// The name per BCP-47 language.
    pub names: BTreeMap<String, String>,
    pub description: Option<String>,
    pub version: Semver,
    pub contract: ContractRange,
    /// Feature names the app cannot run without (`ctx().features`).
    pub requires: Vec<String>,
    pub mode: AppMode,
    /// The page the app opens on, a path inside the bundle.
    pub entry: String,
    pub icon: Option<String>,
    pub publisher: Publisher,
    pub capabilities: Capabilities,
    /// The app's record collections and their shape. A v2 app writes only into these.
    pub collections: BTreeMap<String, CollectionRule>,
    /// What the app asks of the server's budgets; the host grants at most the server's.
    pub budgets: Budgets,
}

/// The bridge contract majors an app runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractRange {
    pub min: u32,
    /// `None` = any later major.
    pub max: Option<u32>,
}

impl ContractRange {
    /// Does a host speaking `major` run it?
    pub fn admits(&self, major: u32) -> bool {
        major >= self.min && self.max.is_none_or(|m| major <= m)
    }
}

/// `persistent` keeps records and shares them with later members; `instant` keeps nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Persistent,
    Instant,
}

impl AppMode {
    /// The install row's word for it (`installed_plugins.mode`).
    pub fn as_str(self) -> &'static str {
        match self {
            AppMode::Persistent => "persistent",
            AppMode::Instant => "instant",
        }
    }
}

/// Who signs the bundle (D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publisher {
    /// `ed25519:` + the key in unpadded base64url, as written.
    pub key_id: String,
    /// The key itself.
    pub key: [u8; 32],
    pub name: String,
    pub contact: Option<String>,
}

/// One record collection's rule — the shapes of the core's `plugin_record_rules`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionRule {
    /// One record per thing; only its author writes it; never a parent.
    Owned,
    /// One record per member per thing (on a parent when `needs_parent`).
    PerMember { needs_parent: bool },
}

/// What the app asks of the server's budgets. `None` = the server's own figure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Budgets {
    /// A member's live records per room.
    pub records: Option<u32>,
    /// A member's record bytes per room.
    pub record_bytes: Option<u64>,
}

impl Budgets {
    /// The figure the host grants: the app's ask, never above the server's.
    pub fn records_within(&self, server: u32) -> u32 {
        self.records.map_or(server, |r| r.min(server))
    }
    /// The same for bytes.
    pub fn bytes_within(&self, server: u64) -> u64 {
        self.record_bytes.map_or(server, |b| b.min(server))
    }
}

/// A capability this reader knows. The set grows: a new one is a new variant, a new name in
/// [`Capability::ALL`], and a widening for every app that already declared it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// `members()` — the room's roster (D8).
    Roster,
    /// `media.upload`, `media.url`.
    Media,
    /// `ui.playVideo`, `ui.placeVideo`.
    Video,
    /// The page reaches its declared origins (D11).
    Network,
    /// `external.fetchLinkMeta`.
    LinkMeta,
    /// `external.videoThumb`.
    VideoThumb,
    /// `library.list`, `ui.playLibrary` — the room's library, read only: what is in it and
    /// playing an item in Sezi's own player. The bytes never reach the app (2026-11-22).
    Library,
}

impl Capability {
    /// Every capability this reader knows, in name order of the contract's table.
    pub const ALL: [Capability; 7] = [
        Capability::Roster,
        Capability::Media,
        Capability::Video,
        Capability::Network,
        Capability::LinkMeta,
        Capability::VideoThumb,
        Capability::Library,
    ];

    /// The name it is granted, consented and refused under.
    pub fn name(self) -> &'static str {
        match self {
            Capability::Roster => "roster",
            Capability::Media => "media",
            Capability::Video => "video",
            Capability::Network => "network",
            Capability::LinkMeta => "external.linkMeta",
            Capability::VideoThumb => "external.videoThumb",
            Capability::Library => "library",
        }
    }
}

/// The declared capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub roster: bool,
    pub media: bool,
    pub video: bool,
    /// The origins the page may reach, lowercase, sorted. Empty = no network.
    pub origins: Vec<String>,
    /// One sentence shown beside the origins.
    pub network_purpose: Option<String>,
    pub link_meta: bool,
    pub video_thumb: bool,
    pub library: bool,
    /// Capability names this reader does not know: parsed, never granted (module doc).
    pub unknown: BTreeSet<String>,
}

impl Capabilities {
    /// Is `c` declared?
    pub fn has(&self, c: Capability) -> bool {
        match c {
            Capability::Roster => self.roster,
            Capability::Media => self.media,
            Capability::Video => self.video,
            Capability::Network => !self.origins.is_empty(),
            Capability::LinkMeta => self.link_meta,
            Capability::VideoThumb => self.video_thumb,
            Capability::Library => self.library,
        }
    }

    /// What this host GRANTS, as names: every known capability declared, and each origin as
    /// `network:<origin>` so that a new origin is a widening of its own. What a member consented
    /// to is kept as this set.
    pub fn granted(&self) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = Capability::ALL
            .into_iter()
            .filter(|c| self.has(*c))
            .map(|c| c.name().to_string())
            .collect();
        for o in &self.origins {
            out.insert(format!("network:{o}"));
        }
        out
    }

    /// What `self` grants beyond `consented` (an earlier [`Capabilities::granted`]): non-empty =
    /// the member is asked again.
    pub fn widened_from(&self, consented: &BTreeSet<String>) -> Vec<String> {
        self.granted().into_iter().filter(|g| !consented.contains(g)).collect()
    }
}

/// `ext:` + a publisher segment + `/` + a name segment (the schema's pattern).
pub fn is_app_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("ext:") else { return false };
    let Some((publisher, name)) = rest.split_once('/') else { return false };
    segment_ok(publisher, 40, false) && segment_ok(name, 64, true)
}

fn segment_ok(s: &str, max: usize, name: bool) -> bool {
    let b = s.as_bytes();
    let inner = |c: u8| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || (name && (c == b'.' || c == b'_'))
    };
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= max
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter().all(|&c| inner(c))
}

/// An origin a manifest may declare: `https://` or `wss://`, a dotted lowercase host with a
/// letters-only top label, an optional port; nothing else (no path, query, user, wildcard).
pub fn is_origin(o: &str) -> bool {
    let rest = o.strip_prefix("https://").or_else(|| o.strip_prefix("wss://"));
    let Some(rest) = rest else { return false };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if !matches!(p.parse::<u32>(), Ok(1..=65535)) {
            return false;
        }
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || host.len() > 253 {
        return false;
    }
    let (top, rest) = labels.split_last().expect("two labels");
    let top_ok = (2..=63).contains(&top.len()) && top.bytes().all(|c| c.is_ascii_lowercase());
    top_ok
        && rest.iter().all(|l| {
            let b = l.as_bytes();
            let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
            (1..=63).contains(&b.len())
                && edge(b[0])
                && edge(b[b.len() - 1])
                && b.iter().all(|&c| edge(c) || c == b'-')
        })
}

/// `ed25519:` + 43 characters of unpadded base64url → the 32-byte key.
pub fn parse_key_id(key_id: &str) -> Option<[u8; 32]> {
    let b64 = key_id.strip_prefix("ed25519:")?;
    if b64.len() != 43 {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).ok()?;
    raw.try_into().ok()
}

/// The key id of a 32-byte key.
pub fn key_id_of(key: &[u8; 32]) -> String {
    format!("ed25519:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key))
}

/// A bundle path (the schema's `path`): relative, no `..`, only `[A-Za-z0-9._/-]`, ≤ 200.
fn is_bundle_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 200
        && !p.starts_with('/')
        && p.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
        && p.split('/').all(|seg| !seg.is_empty() && seg != ".." && seg != ".")
}

fn feature_ok(f: &str) -> bool {
    f.len() <= 64
        && f.split('.').all(|seg| {
            let b = seg.as_bytes();
            !b.is_empty() && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_alphanumeric())
        })
}

/// A capability NAME (known or not): the shape a later host could give a meaning to.
pub(crate) fn capability_name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn text(v: Option<&Value>, max_chars: usize, code: &'static str) -> Result<Option<String>, &'static str> {
    match v {
        None => Ok(None),
        Some(Value::String(s)) => {
            let n = s.chars().count();
            if n == 0 || n > max_chars || s.chars().any(char::is_control) {
                Err(code)
            } else {
                Ok(Some(s.clone()))
            }
        }
        Some(_) => Err(code),
    }
}

fn flag(v: Option<&Value>, code: &'static str) -> Result<bool, &'static str> {
    match v {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(code),
    }
}

/// Read and check a `sezi-app.json`.
pub fn parse_app_manifest(bytes: &[u8]) -> Result<AppManifest, &'static str> {
    if bytes.len() > MAX_APP_MANIFEST_BYTES {
        return Err(BAD_JSON);
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| BAD_JSON)?;
    let Value::Object(m) = v else { return Err(BAD_JSON) };
    if m.get("sezi_app").and_then(Value::as_u64) != Some(APP_MANIFEST_FORMAT) {
        return Err(BAD_FORMAT);
    }
    let id = m.get("id").and_then(Value::as_str).filter(|i| is_app_id(i)).ok_or(BAD_ID)?;
    let name = text(m.get("name"), 48, BAD_FIELD)?.ok_or(BAD_FIELD)?;
    let names = parse_names(m.get("names"))?;
    let description = text(m.get("description"), 500, BAD_FIELD)?;
    let version = m
        .get("version")
        .and_then(Value::as_str)
        .and_then(Semver::parse)
        .ok_or(BAD_VERSION)?;
    let contract = parse_contract(m.get("contract"))?;
    let requires = parse_requires(m.get("requires"))?;
    let mode = match m.get("mode") {
        None => AppMode::Persistent,
        Some(Value::String(s)) if s == "persistent" => AppMode::Persistent,
        Some(Value::String(s)) if s == "instant" => AppMode::Instant,
        Some(_) => return Err(BAD_FIELD),
    };
    let entry = match m.get("entry") {
        None => "index.html".to_string(),
        Some(Value::String(s)) if is_bundle_path(s) => s.clone(),
        Some(_) => return Err(BAD_FIELD),
    };
    let icon = match m.get("icon") {
        None => None,
        Some(Value::String(s)) if is_bundle_path(s) => Some(s.clone()),
        Some(_) => return Err(BAD_FIELD),
    };
    let publisher = parse_publisher(m.get("publisher"))?;
    let capabilities = parse_capabilities(m.get("capabilities"))?;
    let collections = parse_collections(m.get("collections"))?;
    let budgets = parse_budgets(m.get("budgets"))?;
    Ok(AppManifest {
        id: id.to_string(),
        name,
        names,
        description,
        version,
        contract,
        requires,
        mode,
        entry,
        icon,
        publisher,
        capabilities,
        collections,
        budgets,
    })
}

fn object<'a>(
    v: Option<&'a Value>,
    code: &'static str,
) -> Result<Option<&'a Map<String, Value>>, &'static str> {
    match v {
        None => Ok(None),
        Some(Value::Object(o)) => Ok(Some(o)),
        Some(_) => Err(code),
    }
}

fn parse_names(v: Option<&Value>) -> Result<BTreeMap<String, String>, &'static str> {
    let mut out = BTreeMap::new();
    for (lang, name) in object(v, BAD_FIELD)?.into_iter().flatten() {
        let lang_ok = lang.split('-').enumerate().all(|(i, seg)| {
            let b = seg.as_bytes();
            if i == 0 {
                (2..=3).contains(&b.len()) && b.iter().all(u8::is_ascii_lowercase)
            } else {
                (2..=8).contains(&b.len()) && b.iter().all(u8::is_ascii_alphanumeric)
            }
        });
        if !lang_ok {
            return Err(BAD_FIELD);
        }
        out.insert(lang.clone(), text(Some(name), 48, BAD_FIELD)?.ok_or(BAD_FIELD)?);
    }
    Ok(out)
}

fn parse_contract(v: Option<&Value>) -> Result<ContractRange, &'static str> {
    let o = object(v, BAD_CONTRACT)?.ok_or(BAD_CONTRACT)?;
    let major = |v: &Value| v.as_u64().filter(|n| (2..=u32::MAX as u64).contains(n)).map(|n| n as u32);
    let min = o.get("min").and_then(major).ok_or(BAD_CONTRACT)?;
    let max = match o.get("max") {
        None => None,
        Some(v) => Some(major(v).filter(|m| *m >= min).ok_or(BAD_CONTRACT)?),
    };
    Ok(ContractRange { min, max })
}

fn parse_requires(v: Option<&Value>) -> Result<Vec<String>, &'static str> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let list = v.as_array().filter(|l| l.len() <= 64).ok_or(BAD_FIELD)?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for f in list {
        let f = f.as_str().filter(|f| feature_ok(f)).ok_or(BAD_FIELD)?;
        if !seen.insert(f) {
            return Err(BAD_FIELD);
        }
        out.push(f.to_string());
    }
    Ok(out)
}

fn parse_publisher(v: Option<&Value>) -> Result<Publisher, &'static str> {
    let o = object(v, BAD_PUBLISHER)?.ok_or(BAD_PUBLISHER)?;
    let key_id = o.get("key_id").and_then(Value::as_str).ok_or(BAD_PUBLISHER)?;
    let key = parse_key_id(key_id).ok_or(BAD_PUBLISHER)?;
    let name = text(o.get("name"), 64, BAD_PUBLISHER)?.ok_or(BAD_PUBLISHER)?;
    let contact = text(o.get("contact"), 210, BAD_PUBLISHER)?;
    if let Some(c) = &contact {
        let scheme_ok = c.starts_with("https://") || c.starts_with("mailto:");
        if !scheme_ok || c.chars().any(char::is_whitespace) {
            return Err(BAD_PUBLISHER);
        }
    }
    Ok(Publisher { key_id: key_id.to_string(), key, name, contact })
}

fn parse_capabilities(v: Option<&Value>) -> Result<Capabilities, &'static str> {
    let mut caps = Capabilities::default();
    let Some(o) = object(v, BAD_CAPABILITY)? else { return Ok(caps) };
    for (name, value) in o {
        match name.as_str() {
            "roster" => caps.roster = flag(Some(value), BAD_CAPABILITY)?,
            "media" => caps.media = flag(Some(value), BAD_CAPABILITY)?,
            "video" => caps.video = flag(Some(value), BAD_CAPABILITY)?,
            "library" => caps.library = flag(Some(value), BAD_CAPABILITY)?,
            "network" => {
                let n = value.as_object().ok_or(BAD_CAPABILITY)?;
                let list = n.get("origins").and_then(Value::as_array).ok_or(BAD_CAPABILITY)?;
                if list.is_empty() || list.len() > MAX_ORIGINS {
                    return Err(BAD_CAPABILITY);
                }
                let mut origins = BTreeSet::new();
                for o in list {
                    let o = o.as_str().filter(|o| is_origin(o)).ok_or(BAD_ORIGIN)?;
                    if !origins.insert(o.to_string()) {
                        return Err(BAD_ORIGIN);
                    }
                }
                caps.origins = origins.into_iter().collect();
                caps.network_purpose = text(n.get("purpose"), 200, BAD_CAPABILITY)?;
                for key in n.keys().filter(|k| !matches!(k.as_str(), "origins" | "purpose")) {
                    note_unknown(&mut caps, &format!("network.{key}"))?;
                }
            }
            "external" => {
                let e = value.as_object().ok_or(BAD_CAPABILITY)?;
                for (key, value) in e {
                    match key.as_str() {
                        "linkMeta" => caps.link_meta = flag(Some(value), BAD_CAPABILITY)?,
                        "videoThumb" => caps.video_thumb = flag(Some(value), BAD_CAPABILITY)?,
                        other => {
                            if value != &Value::Bool(false) {
                                note_unknown(&mut caps, &format!("external.{other}"))?;
                            }
                        }
                    }
                }
            }
            other => {
                // Declared and switched off is nothing at all, known or not.
                if value != &Value::Bool(false) && !value.is_null() {
                    note_unknown(&mut caps, other)?;
                }
            }
        }
    }
    // A call Sezi makes on the app's behalf with an address the app chose is network too.
    if (caps.link_meta || caps.video_thumb) && caps.origins.is_empty() {
        return Err(BAD_CAPABILITY);
    }
    Ok(caps)
}

fn note_unknown(caps: &mut Capabilities, name: &str) -> Result<(), &'static str> {
    if !capability_name_ok(name) || caps.unknown.len() >= 64 {
        return Err(BAD_CAPABILITY);
    }
    caps.unknown.insert(name.to_string());
    Ok(())
}

fn parse_collections(v: Option<&Value>) -> Result<BTreeMap<String, CollectionRule>, &'static str> {
    let mut out = BTreeMap::new();
    let Some(o) = object(v, BAD_COLLECTION)? else { return Ok(out) };
    if o.len() > MAX_COLLECTIONS {
        return Err(BAD_COLLECTION);
    }
    for (name, rule) in o {
        let name_ok = (1..=64).contains(&name.len())
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
        let r = rule.as_object().ok_or(BAD_COLLECTION)?;
        if !name_ok {
            return Err(BAD_COLLECTION);
        }
        let needs_parent = flag(r.get("needs_parent"), BAD_COLLECTION)?;
        let rule = match r.get("shape") {
            None => CollectionRule::Owned,
            Some(Value::String(s)) if s == "owned" => CollectionRule::Owned,
            Some(Value::String(s)) if s == "per_member" => CollectionRule::PerMember { needs_parent },
            Some(_) => return Err(BAD_COLLECTION),
        };
        // An owned record never has a parent; asking for one is a rule this reader cannot keep.
        if rule == CollectionRule::Owned && needs_parent {
            return Err(BAD_COLLECTION);
        }
        out.insert(name.clone(), rule);
    }
    Ok(out)
}

fn parse_budgets(v: Option<&Value>) -> Result<Budgets, &'static str> {
    let Some(o) = object(v, BAD_FIELD)? else { return Ok(Budgets::default()) };
    let records = match o.get("records") {
        None => None,
        Some(v) => Some(v.as_u64().filter(|n| (1..=u32::MAX as u64).contains(n)).ok_or(BAD_FIELD)? as u32),
    };
    let record_bytes = match o.get("record_bytes") {
        None => None,
        Some(v) => Some(v.as_u64().filter(|n| *n >= 1).ok_or(BAD_FIELD)?),
    };
    Ok(Budgets { records, record_bytes })
}

#[cfg(test)]
#[path = "app_manifest_tests.rs"]
mod tests;
