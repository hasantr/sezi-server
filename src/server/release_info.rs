//! What this relay says about ITSELF for updates (`docs/SERVER_UPDATE_PLAN.md` §2.1, rollout
//! step 2): where it runs, which Cloudflare version it is, which source commit it was built from,
//! and whether its schema is current. All additive on `/capabilities` and `/healthz`: an old app
//! ignores the keys, and an old relay simply lacks them (the core reads them leniently).
//!
//! - `hosting`: `workerd` (the bare-workerd config generator sets `SEZI_HOSTING`,
//!   `scripts/workerd_config.py`), `wrangler` (a legacy `wrangler dev` install that sets the same
//!   var), `cloudflare` (the var says so, or Cloudflare's version metadata binding is there), else
//!   `null` — an old Cloudflare copy without the binding and a bare `wrangler dev` look alike, and
//!   a guess here would send the app down the wrong update path.
//! - `version_id`: the Cloudflare Worker version serving this request, from the
//!   `[version_metadata]` binding the template's `wrangler.toml` declares. It lets the app prove
//!   that the Worker it is about to update IS this server (plan §3.2). `null` elsewhere.
//! - `commit`: the monorepo commit `sync-template.sh` built from (`SEZI_COMMIT` at build time).
//! - `/healthz` `migrations`: `ok`, `failed:<name>` or `unchecked` (`self_provision.rs`).

use serde_json::{json, Value};

/// The `[version_metadata]` binding's name in `worker-rs/template/wrangler.toml`.
pub const VERSION_METADATA: &str = "CF_VERSION_METADATA";

/// Where this relay runs, or `None` when nothing says so.
pub fn hosting(var: Option<&str>, has_version_metadata: bool) -> Option<&'static str> {
    match var.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("workerd") => Some("workerd"),
        Some("wrangler") => Some("wrangler"),
        Some("cloudflare") => Some("cloudflare"),
        Some("") | None if has_version_metadata => Some("cloudflare"),
        _ => None,
    }
}

/// The build's source commit, when the stamp is a git sha (7–40 hex digits), lowercased.
pub fn commit(stamp: Option<&str>) -> Option<String> {
    let s = stamp?.trim();
    ((7..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_ascii_lowercase())
}

/// `/healthz`'s `migrations` word. `checked` = the schema reached the newest migration in this
/// isolate; `failed` = the migration the last attempt could not reach.
pub fn migration_status(checked: bool, failed: Option<&str>) -> String {
    match (checked, failed) {
        (true, _) => "ok".into(),
        (false, Some(name)) => format!("failed:{name}"),
        (false, None) => "unchecked".into(),
    }
}

/// The three `/capabilities` keys, always present (null when unknown).
pub fn fields(hosting: Option<&str>, version_id: Option<String>, commit: Option<String>) -> Value {
    json!({
        "hosting": hosting,
        "version_id": version_id.filter(|v| !v.is_empty()),
        "commit": commit,
    })
}

#[cfg(test)]
#[path = "release_info_tests.rs"]
mod tests;
