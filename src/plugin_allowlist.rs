//! The server owner's plugin allowlist (`docs/PLUGINS_BOTS_REVIEW_2026_11.md` § 3.5, Wave C3;
//! decision D1): the mode (`open` | `allowlist`) and the approved rows, kept here, served to every
//! member on `GET /plugin-policy`, announced on `/capabilities` (`plugin_policy.mode`), and checked
//! at `put_code` (`plugin_blob.rs`). The rule itself is `sezi_plugin_fmt::allowlist`, the one every
//! member's core applies on assign and on receipt.
//!
//! **Stored**: the rows in `plugin_allowlist` (migration 0059, expand-only), the mode as the
//! `server_config` key [`MODE_KEY`] (no key = `open`, as on every relay before; the owner's `open`
//! is stored as the word since 2026-11-08, so it outlives a re-claim's seed). A server claimed from
//! 2026-11-08 on starts in `allowlist` ([`SEED_FRESH_MODE_SQL`]). A build rolled back to one without
//! this file reads neither and runs `open`; the owner's rows are kept.
//!
//! ## What the relay can check, and what it cannot
//!
//! A plugin's code reaches the relay as ciphertext under a key that travels only end to end, so
//! the relay never sees the bundle. An admin's app (C3 or later) therefore PRESENTS, beside the
//! upload, what it claims the bytes are (`sezi_plugin_fmt::allowlist` `HEADER_*`): the plaintext
//! code hash, and for a signed app its `sezi-app.json`, the bundle digest and the publisher's
//! signature line. The relay verifies that signature (`verify_detached`) and judges the claim
//! with the same rule the members use. What that gives:
//!
//! - a stock app of an admin who picks an unapproved app is refused at the upload, `400
//!   plugin/not-approved` — before anything is fanned out to the room;
//! - the relay's decision is about a manifest the publisher really signed, so a row's ceiling
//!   (`max_caps`) is held to what that manifest declares;
//! - an app from before C3 presents nothing and is refused in `allowlist` mode with the same `400`,
//!   which it ends its op on (`is_request_refused`, every app since 2046).
//!
//! What it does NOT give: the relay cannot tell that the bytes are the ones the claim describes.
//! A group admin running a MODIFIED app can present an approved, genuinely signed manifest (a
//! signed manifest is public) and upload other code; small code (≤ 8 KiB inline html) never
//! reaches `put_code` at all, it travels end to end. Neither runs on a member's device: every
//! member's core opens the bytes, verifies the publisher signature over the files and judges the
//! app against this same list before it is cached (`core/src/kernel/plugin_policy.rs`). So the
//! upload check is a first gate and a statement in the relay's terms; the members' cores are the
//! boundary. An attacker holding the server's OWNER seat is the policy's author: it can approve
//! anything or switch the mode to `open` — the list does not protect members from their server's
//! owner, who is who they trusted to make it. A compromised relay can serve members a forged
//! list; it still cannot make an app run that no admin of the room installed, nor a signed app
//! under a key that did not sign it.

use std::collections::BTreeSet;

use sezi_plugin_fmt::allowlist::{
    self as rule, AllowRow, Allowlist, Candidate, Mode, HEADER_APP, HEADER_APP_DIGEST,
    HEADER_APP_SIG, HEADER_CODE_HASH, HEADER_FIRST_PARTY,
};

/// The `server_config` key the mode lives under.
pub(crate) const MODE_KEY: &str = "plugin_policy_mode";

/// The mode a server starts in: written in the batch that registers its FIRST owner (the genesis
/// claim, `auth/verify.rs`), never over a mode already stored. Decision D1 makes the allowlist the
/// default for servers with test groups; nothing marks such a server, so every server claimed on a
/// build from 2026-11-08 on starts in `allowlist`, and every server claimed before keeps what it
/// has (no key = `open`). Built-ins and the first-party apps are exempt from the list, so a fresh
/// server works out of the box. Binds: created_at.
pub(crate) const SEED_FRESH_MODE_SQL: &str = "INSERT INTO server_config (key, value, created_at) \
     VALUES ('plugin_policy_mode', 'allowlist', ?1) ON CONFLICT(key) DO NOTHING";

pub(crate) const READ_MODE_SQL: &str =
    "SELECT value FROM server_config WHERE key = 'plugin_policy_mode' LIMIT 1";
pub(crate) const READ_ROWS_SQL: &str = "SELECT id, publisher_key, app_id, code_hash, max_caps, \
     label, added_at FROM plugin_allowlist ORDER BY id ASC";
pub(crate) const COUNT_SQL: &str = "SELECT COUNT(*) AS n FROM plugin_allowlist";
/// Binds: publisher_key, app_id, code_hash, max_caps, label, added_by, added_at. The same rule
/// again only refreshes its ceiling and label.
pub(crate) const UPSERT_SQL: &str = "INSERT INTO plugin_allowlist \
     (publisher_key, app_id, code_hash, max_caps, label, added_by, added_at) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
     ON CONFLICT (COALESCE(publisher_key, ''), COALESCE(app_id, ''), COALESCE(code_hash, '')) \
     DO UPDATE SET max_caps = excluded.max_caps, label = excluded.label";
pub(crate) const DELETE_SQL: &str = "DELETE FROM plugin_allowlist WHERE id = ?1";

/// One stored row as D1 answers it.
#[derive(serde::Deserialize, Debug)]
pub(crate) struct DbRow {
    pub id: i64,
    pub publisher_key: Option<String>,
    pub app_id: Option<String>,
    pub code_hash: Option<String>,
    pub max_caps: String,
    pub label: String,
    pub added_at: i64,
}

impl DbRow {
    /// The rule's row; `None` for one it cannot hold (written by hand).
    pub(crate) fn to_row(&self) -> Option<AllowRow> {
        let caps: serde_json::Value =
            serde_json::from_str(&self.max_caps).unwrap_or(serde_json::Value::Null);
        rule::row_from_json(&serde_json::json!({
            "id": self.id,
            "publisher_key": self.publisher_key,
            "app_id": self.app_id,
            "code_hash": self.code_hash,
            "max_caps": caps,
            "label": self.label,
            "added_at": self.added_at,
        }))
    }
}

/// The mode from its stored word: no row = `open`.
pub(crate) fn mode_of(stored: Option<&str>) -> Mode {
    Mode::read(stored)
}

/// The mode alone (`/capabilities`): a missing key or a D1 error reads `open`.
pub(crate) async fn read_mode(db: &worker::D1Database) -> Mode {
    #[derive(serde::Deserialize)]
    struct Value {
        value: String,
    }
    let stored = db.prepare(READ_MODE_SQL).first::<Value>(None).await.ok().flatten();
    mode_of(stored.as_ref().map(|v| v.value.as_str()))
}

/// This server's policy. The mode: a missing key or a D1 error reads `open` (the fail-open
/// discipline of every policy read here — the members' cores are the boundary, module doc). The
/// rows: a missing table or an error reads none, so an `allowlist` server then approves nothing.
pub(crate) async fn read(db: &worker::D1Database) -> Allowlist {
    let mode = read_mode(db).await;
    let rows = db
        .prepare(READ_ROWS_SQL)
        .all()
        .await
        .and_then(|r| r.results::<DbRow>())
        .unwrap_or_default();
    Allowlist { mode, rows: rows.iter().filter_map(DbRow::to_row).collect() }
}

/// The policy as `GET /plugin-policy` and the admin writes answer it (beside `disabled`).
pub(crate) fn view(list: &Allowlist) -> serde_json::Value {
    serde_json::json!({
        "mode": list.mode.as_str(),
        "allowed": list.rows.iter().map(rule::row_to_json).collect::<Vec<_>>(),
    })
}

/// What an upload presented, read from its headers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Presented {
    pub code_hash: Option<String>,
    pub app: Option<String>,
    pub sig: Option<String>,
    pub digest: Option<String>,
    /// A first-party web app's id (`HEADER_FIRST_PARTY`).
    pub first_party: Option<String>,
}

impl Presented {
    pub(crate) fn from_headers(h: &worker::Headers) -> Presented {
        let get = |name: &str| h.get(name).ok().flatten().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        Presented {
            code_hash: get(HEADER_CODE_HASH),
            app: get(HEADER_APP),
            sig: get(HEADER_APP_SIG),
            digest: get(HEADER_APP_DIGEST),
            first_party: get(HEADER_FIRST_PARTY),
        }
    }
}

/// May this upload be stored? `Ok` in `open` mode; else the presented claim must be approved by a
/// row: a signed manifest whose signature verifies is judged by its id, key and grants, the code
/// hash by the hash rows. Nothing usable presented (an app from before C3) = refused. A
/// first-party web app's code passes: the list exempts those apps (decision D1, so a fresh
/// `allowlist` server works out of the box), and no client ever runs the bytes uploaded under one
/// of their ids — each runs the code compiled into it — so the claim cannot smuggle code in.
pub(crate) fn upload_decision(list: &Allowlist, p: &Presented) -> Result<(), &'static str> {
    if list.mode == Mode::Open {
        return Ok(());
    }
    if p.first_party.as_deref().is_some_and(rule::is_first_party) {
        return Ok(());
    }
    let signed = match (&p.app, &p.sig, &p.digest) {
        (Some(app), Some(sig), Some(digest)) => rule::open_presented(app, sig, digest).ok(),
        _ => None,
    };
    let none = BTreeSet::new();
    let candidate = Candidate {
        plugin_id: signed.as_ref().map(|s| s.app_id.as_str()).unwrap_or(""),
        publisher_key_id: signed.as_ref().map(|s| s.publisher_key_id.as_str()),
        code_hash: p.code_hash.as_deref().filter(|h| rule::is_code_hash(h)),
        granted: signed.as_ref().map(|s| &s.granted).unwrap_or(&none),
    };
    if list.approves(&candidate) {
        Ok(())
    } else {
        Err(rule::NOT_APPROVED)
    }
}

#[cfg(test)]
#[path = "plugin_allowlist_tests.rs"]
mod tests;
