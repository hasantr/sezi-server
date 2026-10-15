//! Which way a wake goes — the push config, read per key **env FIRST, then D1 `server_config`**.
//!
//! Without env, whatever the owner entered via `PATCH /admin/fcm-config`; failing that, the
//! **shared PUSH RELAY** — the default, so a self-host install that never brings its own service
//! account still gets zero-config push (see `DEFAULT_PUSH_RELAY_URL` and the `push-relay/`
//! worker). With the relay `off`, push is a silent no-op: FAIL-OPEN, because FCM is optional and
//! the worker runs fine without it. See `PushConfig::send_mode`.
//!
//! **An own project that cannot reach some of these phones (K8, 2026-10-14).** The published app's
//! devices hold tokens minted by OUR Firebase project, so a server owner who enters their own
//! project gets a 403 `SENDER_ID_MISMATCH` for each such token. Until the K8 fix every phone on
//! the server then stopped waking while the settings read "Set up". The decision is made PER
//! TOKEN (`wake.rs`): a token Google refused for the owner's project is marked in `push_tokens`
//! (`relay_project`), resent through the shared relay, and from then on always relayed, until the
//! device registers a different token. Every other token keeps going direct, so a mixed fleet
//! (the owner's own build beside the published app) works whatever order its wakes run in, and an
//! own-build token is never handed to the shared relay. The first answer was a server-wide
//! verdict; two wakes racing on a fresh server could then switch an own-build server to a relay
//! that cannot reach it (adversarial review, 2026-10-14). What is left at server level is a
//! SUMMARY for the owner's settings ([`status`]): how many devices are relayed, and whether the
//! project has ever reached one (`KEY_OWN_REACHED`). Saving or clearing the credentials resets
//! both, and the next wake tests each token again. The owner's credentials are never deleted by
//! the server.

use serde::{Deserialize, Serialize};
use worker::*;

use crate::d1util::{d1_int, d1_text};

// ── Config resolution — env-first, D1-fallback ──
//
// DELIBERATELY NOT MEMOIZED, unlike self_provision's keys: those are fixed, this config changes
// by the owner's hand, and a thread_local memo would hide a value they just saved for the whole
// isolate lifetime — the "I saved it but no push arrives" trap. It costs ONE D1 query per wake
// (every key in one SELECT): push fires only for an offline recipient, and that same wake already
// goes to D1 for push_tokens. An env-configured install reads it too — the K8 verdicts live in D1.
//
// SECURITY (the D1-storage trade-off, as in admin/cf_config.rs): FCM_SERVICE_ACCOUNT holds a
// Google private key, and the worker must read it in plaintext to sign the OAuth assertion, so it
// cannot be encrypted with a key we do not hold. It is the owner's own Firebase project and not
// E2E content — push is a contentless wake, so a leaked key forges wakes, it does not open
// messages. No endpoint returns the value, and an owner can move it to an env secret, which wins.

/// The server-wide "Google refused this project" verdict of the first K8 build. It routes
/// nothing any more; the clear below and migration 0048 delete what a server wrote under it.
#[cfg(test)]
pub(crate) const LEGACY_KEY_OWN_REJECTED: &str = "push_own_project_mismatch";
/// The `server_config` key of "this project has reached a device". Its value is a
/// `ProjectVerdict`. A summary for the owner's settings; it routes nothing.
pub(crate) const KEY_OWN_REACHED: &str = "push_own_project_reached";

const KEY_PROJECT_ID: &str = "fcm_project_id";
const KEY_SERVICE_ACCOUNT: &str = "fcm_service_account";
const KEY_RELAY_URL: &str = "push_relay_url";

/// Every push key in one query: what a wake and the admin status read.
const READ_SQL: &str = "SELECT key, value FROM server_config WHERE key IN (?, ?, ?, ?)";

/// What was measured goes when the owner saves or clears the credentials — it was measured against
/// what they just replaced: the server's "reached" (and the legacy verdict), and every token's
/// relay mark ([`CLEAR_TOKEN_ROUTES_SQL`]). The next wake tests each token again.
pub(crate) const CLEAR_VERDICTS_SQL: &str = "DELETE FROM server_config
     WHERE key IN ('push_own_project_mismatch', 'push_own_project_reached')";

/// Every token's relay mark goes with the verdicts.
pub(crate) const CLEAR_TOKEN_ROUTES_SQL: &str =
    "UPDATE push_tokens SET relay_project = NULL WHERE relay_project IS NOT NULL";

/// How many live devices' tokens are relayed because Google refused `?1` (the own project) for
/// them — the owner's summary. A revoked device's row is not counted (the wake skips it too).
pub(crate) const RELAY_ROUTED_COUNT_SQL: &str = "SELECT COUNT(*) AS n FROM push_tokens pt
     WHERE pt.relay_project = ?1
       AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.user_id = pt.user_id
                         AND d.device_id = pt.device_id AND d.revoked_at IS NOT NULL)";

/// One verdict's write. `created_at` stays the first write's stamp, as everywhere in this table;
/// the verdict's own time is in its value.
const RECORD_SQL: &str = "INSERT INTO server_config (key, value, created_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value";

/// The shared push relay — the DEFAULT push path for a self-host install that brings no service
/// account of its own. The URL is NOT a secret: the relay is token-gated and rate-limited, and the
/// worst case is a contentless wake.
const DEFAULT_PUSH_RELAY_URL: &str = "https://sezi-push-relay.hsn-salihoglu.workers.dev";

/// What was measured about the owner's own project, and when. Bound to the project id: a verdict
/// about another project (the owner changed the env var, say) says nothing about this one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProjectVerdict {
    pub(crate) at: i64,
    pub(crate) project: String,
}

/// Trim, then empty → None. env and D1 values are normalized with the SAME discipline
/// (the cf_analytics `normalize` pattern).
fn normalize(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// The env half of the config: each Some wins over its D1 row.
#[derive(Default)]
pub(crate) struct EnvPush {
    pub(crate) project_id: Option<String>,
    pub(crate) service_account: Option<String>,
    pub(crate) relay_url: Option<String>,
}

impl EnvPush {
    fn read(env: &Env) -> Self {
        Self {
            project_id: crate::utils::env_text(env, "FCM_PROJECT_ID").and_then(|v| normalize(&v)),
            service_account: crate::utils::env_text(env, "FCM_SERVICE_ACCOUNT").and_then(|s| normalize(&s)),
            relay_url: crate::utils::env_text(env, "PUSH_RELAY_URL").and_then(|v| normalize(&v)),
        }
    }
}

/// The resolved push config of this server.
#[derive(Clone, Debug, Default)]
pub(crate) struct PushConfig {
    pub(crate) project_id: Option<String>,
    pub(crate) service_account: Option<String>,
    /// Already resolved: the default applied, `off` → None.
    pub(crate) relay_url: Option<String>,
    pub(crate) reached: Option<ProjectVerdict>,
}

impl PushConfig {
    /// env first, then the `server_config` rows. A relay set to `off` in either source is None —
    /// the single switch for an owner who wants push turned off entirely.
    pub(crate) fn resolve(env: EnvPush, rows: &[(String, String)]) -> Self {
        let row = |key: &str| {
            rows.iter().find(|(k, _)| k == key).and_then(|(_, v)| normalize(v))
        };
        let verdict = |key: &str| row(key).and_then(|v| serde_json::from_str(&v).ok());
        let relay_url = match env.relay_url.or_else(|| row(KEY_RELAY_URL)) {
            Some(u) if u.eq_ignore_ascii_case("off") => None,
            Some(u) => Some(u),
            None => Some(DEFAULT_PUSH_RELAY_URL.to_string()),
        };
        Self {
            project_id: env.project_id.or_else(|| row(KEY_PROJECT_ID)),
            service_account: env.service_account.or_else(|| row(KEY_SERVICE_ACCOUNT)),
            relay_url,
            reached: verdict(KEY_OWN_REACHED),
        }
    }

    /// The owner's own project, when BOTH halves are set. A half-configured install (project id
    /// only) falls through to the relay — more useful than a warning on every message.
    fn own(&self) -> Option<(&str, &str)> {
        Some((self.project_id.as_deref()?, self.service_account.as_deref()?))
    }

    fn about_own(&self, v: &Option<ProjectVerdict>) -> bool {
        matches!((self.own(), v), (Some((p, _)), Some(v)) if v.project == p)
    }

    /// The owner's own project has reached a device.
    pub(crate) fn own_reached(&self) -> bool {
        self.about_own(&self.reached)
    }

    /// The way a wake goes: the owner's own project — each token direct unless it is marked for
    /// the relay (`wake.rs`) — otherwise the shared relay; with that `off`, nothing.
    pub(crate) fn send_mode(&self) -> Option<SendMode> {
        if let Some((project_id, service_account)) = self.own() {
            return Some(SendMode::Direct {
                project_id: project_id.to_string(),
                service_account: service_account.to_string(),
                fallback: self.relay_url.clone(),
                reached: self.own_reached(),
            });
        }
        self.relay_url.clone().map(|url| SendMode::Relay { url })
    }

    /// Which way the server is configured to push.
    pub(crate) fn mode(&self) -> PushMode {
        match self.send_mode() {
            Some(SendMode::Direct { .. }) => PushMode::Own,
            Some(SendMode::Relay { .. }) => PushMode::Relay,
            None => PushMode::Off,
        }
    }
}

/// Read the config: env, and every push row in ONE query. None when D1 cannot be read at all —
/// FAIL-OPEN is absolute here: push is optional and must never fail a request.
pub(crate) async fn read(env: &Env, db: &D1Database) -> Option<PushConfig> {
    #[derive(Deserialize)]
    struct Row {
        key: String,
        value: String,
    }
    let rows: Vec<Row> = db
        .prepare(READ_SQL)
        .bind(&[
            d1_text(KEY_PROJECT_ID),
            d1_text(KEY_SERVICE_ACCOUNT),
            d1_text(KEY_RELAY_URL),
            d1_text(KEY_OWN_REACHED),
        ])
        .ok()?
        .all()
        .await
        .ok()?
        .results()
        .ok()?;
    let rows: Vec<(String, String)> = rows.into_iter().map(|r| (r.key, r.value)).collect();
    Some(PushConfig::resolve(EnvPush::read(env), &rows))
}

/// Write one verdict. Best-effort: a lost write only means the next wake measures again.
pub(crate) async fn record(db: &D1Database, key: &str, verdict: &ProjectVerdict) {
    let Ok(value) = serde_json::to_string(verdict) else { return };
    if let Ok(stmt) = db
        .prepare(RECORD_SQL)
        .bind(&[d1_text(key), d1_text(&value), d1_int(verdict.at)])
    {
        let _ = stmt.run().await;
    }
}

/// Forget what was measured — the owner saved or cleared the credentials: the verdicts and every
/// token's relay mark, in one batch.
pub(crate) async fn clear_project_verdicts(db: &D1Database) -> Result<()> {
    db.batch(vec![db.prepare(CLEAR_VERDICTS_SQL), db.prepare(CLEAR_TOKEN_ROUTES_SQL)])
        .await?;
    Ok(())
}

/// The owner's summary from the config and the count of relayed devices. Pure, so the wording
/// rules are tested without D1.
///
/// - `relay_routed`: live devices whose token Google refused for the own project (the published
///   app's), woken through the shared relay.
/// - `own_rejected`: devices were refused and NONE was ever reached directly — the owner's project
///   serves nobody here. The mode then reports what the wake does for those devices: the relay,
///   or nothing with the relay off.
pub(crate) fn summarize(cfg: &PushConfig, relay_routed: u32) -> PushStatus {
    let own_rejected = cfg.own().is_some() && relay_routed > 0 && !cfg.own_reached();
    let mode = match (cfg.mode(), own_rejected) {
        (PushMode::Own, true) if cfg.relay_url.is_some() => PushMode::Relay,
        (PushMode::Own, true) => PushMode::Off,
        (m, _) => m,
    };
    PushStatus { mode, own_rejected, relay_routed: if cfg.own().is_some() { relay_routed } else { 0 } }
}

/// How many live devices are relay-routed under `project` (one D1 query). 0 when unreadable.
async fn relay_routed(db: &D1Database, project: &str) -> u32 {
    #[derive(Deserialize)]
    struct N {
        n: u32,
    }
    let Ok(stmt) = db.prepare(RELAY_ROUTED_COUNT_SQL).bind(&[d1_text(project)]) else {
        return 0;
    };
    stmt.first::<N>(None).await.ok().flatten().map_or(0, |r| r.n)
}

/// What the owner's screens are told about push ([`summarize`]): the mode, how many devices the
/// shared relay wakes because Google refused the owner's project for their tokens, and whether
/// that is every device that was tried.
///
/// `PushMode::can_push()` on top of it answers "will a push go out at all" — the right question
/// for a health indicator (`fcm_configured` on `/admin/stats` and on the fcm-config response), and
/// the WRONG one for the owner's setup screen: the relay URL falls back to a built-in default
/// unless explicitly `off`, so a FRESH server with zero FCM keys reports true, and a bare
/// "configured ✓" would read as "I set this up". That screen asks for the mode itself.
///
/// The read face of a WRITE-ONLY contract: states, never a value. Cheap by design — two D1
/// queries, no call to Google or the relay — and it fails safe to `Off`, because stats must NEVER
/// 500.
pub async fn status(env: &Env) -> PushStatus {
    let off = PushStatus { mode: PushMode::Off, own_rejected: false, relay_routed: 0 };
    let Ok(db) = env.d1("DB") else { return off };
    let Some(cfg) = read(env, &db).await else { return off };
    let routed = match cfg.own() {
        Some((project, _)) => relay_routed(&db, project).await,
        None => 0,
    };
    summarize(&cfg, routed)
}

/// See `status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushStatus {
    pub mode: PushMode,
    pub own_rejected: bool,
    pub relay_routed: u32,
}

/// How a server sends push wakes. `Own` = the owner's own FCM project and service account (a
/// token Google refused for it goes through the relay); `Relay` = the shared push relay (the
/// default, and NOT something the owner configured — or, in the owner's summary, every device
/// tried was refused for the owner's project); `Off` = neither, so an offline recipient gets no
/// wake at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushMode {
    Own,
    Relay,
    Off,
}

impl PushMode {
    /// The wire value for `fcm_mode`. Kept as a lowercase word rather than a number so a log or a
    /// curl reads without a lookup table.
    pub fn as_str(self) -> &'static str {
        match self {
            PushMode::Own => "own",
            PushMode::Relay => "relay",
            PushMode::Off => "off",
        }
    }

    /// Will a push go out at all — the health question, in ONE place.
    ///
    /// It used to be spelled `mode != PushMode::Off` at each call site, with `is_configured`
    /// saying the same thing a fourth time and going unused. The same predicate written in
    /// several places is how two of them end up disagreeing.
    pub fn can_push(self) -> bool {
        !matches!(self, PushMode::Off)
    }
}

/// The push send path: the owner's OWN project goes DIRECT to FCM (`fallback` is the relay a
/// wake Google refuses for a token is resent through; `reached` says the project has woken a
/// device before). Otherwise the shared RELAY (the default, for zero-config self-host).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SendMode {
    Direct {
        project_id: String,
        service_account: String,
        fallback: Option<String>,
        reached: bool,
    },
    Relay {
        url: String,
    },
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
