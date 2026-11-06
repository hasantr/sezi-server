//! What one member may keep in a room's plugin log — the relay half of review 2026-11 H10.
//!
//! The log (`plugin_log.rs`, the `PluginRoomLog` DO) is append-only and kept for as long as the
//! room lives, and before this nothing bounded it but a per-user rate limit that a relay without
//! its `RATE_LIMIT` KV binding does not apply at all (`ratelimit.rs`: a limit there is never a
//! BOUND). So an app left open in a loop could fill the room's Durable Object for good. Now every
//! member has a byte budget per app and one across all apps of the room, counted in the room's own
//! DO, where the append is sequenced — no KV, no second store, no race.
//!
//! **What an entry costs** is [`ENTRY_OVERHEAD_BYTES`] plus the bytes of every field it brings
//! (its ciphertext above all) — [`entry_bytes`] in Rust, [`ENTRY_BYTES_EXPR`] for rows already
//! stored; a test holds the two to one figure.
//!
//! **Expand-only** (AGENTS.md, rollback): two new DO tables, nothing the previous build reads is
//! touched. The count is kept per plugin against the log's own `seq` (`plugin_log_counted`), and
//! every append first counts whatever lies past that mark — so the first append after this build
//! lands counts the log that was already there, and entries a previous build wrote after a
//! rollback are counted the moment this build is back. No figure can drift from the rows.
//!
//! **The refusal** is `400 {"error":"plugin/log-full","scope":"app"|"room","limit_bytes":N}`:
//! a `400` because every app since 2046 ends an op at the first `400` (it walks no retry ladder,
//! `core/src/kernel/op_error.rs` `is_request_refused`), and nothing but a smaller log could make
//! the same entry fit. Each plugin record still reaches the room over its Olm fan-out (the log is
//! a dual write, `core/src/kernel/plugin_log_sync.rs`), so a full log loses no record for the
//! members already there. Compacting a log (keeping only the latest record per id) is the way
//! back under the budget and is not built yet.

use serde::Deserialize;

/// What one member may keep in ONE app's log in one room. Twice the record budget an author has
/// per app per room (decision D9, 16 MiB of live records): the log also keeps the superseded
/// versions until it is compacted.
pub(crate) const MAX_BYTES_PER_MEMBER_PER_APP: i64 = 32 * 1024 * 1024;
/// What one member may keep in the logs of ALL apps of one room together. Apps are named by
/// whoever installs them and the log takes any well-formed id, so a per-app budget alone could be
/// multiplied by inventing ids; this one cannot.
pub(crate) const MAX_BYTES_PER_MEMBER_PER_ROOM: i64 = 64 * 1024 * 1024;
/// What every entry costs beyond its fields: the row's ids, integers and index entry. Without it
/// a stream of near-empty entries would cost nothing.
pub(crate) const ENTRY_OVERHEAD_BYTES: i64 = 64;

/// The refusal's code (`<area>/<reason>`, for the app to word).
pub(crate) const LOG_FULL_CODE: &str = "plugin/log-full";
/// The refusal's status — see the module note.
pub(crate) const LOG_FULL_STATUS: u16 = 400;

/// Which budget an append would break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Full {
    /// [`MAX_BYTES_PER_MEMBER_PER_APP`].
    App,
    /// [`MAX_BYTES_PER_MEMBER_PER_ROOM`].
    Room,
}

impl Full {
    pub(crate) fn scope(self) -> &'static str {
        match self {
            Full::App => "app",
            Full::Room => "room",
        }
    }

    /// The budget this refusal broke, as this server set it.
    pub(crate) fn limit_bytes(self, limits: LogLimits) -> i64 {
        match self {
            Full::App => limits.app_bytes,
            Full::Room => limits.room_bytes,
        }
    }
}

/// The two budgets as this server's owner set them (`plugin_limits.rs` `log_app_bytes`,
/// `log_room_bytes`); the default is the constants above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogLimits {
    pub app_bytes: i64,
    pub room_bytes: i64,
}

impl Default for LogLimits {
    fn default() -> Self {
        Self { app_bytes: MAX_BYTES_PER_MEMBER_PER_APP, room_bytes: MAX_BYTES_PER_MEMBER_PER_ROOM }
    }
}

/// The header the append handler hands the room's DO the server's limits in (the DO reads no
/// D1): `<app_bytes>,<room_bytes>`.
pub(crate) const LIMITS_HEADER: &str = "x-sezi-log-limits";

impl LogLimits {
    /// The [`LIMITS_HEADER`] value.
    pub(crate) fn to_header(self) -> String {
        format!("{},{}", self.app_bytes, self.room_bytes)
    }

    /// Read [`LIMITS_HEADER`]; absent or malformed (a positive pair is required) = the defaults.
    pub(crate) fn from_header(raw: Option<&str>) -> Self {
        let parsed = raw.and_then(|r| {
            let (a, b) = r.split_once(',')?;
            let (a, b) = (a.trim().parse::<i64>().ok()?, b.trim().parse::<i64>().ok()?);
            (a > 0 && b > 0).then_some(Self { app_bytes: a, room_bytes: b })
        });
        parsed.unwrap_or_default()
    }
}

/// May an entry of `cost` bytes go in, given what its author already keeps in this app's log
/// (`app_bytes`) and in the whole room's (`room_bytes`)? `None` = it may. Only what an entry ADDS
/// is measured: a member already past a lowered limit keeps everything, and adds nothing.
pub(crate) fn refusal(app_bytes: i64, room_bytes: i64, cost: i64, limits: LogLimits) -> Option<Full> {
    if app_bytes.saturating_add(cost) > limits.app_bytes {
        return Some(Full::App);
    }
    if room_bytes.saturating_add(cost) > limits.room_bytes {
        return Some(Full::Room);
    }
    None
}

/// The fields an entry is charged for — every variable-length field the row stores except the
/// ids the row is keyed by.
pub(crate) struct EntryFields<'a> {
    pub ciphertext_b64: Option<&'a str>,
    pub nonce_b64: Option<&'a str>,
    pub blob_id: Option<&'a str>,
    pub blob_hash: Option<&'a str>,
    pub aad_hash: &'a str,
    pub prev_hash: Option<&'a str>,
    pub entry_hash: Option<&'a str>,
}

/// What an entry costs, in bytes.
pub(crate) fn entry_bytes(f: &EntryFields<'_>) -> i64 {
    let opt = |o: Option<&str>| o.map(str::len).unwrap_or(0) as i64;
    ENTRY_OVERHEAD_BYTES
        + opt(f.ciphertext_b64)
        + opt(f.nonce_b64)
        + opt(f.blob_id)
        + opt(f.blob_hash)
        + f.aad_hash.len() as i64
        + opt(f.prev_hash)
        + opt(f.entry_hash)
}

/// [`entry_bytes`] of a stored `plugin_log_entries` row, in SQL. `length()` of a TEXT counts
/// characters; the cast to BLOB makes it count bytes, as Rust's `len()` does.
macro_rules! entry_bytes_expr {
    () => {
        "(64 \
         + COALESCE(length(CAST(ciphertext_b64 AS BLOB)), 0) \
         + COALESCE(length(CAST(nonce_b64 AS BLOB)), 0) \
         + COALESCE(length(CAST(blob_id AS BLOB)), 0) \
         + COALESCE(length(CAST(blob_hash AS BLOB)), 0) \
         + length(CAST(aad_hash AS BLOB)) \
         + COALESCE(length(CAST(prev_hash AS BLOB)), 0) \
         + COALESCE(length(CAST(entry_hash AS BLOB)), 0))"
    };
}
#[cfg(test)]
pub(crate) const ENTRY_BYTES_EXPR: &str = entry_bytes_expr!();

/// Bytes and entries each author keeps in each plugin's log of this room.
pub(crate) const CREATE_USAGE_SQL: &str = "CREATE TABLE IF NOT EXISTS plugin_log_usage (
    plugin_id TEXT NOT NULL,
    author_id TEXT NOT NULL,
    bytes INTEGER NOT NULL DEFAULT 0,
    entries INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (plugin_id, author_id)
)";
/// Up to which `seq` of each plugin's log `plugin_log_usage` has counted.
pub(crate) const CREATE_COUNTED_SQL: &str = "CREATE TABLE IF NOT EXISTS plugin_log_counted (
    plugin_id TEXT PRIMARY KEY,
    through_seq INTEGER NOT NULL DEFAULT 0
)";
/// The plugins whose log has entries past the counted mark: `(plugin_id, through_seq, last_seq)`.
pub(crate) const BEHIND_SQL: &str = "SELECT m.plugin_id AS plugin_id, \
        COALESCE(c.through_seq, 0) AS through_seq, m.last_seq AS last_seq \
     FROM plugin_log_meta m LEFT JOIN plugin_log_counted c ON c.plugin_id = m.plugin_id \
     WHERE m.last_seq > COALESCE(c.through_seq, 0)";
/// Count one plugin's entries with `through_seq < seq <= last_seq` into the usage. Binds:
/// plugin_id, through_seq, last_seq.
pub(crate) const CATCH_UP_SQL: &str = concat!(
    "INSERT INTO plugin_log_usage (plugin_id, author_id, bytes, entries) \
     SELECT plugin_id, author_id, SUM(",
    entry_bytes_expr!(),
    "), COUNT(*) FROM plugin_log_entries \
     WHERE plugin_id = ? AND seq > ? AND seq <= ? GROUP BY plugin_id, author_id \
     ON CONFLICT(plugin_id, author_id) DO UPDATE SET \
        bytes = bytes + excluded.bytes, entries = entries + excluded.entries"
);
/// Move a plugin's counted mark forward (never back). Binds: plugin_id, seq.
pub(crate) const MARK_COUNTED_SQL: &str = "INSERT INTO plugin_log_counted (plugin_id, through_seq) \
     VALUES (?, ?) ON CONFLICT(plugin_id) DO UPDATE SET \
        through_seq = MAX(through_seq, excluded.through_seq)";
/// What an author keeps: in this plugin's log, and in the whole room's. Binds: plugin_id,
/// author_id.
pub(crate) const USAGE_SQL: &str = "SELECT \
        COALESCE(SUM(CASE WHEN plugin_id = ? THEN bytes ELSE 0 END), 0) AS app_bytes, \
        COALESCE(SUM(bytes), 0) AS room_bytes \
     FROM plugin_log_usage WHERE author_id = ?";
/// Charge one appended entry. Binds: plugin_id, author_id, bytes.
pub(crate) const CHARGE_SQL: &str = "INSERT INTO plugin_log_usage (plugin_id, author_id, bytes, entries) \
     VALUES (?, ?, ?, 1) ON CONFLICT(plugin_id, author_id) DO UPDATE SET \
        bytes = bytes + excluded.bytes, entries = entries + 1";

/// A [`BEHIND_SQL`] row.
#[derive(Deserialize)]
pub(crate) struct BehindRow {
    pub plugin_id: String,
    pub through_seq: i64,
    pub last_seq: i64,
}

/// A [`USAGE_SQL`] row.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UsageRow {
    pub app_bytes: i64,
    pub room_bytes: i64,
}

/// A bound value of one statement.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Arg<'a> {
    Text(&'a str),
    Int(i64),
}

/// The room log's SQL, as the budget needs it: the Durable Object's storage in the relay, an
/// in-memory SQLite in the tests — one flow ([`admit`], [`charge`]) for both.
pub(crate) trait LogSql {
    fn exec(&self, sql: &str, args: &[Arg<'_>]) -> Result<(), String>;
    fn behind(&self) -> Result<Vec<BehindRow>, String>;
    fn usage(&self, plugin_id: &str, author_id: &str) -> Result<UsageRow, String>;
}

/// Before an append: count whatever the log holds past each plugin's mark, then say whether an
/// entry of `cost` bytes by `author_id` fits, with what the author keeps BEFORE it. `Err` = the
/// count could not be read or written; the caller refuses nothing on it (an append must not fail
/// on its own bookkeeping, and the next append counts again from the mark).
pub(crate) fn admit(
    db: &impl LogSql,
    plugin_id: &str,
    author_id: &str,
    cost: i64,
    limits: LogLimits,
) -> Result<(Option<Full>, UsageRow), String> {
    for row in db.behind()? {
        db.exec(
            CATCH_UP_SQL,
            &[Arg::Text(&row.plugin_id), Arg::Int(row.through_seq), Arg::Int(row.last_seq)],
        )?;
        db.exec(MARK_COUNTED_SQL, &[Arg::Text(&row.plugin_id), Arg::Int(row.last_seq)])?;
    }
    let usage = db.usage(plugin_id, author_id)?;
    Ok((refusal(usage.app_bytes, usage.room_bytes, cost, limits), usage))
}

/// The `usage` block an accepted append answers with — what its author now keeps against this
/// server's limits — so the app can tell its person at 80 % (`plugin_limits::NEAR_PERCENT`)
/// before a refusal ever comes. An app from before ignores it.
pub(crate) fn usage_after(before: &UsageRow, cost: i64, limits: LogLimits) -> serde_json::Value {
    serde_json::json!({
        "app_bytes": before.app_bytes.saturating_add(cost),
        "room_bytes": before.room_bytes.saturating_add(cost),
        "app_limit": limits.app_bytes,
        "room_limit": limits.room_bytes,
    })
}

/// After an append landed as `seq`: charge its author and move the plugin's mark over it.
pub(crate) fn charge(
    db: &impl LogSql,
    plugin_id: &str,
    author_id: &str,
    cost: i64,
    seq: i64,
) -> Result<(), String> {
    db.exec(CHARGE_SQL, &[Arg::Text(plugin_id), Arg::Text(author_id), Arg::Int(cost)])?;
    db.exec(MARK_COUNTED_SQL, &[Arg::Text(plugin_id), Arg::Int(seq)])
}

#[cfg(test)]
#[path = "plugin_log_budget_tests.rs"]
mod tests;
