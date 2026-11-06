//! The plugin limits a server's OWNER sets (Hasan, 2026-11-06, `docs/PLUGINS_BOTS_REVIEW_2026_11.md`
//! "the owner sets the plugin limits"): every one starts at the figure Wave A built in as a constant
//! and can be changed at any time from the app's server settings.
//!
//! | key | what | default | range |
//! |---|---|---|---|
//! | `record_count` | an author's live records of one app in one room (the app's core, A2) | 2,000 | 100 – 100,000 |
//! | `record_bytes` | …and their bytes | 16 MiB | 1 MiB – 1 GiB |
//! | `log_app_bytes` | what a member keeps in one app's plugin log in one room (A3) | 32 MiB | 1 MiB – 4 GiB |
//! | `log_room_bytes` | …in all apps' logs of one room together | 64 MiB | 1 MiB – 16 GiB |
//! | `media_bytes` | a member's plugin media in one room (A3) | 512 MiB | 1 MiB – 64 GiB |
//! | `media_objects` | …and how many blobs | 4,096 | 16 – 1,000,000 |
//! | `ai_daily_calls` | a NEW AI bot's model calls a day, when its owner names none (A4) | 500 | the bot's own `AI_DAILY_CALLS` |
//!
//! The record share is the app's core's to enforce (the relay never sees a record); the relay only
//! keeps and announces it. Everything else is enforced here.
//!
//! **Stored** as ONE row of `server_config` (key [`CONFIG_KEY`], a JSON object holding only what
//! the owner set). No migration: the key-value table exists on every relay, and a previous build
//! never reads the key — a rollback keeps every byte the owner stored and goes back to the
//! constants, which are the defaults. An unset or unreadable value IS the default.
//!
//! **Announced** on `/capabilities` as `plugin_limits` (every key, the effective value), so every
//! member's app learns this server's figures; an app from before ignores the block and keeps its
//! own defaults. A limit is a bound on NEW writes only: lowering one below what someone already
//! holds deletes nothing, it only refuses what would add to it.

use serde_json::{Map, Value};

/// The `server_config` key the owner's values live under.
pub(crate) const CONFIG_KEY: &str = "plugin_limits";

const MIB: i64 = 1024 * 1024;
const GIB: i64 = 1024 * MIB;

/// One owner-settable limit: its wire key, the default (the constant that held before) and the
/// range a write must fall in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LimitDef {
    pub key: &'static str,
    pub default: i64,
    pub min: i64,
    pub max: i64,
    /// `bytes` or `count` — for the app's display.
    pub unit: &'static str,
}

/// `record_count`: the core's `MAX_ACTIVE_RECORDS_PER_AUTHOR`.
pub(crate) const RECORD_COUNT: LimitDef =
    LimitDef { key: "record_count", default: 2_000, min: 100, max: 100_000, unit: "count" };
/// `record_bytes`: the core's `MAX_ACTIVE_BYTES_PER_AUTHOR`.
pub(crate) const RECORD_BYTES: LimitDef =
    LimitDef { key: "record_bytes", default: 16 * MIB, min: MIB, max: GIB, unit: "bytes" };
/// `log_app_bytes`: `plugin_log_budget::MAX_BYTES_PER_MEMBER_PER_APP`.
pub(crate) const LOG_APP_BYTES: LimitDef = LimitDef {
    key: "log_app_bytes",
    default: crate::plugin_log_budget::MAX_BYTES_PER_MEMBER_PER_APP,
    min: MIB,
    max: 4 * GIB,
    unit: "bytes",
};
/// `log_room_bytes`: `plugin_log_budget::MAX_BYTES_PER_MEMBER_PER_ROOM`.
pub(crate) const LOG_ROOM_BYTES: LimitDef = LimitDef {
    key: "log_room_bytes",
    default: crate::plugin_log_budget::MAX_BYTES_PER_MEMBER_PER_ROOM,
    min: MIB,
    max: 16 * GIB,
    unit: "bytes",
};
/// `media_bytes`: `plugin_media::MAX_BYTES_PER_MEMBER_PER_ROOM`.
pub(crate) const MEDIA_BYTES: LimitDef = LimitDef {
    key: "media_bytes",
    default: crate::plugin_media::MAX_BYTES_PER_MEMBER_PER_ROOM,
    min: MIB,
    max: 64 * GIB,
    unit: "bytes",
};
/// `media_objects`: `plugin_media::MAX_OBJECTS_PER_MEMBER_PER_ROOM`.
pub(crate) const MEDIA_OBJECTS: LimitDef = LimitDef {
    key: "media_objects",
    default: crate::plugin_media::MAX_OBJECTS_PER_MEMBER_PER_ROOM,
    min: 16,
    max: 1_000_000,
    unit: "count",
};
/// `ai_daily_calls`: `bots::builtin_rules::DEFAULT_AI_DAILY_CALLS`, within the bot's own range.
pub(crate) const AI_DAILY_CALLS: LimitDef = LimitDef {
    key: "ai_daily_calls",
    default: crate::bots::builtin_rules::DEFAULT_AI_DAILY_CALLS as i64,
    min: *crate::bots::builtin_rules::AI_DAILY_CALLS.start() as i64,
    max: *crate::bots::builtin_rules::AI_DAILY_CALLS.end() as i64,
    unit: "count",
};

/// Every limit, in the order the app lists them.
pub(crate) const ALL: [LimitDef; 7] =
    [RECORD_COUNT, RECORD_BYTES, LOG_APP_BYTES, LOG_ROOM_BYTES, MEDIA_BYTES, MEDIA_OBJECTS, AI_DAILY_CALLS];

/// The owner's stored values — only what was set. [`PluginLimits::get`] gives the effective one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PluginLimits {
    set: Map<String, Value>,
}

impl PluginLimits {
    /// Read the stored row leniently: a value that is not an integer inside its limit's range, a
    /// key no limit has, or a row that is not a JSON object counts as unset — never a refusal.
    pub(crate) fn from_stored(raw: Option<&str>) -> Self {
        let Some(Value::Object(obj)) = raw.and_then(|r| serde_json::from_str::<Value>(r).ok()) else {
            return Self::default();
        };
        let mut set = Map::new();
        for def in ALL {
            if let Some(v) = obj.get(def.key).and_then(Value::as_i64) {
                if (def.min..=def.max).contains(&v) {
                    set.insert(def.key.to_string(), Value::from(v));
                }
            }
        }
        Self { set }
    }

    /// The effective value of `def`: the owner's, else the default.
    pub(crate) fn get(&self, def: LimitDef) -> i64 {
        self.set.get(def.key).and_then(Value::as_i64).unwrap_or(def.default)
    }

    /// The plugin log's two budgets.
    pub(crate) fn log_limits(&self) -> crate::plugin_log_budget::LogLimits {
        crate::plugin_log_budget::LogLimits {
            app_bytes: self.get(LOG_APP_BYTES),
            room_bytes: self.get(LOG_ROOM_BYTES),
        }
    }

    /// Plugin media's two budgets.
    pub(crate) fn media_limits(&self) -> crate::plugin_media::MediaLimits {
        crate::plugin_media::MediaLimits {
            bytes: self.get(MEDIA_BYTES),
            objects: self.get(MEDIA_OBJECTS),
        }
    }

    /// The model calls a day a new AI bot gets when its owner names none.
    pub(crate) fn ai_daily_calls(&self) -> u32 {
        u32::try_from(self.get(AI_DAILY_CALLS)).unwrap_or(crate::bots::builtin_rules::DEFAULT_AI_DAILY_CALLS)
    }

    /// Did the owner set `def`?
    pub(crate) fn is_set(&self, def: LimitDef) -> bool {
        self.set.contains_key(def.key)
    }

    /// What is stored: only the set values.
    pub(crate) fn to_stored(&self) -> String {
        Value::Object(self.set.clone()).to_string()
    }

    /// Apply an owner's write `{key: N | null, …}`: a number sets (inside its range), `null` goes
    /// back to the default. Every key is checked before anything changes, so a refused write
    /// changes nothing. `Err((code, key))`: [`BAD_KEY`] for a key no limit has or a body that is
    /// not an object, [`OUT_OF_RANGE`] for a value outside the range or not an integer.
    pub(crate) fn with_write(&self, body: &Value) -> Result<Self, (&'static str, String)> {
        let Some(obj) = body.as_object() else {
            return Err((BAD_KEY, String::new()));
        };
        if obj.is_empty() {
            return Err((BAD_KEY, String::new()));
        }
        let mut next = self.clone();
        for (key, value) in obj {
            let Some(def) = ALL.iter().find(|d| d.key == key) else {
                return Err((BAD_KEY, key.clone()));
            };
            match value {
                Value::Null => {
                    next.set.remove(def.key);
                }
                v => match v.as_i64().filter(|n| (def.min..=def.max).contains(n)) {
                    Some(n) => {
                        next.set.insert(def.key.to_string(), Value::from(n));
                    }
                    None => return Err((OUT_OF_RANGE, key.clone())),
                },
            }
        }
        Ok(next)
    }

    /// `/capabilities`' `plugin_limits`: every key, the effective value.
    pub(crate) fn announced(&self) -> Value {
        let mut m = Map::new();
        for def in ALL {
            m.insert(def.key.to_string(), Value::from(self.get(def)));
        }
        Value::Object(m)
    }

    /// The owner's view: each limit with its value, default, range, unit and whether it was set.
    pub(crate) fn owner_rows(&self) -> Value {
        Value::Array(
            ALL.iter()
                .map(|def| {
                    serde_json::json!({
                        "key": def.key,
                        "value": self.get(*def),
                        "default": def.default,
                        "min": def.min,
                        "max": def.max,
                        "unit": def.unit,
                        "set": self.is_set(*def),
                    })
                })
                .collect(),
        )
    }
}

/// A write named a key no limit has (or was not an object).
pub(crate) const BAD_KEY: &str = "plugin-limits/bad-key";
/// A write's value is outside its limit's range.
pub(crate) const OUT_OF_RANGE: &str = "plugin-limits/out-of-range";

/// The stored row's statement. Binds: nothing.
pub(crate) const READ_SQL: &str = "SELECT value FROM server_config WHERE key = 'plugin_limits' LIMIT 1";

/// Read this server's limits. A missing table, row or a D1 error reads as "nothing set" — every
/// budget then holds its default, as before this setting existed.
pub(crate) async fn read(db: &worker::D1Database) -> PluginLimits {
    #[derive(serde::Deserialize)]
    struct Row {
        value: String,
    }
    let row = db.prepare(READ_SQL).first::<Row>(None).await.unwrap_or_default();
    PluginLimits::from_stored(row.as_ref().map(|r| r.value.as_str()))
}

/// Store the owner's values (an empty set deletes the row).
pub(crate) async fn store(db: &worker::D1Database, limits: &PluginLimits) -> worker::Result<()> {
    use crate::d1util::{d1_int, d1_text};
    if limits.set.is_empty() {
        db.prepare("DELETE FROM server_config WHERE key = ?")
            .bind(&[d1_text(CONFIG_KEY)])?
            .run()
            .await?;
        return Ok(());
    }
    db.prepare(
        "INSERT INTO server_config (key, value, created_at) VALUES (?, ?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(&[
        d1_text(CONFIG_KEY),
        d1_text(&limits.to_stored()),
        d1_int(crate::utils::now_secs() as i64),
    ])?
    .run()
    .await?;
    Ok(())
}

/// The share of a limit at which a member is told they have used most of it (the decision: 80 %).
pub(crate) const NEAR_PERCENT: i64 = 80;

/// Is `used` at or past [`NEAR_PERCENT`] of `limit`?
pub(crate) fn is_near(used: i64, limit: i64) -> bool {
    limit > 0 && used.saturating_mul(100) >= limit.saturating_mul(NEAR_PERCENT)
}

#[cfg(test)]
#[path = "plugin_limits_tests.rs"]
mod tests;
