//! `bot_hearings_audit` (docs/HEARINGS_BOT_PLAN.md §8.2): one row per record a member sent the
//! hearings bot — WHO and WHEN and HOW MUCH, never WHAT. No text, no name, no file name, no esas
//! no, no court: numbers and codes only, so the office can answer "what went where" without the
//! audit itself becoming a copy of the minutes. Kept `audit_days` (180 by default, the owner's
//! to change), and shown to the owner as counts only (`/bot/state` → `GET /admin/bots`).
//!
//! | column | holds |
//! |---|---|
//! | `user_id`, `at` | who sent it, when (ms) |
//! | `input` | `pdf` / `text` (pasted) / `file` (did not open) |
//! | `pages`, `chars` | the record's size, as read |
//! | `masked_json` | `{"KISI": 4, "ADRES": 2, …}`: places masked per category |
//! | `model`, `tokens_in`, `tokens_out` | the model called and what it cost; NULL when none was |
//! | `outcome` | `ok` (the model's summary passed the checks) or the code of why not |
//! | `sheet` | `updated` / `appended` / `written` / `declined` / `lapsed` / `failed`, NULL until settled |
//!
//! Statements are `const`s, run on rusqlite in the tests as everywhere in this inbox.

pub(super) const TABLES: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS bot_hearings_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, at INTEGER NOT NULL,
        input TEXT NOT NULL, pages INTEGER NOT NULL DEFAULT 0, chars INTEGER NOT NULL DEFAULT 0,
        masked_json TEXT NOT NULL DEFAULT '{}', model TEXT, tokens_in INTEGER, tokens_out INTEGER,
        outcome TEXT NOT NULL, sheet TEXT)",
    "CREATE INDEX IF NOT EXISTS idx_bot_hearings_audit_at ON bot_hearings_audit(at)",
];

/// Bind: user, at, input, pages, chars, masked_json, model (or NULL), tokens_in, tokens_out
/// (or NULL), outcome. Answers the new row's id.
pub(super) const AUDIT_PUT: &str = "INSERT INTO bot_hearings_audit
      (user_id, at, input, pages, chars, masked_json, model, tokens_in, tokens_out, outcome)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id";
/// Bind: sheet outcome, id.
pub(super) const AUDIT_SHEET: &str = "UPDATE bot_hearings_audit SET sheet = ? WHERE id = ?";
/// Bind: cutoff.
pub(super) const AUDIT_EXPIRE: &str = "DELETE FROM bot_hearings_audit WHERE at < ?";
/// The owner's counts. Bind: since.
pub(super) const AUDIT_BY_OUTCOME: &str =
    "SELECT outcome AS k, COUNT(*) AS n FROM bot_hearings_audit WHERE at >= ? GROUP BY outcome ORDER BY outcome";
/// Bind: since.
pub(super) const AUDIT_BY_SHEET: &str = "SELECT sheet AS k, COUNT(*) AS n FROM bot_hearings_audit
      WHERE at >= ? AND sheet IS NOT NULL GROUP BY sheet ORDER BY sheet";
pub(super) const AUDIT_LAST_AT: &str = "SELECT MAX(at) AS t FROM bot_hearings_audit";
/// The owner's view covers this many days back.
pub(super) const OWNER_VIEW_DAYS: i64 = 30;

/// What one record leaves in the audit. Every field is a number, a code or a model id.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct AuditRecord {
    pub(super) input: &'static str,
    pub(super) pages: i64,
    pub(super) chars: i64,
    /// (category tag, places masked).
    pub(super) masked: Vec<(&'static str, u32)>,
    pub(super) model: Option<String>,
    pub(super) tokens_in: Option<i64>,
    pub(super) tokens_out: Option<i64>,
    pub(super) outcome: &'static str,
}

impl AuditRecord {
    /// `{"KISI": 4, …}` in the categories' order.
    pub(super) fn masked_json(&self) -> String {
        let mut m = serde_json::Map::new();
        for (tag, n) in &self.masked {
            m.insert((*tag).to_string(), (*n).into());
        }
        serde_json::Value::Object(m).to_string()
    }

    /// The masked counts of a redaction.
    pub(super) fn counts_of(c: &sezi_redact::Counts) -> Vec<(&'static str, u32)> {
        c.iter().map(|(cat, _, occ)| (cat.tag(), occ)).collect()
    }
}

/// The sheet column of a settled row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SheetOutcome {
    Updated,
    Appended,
    /// Written, the script said not where.
    Written,
    Declined,
    Lapsed,
    Failed,
}

impl SheetOutcome {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            SheetOutcome::Updated => "updated",
            SheetOutcome::Appended => "appended",
            SheetOutcome::Written => "written",
            SheetOutcome::Declined => "declined",
            SheetOutcome::Lapsed => "lapsed",
            SheetOutcome::Failed => "failed",
        }
    }
}

#[cfg(test)]
#[path = "hearings_audit_tests.rs"]
mod tests;
