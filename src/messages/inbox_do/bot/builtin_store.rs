//! The built-in bots' own tables in the bot inbox, and every statement over them. Created with
//! the other bot tables (`store::TABLES`), only in bot mode. As there, every statement is a
//! `const` so the tests run the same text on rusqlite; binds are positional, in the order each
//! const's doc gives.
//!
//! | Table | Holds | Kept |
//! |---|---|---|
//! | `bot_ai_turns` | a member's conversation with an AI bot, message by message | 24 h, the last 10 turns |
//! | `bot_ai_usage` | model calls per member per (UTC) day | 2 days |
//! | `bot_ai_proposals` | the row an AI bot asked a member to confirm | waits 10 min, kept 24 h to say it lapsed |
//! | `bot_sheet_jobs` | rows owed to the sheet, in order | until written, or 23 h |
//! | `bot_sheet_usage` | a sheet bot's rows per member per (UTC) day | 2 days |
//!
//! A "turn" is one exchange — the member's message and the bot's answer — so 10 turns are the
//! last 20 rows.

/// Created beside `store::TABLES`.
pub(super) const TABLES: [&str; 6] = [
    "CREATE TABLE IF NOT EXISTS bot_ai_turns (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
        role TEXT NOT NULL, text TEXT NOT NULL, at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_bot_ai_turns_user ON bot_ai_turns(user_id, id)",
    "CREATE TABLE IF NOT EXISTS bot_ai_usage (
        user_id TEXT NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL,
        PRIMARY KEY (user_id, day))",
    // `room_json` (both tables): the room call it came from, `{"id","name","call_uid"}`, or NULL
    // for a 1:1 message (`builtin_room.rs`).
    "CREATE TABLE IF NOT EXISTS bot_ai_proposals (
        user_id TEXT PRIMARY KEY, row_json TEXT NOT NULL, text TEXT NOT NULL, at INTEGER NOT NULL,
        room_json TEXT)",
    // `confirm` = an AI bot's row the member said yes to: its landing is said ("Kaydedildi").
    // `told` = its author has heard the sheet is failing (so its landing is said, late).
    "CREATE TABLE IF NOT EXISTS bot_sheet_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, name TEXT NOT NULL,
        text TEXT NOT NULL, row_json TEXT, at INTEGER NOT NULL, confirm INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
        told INTEGER NOT NULL DEFAULT 0, room_json TEXT)",
    // Not `bot_ai_usage`: leaving AI mode forgets that one, and a change of kind must not hand a
    // member a fresh day of rows.
    "CREATE TABLE IF NOT EXISTS bot_sheet_usage (
        user_id TEXT NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL,
        PRIMARY KEY (user_id, day))",
];

/// Columns added after the tables first shipped, for an inbox whose tables are older. Run once
/// per inbox (`bot_kv` `builtin_schema` = how many have run); each fails harmlessly on a table
/// `TABLES` just made with the column already in it.
pub(super) const UPGRADES: [&str; 2] = [
    "ALTER TABLE bot_ai_proposals ADD COLUMN room_json TEXT",
    "ALTER TABLE bot_sheet_jobs ADD COLUMN room_json TEXT",
];

/// Turns of context, each two rows.
pub(super) const CONTEXT_TURNS: i64 = 10;
/// How long a conversation is remembered.
pub(super) const TURN_TTL_MS: i64 = 24 * 3600 * 1000;
/// Model calls a member gets a day.
pub(super) const DAILY_CALLS: i64 = 50;
/// Rows a member may send a sheet bot a day, 1:1 and from every room together. Each is a stored
/// job, up to seven subrequests and a line in the owner's sheet; without a cap one member could
/// fill the sheet and keep the queue's head busy for everyone (audit 2026-10-26, note 1.1).
pub(super) const DAILY_ROWS: i64 = 200;
/// How long a proposed row waits for a yes.
pub(super) const PROPOSAL_WAIT_MS: i64 = 10 * 60 * 1000;
/// How long a lapsed proposal is kept, to say so.
pub(super) const PROPOSAL_KEEP_MS: i64 = 24 * 3600 * 1000;
/// A row not written by now is given up on, inside the updates' own 24 h.
pub(super) const JOB_GIVE_UP_MS: i64 = 23 * 3600 * 1000;

/// The UTC day a moment falls on.
pub(super) fn day_of(ms: i64) -> i64 {
    ms.div_euclid(86_400_000)
}

/// Has a proposal made at `at` lapsed by `now`?
pub(super) fn lapsed(at: i64, now: i64) -> bool {
    now - at >= PROPOSAL_WAIT_MS
}

/// A member's remembered rows, oldest first. Bind: user, since, limit (rows).
pub(super) const TURNS_RECENT: &str = "SELECT role, text FROM (
      SELECT id, role, text FROM bot_ai_turns WHERE user_id = ? AND at >= ?
       ORDER BY id DESC LIMIT ?) ORDER BY id";
/// Bind: user, role, text, at.
pub(super) const TURN_PUT: &str = "INSERT INTO bot_ai_turns (user_id, role, text, at) VALUES (?, ?, ?, ?)";
/// Keep a member's newest rows only. Bind: user, user, limit (rows).
pub(super) const TURNS_TRIM: &str = "DELETE FROM bot_ai_turns WHERE user_id = ? AND id NOT IN
      (SELECT id FROM bot_ai_turns WHERE user_id = ? ORDER BY id DESC LIMIT ?)";
/// Bind: cutoff.
pub(super) const TURNS_EXPIRE: &str = "DELETE FROM bot_ai_turns WHERE at < ?";

/// Bind: user, day.
pub(super) const USAGE_GET: &str = "SELECT n FROM bot_ai_usage WHERE user_id = ? AND day = ?";
/// Bind: user, day.
pub(super) const USAGE_BUMP: &str = "INSERT INTO bot_ai_usage (user_id, day, n) VALUES (?, ?, 1)
      ON CONFLICT(user_id, day) DO UPDATE SET n = n + 1";
/// Bind: the oldest day kept.
pub(super) const USAGE_EXPIRE: &str = "DELETE FROM bot_ai_usage WHERE day < ?";

/// A sheet bot's rows from a member on a day. Bind: user, day.
pub(super) const SHEET_USAGE_GET: &str = "SELECT n FROM bot_sheet_usage WHERE user_id = ? AND day = ?";
/// Bind: user, day.
pub(super) const SHEET_USAGE_BUMP: &str = "INSERT INTO bot_sheet_usage (user_id, day, n) VALUES (?, ?, 1)
      ON CONFLICT(user_id, day) DO UPDATE SET n = n + 1";
/// Bind: the oldest day kept.
pub(super) const SHEET_USAGE_EXPIRE: &str = "DELETE FROM bot_sheet_usage WHERE day < ?";

/// Bind: user.
pub(super) const PROPOSAL_GET: &str = "SELECT row_json, text, at, room_json FROM bot_ai_proposals WHERE user_id = ?";
/// Bind: user, row_json, text, at, room_json (or NULL).
pub(super) const PROPOSAL_PUT: &str = "INSERT OR REPLACE INTO bot_ai_proposals (user_id, row_json, text, at, room_json)
      VALUES (?, ?, ?, ?, ?)";
/// Bind: user.
pub(super) const PROPOSAL_DROP: &str = "DELETE FROM bot_ai_proposals WHERE user_id = ?";
/// Every waiting row (the sheet it was meant for changed or went).
pub(super) const PROPOSALS_FORGET: &str = "DELETE FROM bot_ai_proposals";
/// When the oldest remembered turn or proposal is due to go (the alarm comes back for it).
/// Bind: the turns' keep, the proposals' keep.
pub(super) const EXPIRY_NEXT: &str = "SELECT MIN(t) AS t FROM (
      SELECT MIN(at) + ? AS t FROM bot_ai_turns UNION ALL SELECT MIN(at) + ? FROM bot_ai_proposals)";
/// Bind: cutoff.
pub(super) const PROPOSAL_EXPIRE: &str = "DELETE FROM bot_ai_proposals WHERE at < ?";

/// Bind: user, name, text, row_json (or NULL), at, confirm, next_at, created_at, room_json (or NULL).
pub(super) const JOB_PUSH: &str = "INSERT INTO bot_sheet_jobs
      (user_id, name, text, row_json, at, confirm, attempts, next_at, created_at, room_json)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)";
/// Oldest first: rows land in the order they were written. Bind: limit.
pub(super) const JOB_DUE: &str = "SELECT id, user_id, name, text, row_json, at, confirm, attempts, next_at,
      created_at, told, room_json FROM bot_sheet_jobs ORDER BY id LIMIT ?";
/// Authors of rows waiting behind a failing head who have not heard so, oldest first, with their
/// earliest such row's room and words (SQLite takes bare columns from the `MIN(id)` row).
/// Bind: the head's id, limit.
pub(super) const JOB_BEHIND_UNTOLD: &str = "SELECT user_id, room_json, text, MIN(id) AS first FROM bot_sheet_jobs
      WHERE id > ? AND told = 0
      GROUP BY user_id ORDER BY first LIMIT ?";
/// This author has heard the sheet is failing: none of their rows says so again. Bind: user.
pub(super) const JOB_MARK_TOLD: &str = "UPDATE bot_sheet_jobs SET told = 1 WHERE user_id = ?";
/// When the head of the queue is due; NULL when it is empty.
pub(super) const JOB_NEXT: &str = "SELECT next_at AS t FROM bot_sheet_jobs ORDER BY id LIMIT 1";
/// Bind: next_at, id.
pub(super) const JOB_RETRY: &str = "UPDATE bot_sheet_jobs SET attempts = attempts + 1, next_at = ? WHERE id = ?";
/// Bind: id.
pub(super) const JOB_DONE: &str = "DELETE FROM bot_sheet_jobs WHERE id = ?";

/// What a built-in bot owes, oldest first (the webhook's queue, with the age). Bind: limit.
pub(super) const UPDATES_DUE: &str = "SELECT update_id, json, attempts, next_at, created_at FROM bot_updates
      WHERE delivered_at IS NULL ORDER BY update_id LIMIT ?";

/// Every owner's set bumps this `bot_kv` counter; a round that finds it changed after an
/// `await` drops what it was doing (it ran on a configuration that is gone).
pub(super) const GEN_BUMP: &str = "INSERT INTO bot_kv (k, v) VALUES ('builtin_gen', '1')
      ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT)";
pub(super) const GEN_GET: &str = "SELECT CAST(v AS INTEGER) AS g FROM bot_kv WHERE k = 'builtin_gen'";

/// Everything an AI bot remembers of its members, for leaving AI mode.
pub(super) const AI_FORGET: [&str; 3] =
    ["DELETE FROM bot_ai_turns", "DELETE FROM bot_ai_proposals", "DELETE FROM bot_ai_usage"];
/// Rows owed to a sheet the bot no longer writes to.
pub(super) const JOBS_FORGET: &str = "DELETE FROM bot_sheet_jobs";

#[cfg(test)]
#[path = "builtin_store_tests.rs"]
mod tests;
