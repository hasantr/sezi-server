-- Bots in group rooms (docs/BOTS_BUILD.md §2.2, Phase 3).
--
-- A bot is never a `group_members` row: it holds no room key and reads only what a member sends
-- it 1:1. This table is what lets it SPEAK in a room — the relay checks it before a bot's room
-- send and before accepting a member's call to it. A room's admins add and remove the rows
-- (`groups_bots.rs`); the server owner only sees them. Turning a bot off keeps its rows; deleting
-- it removes them in the same batch (`bots/provision.rs`), since the soft delete keeps the
-- `bots` row and the cascade below never fires then.
CREATE TABLE IF NOT EXISTS group_bots (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  bot_id TEXT NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
  added_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  added_at INTEGER NOT NULL,           -- seconds
  PRIMARY KEY(group_id, bot_id)
);
-- "Which rooms is this bot in": the owner's listing and the soft delete.
CREATE INDEX IF NOT EXISTS idx_group_bots_bot ON group_bots(bot_id);
