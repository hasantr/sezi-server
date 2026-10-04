-- Sezgi multi-server admin + access mode.
-- Every server instance keeps its own admin/member roles and its "open/closed"
-- mode setting. The first user to register becomes admin (`src/auth/verify.rs`).

ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member';

CREATE TABLE IF NOT EXISTS server_settings (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  name       TEXT NOT NULL DEFAULT 'Sezgi',
  join_mode  TEXT NOT NULL DEFAULT 'invite_only',
  updated_at INTEGER NOT NULL DEFAULT 0
);

-- Single-row seed (id=1). Leave an existing record untouched.
INSERT OR IGNORE INTO server_settings (id, name, join_mode, updated_at)
  VALUES (1, 'Sezgi', 'invite_only', 0);
