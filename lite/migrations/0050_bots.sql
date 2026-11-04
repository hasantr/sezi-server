-- Bots (docs/BOTS_BUILD.md §2.2, Phase 1).
--
-- A bot is a `users` row of kind 'bot': hidden from the directory, never a group member, never
-- given a refresh token or a JWT. Its end of the encryption lives in its own UserInbox Durable
-- Object; D1 holds only what every relay path already reads (users, devices, keys) plus this.
ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'human' CHECK(kind IN ('human','bot'));

CREATE TABLE IF NOT EXISTS bots (
  bot_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  about TEXT,
  builtin TEXT,                        -- NULL = program-driven; 'reminder' = Hatırlatıcı (Phase 4)
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER,
  deleted_at INTEGER,
  webhook_url TEXT,                    -- Phase 2
  program_seen_at INTEGER              -- last API call or 2xx/3xx webhook (Phase 2)
);

-- The program's key, as sha256 hex (the shape of refresh_tokens). Shown once, never stored.
CREATE TABLE IF NOT EXISTS bot_tokens (
  token_hash TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_bot_tokens_bot ON bot_tokens(bot_id, revoked_at);
