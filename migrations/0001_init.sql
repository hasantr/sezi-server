-- Sezgi D1 v1 şeması.

CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  identity_pubkey BLOB NOT NULL,
  display_name    TEXT,
  fcm_token       TEXT,
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER
);

CREATE TABLE IF NOT EXISTS invite_tokens (
  token       TEXT PRIMARY KEY,
  email_hint  TEXT,
  used        INTEGER NOT NULL DEFAULT 0,
  used_by     TEXT REFERENCES users(id),
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_codes (
  email       TEXT PRIMARY KEY,
  code_hash   TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signed_prekeys (
  user_id     TEXT NOT NULL REFERENCES users(id),
  prekey_id   INTEGER NOT NULL,
  prekey_pub  BLOB NOT NULL,
  signature   BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, prekey_id)
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT NOT NULL REFERENCES users(id),
  prekey_id   INTEGER NOT NULL,
  prekey_pub  BLOB NOT NULL,
  consumed    INTEGER NOT NULL DEFAULT 0,
  UNIQUE (user_id, prekey_id)
);
CREATE INDEX IF NOT EXISTS idx_otk_lookup ON one_time_prekeys(user_id, consumed);

CREATE TABLE IF NOT EXISTS pending_messages (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient_id  TEXT NOT NULL REFERENCES users(id),
  sender_id     TEXT NOT NULL REFERENCES users(id),
  envelope      BLOB NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_messages(recipient_id, id);
CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_messages(created_at);

CREATE TABLE IF NOT EXISTS media_objects (
  blob_id     TEXT PRIMARY KEY,
  uploader_id TEXT NOT NULL REFERENCES users(id),
  size_bytes  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash  TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id),
  expires_at  INTEGER NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
