-- Contacts + server directory V2.
-- Membership, discovery and direct-message authorization remain independent.

ALTER TABLE users ADD COLUMN directory_visibility TEXT NOT NULL DEFAULT 'inherit'
  CHECK(directory_visibility IN ('inherit', 'visible', 'hidden'));
ALTER TABLE users ADD COLUMN profile_revision INTEGER NOT NULL DEFAULT 1;

-- Backwards-compatible policy defaults: an upgrade never exposes the roster and
-- never silently breaks an existing direct conversation.
ALTER TABLE server_settings ADD COLUMN directory_mode TEXT NOT NULL DEFAULT 'off'
  CHECK(directory_mode IN ('off', 'opt_in', 'all_members'));
ALTER TABLE server_settings ADD COLUMN dm_policy TEXT NOT NULL DEFAULT 'members'
  CHECK(dm_policy IN ('members', 'requests', 'contacts_only'));

CREATE TABLE IF NOT EXISTS contact_requests (
  request_id          TEXT PRIMARY KEY,
  source_user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source_device_id    TEXT NOT NULL,
  server_fingerprint  TEXT NOT NULL,
  issued_at           INTEGER NOT NULL,
  nonce_hash          TEXT NOT NULL CHECK(length(nonce_hash) = 64),
  signature_b64       TEXT NOT NULL,
  status              TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending', 'accepted', 'declined', 'expired', 'revoked')),
  trust               TEXT NOT NULL DEFAULT 'server_asserted'
    CHECK(trust = 'server_asserted'),
  created_at          INTEGER NOT NULL,
  expires_at          INTEGER NOT NULL,
  responded_at        INTEGER,
  -- Exactly-once grant materialization marker. Once set, an idempotent accept
  -- retry may never reopen a grant that was subsequently revoked.
  grant_applied       INTEGER NOT NULL DEFAULT 0 CHECK(grant_applied IN (0, 1)),
  CHECK(source_user_id != target_user_id)
);
CREATE INDEX IF NOT EXISTS idx_contact_requests_source
  ON contact_requests(source_user_id, created_at DESC, request_id);
CREATE INDEX IF NOT EXISTS idx_contact_requests_target
  ON contact_requests(target_user_id, created_at DESC, request_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_contact_requests_one_pending_pair
  ON contact_requests(
    CASE WHEN source_user_id < target_user_id THEN source_user_id ELSE target_user_id END,
    CASE WHEN source_user_id < target_user_id THEN target_user_id ELSE source_user_id END
  ) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS contact_grants (
  grant_id             TEXT PRIMARY KEY,
  user_low             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_high            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source               TEXT NOT NULL CHECK(source IN ('request', 'invite', 'qr', 'manual')),
  trust                TEXT NOT NULL CHECK(trust IN ('server_asserted', 'qr_verified')),
  accepted_request_id  TEXT REFERENCES contact_requests(request_id) ON DELETE SET NULL,
  created_at           INTEGER NOT NULL,
  revoked_at           INTEGER,
  revoked_by           TEXT REFERENCES users(id) ON DELETE SET NULL,
  CHECK(user_low < user_high),
  UNIQUE(user_low, user_high)
);
CREATE INDEX IF NOT EXISTS idx_contact_grants_low
  ON contact_grants(user_low, revoked_at, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_contact_grants_high
  ON contact_grants(user_high, revoked_at, created_at DESC);

CREATE TABLE IF NOT EXISTS contact_blocks (
  blocker_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at       INTEGER NOT NULL,
  PRIMARY KEY(blocker_user_id, blocked_user_id),
  CHECK(blocker_user_id != blocked_user_id)
);
CREATE INDEX IF NOT EXISTS idx_contact_blocks_blocked
  ON contact_blocks(blocked_user_id, blocker_user_id);

-- Global monotonically increasing directory log. Consumers capture the current
-- revision before a full page and then use delta pull. `reset` means policy-wide
-- visibility changed and the client must refresh its virtual roster.
CREATE TABLE IF NOT EXISTS directory_revisions (
  revision          INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id          TEXT UNIQUE NOT NULL,
  user_id           TEXT,
  change_type       TEXT NOT NULL CHECK(change_type IN ('upsert', 'tombstone', 'reset')),
  profile_revision  INTEGER,
  created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_directory_revisions_user
  ON directory_revisions(user_id, revision DESC);

CREATE TABLE IF NOT EXISTS directory_tombstones (
  user_id     TEXT PRIMARY KEY,
  revision    INTEGER NOT NULL,
  deleted_at  INTEGER NOT NULL
);

-- Contact changes are account-scoped. Revisions are global (gaps are legal),
-- while each account only receives rows addressed to it.
CREATE TABLE IF NOT EXISTS contact_revisions (
  revision     INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id     TEXT UNIQUE NOT NULL,
  account_id   TEXT NOT NULL,
  peer_id      TEXT,
  entity       TEXT NOT NULL CHECK(entity IN ('request', 'grant', 'block', 'authorization')),
  entity_id    TEXT NOT NULL,
  action       TEXT NOT NULL CHECK(action IN ('upsert', 'tombstone')),
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contact_revisions_account
  ON contact_revisions(account_id, revision);

CREATE TABLE IF NOT EXISTS contact_tombstones (
  account_id  TEXT NOT NULL,
  entity      TEXT NOT NULL,
  entity_id   TEXT NOT NULL,
  peer_id     TEXT,
  revision    INTEGER NOT NULL,
  deleted_at  INTEGER NOT NULL,
  PRIMARY KEY(account_id, entity, entity_id)
);
