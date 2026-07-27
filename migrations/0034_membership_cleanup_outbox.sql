-- Membership deletion has two authorities: D1 owns membership and UserInbox
-- owns durable delivery state.  The D1 row is committed in the same batch as
-- account deletion; a failed cross-DO purge is therefore retried by cron.
CREATE TABLE IF NOT EXISTS account_purge_outbox (
  user_id       TEXT PRIMARY KEY,
  reason        TEXT NOT NULL CHECK(reason IN ('left', 'removed')),
  created_at    INTEGER NOT NULL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  next_at       INTEGER NOT NULL,
  last_error    TEXT
);
CREATE INDEX IF NOT EXISTS idx_account_purge_outbox_due
  ON account_purge_outbox(next_at, created_at);

-- A single-row transaction guard. Membership deletion writes a non-NULL
-- target selected with `role != 'owner'` as the first batch statement. Owner,
-- missing-account or role-race yields NULL and aborts the whole D1 batch.
CREATE TABLE IF NOT EXISTS membership_delete_guard (
  slot       INTEGER PRIMARY KEY CHECK(slot = 1),
  target_id  TEXT NOT NULL
);
