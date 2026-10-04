-- Durable retry for a partially failed group fan-out: a (member, device) pair whose
-- notify_recipient FAILED all three attempts is written here → a cron drain re-notifies it →
-- that member does NOT MISS the group message. It becomes unnecessary once the
-- server-canonical log lands — a deliberate BRIDGE, removable cleanly (the cron + a DROP).
--
-- retry_key = the idempotency key (recipient|device|group|env_hash) → a sender retry or a
-- double enqueue does NOT write the SAME row twice (INSERT OR IGNORE); duplicate pendings and
-- burning the W2 cap are both avoided.
-- next_at = the backoff/lease stamp (epoch-sec): it is pushed forward AT CLAIM TIME (an atomic
-- lease) → an overlapping cron invocation cannot double-notify the SAME row. attempts counts
-- DO errors only (notifying an offline recipient SUCCEEDS → it lands in pending), so reaching
-- MAX means "the DO has been broken for days" = extremely rare.
-- At MAX we do NOT delete (that would be a loss); a TTL GC (the daily cron, parity with
-- pending retention) collects the very old rows.
-- If the table does not exist (the migration was never applied) the enqueue is best-effort →
-- sending does NOT break (graceful).
CREATE TABLE IF NOT EXISTS fanout_retry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  retry_key TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  recipient_device TEXT,           -- NULL = device-blind (a member that published no device)
  sender_id TEXT NOT NULL,
  sender_device TEXT,
  envelope_b64 TEXT NOT NULL,
  group_id TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,        -- epoch-sec; pushed forward on claim (the lease)
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fanout_retry_key ON fanout_retry(retry_key);
CREATE INDEX IF NOT EXISTS idx_fanout_retry_next ON fanout_retry(next_at);
