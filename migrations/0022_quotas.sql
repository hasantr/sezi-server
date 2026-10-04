-- Quotas, first step — SHADOW-MODE usage counters (NO ENFORCEMENT; counting only).
--
-- The quota columns on server_settings are NULLABLE: NULL = the owner set NO limit =
-- unlimited. At this stage nothing reads or enforces them (shadow mode — the defaults get
-- calibrated against real traffic); enforcement lands later at the choke points (the
-- 429 quota_exceeded contract).
ALTER TABLE server_settings ADD COLUMN max_storage_bytes INTEGER;
ALTER TABLE server_settings ADD COLUMN max_requests_day INTEGER;

-- The live per-user storage counter — an O(1) cache of the media_objects SUM.
-- Updated best-effort (upload +size, ack/cron-expire −size, clamped at 0); the daily cron
-- recomputes it from the media_objects truth, so drift self-heals.
CREATE TABLE IF NOT EXISTS user_storage (
  user_id TEXT PRIMARY KEY,
  bytes   INTEGER NOT NULL DEFAULT 0
);

-- The server-wide media counter (a single row, id=1) — the storage twin of the turn_usage
-- budget-guard pattern (0009). /admin/stats reads from here.
CREATE TABLE IF NOT EXISTS server_stats (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  media_bytes INTEGER NOT NULL DEFAULT 0,
  media_count INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL DEFAULT 0
);

-- Day-keyed general usage counters (kind is e.g. requests, upload_bytes…).
-- At this stage only /admin/stats READS them (the request-counting hook is not wired yet → 0);
-- they fill in by themselves once the choke-point counting is connected.
CREATE TABLE IF NOT EXISTS usage_counters (
  day   TEXT NOT NULL,                -- "YYYY-MM-DD" (UTC)
  kind  TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, kind)
);
