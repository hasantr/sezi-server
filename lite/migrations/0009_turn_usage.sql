-- The TURN budget guard (the relay for calls that go over the internet).
--
-- When P2P fails, call media goes through CF Realtime TURN ($0.05/GB, the first 1 TB per
-- month free). CF has NO hard spend ceiling → to avoid a surprise bill the worker enforces
-- one of its own: this table holds a monthly credential-issue counter, and once
-- `TURN_MONTHLY_CAP` is exceeded the worker issues NO credential (the client falls back to
-- direct/STUN and the CF bill stops there). One credential is roughly one call.
CREATE TABLE IF NOT EXISTS turn_usage (
    month  TEXT PRIMARY KEY,          -- "YYYY-MM" (UTC), the budget window
    issued INTEGER NOT NULL DEFAULT 0 -- TURN credentials issued during that month
);
