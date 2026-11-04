-- The data-retention declaration + the owner's setting.
-- retention_days: how many days media is kept when it is NOT DELIVERED (the cron fallback
-- window). Delivered content is already deleted on delivery (the relay model) — this window
-- is only for the "nobody collected it" case. /capabilities announces it; the owner edits it.
ALTER TABLE server_settings ADD COLUMN retention_days INTEGER NOT NULL DEFAULT 30;
