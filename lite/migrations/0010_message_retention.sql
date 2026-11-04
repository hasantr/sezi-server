-- Message retention — admin-configurable.
-- message_retention_days: how many days an UNDELIVERED message is kept in each recipient's
-- Durable Object `pending` queue (the DO alarm's cleanup window). The owner sets it from D1
-- (the twin of the media retention_days pattern). A delivered message is already deleted on
-- ack (the relay model) — this window is only for the "the recipient never connected" case.
-- /capabilities announces it as `retention.message_days`; the owner edits it.
ALTER TABLE server_settings ADD COLUMN message_retention_days INTEGER NOT NULL DEFAULT 30;
