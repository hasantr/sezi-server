-- The "delete for everyone" window (delete_window_hours) — owner-configurable.
-- delete_window_hours: how many HOURS after a message was SENT it can still be deleted for
-- everyone. The receiving side is to ENFORCE this (message age > the window → reject); this
-- column only carries the VALUE (server_settings → /capabilities → the client). The twin of
-- the retention_days / message_retention_days pattern (the owner sets it from D1;
-- /capabilities announces it; the owner edits it with PATCH /admin/server-settings).
-- DEFAULT 48 hours.
ALTER TABLE server_settings ADD COLUMN delete_window_hours INTEGER NOT NULL DEFAULT 48;
