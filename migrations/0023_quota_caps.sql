-- Quotas: the per-user storage cap (NULL = unlimited). The server-total cap
-- (max_storage_bytes) already exists in 0022. The owner sets it with
-- PATCH /admin/server-settings; while it stays NULL there is NO enforcement (fail-open, so
-- nobody is cut off by surprise).
ALTER TABLE server_settings ADD COLUMN max_user_storage_bytes INTEGER;
