-- CF Analytics config (the owner enters it from the app; falls back to an env secret).
-- NULL = never entered. The read chain per key: the env secret/var FIRST, then these columns
-- (cf_analytics.rs).
-- WRITE-ONLY: /admin/stats NEVER returns the token, only the cf_configured bool.
ALTER TABLE server_settings ADD COLUMN cf_api_token TEXT;
ALTER TABLE server_settings ADD COLUMN cf_account_id TEXT;
