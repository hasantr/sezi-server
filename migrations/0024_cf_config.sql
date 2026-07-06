-- CF Analytics config (owner app'ten girer; env-secret'a fallback). NULL = girilmedi.
-- Okuma zinciri per-key: env secret/var ÖNCE, yoksa bu kolonlar (cf_analytics.rs).
-- WRITE-ONLY: /admin/stats token'ı ASLA döndürmez, yalnız cf_configured bool.
ALTER TABLE server_settings ADD COLUMN cf_api_token TEXT;
ALTER TABLE server_settings ADD COLUMN cf_account_id TEXT;
