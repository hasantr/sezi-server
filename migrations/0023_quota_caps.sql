-- Kota Faz 1a: per-user depolama cap'i (NULL = sınırsız). Sunucu-toplam cap
-- (max_storage_bytes) 0022'de zaten var. Owner PATCH /admin/server-settings ile
-- koyar; NULL kalırsa zorlama YOK (fail-open, sürpriz kesinti yok).
ALTER TABLE server_settings ADD COLUMN max_user_storage_bytes INTEGER;
