-- Kota epic Faz 0 — SHADOW-MODE kullanım sayaçları (ZORLAMA YOK; yalnız sayım).
--
-- server_settings kota kolonları NULLABLE: NULL = owner limit KOYMADI = sınırsız.
-- Faz 0 bunları okumaz/zorlamaz (shadow — gerçek trafikle default'lar kalibre
-- edilir); Faz 1 choke-point'lerde zorlayacak (429 quota_exceeded sözleşmesi).
ALTER TABLE server_settings ADD COLUMN max_storage_bytes INTEGER;
ALTER TABLE server_settings ADD COLUMN max_requests_day INTEGER;

-- Per-user canlı depolama sayacı — media_objects SUM'unun O(1) önbelleği.
-- Best-effort güncellenir (upload +size, ack/cron-expire −size, 0-clamp);
-- günlük cron media_objects gerçeğinden yeniden-hesaplar (drift self-heal).
CREATE TABLE IF NOT EXISTS user_storage (
  user_id TEXT PRIMARY KEY,
  bytes   INTEGER NOT NULL DEFAULT 0
);

-- Sunucu-geneli medya sayacı (tek satır id=1) — turn_usage bütçe-bekçisi
-- deseninin (0009) depolama ikizi. /admin/stats buradan okur.
CREATE TABLE IF NOT EXISTS server_stats (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  media_bytes INTEGER NOT NULL DEFAULT 0,
  media_count INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL DEFAULT 0
);

-- Gün-anahtarlı genel kullanım sayaçları (kind örn: requests, upload_bytes...).
-- Faz 0'da yalnız /admin/stats OKUR (istek-sayım hook'u henüz bağlı değil → 0);
-- Faz 1'de choke-point sayımları bağlanınca kendiliğinden dolar.
CREATE TABLE IF NOT EXISTS usage_counters (
  day   TEXT NOT NULL,                -- "YYYY-MM-DD" (UTC)
  kind  TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, kind)
);
