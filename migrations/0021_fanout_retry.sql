-- W4-b (grup fan-out kısmi-fail durable-retry): notify_recipient 3-deneme de FAIL eden
-- (üye,cihaz) çifti buraya yazılır → cron drain re-notify eder → o üye grup mesajını KAÇIRMAZ.
-- Faz-2 (server-canonical-log) gelince gereksizleşir = bilinçli KÖPRÜ (temiz söküm: cron + DROP).
--
-- retry_key = idempotency anahtarı (recipient|device|group|env_hash) → sender-retry / çift-enqueue
-- AYNI satırı çift-yazMAZ (INSERT OR IGNORE); dup-pending + W2-cap tüketimi önlenir.
-- next_at = backoff/lease damgası (epoch-sec): claim ANINDA ileri itilir (atomic lease) → çakışan
-- cron invocation'ı AYNI satırı double-notify etmez. attempts yalnız DO-hatası sayar (offline
-- alıcıya notify BAŞARILIDIR → pending'e yazar) → MAX'a ulaşmak "DO günlerce bozuk"=aşırı nadir.
-- MAX'ta SİLMEYİZ (kayıp); TTL-GC (günlük-cron, pending-retention paritesi) çok-eskiyi toplar.
-- Tablo yoksa (migration uygulanmamış) enqueue best-effort → send KIRILMAZ (graceful).
CREATE TABLE IF NOT EXISTS fanout_retry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  retry_key TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  recipient_device TEXT,           -- NULL = device-blind (cihaz-yayınlamamış üye)
  sender_id TEXT NOT NULL,
  sender_device TEXT,
  envelope_b64 TEXT NOT NULL,
  group_id TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,        -- epoch-sec; claim'de ileri itilir (lease)
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fanout_retry_key ON fanout_retry(retry_key);
CREATE INDEX IF NOT EXISTS idx_fanout_retry_next ON fanout_retry(next_at);
