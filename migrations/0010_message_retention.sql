-- Mesaj bekletme süresi (message retention) — admin-ayarlı.
-- message_retention_days: teslim EDİLMEYEN mesaj her alıcının Durable Object
-- `pending` kuyruğunda en çok kaç gün tutulur (DO alarm temizlik penceresi).
-- Önceden DO'da hard-coded 30 gündü; artık owner D1'den ayarlar (medya
-- retention_days deseninin ikizi). Teslim edilen mesaj zaten ack'te silinir
-- (relay modeli) — bu pencere yalnız "alıcı hiç bağlanmadı" senaryosu içindir.
-- /capabilities bunu `retention.message_days` olarak ilan eder; owner düzenler.
ALTER TABLE server_settings ADD COLUMN message_retention_days INTEGER NOT NULL DEFAULT 30;
