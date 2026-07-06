-- Veri saklama (retention) ilanı + owner ayarı.
-- retention_days: medya TESLİM EDİLMEZSE kaç gün tutulur (cron fallback penceresi).
-- Teslim edilen içerik zaten teslimde silinir (relay modeli) — bu pencere yalnız
-- "kimse almadı" senaryosu içindir. /capabilities bunu ilan eder; owner düzenler.
ALTER TABLE server_settings ADD COLUMN retention_days INTEGER NOT NULL DEFAULT 30;
