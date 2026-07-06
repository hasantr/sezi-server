-- Sezgi: çoklu-cihaz adresleme S1 (TEMEL — strictly additive, davranış DEĞİŞMEZ).
--
-- M2-S1 device_id raylarını döşer; ESKİ WIRE AYNEN çalışmaya devam eder.
-- Burada YALNIZCA NULLABLE kolonlar eklenir → eski register/login gövdesi
-- (yeni alansız) ve eski token (device_id claim'siz) AYNEN doğrulanır.
--
-- one_time_prekeys / signed_prekeys / refresh_tokens : NULL = legacy/birincil
--   cihaz. S1'de bu kolon YAZILIR (cihaz device_id gönderirse) ama henüz
--   TÜKETİLMEZ — claim/lookup hâlâ user_id düzeyinde (per-device havuz S2'de).
-- users.identity_ed_pub : kullanıcının Ed25519 imza pub'ı (BLOB). NULL = legacy.
--   register/verify yolunda `identity_ed_pub_b64` gelirse doldurulur; imzalı
--   cihaz-listesi doğrulamasının doğrudan-karşılaştırma zinciri için (§3.3).
--
-- ⚠️ UNIQUE / PRIMARY KEY KESİNLİKLE DEĞİŞMEZ — per-device anahtarlama göçü
-- (yeni tablo + kopya) M2-S2'nin işidir. Bu migration salt kolon ekler.

ALTER TABLE one_time_prekeys ADD COLUMN device_id TEXT;  -- NULL = legacy/birincil
ALTER TABLE signed_prekeys   ADD COLUMN device_id TEXT;  -- NULL = legacy/birincil
ALTER TABLE refresh_tokens   ADD COLUMN device_id TEXT;  -- NULL = legacy/birincil
ALTER TABLE users            ADD COLUMN identity_ed_pub BLOB;  -- NULL = legacy
