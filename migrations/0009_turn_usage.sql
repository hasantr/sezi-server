-- TURN bütçe bekçisi (calls Faz 1.5 — internet üstü arama relay'i).
--
-- Aramalar P2P başarısız olunca medya CF Realtime TURN'den geçer ($0.05/GB,
-- ilk 1 TB/ay bedava). CF'de sert harcama-tavanı YOK → sürpriz faturayı
-- önlemek için worker kendi tavanını uygular: bu tabloda aylık kimlik-üretim
-- sayacı tutulur; `TURN_MONTHLY_CAP` aşılınca worker kimlik ÜRETMEZ (client
-- doğrudan/STUN'a düşer, CF faturası o noktada durur). Her kimlik ~bir arama.
CREATE TABLE IF NOT EXISTS turn_usage (
    month  TEXT PRIMARY KEY,          -- "YYYY-MM" (UTC) bütçe penceresi
    issued INTEGER NOT NULL DEFAULT 0 -- o ay üretilen TURN kimliği sayısı
);
