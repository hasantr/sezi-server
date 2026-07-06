-- Sezgi: grup AYAR TORBASI (protokol substratı Faz 1).
--
-- Grupları sabit-özellik yerine ESNEK substrata çevirmenin ilk adımı: oda
-- ayarları iki katman.
--   1. SUNUCU-kolonları — sunucunun ACT etmesi gereken ayarlar (sunucu okur +
--      davranış değiştirir; ileride dizin/auto-join):
--        visibility  : 'private' | 'public' (üye-dizini görünürlüğü — Faz 5)
--        auto_join   : 0 | 1 (yeni sunucu-üyesi otomatik katılır — Faz 5)
--   2. CLIENT JSON torbası — sunucunun umursamadığı, yalnız client/eklentilerin
--      okuduğu her şey (tema, eklenti-config, sıralama…). Opak blob; sunucu
--      sadece saklar. Yeni özellik = yeni anahtar, ŞEMA DEĞİŞMEZ.
--        settings_json : TEXT (NULL = boş torba)
--
-- E2E korunur: ayarlar içerik DEĞİL (üyelik-meta gibi). Faz 1 yalnız boru-döşeme
-- (okuma/yazma); visibility/auto_join'i tüketen dizin + verify-hook Faz 5.

ALTER TABLE groups ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private';
ALTER TABLE groups ADD COLUMN auto_join INTEGER NOT NULL DEFAULT 0;
ALTER TABLE groups ADD COLUMN settings_json TEXT;
