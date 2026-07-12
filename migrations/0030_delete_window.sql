-- "Herkesten sil" penceresi (delete_window_hours) — owner-ayarlı.
-- delete_window_hours: bir mesaj GÖNDERİLDİKTEN sonra en çok kaç SAAT içinde
-- "herkesten sil" yapılabilir. Alıcı taraf ileride bunu ZORLAR (mesaj-yaşı >
-- pencere → red); bu kolon yalnız DEĞERİ taşır (server_settings → /capabilities
-- → client). retention_days / message_retention_days deseninin ikizi (owner
-- D1'den ayarlar; /capabilities ilan eder; owner PATCH /admin/server-settings
-- ile düzenler). DEFAULT 48 saat.
ALTER TABLE server_settings ADD COLUMN delete_window_hours INTEGER NOT NULL DEFAULT 48;
