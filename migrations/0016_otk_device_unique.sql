-- M2-S3.5 SAHA-KRİTİK: one_time_prekeys UNIQUE (user_id, prekey_id) ->
--   UNIQUE (user_id, device_id, prekey_id). (signed_prekeys mig 0015 ile aynı sınıf.)
--
-- Çıkış: çoklu-cihazda OTK replenish "UNIQUE constraint failed:
--   one_time_prekeys.user_id, one_time_prekeys.prekey_id" -> 500. Her cihaz kendi
--   prekey_id namespace'inden (ikisi de düşük id'den) OTK üretir; user_id ORTAK
--   (linked = primary'nin user_id'si) olduğundan aynı prekey_id farklı device'larda
--   ÇAKIŞIYORDU -> HİÇBİR cihaz OTK yayınlayamıyor -> peer first-contact için OTK yok
--   ("ilk mesaj için OTK gerekli") -> bağlı cihaz mesaj alamıyor + revoke-sonrası
--   yeni cihaz kurulamıyor. mig 0012 device_id kolonunu ekledi ama UNIQUE'e girmedi.
--
-- SQLite UNIQUE değiştirilemez -> tablo rebuild. device_id NULL (legacy/birincil) -> ''
-- sentinel (NOT NULL DEFAULT ''; signed_prekeys mig 0015 paritesi). `id` autoincrement
-- PK korunur. one_time_prekeys leaf tablo (yalnız users'a referans) -> DROP güvenli.
CREATE TABLE one_time_prekeys_new (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT NOT NULL REFERENCES users(id),
  device_id   TEXT NOT NULL DEFAULT '',
  prekey_id   INTEGER NOT NULL,
  prekey_pub  BLOB NOT NULL,
  consumed    INTEGER NOT NULL DEFAULT 0,
  UNIQUE (user_id, device_id, prekey_id)
);

INSERT INTO one_time_prekeys_new (id, user_id, device_id, prekey_id, prekey_pub, consumed)
  SELECT id, user_id, COALESCE(device_id, ''), prekey_id, prekey_pub, consumed
  FROM one_time_prekeys;

DROP TABLE one_time_prekeys;
ALTER TABLE one_time_prekeys_new RENAME TO one_time_prekeys;

CREATE INDEX IF NOT EXISTS idx_otk_lookup ON one_time_prekeys(user_id, consumed);
