-- M2-S3.2c bug-fix: signed_prekeys PK (user_id, prekey_id) -> (user_id, device_id, prekey_id).
--
-- Cikis: coklu-cihaz link finalize'da BAGLI cihaz kendi SPK'sini yayinlarken
--   "UNIQUE constraint failed: signed_prekeys.user_id, signed_prekeys.prekey_id" -> 500.
-- Neden: her cihaz kendi prekey_id namespace'inde SPK uretir (ikisi de dusuk id'den
--   baslar); user_id ORTAK oldugundan (linked = primary'nin user_id'si) ayni prekey_id
--   farkli device'larda CAKISIYORDU. PK'ya device_id girmeli.
-- mig 0012 device_id kolonunu ekledi ama PK (user_id, prekey_id) kaldi.
--
-- SQLite PK degistirilemez -> tablo rebuild. device_id NULL (legacy/birincil) -> '' sentinel
-- (NOT NULL DEFAULT '' ile PK'da NULL sorunu olmaz). signed_prekeys leaf tablo
-- (yalniz users'a referans, kimse ona referans vermiyor) -> DROP guvenli.
CREATE TABLE signed_prekeys_new (
  user_id     TEXT NOT NULL REFERENCES users(id),
  device_id   TEXT NOT NULL DEFAULT '',
  prekey_id   INTEGER NOT NULL,
  prekey_pub  BLOB NOT NULL,
  signature   BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, device_id, prekey_id)
);

INSERT INTO signed_prekeys_new (user_id, device_id, prekey_id, prekey_pub, signature, created_at)
  SELECT user_id, COALESCE(device_id, ''), prekey_id, prekey_pub, signature, created_at
  FROM signed_prekeys;

DROP TABLE signed_prekeys;
ALTER TABLE signed_prekeys_new RENAME TO signed_prekeys;
