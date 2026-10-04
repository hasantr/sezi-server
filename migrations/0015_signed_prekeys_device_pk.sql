-- Bug fix: signed_prekeys PK (user_id, prekey_id) -> (user_id, device_id, prekey_id).
--
-- The symptom: while finalising a multi-device link, a LINKED device publishing its own SPK
--   got "UNIQUE constraint failed: signed_prekeys.user_id, signed_prekeys.prekey_id" -> 500.
-- Why: every device generates its SPK in its own prekey_id namespace (both starting from a
--   low id), and because user_id is SHARED (a linked device carries the primary's user_id)
--   the same prekey_id COLLIDED across devices. device_id has to be in the PK.
-- Mig 0012 added the device_id column but the PK stayed (user_id, prekey_id).
--
-- A SQLite PK cannot be altered -> rebuild the table. device_id NULL (legacy/primary) -> the
-- '' sentinel (NOT NULL DEFAULT '' keeps NULL out of the PK). signed_prekeys is a leaf table
-- (it only references users and nothing references it) -> the DROP is safe.
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
