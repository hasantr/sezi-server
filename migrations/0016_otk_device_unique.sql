-- FIELD-CRITICAL: one_time_prekeys UNIQUE (user_id, prekey_id) ->
--   UNIQUE (user_id, device_id, prekey_id). (The same class as signed_prekeys in mig 0015.)
--
-- The symptom: with multiple devices, an OTK replenish returned "UNIQUE constraint failed:
--   one_time_prekeys.user_id, one_time_prekeys.prekey_id" -> 500. Every device generates its
--   OTKs out of its own prekey_id namespace (both starting from a low id), and because
--   user_id is SHARED (a linked device carries the primary's user_id) the same prekey_id
--   COLLIDED across devices -> NO device could publish OTKs -> no OTK for a peer's first
--   contact ("an OTK is required for the first message") -> a linked device received nothing
--   and a new device could not be set up after a revoke. Mig 0012 added the device_id column
--   but never put it into the UNIQUE.
--
-- A SQLite UNIQUE cannot be altered -> rebuild the table. device_id NULL (legacy/primary) ->
-- the '' sentinel (NOT NULL DEFAULT ''; parity with signed_prekeys in mig 0015). The `id`
-- autoincrement PK is preserved. one_time_prekeys is a leaf table (it only references users)
-- -> the DROP is safe.
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
