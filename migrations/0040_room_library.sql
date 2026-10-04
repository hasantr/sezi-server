-- 0040: the group LIBRARY — a durable, per-group storage class for recordings and course
-- materials (docs/CAMPUS_PLAN.md, ruling R1 and Wave D step 1).
--
-- What the server holds here is ENCRYPTED PARTS it cannot read: a recording is cut into
-- ~32 MiB parts on a member's device, each part encrypted under a key the server never sees,
-- and each part stored as one object. The record that names the parts (title, length, key)
-- travels end to end on the group channel. The operator sees sizes, never content.
--
-- DELIBERATELY SEPARATE from the two neighbouring tables:
--   * media_objects is the RELAY class — every row expires after `retention_days` (30 by
--     default), and R1 keeps chat media on that model untouched. A library must outlive it.
--   * plugin_media_objects is persistent but charged to its UPLOADER (`user_storage`), so a
--     teacher who records a course would pay for the whole course out of a personal cap.
--     Library bytes are charged to the ROOM (`max_room_library_bytes`) and to the server total,
--     never to the person who happened to press record.
--
-- `expires_at` is NULLABLE: NULL = kept until deleted (the default, because
-- `library_retention_days` defaults to NULL). When the owner sets a retention, it is FROZEN into
-- the row at upload — the media_objects rule — so a later change never silently shortens what a
-- group was promised when it uploaded.
--
-- No foreign keys, on purpose. Not onto `groups`: the group teardown (`groups_delete.rs`) queues
-- the blobs and drops these rows in one batch, as it does for plugin media. Not onto `users`:
-- a library belongs to the group, so an uploader who leaves the server must not take the
-- course's recordings with them — and on D1, which enforces foreign keys, a reference would make
-- the account deletion fail outright.
--
-- `kind` is a short label the CLIENT chooses ('part' unless it says otherwise). The server stores
-- and returns it and never acts on it; it is visible to the operator, so the client keeps it
-- coarse.
CREATE TABLE IF NOT EXISTS room_library_objects (
  room_id     TEXT NOT NULL,
  object_id   TEXT NOT NULL,                       -- opaque, client-chosen, random (≥16 chars)
  uploader_id TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'part',
  size_bytes  INTEGER NOT NULL,
  store_id    TEXT NOT NULL DEFAULT 'r2-primary',
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER,                             -- NULL = keep until deleted
  PRIMARY KEY (room_id, object_id)
);

-- The drain/move engine and the daily per-backend reconcile group by store.
CREATE INDEX IF NOT EXISTS idx_room_library_store ON room_library_objects (store_id);

-- The daily sweep reads only rows that CAN expire; keep-forever rows stay out of the index.
CREATE INDEX IF NOT EXISTS idx_room_library_expiry ON room_library_objects (expires_at)
  WHERE expires_at IS NOT NULL;

-- Library retention in days, frozen into `expires_at` at upload. NULL = keep until deleted — the
-- default, because a course library that silently empties itself after a month is the failure
-- the class exists to prevent. Announced as `/capabilities` `retention.library_days`.
ALTER TABLE server_settings ADD COLUMN library_retention_days INTEGER;

-- Per-group library cap in bytes. NULL = unlimited, the `max_storage_bytes` convention: no
-- existing server gets a surprise refusal until its owner sets a number.
ALTER TABLE server_settings ADD COLUMN max_room_library_bytes INTEGER;
