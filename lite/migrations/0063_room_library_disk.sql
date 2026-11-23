-- The group library's items read from the server's own disk (docs/DRIVE_PLAN.md §6, "6b").
--
-- A self-hosted server can offer a folder of its own disk to a group's library: the box's disk
-- gateway (`core/crates/sezi-disk-gateway`) reads a file once for its BLAKE3 and item key, and
-- seals each part on demand when a member reads it. Nothing is uploaded and nothing is stored in a
-- blob store, so these items are NOT `room_library_objects` rows: they hold no store bytes, are
-- charged to no room and to no server total, and are never swept by a library retention. One row
-- per ITEM — its parts are `<item_id>-<index>` and their sizes follow from `size` and
-- `part_size` (the relay computes them as `sezi_file::part` does).
--
-- Expand-only: a new table. The previous build never reads it; while rolled back these items'
-- parts answer 404 and members see them fail to download, which going forward again undoes.
CREATE TABLE IF NOT EXISTS room_library_disk (
  room_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  item_id    TEXT NOT NULL,
  adder_id   TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  part_size  INTEGER NOT NULL,
  parts      INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (room_id, item_id)
);

-- A CATALOG: a folder of the server's disk its owner opens to a group. Members browse and search
-- it and open any file in it; a file opened becomes a `room_library_disk` item of the room (so its
-- parts are readable there) without a library record — nothing is added to the group's library
-- for everyone. Files the owner puts into the folder later are in the catalog at once: it is the
-- folder, read when asked, not a copy of it. Removing a catalog leaves the disk alone.
CREATE TABLE IF NOT EXISTS disk_catalogs (
  room_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  catalog_id TEXT NOT NULL,
  path       TEXT NOT NULL,
  name       TEXT NOT NULL,
  added_by   TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (room_id, catalog_id)
);
