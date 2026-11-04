-- 0035: the profile/group avatar blob store (Profile Photo epic §2.3).
-- ONE LOGICAL SLOT PER USER for the E2E-encrypted avatar blobs.
--
-- DELIBERATELY kept SEPARATE from media_objects:
--   * there is NO expires_at → the rows are DURABLE. The message-retention TTL cleanup
--     (maintenance::cleanup_expired, which only deletes where media_objects.expires_at < now)
--     does NOT TOUCH this table → the avatar class is EXEMPT from retention (plan §2.3). An
--     avatar is a profile STATE, not ephemeral media.
--   * user_id is the PRIMARY KEY → one logical slot: a new upload drops the previous blob into
--     storage_orphans (the existing orphan/cleanup machinery — the daily retry_orphans deletes
--     it from the store).
--
-- The blob CONTENT is BLIND to the server: the key travels only on the E2E channel and the
-- server holds nothing but opaque bytes.
CREATE TABLE IF NOT EXISTS avatar_objects (
  user_id     TEXT PRIMARY KEY REFERENCES users(id),
  object_id   TEXT NOT NULL,                 -- avatar_ref: the opaque capability carried over E2E; the download resolves with it
  store_id    TEXT NOT NULL DEFAULT 'r2-primary',
  size_bytes  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- The download resolves through the single-segment opaque object_id (the store key is
-- avatar/{user}/{object_id} and contains a '/', so it cannot be a path param). One slot: an
-- upsert drops the old object_id → the old ref no longer resolves (404) and the old blob waits
-- in storage_orphans.
CREATE UNIQUE INDEX IF NOT EXISTS idx_avatar_object_id ON avatar_objects (object_id);
