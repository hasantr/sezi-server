-- Metadata for DURABLE, member-uploadable plugin-media blobs (for quota accounting).
--
-- DELIBERATELY SEPARATE from media_objects: there is NO expires_at → the rows are DURABLE (the
-- daily cleanup cron does NOT TOUCH this table, and there is no ack-delete either).
-- Room-scoped (IDOR closed — the R2 key is plugin-media/{room}/{id}).
-- PRIMARY KEY(room_id, blob_id) = an idempotent PUT + ON CONFLICT double-count protection.
--
-- Quota: the user_storage/server_stats counters are reconciled from BOTH media_objects AND
-- this table (usage::reconcile_storage) → check_upload applies the storage cap to the SUM of
-- the two channels. size_bytes = content-length (the server is E2E-blind; content is not counted).
CREATE TABLE IF NOT EXISTS plugin_media_objects (
  room_id     TEXT NOT NULL,
  blob_id     TEXT NOT NULL,
  uploader_id TEXT NOT NULL,
  size_bytes  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (room_id, blob_id)
);

-- The per-user quota reconcile does a GROUP BY on uploader_id (and a user deletion may need
-- to clean up by it) → index on the uploader.
CREATE INDEX IF NOT EXISTS idx_plugin_media_uploader ON plugin_media_objects (uploader_id);
