-- Pluggable Storage — the D1 placement/inventory schema.
-- (Plan: PLUGGABLE_STORAGE_PLAN.md §3; numbered 0027→0028 because 0027 went to
-- server_plugin_policy.)
--
-- The store catalogue. It CONTAINS SECRETS (config_json) → the cf/fcm-config precedent:
-- WRITE-ONLY, owner-only, D1 at rest (CF disk-encrypted); no endpoint returns config_json.
CREATE TABLE IF NOT EXISTS storage_backends (
  store_id        TEXT PRIMARY KEY,              -- 'r2-primary' | 's3-<8 random hex>'
  kind            TEXT NOT NULL,                 -- 'r2_binding' | 's3'  (later: 'webdav')
  label           TEXT NOT NULL,                 -- the owner-visible name ("B2 — personal")
  state           TEXT NOT NULL DEFAULT 'active',-- active | readonly | draining | disabled
  priority        INTEGER NOT NULL DEFAULT 100,  -- smaller = written to first (r2-primary=0)
  max_bytes       INTEGER,                       -- NULL = unlimited (the owner's per-store cap)
  used_bytes      INTEGER NOT NULL DEFAULT 0,    -- counter (best-effort + a daily reconcile)
  object_count    INTEGER NOT NULL DEFAULT 0,
  config_json     TEXT NOT NULL DEFAULT '{}',
  last_health_at  INTEGER,                       -- last probe, epoch-sec
  last_health_ok  INTEGER,                       -- NULL = never probed; 0/1
  last_health_err TEXT,                          -- a short error (trimmed to 120 chars, no secrets)
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
-- The default store: the existing R2 binding. On a Lite install with no binding the row still
-- exists; availability is decided at runtime by the binding lookup
-- (StorageRouter::any_available).
INSERT OR IGNORE INTO storage_backends
  (store_id, kind, label, state, priority, created_at, updated_at)
  VALUES ('r2-primary', 'r2_binding', 'Cloudflare R2', 'active', 0,
          CAST(strftime('%s','now') AS INTEGER), CAST(strftime('%s','now') AS INTEGER));

-- Placement columns: DEFAULT 'r2-primary' labels the existing rows correctly by itself (today
-- every blob is in R2). content_type: on an external backend, the type guarantee comes from D1.
ALTER TABLE media_objects ADD COLUMN store_id TEXT NOT NULL DEFAULT 'r2-primary';
ALTER TABLE media_objects ADD COLUMN content_type TEXT;
ALTER TABLE plugin_media_objects ADD COLUMN store_id TEXT NOT NULL DEFAULT 'r2-primary';

-- The FIRST inventory for the plugin-CODE channel (it had no D1 metadata, so "where is it"
-- could not be answered). NOTE: it is NOT INCLUDED in the quota counters
-- (user_storage/server_stats) so the existing quota semantics stay bit-identical; it only
-- enters the per-store used_bytes / inventory truth.
CREATE TABLE IF NOT EXISTS plugin_code_objects (
  room_id     TEXT NOT NULL,
  blob_id     TEXT NOT NULL,
  uploader_id TEXT NOT NULL,
  size_bytes  INTEGER NOT NULL,
  store_id    TEXT NOT NULL DEFAULT 'r2-primary',
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (room_id, blob_id)
);

CREATE INDEX IF NOT EXISTS idx_media_objects_store ON media_objects (store_id);
CREATE INDEX IF NOT EXISTS idx_plugin_media_store  ON plugin_media_objects (store_id);
CREATE INDEX IF NOT EXISTS idx_plugin_code_store   ON plugin_code_objects (store_id);

-- Tombstones: blobs that SHOULD be deleted but could not be, because the store errored.
-- The daily maintenance retries them → an orphaned blob does not become permanent on an
-- external store. (It starts filling in a later phase.)
CREATE TABLE IF NOT EXISTS storage_orphans (
  store_id    TEXT NOT NULL,
  key         TEXT NOT NULL,                 -- the full store key ("media/x", "plugin-media/r/x")
  size_bytes  INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  retry_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (store_id, key)
);
