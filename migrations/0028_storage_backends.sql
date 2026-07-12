-- Takılabilir-Depolama (Pluggable Storage) Faz 1 — D1 placement/envanter şeması.
-- (Plan PLUGGABLE_STORAGE_PLAN.md c.3; numara 0027→0028: 0027 server_plugin_policy'ye gitti.)
--
-- Depo kataloğu. SECRET İÇERİR (config_json) → cf/fcm-config emsali: WRITE-ONLY,
-- owner-only, D1-at-rest (CF disk-şifreli); hiçbir endpoint config_json döndürmez.
CREATE TABLE IF NOT EXISTS storage_backends (
  store_id        TEXT PRIMARY KEY,              -- 'r2-primary' | 's3-<8hex rastgele>'
  kind            TEXT NOT NULL,                 -- 'r2_binding' | 's3'  (Faz 6: 'webdav')
  label           TEXT NOT NULL,                 -- owner-görünen ad ("B2 — kişisel")
  state           TEXT NOT NULL DEFAULT 'active',-- active | readonly | draining | disabled
  priority        INTEGER NOT NULL DEFAULT 100,  -- küçük = önce yazılır (r2-primary=0)
  max_bytes       INTEGER,                       -- NULL = sınırsız (owner per-depo tavanı)
  used_bytes      INTEGER NOT NULL DEFAULT 0,    -- sayaç (best-effort + günlük reconcile)
  object_count    INTEGER NOT NULL DEFAULT 0,
  config_json     TEXT NOT NULL DEFAULT '{}',
  last_health_at  INTEGER,                       -- son probe epoch-sn
  last_health_ok  INTEGER,                       -- NULL=hiç probe olmadı; 0/1
  last_health_err TEXT,                          -- kısa hata (120 char kırpık, secret'sız)
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
-- Default depo: mevcut R2 binding'i. Binding'siz Lite kurulumda satır yine durur;
-- kullanılabilirlik runtime'da binding-lookup ile belli olur (StorageRouter::any_available).
INSERT OR IGNORE INTO storage_backends
  (store_id, kind, label, state, priority, created_at, updated_at)
  VALUES ('r2-primary', 'r2_binding', 'Cloudflare R2', 'active', 0,
          CAST(strftime('%s','now') AS INTEGER), CAST(strftime('%s','now') AS INTEGER));

-- Placement kolonları: DEFAULT 'r2-primary' mevcut satırları otomatik doğru işaretler
-- (bugün her blob R2'de). content_type: harici backend'lerde tip-güvencesi D1'den.
ALTER TABLE media_objects ADD COLUMN store_id TEXT NOT NULL DEFAULT 'r2-primary';
ALTER TABLE media_objects ADD COLUMN content_type TEXT;
ALTER TABLE plugin_media_objects ADD COLUMN store_id TEXT NOT NULL DEFAULT 'r2-primary';

-- Eklenti-KODU kanalına İLK envanter (bugün D1-meta'sız → "nerede" bilinemezdi).
-- NOT: kota sayaçlarına (user_storage/server_stats) DAHİL EDİLMEZ (mevcut kota
-- semantiği bit-aynı kalsın); yalnız per-depo used_bytes/envanter gerçeğine girer.
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

-- Tombstone: silinmesi GEREKEN ama depo-hatası yüzünden silinemeyen blob'lar.
-- Günlük bakım tekrar dener → harici depoda öksüz-blob kalıcılaşmaz. (Faz 3'te dolar.)
CREATE TABLE IF NOT EXISTS storage_orphans (
  store_id    TEXT NOT NULL,
  key         TEXT NOT NULL,                 -- tam depo anahtarı ("media/x", "plugin-media/r/x")
  size_bytes  INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  retry_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (store_id, key)
);
