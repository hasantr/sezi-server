-- Üye-yüklenebilir KALICI eklenti-medya blob meta tablosu (kota muhasebesi).
--
-- media_objects'ten BİLİNÇLİ AYRI: expires_at YOK → KALICI (günlük cleanup cron'u
-- bu tabloya DOKUNMAZ; ack-delete de yok). room-scope'lu (IDOR kapalı — R2 anahtarı
-- plugin-media/{room}/{id}). PRIMARY KEY(room_id, blob_id) = idempotent-PUT +
-- ON CONFLICT çift-sayım koruması.
--
-- Kota: user_storage/server_stats sayaçları HEM media_objects HEM bu tablodan
-- reconcile edilir (usage::reconcile_storage) → check_upload depolama cap'ini iki
-- kanalın TOPLAMINA uygular. size_bytes = content-length (server E2E-kör; içerik sayılmaz).
CREATE TABLE IF NOT EXISTS plugin_media_objects (
  room_id     TEXT NOT NULL,
  blob_id     TEXT NOT NULL,
  uploader_id TEXT NOT NULL,
  size_bytes  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (room_id, blob_id)
);

-- Per-user kota reconcile'ı uploader_id GROUP BY yapar (+ kullanıcı-silmede olası
-- temizlik) → yükleyen üstünden index.
CREATE INDEX IF NOT EXISTS idx_plugin_media_uploader ON plugin_media_objects (uploader_id);
