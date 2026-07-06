-- M2-S3.2: QR-link akışı — ikinci cihazın birincile kriptografik bağlanması.
--
-- `link_requests` = kısa-ömürlü (TTL ~60s) tek-kullanımlık bağlama isteği:
--   1) Yeni cihaz `link-start` ile ed/x pub + device_id + PoP-imza yollar →
--      server `link_code` üretir (pre-auth; user_id henüz NULL).
--   2) Birincil QR'ı tarar → yeni listeyi (rev+1) imzalar → `link-approve`
--      (birincil-auth) → server cross-check + listeyi atomik saklar + (user,device)
--      token üretir, satıra `access_token`/`refresh_token` yazar (status=approved).
--   3) Yeni cihaz `link-status` (ed-imzalı proof ile) poll eder → approved'da
--      token'ı TEK SEFER alır (status=consumed → satır derhal silinir).
--
-- Güvenlik: token'lar yalnız approve→consume penceresinde (kısa TTL) düz-metin
-- saklanır; consume satırı siler. cleanup cron süresi dolanları da temizler.
CREATE TABLE link_requests (
  link_code      TEXT PRIMARY KEY,         -- b64u(random 32) — yüksek entropi, tek-kullanım
  user_id        TEXT,                     -- NULL until approve (link-start pre-auth)
  new_ed_pub     BLOB NOT NULL,            -- bağlanacak cihazın Ed25519 pub (32B)
  new_x_pub      BLOB NOT NULL,            -- bağlanacak cihazın Curve25519 pub (32B)
  new_device_id  TEXT NOT NULL,            -- 16 hex (yeni cihaz iddiası; cross-check'lenir)
  label          TEXT,
  status         TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected (consume = satır DELETE; 'consumed' persist EDİLMEZ)
  reason         TEXT,                     -- rejected gerekçesi (forward-compat)
  access_token   TEXT,                     -- approve'da üretilir, consume'da TEK SEFER teslim
  refresh_token  TEXT,                     -- düz-metin tek-atış (consume'da teslim + satır silinir)
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);

CREATE INDEX idx_link_requests_expiry ON link_requests (expires_at);
