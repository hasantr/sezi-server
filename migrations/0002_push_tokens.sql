-- Sezgi push token kayıtları (Oturum 12.A).
-- Çoklu cihaz desteği: her (user_id, device_id) çifti benzersiz.
-- users.fcm_token kolonu legacy; bu tablo onun yerine geçer.

CREATE TABLE IF NOT EXISTS push_tokens (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id     TEXT NOT NULL,
  fcm_token     TEXT NOT NULL,
  platform      TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  UNIQUE (user_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_push_user ON push_tokens(user_id);
