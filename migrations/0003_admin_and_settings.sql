-- Sezgi multi-server admin + erişim modu (Oturum 13 Faz D).
-- Her sunucu örneği kendi içinde admin/member rollerini ve "açık/kapalı"
-- mod ayarını tutar. İlk kayıt olan kullanıcı admin olur (verify.ts).

ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member';

CREATE TABLE IF NOT EXISTS server_settings (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  name       TEXT NOT NULL DEFAULT 'Sezgi',
  join_mode  TEXT NOT NULL DEFAULT 'invite_only',
  updated_at INTEGER NOT NULL DEFAULT 0
);

-- Tek satır seed (id=1). Mevcut kayıt varsa dokunma.
INSERT OR IGNORE INTO server_settings (id, name, join_mode, updated_at)
  VALUES (1, 'Sezgi', 'invite_only', 0);
