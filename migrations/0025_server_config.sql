-- 0025: server_config — self-provision anahtar deposu (self-host Faz A).
--
-- Generic key-value: `jwt_signing_key` (Ed25519 PKCS8 PEM) / `admin_invite_key`
-- (b64url 32B) satırları. Taze fork ilk boot'ta worker anahtarları ÜRETİP buraya
-- persist eder (src/self_provision.rs) — `wrangler secret put` bilmeyen kullanıcı
-- da çalışan server alır.
--
-- GÜVENLİK NOTU: değerler D1-at-rest durur (CF disk-şifreli) — self-host
-- dürüst-server modeli. env secret girilirse HER ZAMAN kazanır (güvenlik-bilinçli
-- owner anahtarı secret'a taşıyabilir; o zaman bu tablo hiç kullanılmaz).
-- Bu değerler HİÇBİR endpoint'ten dönmez (yalnız worker-içi okuma/yazma).

CREATE TABLE IF NOT EXISTS server_config (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
