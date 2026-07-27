-- P0: davet redeem -> verify arasindaki kimlik/attribution bagini kalici tut.
--
-- GUVENLIK: bearer invite token bir yetkilendirme sirridir; kalici audit/grant
-- tablosunda ASLA ham saklanmaz. Rust redeem akisi SHA-256(token) hesaplar.
-- Ham token yalniz mevcut TTL'li invite_tokens satirinda ve verify tamamlaninca
-- silinen verification_codes legacy koprusunde kalir.
ALTER TABLE invite_tokens ADD COLUMN token_hash TEXT;
ALTER TABLE verification_codes ADD COLUMN invite_token_hash TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_invite_tokens_hash
  ON invite_tokens(token_hash) WHERE token_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS invite_attributions (
  invite_token_hash  TEXT PRIMARY KEY CHECK(length(invite_token_hash) = 64),
  email_hint         TEXT,
  inviter_user_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
  inviter_ed_pub     BLOB,
  used_by            TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at         INTEGER NOT NULL,
  expires_at         INTEGER NOT NULL,
  redeemed_at        INTEGER NOT NULL,
  verified_at        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_invite_attr_inviter
  ON invite_attributions(inviter_user_id, redeemed_at DESC);
CREATE INDEX IF NOT EXISTS idx_invite_attr_used_by
  ON invite_attributions(used_by, redeemed_at DESC);

-- SQL katmaninda SHA-256 primitive'i garanti degil; bu nedenle eski ham token'lar
-- migration dosyasinda ledger'a kopyalanmaz. Rust verify yolu in-flight kodu,
-- maintenance yolu da henuz mevcut kullanilmis davetleri hashleyip guvenli sekilde
-- backfill eder. Boylece migration hicbir kalici tabloya bearer sirri yazmaz.
