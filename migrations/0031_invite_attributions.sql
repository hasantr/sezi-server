-- Keep the identity/attribution link between an invite redeem and its verify durable.
--
-- SECURITY: a bearer invite token is an authorization secret; it is NEVER stored raw in a
-- durable audit/grant table. The Rust redeem path computes SHA-256(token). The raw token
-- survives only in the existing TTL-bounded invite_tokens row and in the legacy
-- verification_codes bridge, which is deleted once verify completes.
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

-- A SHA-256 primitive is not guaranteed at the SQL layer, so old raw tokens are not copied
-- into the ledger from this migration file. The Rust verify path handles the in-flight codes,
-- and the maintenance path hashes the already-used invites and backfills them safely. That
-- way the migration writes no bearer secret into any durable table.
