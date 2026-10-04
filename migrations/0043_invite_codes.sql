-- 0043: a short, TYPEABLE code for every newly minted invite (campus plan Wave F; board
-- R4-Class-Invite: "sezi.kampus.edu.tr/K7QM-4827" under the projector QR).
--
-- The bearer token is 24 base64url characters — fine inside a QR, impossible to read off a wall
-- from row 30. The code is eight symbols from an alphabet without look-alikes
-- (`auth/invite_code.rs`), and redeem accepts it wherever it accepts the token.
--
-- `code` is kept raw for the same reason `token` is: the admin list shows it again ("Copy
-- code", "Show on projector"), and the row is TTL-bounded like the token. `code_hash` is the
-- lookup key redeem uses, so the code is never compared as a plain string in SQL and a lookup is
-- one index probe.
ALTER TABLE invite_tokens ADD COLUMN code TEXT;
ALTER TABLE invite_tokens ADD COLUMN code_hash TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_invite_tokens_code_hash
  ON invite_tokens(code_hash) WHERE code_hash IS NOT NULL;
