-- 0018: the owner race — a single-owner guarantee (two concurrent first registrations must
-- not produce TWO owners).
--
-- The problem: `auth/verify.rs` makes the first user the owner (role='owner' when
-- `SELECT id FROM users LIMIT 1` comes back empty). If two requests see that SELECT empty at
-- the same moment, BOTH users can be INSERTed as owner (TOCTOU). The owner is the server's
-- founder and a protected role → two owners break the authority model.
--
-- The fix: a D1 (SQLite) partial UNIQUE index that enforces uniqueness over the role='owner'
-- rows alone. A second owner INSERT fails with a UNIQUE violation (atomic in the DB; the
-- TOCTOU window closes). member/admin rows are NOT in the index → they stay unconstrained.
-- IF NOT EXISTS → a re-run is idempotent and safe.

-- DEPLOY HAZARD, so de-duplicate first. If a production DB already carries the dirty state
-- these bugs produced (>=2 owners, from the transfer-owner race or the bootstrap TOCTOU), the
-- CREATE UNIQUE INDEX below BLOWS UP → the D1 migration batch aborts → the DEPLOY IS BLOCKED.
-- Idempotent cleanup: KEEP the OLDEST owner (created_at MIN, rowid MIN as the tie-break) and
-- demote every other owner to admin. With 0 or 1 owner this is a NO-OP (a harmless re-run).
-- created_at = INTEGER (0001_init).
UPDATE users SET role = 'admin'
 WHERE role = 'owner'
   AND id NOT IN (
     SELECT id FROM users WHERE role = 'owner'
      ORDER BY created_at ASC, rowid ASC LIMIT 1
   );

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_owner ON users(role) WHERE role = 'owner';

-- The bootstrap race — concurrent /bootstrap calls could produce several genesis tokens (both
-- saw "there is no genesis yet" and INSERTed). A genesis row = `owner_user_id IS NULL AND
-- used = 0` (system-generated, unused). The partial UNIQUE index → AT MOST one unused genesis
-- invite can exist at a time; a second concurrent INSERT fails with a UNIQUE violation → the
-- bootstrap handler swallows the error and re-SELECTs the single existing row (idempotent,
-- one token returned). Real invites (`create_invite`, owner_user_id set) are NOT in this index
-- → unconstrained. A used=1 genesis is outside the index too: once it has been used there is
-- no need for the uniqueness constraint again, and the door returns 410 as soon as an owner
-- exists. `used` is the indexed column, but across every partial row used=0 → a constant
-- value, so uniqueness here means one row in the owner_user_id-NULL + used=0 set.
-- DEPLOY HAZARD, so de-duplicate first: if the bootstrap race left >=2 unused genesis rows,
-- the CREATE UNIQUE INDEX blows up. KEEP the OLDEST unused genesis (created_at MIN, rowid MIN
-- as the tie-break) and mark the rest used=1 → they leave the index. invite_tokens columns:
-- token(PK)/used/expires_at/created_at(INTEGER, 0001_init)/owner_user_id (0004). With 0 or 1
-- genesis this is a NO-OP. token is the PK → the NOT IN subquery keys on token.
UPDATE invite_tokens SET used = 1
 WHERE owner_user_id IS NULL AND used = 0
   AND token NOT IN (
     SELECT token FROM invite_tokens
      WHERE owner_user_id IS NULL AND used = 0
      ORDER BY created_at ASC, rowid ASC LIMIT 1
   );

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_genesis_invite
  ON invite_tokens(used) WHERE owner_user_id IS NULL AND used = 0;
