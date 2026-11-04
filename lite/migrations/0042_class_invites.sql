-- 0042: CLASS invites — one expiring, multi-use invite that admits a whole class (campus plan
-- R5, Wave F; board R4-Class-Invite).
--
-- Until now every invite was single-use: redeem claimed it on the `invite_attributions` primary
-- key (the token hash) and flipped `used`. A lecture hall of 120 needed 120 invites, and every
-- one of them made the minting admin the joiner's contact. A class invite keeps ONE token (and
-- one short code, 0043) and counts its seats instead.
--
-- invite_tokens:
--   kind                    'personal' (every row so far — and the genesis invite) | 'class'
--   max_uses                seats; 1 for a personal invite
--   uses                    seats taken, incremented atomically by the class claim
--                           (`auth/class_invite.rs`), refused beyond `max_uses`
--   introduce               1 = the joiner and the minter become contacts (personal, as today);
--                           0 = they do not (class: one admin must not become 120 students' contact)
--   landing_room_id         optional group the joiner is put into after verify
--   landing_needs_approval  1 = the joiner waits as a join request (0044) until a group admin says
--                           yes; only ever 1 on a class invite
--   revoked_at              a class invite is revoked by marking it, so its card and its count stay
--                           listable; a personal invite is still revoked by deleting its row
--   claim_nonce             scratch for the class claim's two-statement batch: the seat UPDATE
--                           writes it and the ledger INSERT reads it back, so the INSERT happens
--                           exactly when the seat was won
ALTER TABLE invite_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'personal';
ALTER TABLE invite_tokens ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1;
ALTER TABLE invite_tokens ADD COLUMN uses INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invite_tokens ADD COLUMN introduce INTEGER NOT NULL DEFAULT 1;
ALTER TABLE invite_tokens ADD COLUMN landing_room_id TEXT;
ALTER TABLE invite_tokens ADD COLUMN landing_needs_approval INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invite_tokens ADD COLUMN revoked_at INTEGER;
ALTER TABLE invite_tokens ADD COLUMN claim_nonce TEXT;

-- A personal invite that was already used has taken its one seat.
UPDATE invite_tokens SET uses = 1 WHERE used = 1;

-- invite_attributions keeps ONE row per REDEMPTION, as before. A personal redemption is still
-- keyed by its token hash; a class redemption is keyed by SHA-256(token_hash ':' nonce), so 120
-- redemptions of one invite are 120 rows, each with its own verify, its own `used_by` and its own
-- snapshot. `source_hash` names the class invite they came through (NULL for personal) — the
-- live count, the per-invite rate limit and revocation all find a class's redemptions by it.
-- `introduce`, `landing_room_id` and `landing_needs_approval` are snapshotted at the claim for the
-- same reason `genesis` is: verify must not depend on a source row that can be revoked or
-- TTL-swept in between.
ALTER TABLE invite_attributions ADD COLUMN kind TEXT NOT NULL DEFAULT 'personal';
ALTER TABLE invite_attributions ADD COLUMN source_hash TEXT;
ALTER TABLE invite_attributions ADD COLUMN introduce INTEGER NOT NULL DEFAULT 1;
ALTER TABLE invite_attributions ADD COLUMN landing_room_id TEXT;
ALTER TABLE invite_attributions ADD COLUMN landing_needs_approval INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_invite_attr_source
  ON invite_attributions(source_hash, verified_at) WHERE source_hash IS NOT NULL;
