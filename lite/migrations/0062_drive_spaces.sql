-- Drive spaces (docs/DRIVE_PLAN.md §8.1): a Drive space is a room with no chat, a `groups` row of
-- a kind other than 'group'. 'drive_personal' is a member's own drive, one per member (the index);
-- 'drive' (a shared space) is reserved and created by nothing yet.
--
-- Expand-only. The previous build never reads `kind`, and its INSERTs still work through the
-- default. While rolled back it would list a personal space as an ordinary group named "drive"
-- (read-only confusion, nothing lost) and would freeze the server's library retention onto new
-- Drive parts if the owner set one — both undone by going forward again.
ALTER TABLE groups ADD COLUMN kind TEXT NOT NULL DEFAULT 'group';
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_personal_drive
  ON groups (created_by) WHERE kind = 'drive_personal';
