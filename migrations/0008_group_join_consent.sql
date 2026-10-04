-- Sezgi: group JOIN CONSENT (consent-first).
--
-- "Being added ≠ joining automatically": a user added to a group does NOT become a member
-- SILENTLY; they receive an invite in the 'pending' state → ACCEPT (active) or DECLINE (the
-- row is deleted).
--   status   : 'pending' | 'active'  (only an active member sends, receives and counts)
--   added_by : who sent the invite (on acceptance they receive GroupJoinAccepted and
--              distribute the key; E2E: the key only flows AFTER the acceptance).
--
-- Backward compatibility: DEFAULT 'active' → existing (already joined) members and old rows
-- stay active. ONLY newly added members (the first members of create_group + add-member) are
-- written as pending. added_by NULL = an old row, or the creator.

ALTER TABLE group_members ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE group_members ADD COLUMN added_by TEXT;
