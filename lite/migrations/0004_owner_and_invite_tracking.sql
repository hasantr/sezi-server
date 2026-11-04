-- Sezgi: the owner role + invite tracking.
-- users.role now carries 'owner' | 'admin' | 'member' (the first registration = owner, verify.rs).
-- owner_user_id: the admin/owner who created the invite (set in create_invite).
-- invite_token: the redeem→verify bridge; used_by is filled in once verify creates the user.

ALTER TABLE invite_tokens ADD COLUMN owner_user_id TEXT REFERENCES users(id);
ALTER TABLE verification_codes ADD COLUMN invite_token TEXT;
