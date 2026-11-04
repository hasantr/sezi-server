-- 0039: ownership comes from redeeming the genesis invite, not from an empty `users` table.
--
-- Until now `auth/verify.rs` made whoever registered first the owner (`SELECT id FROM users
-- LIMIT 1` came back empty). That coincided with "whoever redeemed the genesis invite" only
-- because a fresh invite_only server has no other token. Anything that let a different
-- registration reach an empty `users` table — open join mode, a removed admin's leftover invite,
-- a future multi-use invite — handed the server to it.
--
-- The redeem claim (`auth/invite_attribution.rs` `CLAIM_INVITE_SQL`) now records, in the same
-- statement that wins the claim, whether the invite it claimed was the genesis invite, and verify
-- grants `owner` from that record alone. It is a column of its own rather than a reading of
-- `inviter_user_id IS NULL`, because that column is not stable: removing the inviter clears it
-- (`membership.rs`, and the foreign key's ON DELETE SET NULL), so an ordinary invite whose minter
-- was removed between redeem and verify would read as the genesis one.
ALTER TABLE invite_attributions ADD COLUMN genesis INTEGER NOT NULL DEFAULT 0;

-- Existing rows default to 0, which is right for every row but one kind: a genesis claim redeemed
-- before this migration and verified after it. Such a claim is still in flight — it has a
-- verification_codes row pointing at it — and, never having had an inviter, carries no
-- inviter_user_id. Mark exactly those, so a server being claimed during the upgrade still gets
-- its owner. (A removed admin's invite in the same state is marked too; the one-owner index then
-- refuses it at verify, which is the outcome that invite should have had anyway.)
UPDATE invite_attributions SET genesis = 1
 WHERE verified_at IS NULL
   AND inviter_user_id IS NULL
   AND invite_token_hash IN (
     SELECT invite_token_hash FROM verification_codes WHERE invite_token_hash IS NOT NULL
   );
