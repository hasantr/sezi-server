-- 0017: the device-list rev HIGH WATER — the revoke-resurrection fix.
--
-- The problem: if the `device_lists` row is lost to D1 churn, an old primary-signed doc (from
-- before the deletion, carrying no tombstone) would be accepted as a fresh insert, and the
-- active-device upsert could resurrect a REMOVED device with `revoked_at=NULL`. A tombstone
-- only protects when the restoring doc CARRIES it, and a stale pre-deletion doc does not.
--
-- The fix: `users.device_list_rev` = the highest device-list rev ever SEEN for this user, a
-- column INDEPENDENT of the `device_lists` blob, so it survives the loss of that row. The
-- worker's `validate_and_store_signed_list` now rejects a PUT whose `doc.rev <
-- device_list_rev` (stale → the resurrection is blocked) and the winning writer advances the
-- high water with MAX. An EQUAL rev (== high_water) is allowed so a RESTORE still works (the
-- signature is already verified = it really is the newest doc).
--
-- Backfill: start from the existing device_lists.rev so the deploy-moment window is zero.
-- Without it the high water starts at 0 and catches up on the first PUT — still safe, but the
-- backfill is cleaner.

ALTER TABLE users ADD COLUMN device_list_rev INTEGER NOT NULL DEFAULT 0;

UPDATE users SET device_list_rev = COALESCE(
  (SELECT rev FROM device_lists WHERE device_lists.user_id = users.id),
  0
);
