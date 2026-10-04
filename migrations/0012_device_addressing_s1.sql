-- Sezgi: multi-device addressing, the FOUNDATION — strictly additive, behaviour UNCHANGED.
--
-- This lays the device_id rails; the OLD WIRE keeps working exactly as before.
-- ONLY NULLABLE columns are added here → an old register/login body (without the new fields)
-- and an old token (without the device_id claim) still verify unchanged.
--
-- one_time_prekeys / signed_prekeys / refresh_tokens : NULL = a legacy/primary device.
--   The column IS WRITTEN at this stage (when the device sends a device_id) but not yet
--   CONSUMED — claim/lookup is still at user_id level (the per-device pool comes later).
-- users.identity_ed_pub : the user's Ed25519 signing pubkey (BLOB). NULL = legacy.
--   Filled in when `identity_ed_pub_b64` arrives on the register/verify path; it feeds the
--   direct-comparison chain of signed device-list verification (§3.3).
--
-- ⚠️ The UNIQUE / PRIMARY KEY definitions DO NOT CHANGE — the move to per-device keying
-- (a new table + a copy) is a later step. This migration only adds columns.

ALTER TABLE one_time_prekeys ADD COLUMN device_id TEXT;  -- NULL = legacy/primary
ALTER TABLE signed_prekeys   ADD COLUMN device_id TEXT;  -- NULL = legacy/primary
ALTER TABLE refresh_tokens   ADD COLUMN device_id TEXT;  -- NULL = legacy/primary
ALTER TABLE users            ADD COLUMN identity_ed_pub BLOB;  -- NULL = legacy
