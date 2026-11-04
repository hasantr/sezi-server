-- D8 review F6 (2026-10-13): revoking a device now deletes its push token in the same batch
-- (`PUT /devices/list`). Tokens of devices revoked BEFORE that change are deleted here once, so a
-- device-blind wake can no longer reach a phone its owner removed.
DELETE FROM push_tokens
WHERE EXISTS (
    SELECT 1 FROM devices d
    WHERE d.user_id = push_tokens.user_id
      AND d.device_id = push_tokens.device_id
      AND d.revoked_at IS NOT NULL
);
