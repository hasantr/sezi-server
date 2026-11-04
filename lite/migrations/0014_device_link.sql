-- The QR link flow — cryptographically binding a second device to the primary.
--
-- `link_requests` = a short-lived (TTL ~60s), single-use linking request:
--   1) The new device sends its ed/x pub + device_id + a PoP signature with `link-start` →
--      the server produces a `link_code` (pre-auth; user_id is still NULL).
--   2) The primary scans the QR → signs the new list (rev+1) → `link-approve`
--      (primary-authenticated) → the server cross-checks, stores the list atomically, issues
--      a (user,device) token and writes `access_token`/`refresh_token` onto the row
--      (status=approved).
--   3) The new device polls `link-status` (with an ed-signed proof) → once approved it
--      collects the token EXACTLY ONCE (status=consumed → the row is deleted immediately).
--
-- Security: the tokens sit in plaintext only inside the approve→consume window (a short
-- TTL); consuming deletes the row. The cleanup cron also clears expired ones.
CREATE TABLE link_requests (
  link_code      TEXT PRIMARY KEY,         -- b64u(random 32) — high entropy, single use
  user_id        TEXT,                     -- NULL until approve (link-start pre-auth)
  new_ed_pub     BLOB NOT NULL,            -- the Ed25519 pub of the device being linked (32B)
  new_x_pub      BLOB NOT NULL,            -- the Curve25519 pub of the device being linked (32B)
  new_device_id  TEXT NOT NULL,            -- 16 hex (the new device's claim; cross-checked)
  label          TEXT,
  status         TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected (consume = DELETE the row; 'consumed' is NOT persisted)
  reason         TEXT,                     -- the reason for a rejection (forward-compat)
  access_token   TEXT,                     -- issued on approve, handed over EXACTLY ONCE on consume
  refresh_token  TEXT,                     -- plaintext, single shot (handed over on consume, then the row is deleted)
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);

CREATE INDEX idx_link_requests_expiry ON link_requests (expires_at);
