-- 0025: server_config — the self-provisioning key store (self-hosting).
--
-- A generic key-value table: the `jwt_signing_key` (Ed25519 PKCS8 PEM) and
-- `admin_invite_key` (b64url 32B) rows. On a fresh fork's first boot the worker GENERATES
-- the keys and persists them here (src/self_provision.rs) — so a user who has never heard of
-- `wrangler secret put` still gets a working server.
--
-- SECURITY NOTE: the values sit in D1 at rest (CF disk-encrypted) — the honest-server model of
-- self-hosting. An env secret ALWAYS wins when one is present (a security-conscious owner can
-- move the key into a secret, and then this table is never used at all).
-- These values are returned from NO endpoint (they are read and written inside the worker only).

CREATE TABLE IF NOT EXISTS server_config (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
