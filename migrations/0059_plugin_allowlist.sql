-- 0059: THE OWNER'S PLUGIN ALLOWLIST (docs/PLUGINS_BOTS_REVIEW_2026_11.md § 3.5, Wave C3;
-- decision D1). One row per app or publisher the server owner approved; the mode that says whether
-- the list is in force (`open` | `allowlist`) is a `server_config` key, `plugin_policy_mode`
-- (`plugin_allowlist.rs`).
--
-- A row approves EITHER a publisher's Ed25519 key — every app it signs (`app_id` NULL) or one app
-- id of it — OR one exact bundle by the BLAKE3 of its plaintext code (`code_hash`, the vodozemac
-- base64 the install wire carries), each up to `max_caps` (a JSON array of capability names). The
-- rule is `sezi_plugin_fmt::allowlist`, which every member's core applies too.
--
-- Expand-only: a new table, read by nothing older. A relay rolled back to a build without it keeps
-- the rows and the mode key untouched and runs `open`, as it did before.
CREATE TABLE IF NOT EXISTS plugin_allowlist (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  publisher_key TEXT,                        -- `ed25519:` + base64url, or NULL for a hash row
  app_id        TEXT,                        -- `ext:<publisher>/<name>`, NULL = every app of the key
  code_hash     TEXT,                        -- BLAKE3 of the plaintext code, or NULL for a key row
  max_caps      TEXT NOT NULL DEFAULT '[]',  -- JSON array of capability names
  label         TEXT NOT NULL DEFAULT '',
  added_by      TEXT NOT NULL,               -- the owner's user id
  added_at      INTEGER NOT NULL             -- ms
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_plugin_allowlist_rule
  ON plugin_allowlist (COALESCE(publisher_key, ''), COALESCE(app_id, ''), COALESCE(code_hash, ''));
