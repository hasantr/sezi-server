-- 0027: server_plugin_policy — the server-wide plugin availability policy.
--
-- From the server-administration screen in the client, an owner/admin marks a plugin
-- UNAVAILABLE (DISABLED) across the whole server. Everything is ENABLED by DEFAULT → only the
-- DISABLED plugins hold a row here (the existence of a row = disabled). An empty table =
-- everything is on.
--
-- In a one-server-one-database architecture no server_id column is NEEDED (the
-- server_config/server_settings pattern: the table is the state of the single server).
-- Read: GET /plugin-policy (ANY active member → it filters the client's picker).
-- Write: POST /admin/plugin-policy (require_admin: admin|owner).

CREATE TABLE IF NOT EXISTS server_plugin_policy (
  plugin_id   TEXT PRIMARY KEY,
  disabled_at INTEGER NOT NULL
);
