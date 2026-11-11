-- 0060: THE SERVER'S APP CATALOG (docs/PLUGINS_BOTS_REVIEW_2026_11.md § 3.4, Wave C5; decision D3).
-- The signed web apps this server's owner put up for group admins to pick from. One row per bundle;
-- the bundle's bytes live in the media store under `apps/<id>.tar` (`app_catalog.rs`), the row says
-- which store holds them.
--
-- `id` is the hex BLAKE3 of the bundle tar (a path segment), `code_hash` the same digest in the
-- vodozemac base64 the install wire and the allowlist's hash rows carry. `manifest` is the
-- `sezi-app.json` the publisher signed, kept so the list needs no store read.
--
-- Expand-only: a new table, read by nothing older. A relay rolled back to a build without it keeps
-- the rows and the objects and serves no catalog; groups that installed from it keep their apps
-- (their code was uploaded to the room like any other).
CREATE TABLE IF NOT EXISTS app_catalog (
  id             TEXT PRIMARY KEY,
  code_hash      TEXT NOT NULL,
  app_id         TEXT NOT NULL,
  name           TEXT NOT NULL,
  version        TEXT NOT NULL,
  publisher_key  TEXT NOT NULL,
  publisher_name TEXT NOT NULL DEFAULT '',
  manifest       TEXT NOT NULL,
  size_bytes     INTEGER NOT NULL,
  store_id       TEXT NOT NULL,
  added_by       TEXT NOT NULL,
  added_at       INTEGER NOT NULL        -- ms
);
CREATE INDEX IF NOT EXISTS ix_app_catalog_app ON app_catalog (app_id);
