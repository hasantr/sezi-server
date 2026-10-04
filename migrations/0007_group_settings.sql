-- Sezgi: the group SETTINGS BAG (the protocol substrate).
--
-- The first step in turning groups from a fixed feature into a FLEXIBLE substrate: room
-- settings come in two layers.
--   1. SERVER columns — settings the server has to ACT on (it reads them and changes its
--      behaviour; the directory / auto-join):
--        visibility  : 'private' | 'public' (visibility in the member directory)
--        auto_join   : 0 | 1 (a new server member joins automatically)
--   2. The CLIENT JSON bag — everything the server does not care about and only the client
--      or its plugins read (theme, plugin config, ordering…). An opaque blob; the server
--      only stores it. A new feature = a new key, and the SCHEMA DOES NOT CHANGE.
--        settings_json : TEXT (NULL = an empty bag)
--
-- E2E is preserved: settings are NOT content (they are membership metadata). This step only
-- lays the pipe (read/write); the directory and the verify hook that consume
-- visibility/auto_join come later.

ALTER TABLE groups ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private';
ALTER TABLE groups ADD COLUMN auto_join INTEGER NOT NULL DEFAULT 0;
ALTER TABLE groups ADD COLUMN settings_json TEXT;
