-- A bot's interface (docs/BOT_APP_PLAN.md): the app catalog entry (the BLAKE3 of a signed bundle,
-- hex) the server's owner linked to the bot. Members' apps open it from the bot's chat; NULL = the
-- bot has none, which every bot before this has. Expand-only: the previous build never reads it.
ALTER TABLE bots ADD COLUMN app_entry TEXT;
