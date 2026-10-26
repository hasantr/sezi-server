-- A built-in bot's provider, for the members' listing (docs/BOTS_HELPER_PLAN.md): an AI bot's
-- chat tells its members which provider their words go to. `bots.builtin` already says the kind;
-- the configuration and its secrets live in the bot's own inbox, never here.
ALTER TABLE bots ADD COLUMN ai_provider TEXT;
