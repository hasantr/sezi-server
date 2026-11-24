-- A bot's commands (bot API 1.6 `setMyCommands`): the program's own list, as a JSON array of
-- {command, description, app?} the relay checked (bots/commands.rs). Members' apps get it on
-- `GET /bots` and show it under the chat's Menü and "/". NULL = the bot set none, which every bot
-- before this has. Expand-only: the previous build never reads it.
ALTER TABLE bots ADD COLUMN commands_json TEXT;
