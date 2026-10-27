-- Where a built-in bot's model runs, for the members' listing (docs/HEARINGS_BOT_PLAN.md §8.3):
-- a hearing bot calling Anthropic says its `inference_geo` (`us` / `global`), so its members
-- read "(Anthropic, ABD)". NULL for every other bot, and whenever no model is called.
ALTER TABLE bots ADD COLUMN ai_geo TEXT;
