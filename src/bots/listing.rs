//! `GET /bots` — the server's enabled bots, for any active member (docs/BOTS_BUILD.md §2.5).
//!
//! `{bots:[{bot_id, name, about, builtin, ai_provider, ai_geo, commands}]}`. A client keeps this to
//! tell a bot from a person (its own section, the "Bot" label, no E2E chip). `commands` is `[]`
//! until `setCommands` (Phase 4) gives a bot any. Nothing about the program is here — whether it
//! answers, its webhook — that is the owner's (`GET /admin/bots`). `ai_provider` is there for the
//! bot chat's disclosure chip: an AI bot's members are told which provider their words go to.
//! `ai_geo` (`us` | `global` | null) says where that provider runs the model, for a hearing bot
//! that sets it (docs/HEARINGS_BOT_PLAN.md §8.3: "(Anthropic, ABD)").

use crate::auth::middleware::require_active_auth;
use serde::{Deserialize, Serialize};
use worker::*;

/// Enabled, not deleted, in creation order.
pub(crate) const LIST_SQL: &str = "SELECT bot_id, name, about, builtin, ai_provider, ai_geo FROM bots
      WHERE deleted_at IS NULL AND disabled_at IS NULL ORDER BY created_at, bot_id";

#[derive(Deserialize, Serialize)]
pub(crate) struct ListedBot {
    pub(crate) bot_id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) about: Option<String>,
    #[serde(default)]
    pub(crate) builtin: Option<String>,
    #[serde(default)]
    pub(crate) ai_provider: Option<String>,
    #[serde(default)]
    pub(crate) ai_geo: Option<String>,
}

pub async fn list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = require_active_auth(&req, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let rows: Vec<ListedBot> = db.prepare(LIST_SQL).all().await?.results()?;
    let bots: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|b| {
            serde_json::json!({
                "bot_id": b.bot_id,
                "name": b.name,
                "about": b.about,
                "builtin": b.builtin,
                "ai_provider": b.ai_provider,
                "ai_geo": b.ai_geo,
                "commands": [],
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "bots": bots }))
}
