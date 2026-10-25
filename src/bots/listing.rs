//! `GET /bots` — the server's enabled bots, for any active member (docs/BOTS_BUILD.md §2.5).
//!
//! `{bots:[{bot_id, name, about, builtin, commands}]}`. A client keeps this to tell a bot from a
//! person (its own section, the "Bot" label, no E2E chip). `commands` is `[]` until `setCommands`
//! (Phase 4) gives a bot any. Nothing about the program is here — whether it answers, its
//! webhook — that is the owner's (`GET /admin/bots`).

use crate::auth::middleware::require_active_auth;
use serde::{Deserialize, Serialize};
use worker::*;

/// Enabled, not deleted, in creation order.
pub(crate) const LIST_SQL: &str = "SELECT bot_id, name, about, builtin FROM bots
      WHERE deleted_at IS NULL AND disabled_at IS NULL ORDER BY created_at, bot_id";

#[derive(Deserialize, Serialize)]
pub(crate) struct ListedBot {
    pub(crate) bot_id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) about: Option<String>,
    #[serde(default)]
    pub(crate) builtin: Option<String>,
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
                "commands": [],
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({ "bots": bots }))
}
