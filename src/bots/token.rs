//! A bot program's key (docs/BOTS_BUILD.md §2.5).
//!
//! `sezibot_<bot_id>_<43-char b64url secret>`. The bot id travels inside the token so a lookup
//! is one primary-key read on the hash — no prefix search, no scan. Only the sha256 hex of the
//! WHOLE token is stored (`bot_tokens`, the shape of `refresh_tokens`); the token is shown once.
//!
//! The token goes in `Authorization: Bearer`, never in a URL: URLs are logged (`lib.rs`).

use crate::auth::hashing::sha256_hex;
use crate::d1util::d1_text;
use crate::utils::{b64u_encode, random_bytes};
use serde::Deserialize;
use worker::*;

pub(crate) const PREFIX: &str = "sezibot_";
/// 32 random bytes, b64url without padding.
const SECRET_LEN: usize = 43;

/// A fresh token for `bot_id`.
pub(crate) fn mint(bot_id: &str) -> String {
    format!("{PREFIX}{bot_id}_{}", b64u_encode(&random_bytes(32)))
}

/// The bot id inside a well-formed token, or `None`. The id is a UUID (hex and `-`, never `_`),
/// so the first `_` after the prefix ends it; the secret itself may contain `_`.
pub(crate) fn parse(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(PREFIX)?;
    let (bot_id, secret) = rest.split_once('_')?;
    let id_ok = bot_id.len() == 36
        && bot_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    let secret_ok = secret.len() == SECRET_LEN
        && secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    (id_ok && secret_ok).then_some(bot_id)
}

/// What `bot_tokens.token_hash` holds for a token.
pub(crate) fn hash(token: &str) -> String {
    sha256_hex(token)
}

/// The bot behind a live token: the hash matches, the token is not revoked, it belongs to the
/// bot id it names, and the bot is not deleted. A DISABLED bot is still returned — the caller
/// answers `bot/disabled`, which is a different thing from a wrong key. Bind order: hash, bot_id.
pub(crate) const TOKEN_LOOKUP_SQL: &str = "SELECT b.bot_id, b.name, b.about, b.disabled_at
       FROM bot_tokens t JOIN bots b ON b.bot_id = t.bot_id
      WHERE t.token_hash = ?1 AND t.bot_id = ?2
        AND t.revoked_at IS NULL AND b.deleted_at IS NULL
      LIMIT 1";

/// Every live token of a bot stops at once (renewal, delete). Bind order: bot_id, now.
pub(crate) const REVOKE_TOKENS_SQL: &str =
    "UPDATE bot_tokens SET revoked_at = ?2 WHERE bot_id = ?1 AND revoked_at IS NULL";

/// Bind order: hash, bot_id, now.
pub(crate) const INSERT_TOKEN_SQL: &str =
    "INSERT INTO bot_tokens (token_hash, bot_id, created_at, revoked_at) VALUES (?1, ?2, ?3, NULL)";

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct BotAuth {
    pub(crate) bot_id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) about: Option<String>,
    #[serde(default)]
    pub(crate) disabled_at: Option<i64>,
}

/// The bearer token's bot, or `None` for a missing, malformed, unknown or revoked key.
pub(crate) async fn authenticate(req: &Request, db: &D1Database) -> Result<Option<BotAuth>> {
    let Some(token) = crate::auth::middleware::extract_bearer(req) else {
        return Ok(None);
    };
    let Some(bot_id) = parse(&token) else {
        return Ok(None);
    };
    db.prepare(TOKEN_LOOKUP_SQL)
        .bind(&[d1_text(&hash(&token)), d1_text(bot_id)])?
        .first(None)
        .await
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
