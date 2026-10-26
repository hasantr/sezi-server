//! The built-in bots' rules (docs/BOTS_HELPER_PLAN.md, "Boundaries"): what the owner may set,
//! its limits, and where a built-in bot may send a request. Pure, so both halves use one copy —
//! the owner's route validates with it, the bot's inbox runs by it.
//!
//! **Where a request may go.** Only to the URL / provider the owner set: `https`, a host with a
//! dot in it, and never an IP literal, `localhost`, or a name ending `.localhost`, `.local`,
//! `.internal`, `.lan`, `.home.arpa`, `.localdomain`, `.box`, `.corp` or `.home` — a self-hosted
//! relay sits on someone's LAN, and its fetch reaches whatever that LAN has. The same rule is
//! applied to every redirect hop the sheet follows. It judges NAMES only: a public name that
//! resolves to a private address gets through.
//!
//! **The lab escape.** `BOT_BUILTIN_ALLOW_LAN=1` in the relay's environment lifts the host rule
//! and allows `http`, so the E2E lab can point a bot at a stand-in endpoint on its own network.
//! It is off unless set to exactly `1`; no deployed relay sets it.

use serde::{Deserialize, Serialize};
use worker::Url;

/// The owner's instructions to an AI bot, at most.
pub(crate) const MAX_INSTRUCTIONS_CHARS: usize = 4000;
/// A model id, at most.
const MAX_MODEL_CHARS: usize = 128;
/// A provider key, at most.
const MAX_KEY_CHARS: usize = 512;
/// An outbound URL, at most.
const MAX_URL_LEN: usize = 512;
/// The environment switch that lets the lab reach its own network (module doc).
pub(crate) const ALLOW_LAN_VAR: &str = "BOT_BUILTIN_ALLOW_LAN";

/// What a built-in bot is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    /// Each message becomes a row in the owner's sheet.
    Sheet,
    /// Answers with the owner's model and instructions.
    Ai,
}

impl Kind {
    /// `bots.builtin`'s value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::Sheet => "sheet",
            Kind::Ai => "ai",
        }
    }
}

/// The language the bot itself speaks (its fixed lines; the model answers as instructed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Lang {
    #[default]
    Tr,
    En,
}

/// The two wire dialects (as `core/src/ai.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Provider {
    /// `POST {base}/v1/messages`, `x-api-key`, `anthropic-version`.
    Anthropic,
    /// `POST {base}/chat/completions`, `Authorization: Bearer` — OpenAI, OpenRouter and friends.
    Openai,
}

impl Provider {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Openai => "openai",
        }
    }

    /// Where the service lives when the owner gave no address (`core/src/ai.rs`'s defaults).
    pub(crate) fn default_base_url(self) -> &'static str {
        match self {
            Provider::Anthropic => "https://api.anthropic.com",
            Provider::Openai => "https://openrouter.ai/api/v1",
        }
    }

    /// The service a key visibly belongs to, when its prefix says so beyond doubt
    /// (`ai::provider_for_key`).
    pub(crate) fn for_key(key: &str) -> Option<Self> {
        let k = key.trim();
        if k.starts_with("sk-ant-") {
            Some(Provider::Anthropic)
        } else if k.starts_with("sk-or-") {
            Some(Provider::Openai)
        } else {
            None
        }
    }
}

/// `PUT /admin/bots/:id/builtin`, as sent.
#[derive(Deserialize, Default)]
pub(crate) struct PutBody {
    /// `null` (or absent) returns the bot to "program" mode.
    #[serde(default)]
    pub(crate) kind: Option<Kind>,
    #[serde(default)]
    pub(crate) lang: Option<Lang>,
    #[serde(default)]
    pub(crate) sheet: Option<SheetIn>,
    #[serde(default)]
    pub(crate) ai: Option<AiIn>,
}

#[derive(Deserialize, Default)]
pub(crate) struct SheetIn {
    #[serde(default)]
    pub(crate) url: String,
}

#[derive(Deserialize, Default)]
pub(crate) struct AiIn {
    #[serde(default)]
    pub(crate) provider: Option<Provider>,
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    #[serde(default)]
    pub(crate) model: String,
    /// Absent keeps the stored one.
    #[serde(default)]
    pub(crate) api_key: Option<String>,
    #[serde(default)]
    pub(crate) instructions: String,
    #[serde(default)]
    pub(crate) sheet_tool: bool,
}

/// What the bot's inbox keeps (`bot_kv` `builtin`). No key and no secret are in it: those are
/// their own `bot_kv` rows, so this one can be answered back to the owner whole.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Config {
    pub(crate) kind: Kind,
    pub(crate) lang: Lang,
    /// The sheet's `/exec` address: the sheet bot's, or the AI bot's when it writes rows.
    #[serde(default)]
    pub(crate) sheet_url: Option<String>,
    #[serde(default)]
    pub(crate) ai: Option<AiConfig>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct AiConfig {
    pub(crate) provider: Provider,
    /// `None` = the provider's default address.
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    pub(crate) model: String,
    pub(crate) instructions: String,
    #[serde(default)]
    pub(crate) sheet_tool: bool,
}

impl Config {
    /// Is this bot meant to write to a sheet (and so needs a sheet secret)? True before the
    /// sheet is connected: the helper hands the script (with the secret) over first, and the
    /// `/exec` address exists only once the owner has deployed it.
    pub(crate) fn wants_sheet(&self) -> bool {
        self.kind == Kind::Sheet || self.ai.as_ref().is_some_and(|a| a.sheet_tool)
    }

    /// Does this bot write to a sheet NOW — meant to, and its address set?
    pub(crate) fn writes_sheet(&self) -> bool {
        self.wants_sheet() && self.sheet_url.is_some()
    }

    /// Meant to write to a sheet whose address is not set yet ("not connected").
    pub(crate) fn sheet_not_connected(&self) -> bool {
        self.wants_sheet() && self.sheet_url.is_none()
    }

    /// The configuration as the owner's `GET /admin/bots/:id/builtin` answers it.
    pub(crate) fn to_owner_json(&self, has_api_key: bool) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind,
            "lang": self.lang,
            "sheet": self.wants_sheet().then(|| serde_json::json!({ "url": self.sheet_url })),
            "ai": self.ai.as_ref().map(|a| serde_json::json!({
                "provider": a.provider,
                "base_url": a.base_url,
                "model": a.model,
                "instructions": a.instructions,
                "sheet_tool": a.sheet_tool,
            })),
            "has_api_key": has_api_key,
        })
    }
}

/// A checked PUT: the configuration (`None` = program mode) and a new key, if one was sent.
#[derive(Debug, PartialEq)]
pub(crate) struct Checked {
    pub(crate) config: Option<Config>,
    pub(crate) api_key: Option<String>,
}

/// Check the owner's PUT. The error is the code the route answers with (HTTP 400).
pub(crate) fn validate(body: PutBody, allow_lan: bool) -> Result<Checked, &'static str> {
    let Some(kind) = body.kind else {
        return Ok(Checked { config: None, api_key: None });
    };
    let lang = body.lang.unwrap_or_default();
    let sheet_url = match &body.sheet {
        Some(s) if !s.url.trim().is_empty() => {
            Some(outbound_url(&s.url, allow_lan).ok_or("builtin/sheet-url")?.to_string())
        }
        _ => None,
    };
    match kind {
        Kind::Sheet => {
            // No address yet is "not connected": the secret comes first (`wants_sheet`).
            let config = Config { kind, lang, sheet_url, ai: None };
            Ok(Checked { config: Some(config), api_key: None })
        }
        Kind::Ai => {
            let ai = body.ai.ok_or("builtin/ai")?;
            let api_key = match ai.api_key.as_deref().map(str::trim) {
                None | Some("") => None,
                Some(k) if key_ok(k) => Some(k.to_string()),
                Some(_) => return Err("builtin/ai-key"),
            };
            let provider = ai
                .provider
                .or_else(|| api_key.as_deref().and_then(Provider::for_key))
                .ok_or("builtin/ai-provider")?;
            let base_url = match ai.base_url.as_deref().map(str::trim) {
                None | Some("") => None,
                Some(raw) => {
                    let url = outbound_url(raw, allow_lan).ok_or("builtin/ai-base-url")?;
                    Some(url.as_str().trim_end_matches('/').to_string())
                }
            };
            let model = ai.model.trim();
            let model_ok = !model.is_empty()
                && model.chars().count() <= MAX_MODEL_CHARS
                && !model.chars().any(|c| c.is_whitespace() || c.is_control());
            if !model_ok {
                return Err("builtin/ai-model");
            }
            let instructions = ai.instructions.trim();
            if instructions.is_empty() || instructions.chars().count() > MAX_INSTRUCTIONS_CHARS {
                return Err("builtin/ai-instructions");
            }
            let config = Config {
                kind,
                lang,
                // A sheet address sent without `sheet_tool` is not kept: only a writing bot
                // has any use for it.
                sheet_url: sheet_url.filter(|_| ai.sheet_tool),
                ai: Some(AiConfig {
                    provider,
                    base_url,
                    model: model.to_string(),
                    instructions: instructions.to_string(),
                    sheet_tool: ai.sheet_tool,
                }),
            };
            Ok(Checked { config: Some(config), api_key })
        }
    }
}

/// A key that can travel in a header: printable ASCII, no spaces, at most 512.
fn key_ok(k: &str) -> bool {
    !k.is_empty() && k.len() <= MAX_KEY_CHARS && k.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// Is `host` one a built-in bot may never reach (module doc)? `host` is a domain name; IP
/// literals are refused by the caller from the parsed URL.
fn private_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost" || !h.contains('.') || PRIVATE_SUFFIXES.iter().any(|s| h.ends_with(s))
}

/// Name endings that only ever mean a private network: RFC 6762's `.local`, RFC 8375's
/// `.home.arpa`, and what routers and offices use (`fritz.box`, `.localdomain`, `.corp`, `.home`).
/// A name is all this checks: a public name that RESOLVES to a private address is not caught
/// here (the relay's fetch resolves it; the Worker cannot see the address first).
const PRIVATE_SUFFIXES: [&str; 9] =
    [".localhost", ".local", ".internal", ".lan", ".home.arpa", ".localdomain", ".box", ".corp", ".home"];

/// Does a stored key still belong with `new`? Only while the provider and address it was given
/// for are unchanged: otherwise a key for one service would be sent to another.
pub(crate) fn key_follows(old: Option<&AiConfig>, new: &AiConfig) -> bool {
    old.is_some_and(|o| o.provider == new.provider && o.base_url == new.base_url)
}

/// The URL, when a built-in bot may send a request to it; else `None`.
pub(crate) fn outbound_url(raw: &str, allow_lan: bool) -> Option<Url> {
    let raw = raw.trim();
    if raw.len() > MAX_URL_LEN {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    let scheme_ok = url.scheme() == "https" || (allow_lan && url.scheme() == "http");
    if !scheme_ok || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return None;
    }
    let host = url.host_str().filter(|h| !h.is_empty())?;
    // The URL parser writes every IPv4 spelling (`0x7f.1`, `2130706433`) as a dotted quad and an
    // IPv6 literal in brackets, so these two tests see every IP literal.
    let ip_literal = host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok();
    let host_ok = allow_lan || (!ip_literal && !private_name(host));
    host_ok.then_some(url)
}

/// Is the lab escape on in this environment?
pub(crate) fn allow_lan(env: &worker::Env) -> bool {
    crate::utils::env_text(env, ALLOW_LAN_VAR).as_deref() == Some("1")
}

#[cfg(test)]
#[path = "builtin_rules_tests.rs"]
mod tests;
