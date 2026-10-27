//! What the owner may set for the hearing-minutes bot (`kind: "hearings"`,
//! docs/HEARINGS_BOT_PLAN.md §6.1, decisions 2–4 of §10), checked here before it reaches the
//! bot's inbox. Pure, beside `builtin_rules.rs`, whose URL rule and key check it reuses.
//!
//! ```json
//! {"kind": "hearings", "lang": "tr",
//!  "hearings": {"ai": true, "provider": "anthropic", "model": "claude-sonnet-5-5", "api_key": "…?",
//!               "base_url": null, "inference_geo": "us",
//!               "sheet": {"url": "https://script.google.com/macros/s/…/exec"},
//!               "columns": {"court": "Mahkeme", "esas": "Esas No", …},
//!               "allowed_room": "<room_id>", "criminal_ai": false, "audit_days": 180,
//!               "daily_calls": 300}}
//! ```
//!
//! - **`allowed_room` is required** (decision 2): only active members of that room may use the
//!   bot. The route checks the room exists; the round checks the member at every use.
//! - **Providers are called direct** (§5.1): an OpenRouter address is refused, and so is the
//!   OpenAI dialect with no address of its own (its default IS OpenRouter). A LAN model (decision
//!   4's alternative) is reachable only under the lab's escape, as for every built-in bot.
//! - **`ai: false`** is a rule-only bot: no model, no key needed.
//! - **`inference_geo`** is Anthropic's (`us`, the default, or `global`); the OpenAI dialect has
//!   no such field and ignores it.
//! - **`daily_calls`** bounds the bot's model calls a (UTC) day, every member together
//!   ([`DEFAULT_DAILY_CALLS`]); past it a record is answered by the rules alone. Each member's
//!   own 50 a day still holds under it.

use super::builtin_rules::{key_ok, outbound_url, Lang, Provider, SheetIn};
use serde::{Deserialize, Serialize};

/// The model when the owner names none (decision 4).
pub(crate) const DEFAULT_MODEL: &str = "claude-sonnet-5-5";
/// The audit rows' keep when the owner says nothing (§8.2), and its bounds.
pub(crate) const DEFAULT_AUDIT_DAYS: u32 = 180;
const AUDIT_DAYS: std::ops::RangeInclusive<u32> = 1..=730;
/// The bot's model calls a day, every member together, when the owner says nothing.
///
/// Without it the owner's spend grew with the office: 50 calls a member a day, each up to ~60k
/// tokens in and up to 32k out, thinking included (`hearings_prompt::ANTHROPIC_MAX_OUTPUT_TOKENS`;
/// a ceiling — at `medium` effort a call uses a fraction of it). 300 covers an office of 20–30
/// lawyers each reading ten or so records a working day, and bounds the worst day at about 18M
/// tokens in and 9.6M out, whatever the number of members.
pub(crate) const DEFAULT_DAILY_CALLS: u32 = 300;
/// What the owner may set it to. Past 2,000 (forty members at their own 50) the bound means
/// little, and a typed 30000 is likelier a slip than a plan.
const DAILY_CALLS: std::ops::RangeInclusive<u32> = 1..=2000;
/// A column name, at most (the sheet's own cap, `builtin_sheet::MAX_COLUMN_CHARS`).
const MAX_COLUMN_CHARS: usize = 64;
/// A room id, at most.
const MAX_ROOM_ID: usize = 64;
const MAX_MODEL_CHARS: usize = 128;

/// Where Anthropic runs the inference (`inference_geo`, §5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Geo {
    #[default]
    Us,
    Global,
}

impl Geo {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Geo::Us => "us",
            Geo::Global => "global",
        }
    }
}

/// `hearings` in the owner's PUT, as sent.
#[derive(Deserialize, Default)]
pub(crate) struct HearingsIn {
    #[serde(default)]
    pub(crate) ai: Option<bool>,
    #[serde(default)]
    pub(crate) provider: Option<Provider>,
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    /// Absent keeps the stored one (for the same service).
    #[serde(default)]
    pub(crate) api_key: Option<String>,
    #[serde(default)]
    pub(crate) inference_geo: Option<String>,
    #[serde(default)]
    pub(crate) sheet: Option<SheetIn>,
    #[serde(default)]
    pub(crate) columns: Option<ColumnsIn>,
    #[serde(default)]
    pub(crate) allowed_room: Option<String>,
    #[serde(default)]
    pub(crate) criminal_ai: bool,
    #[serde(default)]
    pub(crate) audit_days: Option<u32>,
    #[serde(default)]
    pub(crate) daily_calls: Option<u32>,
}

/// The sheet's column names, each optional (the bot's language names the rest).
#[derive(Deserialize, Default)]
pub(crate) struct ColumnsIn {
    #[serde(default)]
    court: Option<String>,
    #[serde(default)]
    esas: Option<String>,
    #[serde(default)]
    hearing: Option<String>,
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    decisions: Option<String>,
    #[serde(default)]
    lawyer: Option<String>,
    #[serde(default)]
    updated: Option<String>,
}

/// The office sheet's columns the bot writes. `court` + `esas` are the row's key (§6.3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Columns {
    pub(crate) court: String,
    pub(crate) esas: String,
    pub(crate) hearing: String,
    pub(crate) next: String,
    pub(crate) decisions: String,
    pub(crate) lawyer: String,
    pub(crate) updated: String,
}

impl Columns {
    /// The plan's names, in the bot's language.
    pub(crate) fn defaults(lang: Lang) -> Self {
        let n = |tr: &str, en: &str| if lang == Lang::Tr { tr } else { en }.to_string();
        Columns {
            court: n("Mahkeme", "Court"),
            esas: n("Esas No", "Case No"),
            hearing: n("Duruşma Tarihi", "Hearing Date"),
            next: n("Sonraki Duruşma", "Next Hearing"),
            decisions: n("Ara Karar", "Interim Decisions"),
            lawyer: n("Avukat", "Lawyer"),
            updated: n("Güncelleme", "Updated"),
        }
    }

    fn all(&self) -> [&str; 7] {
        [&self.court, &self.esas, &self.hearing, &self.next, &self.decisions, &self.lawyer, &self.updated]
    }
}

/// What the bot's inbox keeps for the hearings kind (no key: that is its own `bot_kv` row).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct HearingsConfig {
    /// `false` = rule-only: no model at all.
    pub(crate) ai: bool,
    pub(crate) provider: Provider,
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    pub(crate) model: String,
    #[serde(default)]
    pub(crate) inference_geo: Geo,
    pub(crate) columns: Columns,
    /// The room whose active members may use the bot (decision 2).
    pub(crate) allowed_room: String,
    /// Criminal records go to the model too (decision 3 says no: default `false`).
    #[serde(default)]
    pub(crate) criminal_ai: bool,
    pub(crate) audit_days: u32,
    /// Model calls a day for the whole bot ([`DEFAULT_DAILY_CALLS`] for a configuration stored
    /// before the setting existed).
    #[serde(default = "default_daily_calls")]
    pub(crate) daily_calls: u32,
}

fn default_daily_calls() -> u32 {
    DEFAULT_DAILY_CALLS
}

impl HearingsConfig {
    pub(crate) fn to_owner_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ai": self.ai,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "inference_geo": self.inference_geo,
            "columns": self.columns,
            "allowed_room": self.allowed_room,
            "criminal_ai": self.criminal_ai,
            "audit_days": self.audit_days,
            "daily_calls": self.daily_calls,
        })
    }
}

/// A checked `hearings` object: the configuration, the sheet's address, and a new key.
#[derive(Debug, PartialEq)]
pub(crate) struct CheckedHearings {
    pub(crate) config: HearingsConfig,
    pub(crate) sheet_url: Option<String>,
    pub(crate) api_key: Option<String>,
}

/// Check the hearings kind's set. `top_sheet` is a top-level `sheet` (the other kinds' place for
/// it), used when `hearings.sheet` is absent. The error is the route's 400 code.
pub(crate) fn validate(
    h: Option<HearingsIn>,
    top_sheet: Option<SheetIn>,
    lang: Lang,
    allow_lan: bool,
) -> Result<CheckedHearings, &'static str> {
    let h = h.ok_or("builtin/hearings")?;
    let sheet_url = match h.sheet.or(top_sheet) {
        Some(s) if !s.url.trim().is_empty() => {
            Some(outbound_url(&s.url, allow_lan).ok_or("builtin/sheet-url")?.to_string())
        }
        _ => None,
    };
    let api_key = match h.api_key.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(k) if key_ok(k) => Some(k.to_string()),
        Some(_) => return Err("builtin/ai-key"),
    };
    // Anthropic unless said otherwise (decision 4), or unless the key says otherwise.
    let provider = h
        .provider
        .or_else(|| api_key.as_deref().and_then(Provider::for_key))
        .unwrap_or(Provider::Anthropic);
    let base_url = match h.base_url.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => {
            let url = outbound_url(raw, allow_lan).ok_or("builtin/ai-base-url")?;
            Some(url.as_str().trim_end_matches('/').to_string())
        }
    };
    if !direct(provider, base_url.as_deref()) {
        return Err("builtin/hearings-provider");
    }
    let model = h.model.as_deref().map(str::trim).filter(|m| !m.is_empty()).unwrap_or(DEFAULT_MODEL);
    if model.chars().count() > MAX_MODEL_CHARS || model.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("builtin/ai-model");
    }
    let inference_geo = match h.inference_geo.as_deref().map(str::trim) {
        None | Some("") | Some("us") => Geo::Us,
        Some("global") => Geo::Global,
        Some(_) => return Err("builtin/hearings-geo"),
    };
    let columns = columns(h.columns.unwrap_or_default(), lang)?;
    let allowed_room = h.allowed_room.as_deref().map(str::trim).unwrap_or("");
    let room_ok = !allowed_room.is_empty()
        && allowed_room.len() <= MAX_ROOM_ID
        && allowed_room.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !room_ok {
        return Err("builtin/hearings-room");
    }
    let audit_days = h.audit_days.unwrap_or(DEFAULT_AUDIT_DAYS);
    if !AUDIT_DAYS.contains(&audit_days) {
        return Err("builtin/hearings-audit-days");
    }
    let daily_calls = h.daily_calls.unwrap_or(DEFAULT_DAILY_CALLS);
    if !DAILY_CALLS.contains(&daily_calls) {
        return Err("builtin/hearings-daily-calls");
    }
    let config = HearingsConfig {
        ai: h.ai.unwrap_or(true),
        provider,
        base_url,
        model: model.to_string(),
        inference_geo,
        columns,
        allowed_room: allowed_room.to_string(),
        criminal_ai: h.criminal_ai,
        audit_days,
        daily_calls,
    };
    Ok(CheckedHearings { config, sheet_url, api_key })
}

/// Is this a direct call to a provider (§5.1)? OpenRouter adds a second company in the path,
/// and the OpenAI dialect's default address is OpenRouter's.
fn direct(provider: Provider, base_url: Option<&str>) -> bool {
    let host = |u: &str| worker::Url::parse(u).ok().and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    match (provider, base_url) {
        (Provider::Openai, None) => false,
        (_, Some(u)) => host(u).is_some_and(|h| h != "openrouter.ai" && !h.ends_with(".openrouter.ai")),
        (Provider::Anthropic, None) => true,
    }
}

fn columns(c: ColumnsIn, lang: Lang) -> Result<Columns, &'static str> {
    let d = Columns::defaults(lang);
    let pick = |v: Option<String>, def: String| -> Result<String, &'static str> {
        let v = v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or(def);
        let ok = v.chars().count() <= MAX_COLUMN_CHARS && !v.chars().any(char::is_control);
        ok.then_some(v).ok_or("builtin/hearings-columns")
    };
    let out = Columns {
        court: pick(c.court, d.court)?,
        esas: pick(c.esas, d.esas)?,
        hearing: pick(c.hearing, d.hearing)?,
        next: pick(c.next, d.next)?,
        decisions: pick(c.decisions, d.decisions)?,
        lawyer: pick(c.lawyer, d.lawyer)?,
        updated: pick(c.updated, d.updated)?,
    };
    // Two columns of one name would write one cell twice; the script matches names without case.
    let mut seen: Vec<String> = out.all().iter().map(|n| n.to_lowercase()).collect();
    seen.sort();
    seen.dedup();
    if seen.len() != 7 {
        return Err("builtin/hearings-columns");
    }
    Ok(out)
}

#[cfg(test)]
#[path = "builtin_hearings_rules_tests.rs"]
mod tests;
