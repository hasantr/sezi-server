//! The AI bot's model call, in the two dialects `core/src/ai.rs` speaks — Anthropic Messages and
//! the OpenAI-compatible `chat/completions` — re-done here at their minimum, because the relay
//! cannot depend on the core's root crate. Request building, answer reading and the row a model
//! proposes are pure; `call` is the one fetch.
//!
//! **A proposed row.** With "tabloya da yazsın" on, the system prompt asks the model to end its
//! answer with one line `ROW: {"Column": "value", …}` when the member's message holds something
//! to record. The line is cut from what the member sees; the relay asks the member to confirm
//! the row (`builtin_run.rs`) and writes it only on their yes. A text marker rather than tool
//! use, so both dialects share one parser and a model without tool support still works.
//!
//! The limits (docs/BOTS_HELPER_PLAN.md, "Limits on an AI bot"): at most 2,048 output tokens, a
//! member's message cut at 4,000 characters, the member's last 10 turns as context.

use super::builtin_sheet::Row;
use crate::bots::builtin_rules::{outbound_url, AiConfig, Provider};
use worker::*;

/// Output tokens one answer may take, the model's thinking included. Current Claude models think
/// by default when no `thinking` is sent (Haiku 5.5, Sonnet 5.5, Opus 5.5), and those tokens count
/// against `max_tokens`: at 800, Haiku 5.5 spent most of it thinking and cut a 583-character
/// answer off in the middle of its `ROW:` line (lab, 2026-10-26). The answer itself is kept short
/// by the system prompt; this is room for thinking plus that answer.
pub(super) const MAX_OUTPUT_TOKENS: u32 = 2048;
/// A member's message is cut here (characters).
pub(super) const MAX_INPUT_CHARS: usize = 4000;
/// Anthropic's API version header.
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// How long a model may take to answer.
const CALL_TIMEOUT_MS: u64 = 60_000;
/// The marker a proposed row's line starts with.
const ROW_MARKER: &str = "ROW:";

/// Who said a stored message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    User,
    Assistant,
}

impl Role {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }

    pub(super) fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Role::User),
            "assistant" => Some(Role::Assistant),
            _ => None,
        }
    }
}

/// One stored message of a member's conversation with the bot.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Turn {
    pub(super) role: Role,
    pub(super) text: String,
}

/// `text` cut to `n` characters.
pub(super) fn cut(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// The system prompt: who the bot is and who it talks to, the owner's instructions verbatim,
/// and — for a bot that writes rows to a connected sheet (`rows`) — the row protocol. `room` is
/// the group's name when the member called the bot there (everyone in it sees the answer).
/// English, as an instruction to a model.
pub(super) fn system_prompt(
    ai: &AiConfig,
    bot_name: &str,
    member_name: &str,
    room: Option<&str>,
    rows: bool,
    now_ms: i64,
) -> String {
    let setting = match room {
        None => format!("talking one to one with a member named \"{member_name}\""),
        Some(group) => format!(
            "answering a member named \"{member_name}\" who called you in the group \"{group}\"; \
             everyone in the group sees your answer, so write it for them all"
        ),
    };
    let mut s = format!(
        "You are \"{bot_name}\", a bot on a private Sezi messaging server, {setting}. Answer in \
         plain text without Markdown, briefly, in the language of the member's latest message \
         unless the instructions say otherwise. You see only what this member writes to you. \
         {}\n\nThe bot owner's instructions:\n<instructions>\n{}\n</instructions>",
        today_line(now_ms),
        ai.instructions
    );
    if rows {
        // Each sentence below answers a way Haiku went wrong in the lab (2026-10-26): it wrote
        // "yarın" / "Salı" into the Tarih cell, told members to answer "onaylıyorum" (which no one
        // reads), and listed rows long settled as still waiting, or saved rows as never saved.
        s.push_str(
            "\n\nRecording rows: the owner keeps a spreadsheet. When the member's message holds \
             something the instructions say to record, propose ONE row by ending your answer with a \
             single last line of the form\nROW: {\"Column\": \"value\", ...}\nthat is one JSON \
             object on one line, string values, columns named as the instructions name them. Write \
             a relative day (tomorrow, Monday, next week) as the actual date, from today's date \
             above. Sezi shows the member the row and asks them to answer yes or no; do not \
             ask for the confirmation yourself and do not suggest other words for it. When there \
             is nothing to record, write no ROW line.\n\
             How confirmation works: only the row in your latest answer can be confirmed, and only \
             by the member's very next message. Whatever that message is, the row is settled by \
             then: when you are writing, NO row is waiting for confirmation, so never list rows as \
             pending. In the conversation, a member's yes followed by \"Kaydedildi.\" / \"Saved.\" \
             means that row was saved; anything else means it was not. Never claim a row was \
             saved otherwise. You remember only this member's last 10 exchanges from the past \
             day and you cannot see the spreadsheet: about anything older, say you do not know.",
        );
    }
    s
}

/// Today's date as the model is told it ("Today is Monday, 26 October 2026 (UTC)."): without it
/// a model writes "yarın" into a date cell. UTC, because the relay does not know the member's
/// zone; near midnight in Türkiye it can be a day behind, which the model is not told to hide.
pub(super) fn today_line(now_ms: i64) -> String {
    const DAYS: [&str; 7] = ["Thursday", "Friday", "Saturday", "Sunday", "Monday", "Tuesday", "Wednesday"];
    const MONTHS: [&str; 12] = [
        "January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
        "November", "December",
    ];
    let days = now_ms.div_euclid(86_400_000);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let weekday = DAYS[days.rem_euclid(7) as usize];
    format!("Today is {weekday}, {day} {} {year} (UTC).", MONTHS[(month - 1) as usize])
}

/// The full URL to POST to (`ai::endpoint`).
pub(super) fn endpoint(ai: &AiConfig) -> String {
    let base = ai.base_url.as_deref().unwrap_or(ai.provider.default_base_url()).trim_end_matches('/');
    match ai.provider {
        Provider::Anthropic => format!("{base}/v1/messages"),
        Provider::Openai => format!("{base}/chat/completions"),
    }
}

/// The auth and version headers (`ai::auth_headers`).
pub(super) fn auth_headers(provider: Provider, key: &str) -> Vec<(&'static str, String)> {
    match provider {
        Provider::Anthropic => vec![("x-api-key", key.to_string()), ("anthropic-version", ANTHROPIC_VERSION.into())],
        Provider::Openai => vec![("authorization", format!("Bearer {key}"))],
    }
}

/// The request body: the system prompt, the member's earlier turns, then this message.
/// Anthropic takes the system prompt as a top-level field, the OpenAI shape as the first message.
pub(super) fn request_body(ai: &AiConfig, system: &str, history: &[Turn], user: &str) -> serde_json::Value {
    let mut messages: Vec<serde_json::Value> = Vec::with_capacity(history.len() + 2);
    if ai.provider == Provider::Openai {
        messages.push(serde_json::json!({ "role": "system", "content": system }));
    }
    for t in history {
        messages.push(serde_json::json!({ "role": t.role.as_str(), "content": t.text }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": cut(user, MAX_INPUT_CHARS) }));
    match ai.provider {
        Provider::Anthropic => serde_json::json!({
            "model": ai.model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "system": system,
            "messages": messages,
        }),
        Provider::Openai => serde_json::json!({
            "model": ai.model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "messages": messages,
        }),
    }
}

/// The answer's text, or the failure's code (`ai::parse_response`'s codes). `status` 0 = nothing
/// answered. A cut-off answer (the token ceiling) is kept and marked with "…": in a chat a
/// truncated answer still says something, unlike the card the core's parser guards.
pub(super) fn parse_response(provider: Provider, status: u16, body: &str) -> std::result::Result<String, &'static str> {
    match status {
        0 => return Err("ai/unreachable"),
        401 | 403 => return Err("ai/bad-key"),
        404 => return Err("ai/bad-model"),
        429 => return Err("ai/rate-limited"),
        502 | 503 | 529 => return Err("ai/overloaded"),
        s if !(200..300).contains(&s) => return Err("ai/bad-response"),
        _ => {}
    }
    let json: serde_json::Value = serde_json::from_str(body).map_err(|_| "ai/bad-response")?;
    let (text, cut_off) = match provider {
        Provider::Anthropic => {
            let stop = json.get("stop_reason").and_then(|v| v.as_str());
            if stop == Some("refusal") {
                return Err("ai/refused");
            }
            let blocks = json.get("content").and_then(|c| c.as_array()).ok_or("ai/bad-response")?;
            let text: String = blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect();
            (text, stop == Some("max_tokens"))
        }
        Provider::Openai => {
            let choice = json
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|c| c.first())
                .ok_or("ai/bad-response")?;
            let finish = choice.get("finish_reason").and_then(|v| v.as_str());
            if finish == Some("content_filter") {
                return Err("ai/refused");
            }
            let text = choice
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
                .ok_or("ai/bad-response")?
                .to_string();
            (text, finish == Some("length"))
        }
    };
    let text = text.trim();
    if text.is_empty() {
        return Err("ai/bad-response");
    }
    Ok(if cut_off { format!("{text}…") } else { text.to_string() })
}

/// Is this failure worth a second try a few seconds later?
pub(super) fn transient(code: &str) -> bool {
    matches!(code, "ai/unreachable" | "ai/overloaded" | "ai/rate-limited")
}

/// The answer as the member sees it, and the row it proposes (its last `ROW:` line, when that
/// parses). Every `ROW:` line is cut from what the member sees, parsed or not.
pub(super) fn split_row(answer: &str) -> (String, Option<Row>) {
    let mut row = None;
    let mut kept = Vec::new();
    for line in answer.lines() {
        match line.trim().strip_prefix(ROW_MARKER) {
            Some(json) => {
                if let Some(r) = Row::parse(json.trim()) {
                    row = Some(r);
                }
            }
            None => kept.push(line),
        }
    }
    (kept.join("\n").trim().to_string(), row)
}

/// A member's yes or no to a proposed row: `Some(true)` / `Some(false)`, else `None`. Either
/// language, whatever the bot's own; case, spacing and closing punctuation do not matter.
pub(super) fn yes_or_no(text: &str) -> Option<bool> {
    // Punctuation anywhere and repeated spaces do not matter: "Evet, kaydet." is "evet kaydet".
    let t: String = text
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    // Measured in the lab on Haiku (2026-10-26): members answered "tamam kaydet" and "vazgeç",
    // and the model itself told them to say "onaylıyorum"; each fell through as a new message and
    // the row was silently dropped. These are the short answers that can mean nothing else.
    const YES: [&str; 14] = [
        "evet", "evet kaydet", "kaydet", "tamam", "tamam kaydet", "olur", "onay", "onayla",
        "onaylıyorum", "onayliyorum", "yes", "ok", "okay", "save",
    ];
    const NO: [&str; 12] = [
        "hayır", "hayir", "hayır kaydetme", "kaydetme", "vazgeç", "vazgec", "iptal", "istemiyorum",
        "no", "cancel", "dont", "don t",
    ];
    if YES.contains(&t.as_str()) {
        Some(true)
    } else if NO.contains(&t.as_str()) {
        Some(false)
    } else {
        None
    }
}

/// `f`, or `None` when it has not finished in `ms`.
pub(super) async fn with_timeout<F: std::future::Future>(f: F, ms: u64) -> Option<F::Output> {
    use futures_util::future::{select, Either};
    let delay = Delay::from(std::time::Duration::from_millis(ms));
    match select(Box::pin(f), Box::pin(delay)).await {
        Either::Left((out, _)) => Some(out),
        Either::Right(_) => None,
    }
}

/// The address a model call goes to, judged NOW by the rule the owner's `base_url` met when it was
/// set (`builtin_rules::outbound_url`): one stored under the lab's LAN escape, since turned off,
/// is not called (audit 2026-10-26, beside note 1.4). Refused = `ai/unreachable`, as a dead host.
pub(super) fn call_url(ai: &AiConfig, allow_lan: bool) -> std::result::Result<String, &'static str> {
    outbound_url(&endpoint(ai), allow_lan).map(|u| u.to_string()).ok_or("ai/unreachable")
}

/// One model call: the answer's text, or the failure's code. Nothing about the request or the
/// answer is logged.
pub(super) async fn call(
    ai: &AiConfig,
    key: &str,
    body: &serde_json::Value,
    allow_lan: bool,
) -> std::result::Result<String, &'static str> {
    let url = call_url(ai, allow_lan)?;
    let headers = Headers::new();
    let set = |k: &str, v: &str| headers.set(k, v).map_err(|_| "ai/bad-key");
    set("content-type", "application/json")?;
    for (k, v) in auth_headers(ai.provider, key) {
        set(k, &v)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual)
        .with_body(Some(body.to_string().into()));
    let req = Request::new_with_init(&url, &init).map_err(|_| "ai/bad-response")?;
    let Some(Ok(mut resp)) = with_timeout(Fetch::Request(req).send(), CALL_TIMEOUT_MS).await else {
        return Err("ai/unreachable");
    };
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    parse_response(ai.provider, status, &text)
}

#[cfg(test)]
#[path = "builtin_ai_tests.rs"]
mod tests;
