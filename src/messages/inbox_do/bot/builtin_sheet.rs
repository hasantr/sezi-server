//! The sheet bot's one request: a POST to the owner's Apps Script web app
//! (docs/BOTS_HELPER_PLAN.md, "Relay — the sheet POST").
//!
//! ```json
//! {"v": 1, "secret": "<sheet_secret>", "test": false, "row_id": "<bot>-<job>" | null, "at": 1761200000000,
//!  "who": {"user_id": "…", "name": "…"}, "room": {"id": "…", "name": "…"} | null,
//!  "text": "…", "row": {"Tarih": "…", …} | null}
//! ```
//!
//! `room` (Phase 3) names the group a call came from; `null` for a 1:1 message and for the owner's
//! test. The core's script writes it to a "Grup" / "Group" column when present.
//!
//! The secret is in the BODY because an Apps Script web app cannot read headers. `row_id` stays
//! the same across every re-send of one row: a POST may land and still be sent again (its GET
//! hop failed twice, or timed out), and the script skips a `row_id` it already wrote. Keys go out in
//! exactly this order (a struct, not a map), and a row's columns in the order the model wrote
//! them, so the shared test vector is exact bytes.
//!
//! Apps Script answers the POST with a 302 to `script.googleusercontent.com`, whose GET returns
//! what the script printed. The redirects are followed HERE, by hand, so every hop meets the
//! same URL rule the owner's address did (`builtin_rules::outbound_url`) — a fetch that followed
//! on its own could be sent anywhere on the relay's network. A 301/302/303 continues as a GET
//! (as `fetch` does), a 307/308 repeats the POST. A hop to Google's sign-in page means the web
//! app was not deployed for "Anyone" (`bot/sheet-access`). Success is a final 2xx whose JSON
//! says `"ok": true`. A GET hop whose connection dropped is asked once more; the POST never is.

use crate::bots::builtin_rules::outbound_url;
use serde::ser::{Serialize, SerializeMap, Serializer};
use worker::*;

/// Hops one write may take: the POST and its redirects.
const MAX_HOPS: u32 = 4;
/// Subrequests one write may take at worst: every hop, and every GET hop asked twice.
pub(super) const MAX_SPEND: u32 = 2 * MAX_HOPS - 1;
/// How long one hop may take.
const HOP_TIMEOUT_MS: u64 = 30_000;
/// A row's columns, at most.
pub(super) const MAX_COLUMNS: usize = 20;
/// A column name, at most (characters).
pub(super) const MAX_COLUMN_CHARS: usize = 64;
/// A cell, at most (characters).
pub(super) const MAX_CELL_CHARS: usize = 500;

/// A row: column names and their values, in the order they were written.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Row(pub(crate) Vec<(String, String)>);

impl Serialize for Row {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl Row {
    /// A JSON object's members as a row, in their written order: a string as it is, a number or
    /// a boolean as its text, anything else dropped; names and cells cut to their caps. `None`
    /// when the text is not an object or nothing is left.
    pub(crate) fn parse(json: &str) -> Option<Row> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<(String, serde_json::Value)>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(e) = a.next_entry::<String, serde_json::Value>()? {
                    out.push(e);
                }
                Ok(out)
            }
        }
        let mut de = serde_json::Deserializer::from_str(json);
        let members = serde::Deserializer::deserialize_map(&mut de, V).ok()?;
        de.end().ok()?;
        let cut = |s: &str, n: usize| s.trim().chars().take(n).collect::<String>();
        let mut row = Vec::new();
        for (k, v) in members {
            let value = match v {
                serde_json::Value::String(s) => s,
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            let k = cut(&k, MAX_COLUMN_CHARS);
            if k.is_empty() || row.iter().any(|(n, _)| *n == k) {
                continue;
            }
            row.push((k, cut(&value, MAX_CELL_CHARS)));
            if row.len() == MAX_COLUMNS {
                break;
            }
        }
        (!row.is_empty()).then_some(Row(row))
    }

    pub(crate) fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}

#[derive(serde::Serialize)]
struct Who<'a> {
    user_id: &'a str,
    name: &'a str,
}

/// The group a row's call came from.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
pub(crate) struct SheetRoom<'a> {
    pub(crate) id: &'a str,
    pub(crate) name: &'a str,
}

/// The POST's fields, in the contract's order.
#[derive(serde::Serialize)]
struct Body<'a> {
    v: u32,
    secret: &'a str,
    test: bool,
    row_id: Option<&'a str>,
    at: i64,
    who: Who<'a>,
    room: Option<SheetRoom<'a>>,
    text: &'a str,
    row: Option<&'a Row>,
}

/// One write's body, exactly as sent. `row_id` is stable across re-sends of one row
/// (`<bot>-<job>`), so the script can skip a row it already wrote; a test sends none.
#[allow(clippy::too_many_arguments)]
pub(crate) fn body_json(
    secret: &str,
    test: bool,
    row_id: Option<&str>,
    at: i64,
    user_id: &str,
    name: &str,
    room: Option<SheetRoom<'_>>,
    text: &str,
    row: Option<&Row>,
) -> String {
    let b = Body { v: 1, secret, test, row_id, at, who: Who { user_id, name }, room, text, row };
    serde_json::to_string(&b).unwrap_or_default()
}

/// What a final answer means: `Ok` for `{"ok": true}`, else the typed code.
pub(crate) fn judge(status: u16, body: &str) -> std::result::Result<(), &'static str> {
    let json: Option<serde_json::Value> = serde_json::from_str(body.trim()).ok();
    let ok = json.as_ref().and_then(|j| j.get("ok")).and_then(|v| v.as_bool());
    match (status, ok) {
        (200..=299, Some(true)) => Ok(()),
        (_, Some(false)) => match json.as_ref().and_then(|j| j.get("error")).and_then(|e| e.as_str()) {
            Some("secret") => Err("bot/sheet-secret"),
            // The script is not bound to a spreadsheet (made outside Uzantılar › Apps Script).
            Some("no-sheet") => Err("bot/sheet-no-sheet"),
            _ => Err("bot/sheet-refused"),
        },
        (404, _) => Err("bot/sheet-not-found"),
        _ => Err("bot/sheet-bad-response"),
    }
}

/// What to do after a 3xx.
#[derive(Debug, PartialEq)]
pub(crate) enum Hop {
    /// Fetch this next; `true` = still a POST.
    Next(String, bool),
    Fail(&'static str),
}

/// The hop after a redirect, under the URL rule. `post` = the hop that answered was a POST.
pub(crate) fn next_hop(status: u16, location: Option<&str>, from: &str, post: bool, allow_lan: bool) -> Hop {
    let Some(loc) = location.filter(|l| !l.trim().is_empty()) else {
        return Hop::Fail("bot/sheet-bad-response");
    };
    let Some(target) = Url::parse(from).ok().and_then(|base| base.join(loc.trim()).ok()) else {
        return Hop::Fail("bot/sheet-bad-response");
    };
    if target.host_str() == Some("accounts.google.com") {
        return Hop::Fail("bot/sheet-access");
    }
    let Some(target) = outbound_url(target.as_str(), allow_lan) else {
        return Hop::Fail("bot/sheet-url-refused");
    };
    let still_post = post && matches!(status, 307 | 308);
    Hop::Next(target.to_string(), still_post)
}

/// One request, or `None` when nothing answered in time.
async fn fetch_once(url: &str, body: Option<&str>) -> Option<Response> {
    let mut init = RequestInit::new();
    init.with_redirect(RequestRedirect::Manual);
    match body {
        Some(b) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json").ok()?;
            init.with_method(Method::Post).with_headers(headers).with_body(Some(b.into()));
        }
        None => {
            init.with_method(Method::Get);
        }
    }
    let req = Request::new_with_init(url, &init).ok()?;
    super::builtin_ai::with_timeout(Fetch::Request(req).send(), HOP_TIMEOUT_MS)
        .await
        .and_then(|r| r.ok())
}

/// The sheet's own address, judged NOW by the rule every redirect hop meets (`next_hop`) and the
/// owner's address met when it was set: one stored under the lab's LAN escape, since turned off,
/// is not fetched (audit 2026-10-26, beside note 1.4). Refused = unreachable, spending nothing.
pub(crate) fn first_hop(url: &str, allow_lan: bool) -> std::result::Result<String, &'static str> {
    outbound_url(url, allow_lan).map(|u| u.to_string()).ok_or("bot/sheet-unreachable")
}

/// Write one body to the sheet: the outcome, and the subrequests it took.
pub(crate) async fn post(url: &str, body: &str, allow_lan: bool) -> (std::result::Result<(), &'static str>, u32) {
    let Ok(first) = first_hop(url, allow_lan) else {
        return (Err("bot/sheet-unreachable"), 0);
    };
    let mut at = first;
    let mut as_post = true;
    let mut spent = 0;
    for _ in 0..MAX_HOPS {
        spent += 1;
        let mut answer = fetch_once(&at, as_post.then_some(body)).await;
        // A GET hop is asked once more when the connection dropped under it (measured in the
        // lab: a pooled connection the server had closed answers "Network connection lost").
        // A POST is never repeated here — it may have landed; the queue's ladder retries it.
        if answer.is_none() && !as_post {
            spent += 1;
            answer = fetch_once(&at, None).await;
        }
        let Some(mut resp) = answer else {
            return (Err("bot/sheet-unreachable"), spent);
        };
        let status = resp.status_code();
        if (300..400).contains(&status) {
            let location = resp.headers().get("location").ok().flatten();
            match next_hop(status, location.as_deref(), &at, as_post, allow_lan) {
                Hop::Next(next, post) => {
                    at = next;
                    as_post = post;
                    continue;
                }
                Hop::Fail(code) => return (Err(code), spent),
            }
        }
        let text = resp.text().await.unwrap_or_default();
        return (judge(status, &text), spent);
    }
    (Err("bot/sheet-redirects"), spent)
}

#[cfg(test)]
#[path = "builtin_sheet_tests.rs"]
mod tests;
