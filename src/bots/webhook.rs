//! A bot's webhook: one signed POST per update (docs/BOTS_BUILD.md §2.5).
//!
//! The secret is DERIVED from the bot's one key, never stored apart from it by the owner:
//! `webhook_secret = hex(HMAC-SHA256(key = token, "sezi-bot-webhook-v1"))`. The relay keeps only
//! the token's hash, so the secret is computed where the token is in hand — `setWebhook` (the
//! program's own call) and the owner's key renewal — and handed to the bot's inbox, which signs.
//!
//! The body is an envelope, because an Apps Script web app cannot read request headers:
//!
//! ```json
//! {"v":1, "ts":1761200000000, "update_json":"<one Update, as an exact string>", "sig":"<hex>"}
//! ```
//!
//! `sig = hex(HMAC-SHA256(key = webhook_secret as UTF-8, ts + "." + update_json))`. The same
//! value also travels as `X-Sezi-Signature: t=<ts>,v1=<hex>` for programs that read headers.
//! `ts` is the time of THIS attempt (ms), so a retry an hour later is still fresh to a program
//! that refuses anything signed more than 5 minutes ago; the update's own `at` stays when the
//! member wrote.
//!
//! Delivered = a 2xx or a 3xx, fetched with `redirect: manual`: an Apps Script web app answers
//! its POST with a 302 after the script ran, and following it would only fetch the result page.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use worker::*;

type HmacSha256 = Hmac<Sha256>;

/// The label the secret is derived under.
const SECRET_LABEL: &[u8] = b"sezi-bot-webhook-v1";
/// The envelope's version.
pub(crate) const ENVELOPE_V: u32 = 1;
/// The longest webhook URL accepted.
const MAX_URL_LEN: usize = 512;

fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// The webhook secret a token gives.
pub(crate) fn derive_secret(token: &str) -> String {
    hmac_hex(token.as_bytes(), SECRET_LABEL)
}

/// The signature of one attempt.
pub(crate) fn sign(secret: &str, ts_ms: i64, update_json: &str) -> String {
    hmac_hex(secret.as_bytes(), format!("{ts_ms}.{update_json}").as_bytes())
}

/// The POST body of one attempt.
pub(crate) fn envelope(secret: &str, ts_ms: i64, update_json: &str) -> String {
    serde_json::json!({
        "v": ENVELOPE_V,
        "ts": ts_ms,
        "update_json": update_json,
        "sig": sign(secret, ts_ms, update_json),
    })
    .to_string()
}

/// Did the program take it? A 2xx, or a 3xx not followed.
pub(crate) fn taken(status: u16) -> bool {
    (200..400).contains(&status)
}

/// An `https://` URL with a host, no credentials and no fragment, at most 512 bytes, whose host
/// is not an IP literal or a private name — the built-in bots' rule (`builtin_rules::outbound_url`,
/// with its lab escape); else `None`.
///
/// The host rule is not optional. A relay on Cloudflare cannot reach a private network, but a
/// self-hosted one runs on bare workerd with miniflare's `internet` service, which allows
/// `private` addresses: there the bot inbox's POST reaches whatever the owner's LAN and the
/// relay's own machine have (the router's page, a NAS, a local admin port). Whoever holds a bot's
/// key — the owner's program, a developer it was given to, someone it leaked to — would have had
/// that reach. As with the built-in rule, a public NAME that resolves to a private address is not
/// caught here.
pub(crate) fn clean_url(raw: &str, allow_lan: bool) -> Option<String> {
    if raw.trim().len() > MAX_URL_LEN {
        return None;
    }
    crate::bots::builtin_rules::outbound_url(raw, allow_lan).map(|url| url.to_string())
}

/// One attempt. `Ok(status)` for any answer, `Err` when nothing answered.
pub(crate) async fn post(url: &str, secret: &str, ts_ms: i64, update_json: &str) -> Result<u16> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(
        "x-sezi-signature",
        &format!("t={ts_ms},v1={}", sign(secret, ts_ms, update_json)),
    )?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual)
        .with_body(Some(envelope(secret, ts_ms, update_json).into()));
    let req = Request::new_with_init(url, &init)?;
    let resp = Fetch::Request(req).send().await?;
    Ok(resp.status_code())
}

#[cfg(test)]
#[path = "webhook_tests.rs"]
mod tests;
