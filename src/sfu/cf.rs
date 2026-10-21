//! Calls to the Cloudflare Realtime SFU API (`rtc.live.cloudflare.com/v1/apps/<app>/…`), with the
//! app's token added here and never anywhere else.

use worker::*;

const BASE: &str = "https://rtc.live.cloudflare.com/v1/apps";

/// One call: `(status, body text)`. `path` is relative to the app (`sessions/new`,
/// `sessions/<id>/tracks/new`, …). A transport failure is an `Err`.
pub async fn call(
    app_id: &str,
    token: &str,
    method: Method,
    path: &str,
    body: Option<String>,
) -> Result<(u16, String)> {
    let mut init = RequestInit::new();
    init.with_method(method);
    if let Some(b) = body {
        init.with_body(Some(b.into()));
    }
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {token}"))?;
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let req = Request::new_with_init(&format!("{BASE}/{app_id}/{path}"), &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

/// Open one session; its id, or None when Cloudflare refused (a wrong app or token).
pub async fn new_session(app_id: &str, token: &str) -> Result<Option<String>> {
    let (status, text) = call(app_id, token, Method::Post, "sessions/new", None).await?;
    if !(200..300).contains(&status) {
        return Ok(None);
    }
    Ok(serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("sessionId").and_then(|s| s.as_str()).map(str::to_string)))
}
