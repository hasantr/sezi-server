//! TURN credential issuing plus a budget guard (calls Faz 1.5 — calls over the internet).
//!
//! Calls are P2P by default (direct over LAN/WiFi). Once the two ends are on different
//! networks and NAT gets in the way, media is relayed through **CF Realtime TURN**. A CF
//! Worker cannot BE a TURN server itself — it has no raw UDP — but CF offers a managed TURN
//! service (`turn.cloudflare.com`). All the worker does here is **issue short-lived TURN
//! credentials** by calling the CF TURN API; the main API token never reaches the client.
//!
//! **Budget guard:** CF has no hard spending cap, so to avoid a surprise bill the worker
//! keeps a monthly counter of issued credentials (`turn_usage`). Once `TURN_MONTHLY_CAP` is
//! exceeded it issues nothing (`capped`), the client falls back to direct/STUN, and the CF
//! bill stops there. If the secrets are unset, TURN is simply `disabled`.

use crate::auth::middleware::require_active_auth;
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

/// TURN credential TTL in seconds: long enough (6 hours) to cover an entire call, short
/// enough to bound the window if one leaks.
const TURN_TTL_SECS: u32 = 21_600;

/// Default monthly ceiling on issued credentials; env `TURN_MONTHLY_CAP` overrides it.
/// More than ample for personal use — this is a backstop against runaway usage and abuse.
/// One credential is roughly one call, and relayed audio costs ~30 MB per hour, so 5000
/// credentials is a very low-risk bound.
const DEFAULT_MONTHLY_CAP: i64 = 5_000;

#[derive(Deserialize)]
struct CfIceResponse {
    #[serde(rename = "iceServers")]
    ice_servers: serde_json::Value,
}

#[derive(Deserialize)]
struct UsageRow {
    issued: i64,
}

/// `POST /turn/credentials` — issue a short-lived CF TURN credential to an authenticated
/// user, which the client adds to its ICE config. Auth is mandatory: registered users only.
/// Response: `{iceServers:[...], ttl}` · disabled: `{iceServers:[], disabled:true}` · over
/// the cap: `{iceServers:[], capped:true}`. Even on failure the client is unharmed, because
/// an empty list simply means falling back to direct/STUN.
pub async fn credentials(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = &ctx.env;

    // 1. Auth — only a registered user may obtain a credential, and only for their own call.
    if let Err(resp) = require_active_auth(&req, env).await {
        return Ok(resp);
    }

    // 2. Are the secrets set? If not, TURN is disabled gracefully and the client uses STUN.
    let key_id = env.secret("TURN_KEY_ID").map(|v| v.to_string()).ok();
    let api_token = env.secret("TURN_API_TOKEN").map(|v| v.to_string()).ok();
    let (key_id, api_token) = match (key_id, api_token) {
        (Some(k), Some(t)) if !k.is_empty() && !t.is_empty() => (k, t),
        _ => {
            return Response::from_json(&serde_json::json!({
                "iceServers": [],
                "disabled": true,
            }));
        }
    };

    // 3. Budget guard — the monthly ceiling. Once exceeded, issue NOTHING: the CF bill stops.
    let cap = monthly_cap(env);
    let month = current_month_utc();
    let db = env.d1("DB")?;
    // Reading the counter fails open: a missing table (migration not applied) or any D1 error
    // counts as 0 and does NOT block issuing — this guard is a cost backstop, not a security
    // control. If the cap is genuinely reached, the counter will say so.
    let issued: i64 = match db
        .prepare("SELECT issued FROM turn_usage WHERE month = ? LIMIT 1")
        .bind(&[JsValue::from_str(&month)])
    {
        Ok(stmt) => stmt
            .first::<UsageRow>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.issued)
            .unwrap_or(0),
        Err(_) => 0,
    };
    if issued >= cap {
        return Response::from_json(&serde_json::json!({
            "iceServers": [],
            "capped": true,
        }));
    }

    // 4. Ask the CF TURN API to mint a short-lived credential.
    let url = format!(
        "https://rtc.live.cloudflare.com/v1/turn/keys/{}/credentials/generate-ice-servers",
        key_id
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(
        serde_json::json!({ "ttl": TURN_TTL_SECS })
            .to_string()
            .into(),
    ));
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {}", api_token))?;
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let cf_req = Request::new_with_init(&url, &init)?;
    let mut cf_resp = Fetch::Request(cf_req).send().await?;
    if cf_resp.status_code() >= 300 {
        return json_err(502, "turn_upstream_error");
    }
    let parsed: CfIceResponse = cf_resp.json().await?;

    // 5. Bump the counter now that issuing succeeded. Best-effort: with a missing table or on
    //    error the credential is still returned — the counter just undercounts, and the call
    //    is not broken. Upserted per month.
    if let Ok(stmt) = db
        .prepare(
            "INSERT INTO turn_usage (month, issued) VALUES (?, 1) \
             ON CONFLICT(month) DO UPDATE SET issued = issued + 1",
        )
        .bind(&[JsValue::from_str(&month)])
    {
        let _ = stmt.run().await;
    }

    // 6. Return iceServers to the client, ready to drop into an RTCPeerConnection config.
    Response::from_json(&serde_json::json!({
        "iceServers": parsed.ice_servers,
        "ttl": TURN_TTL_SECS,
    }))
}

/// The monthly TURN credential ceiling: env `TURN_MONTHLY_CAP`, falling back to
/// `DEFAULT_MONTHLY_CAP` when absent or unparseable. `pub(crate)` so that the budget guard
/// (`credentials` above) and the /admin/stats report (Faz 1c) read the SAME ceiling —
/// what is advertised matches what is enforced, as with retention.
pub(crate) fn monthly_cap(env: &Env) -> i64 {
    env.var("TURN_MONTHLY_CAP")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_MONTHLY_CAP)
}

/// Epoch seconds → "YYYY-MM" in UTC, via Howard Hinnant's civil-from-days algorithm so we
/// need no chrono dependency. This is the budget window key, aligned to the calendar month.
/// `pub(crate)` so /admin/stats (Faz 1c) reads this month's `turn_usage.issued` row with the
/// SAME key — whoever writes the counter and whoever reports it agree on the window.
pub(crate) fn current_month_utc() -> String {
    let secs = now_secs() as i64;
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}", y, m)
}
