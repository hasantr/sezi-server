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
//! bill stops there. If the credentials are unset, TURN is simply `disabled`.
//!
//! **Where the credentials come from (the fcm.rs chain, verbatim):** per key, env FIRST and D1
//! `server_config` second, so an env-set value keeps the production path bit-identical while an
//! owner with no shell can paste the pair into the Sezi app instead (`PATCH /admin/turn-config`).
//! Requiring `wrangler secret put` for this was the actual blocker: it puts a beta-blocking feature
//! behind SSH access to a Raspberry Pi, which no ordinary self-hoster has.

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

/// Trim, and treat an all-whitespace value as absent — a pasted field that looks empty must not
/// count as configured.
fn normalize(v: String) -> Option<String> {
    let t = v.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// One `server_config` row, or None. Mirrors `push/fcm.rs`'s reader; kept local rather than shared
/// so neither module's read chain can be changed from under the other.
async fn read_db_config(db: &D1Database, key: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Row {
        value: String,
    }
    let row: Option<Row> = db
        .prepare("SELECT value FROM server_config WHERE key = ? LIMIT 1")
        .bind(&[crate::d1util::d1_text(key)])
        .ok()?
        .first(None)
        .await
        .ok()?;
    normalize(row?.value)
}

/// The CF TURN key id: env secret FIRST (the existing production path), then the D1 row the owner
/// entered from the app.
async fn resolve_key_id(env: &Env, db: &D1Database) -> Option<String> {
    if let Some(v) = env.secret("TURN_KEY_ID").ok().and_then(|v| normalize(v.to_string())) {
        return Some(v);
    }
    read_db_config(db, "turn_key_id").await
}

/// The CF TURN API token: env secret FIRST, then D1. This is the strong half of the pair — it can
/// mint credentials — which is why writing it is owner-only and no endpoint ever returns it.
async fn resolve_api_token(env: &Env, db: &D1Database) -> Option<String> {
    if let Some(v) = env
        .secret("TURN_API_TOKEN")
        .ok()
        .and_then(|v| normalize(v.to_string()))
    {
        return Some(v);
    }
    read_db_config(db, "turn_api_token").await
}

/// Is TURN usable — backs `turn_configured` on `/admin/stats` and the `PATCH /admin/turn-config`
/// response. Both halves must be present; either source counts. Write-only contract: only this bool
/// ever leaves the server, never a value. Fails open to false (no D1 binding → "not configured"),
/// because stats must not 500.
pub async fn is_configured(env: &Env) -> bool {
    let Ok(db) = env.d1("DB") else {
        return false;
    };
    resolve_key_id(env, &db).await.is_some() && resolve_api_token(env, &db).await.is_some()
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

    // 2. Are the credentials set (env secret, or the D1 row the owner entered from the app)? If
    //    not, TURN is disabled gracefully and the client uses STUN — a call on the same network
    //    still works, which is why an unconfigured server is not a broken one.
    let db = env.d1("DB")?;
    let key_id = resolve_key_id(env, &db).await;
    let api_token = resolve_api_token(env, &db).await;
    let (key_id, api_token) = match (key_id, api_token) {
        (Some(k), Some(t)) => (k, t),
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
