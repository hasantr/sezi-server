//! CF GraphQL Analytics — BILLING-ACCURATE usage numbers (quota epic **phase 3**).
//! Alongside the self-reported counters in `/admin/stats` (phase 1c) this adds
//! Cloudflare's own measurements: request count (workersInvocationsAdaptive) and R2
//! storage (r2StorageAdaptiveGroups), giving stats its "authoritative" dual logic.
//!
//! ⚠️ FAIL-OPEN IS ABSOLUTE (this module was written without any LIVE testing — there
//! was no CF_API_TOKEN yet): EVERY error path returns `None` → stats falls back to the
//! self-reported numbers, the endpoint NEVER 500s, and existing fields are NEVER
//! disturbed. The chain:
//!   0. Config resolution is per key: **env secret/var FIRST, D1 `server_settings`
//!      second** (0024; the owner enters it from the app via `PATCH /admin/cf-config`).
//!      env wins, so a mixed setup works — account id in env, token entered in the UI
//!      and stored in D1. The D1 read is FAIL-OPEN: a missing table/column (before the
//!      migration) or any D1 error simply drops that source (env-only, today's
//!      behavior). If both env keys are set, D1 is NEVER queried.
//!   1. Token or account missing/empty in EVERY source → early None, without ever
//!      touching the CF network (a VPS/standalone deployment, or CF without a token,
//!      behaves EXACTLY as it does today).
//!   2. fetch/network error → `console_warn` + None for that query.
//!   3. HTTP status != 200 → `console_warn` (status + body) + None for that query.
//!   4. Body fails to parse as JSON → `console_warn` (raw body, truncated) + None.
//!   5. Non-empty GraphQL `errors` → `console_warn` with CF's message (visible in
//!      `wrangler tail` once a token exists), then STILL attempt to parse data —
//!      partial success is possible.
//!   6. Per-field DEFENSIVE parsing: each metric is its own `.get(..).and_then(..)`
//!      chain, so missing/null/schema-changed only nulls that one metric.
//!   7. The request-count and R2 queries are SEPARATE POSTs: if the R2 subquery turns
//!      out to be schema-incompatible (a validation error would sink the WHOLE query),
//!      the primary metric — request counts — is UNAFFECTED.
//!   8. ALL metrics None → None (no CF data at all means we are NOT authoritative).
//!
//! Setup: CF dashboard → API token (Account Analytics: Read) → either the owner enters
//! it in the Sezi app (Server usage → CF Analytics; stored in D1, WRITE-ONLY — no
//! endpoint hands it back) or via CLI with `wrangler secret put CF_API_TOKEN` plus
//! `CF_ACCOUNT_ID` (either a var or a secret).

use worker::*;

/// Usage as measured by CF. Every field is an independent Option, so if one part of
/// the query is schema-incompatible the rest still arrive (per-field fail-open).
pub struct CfUsage {
    /// Worker requests today (since 00:00 UTC) — matches the CF bill exactly.
    pub requests_today: Option<i64>,
    /// Worker requests this month (since the first of the month, UTC).
    pub requests_month: Option<i64>,
    /// R2 storage in payload bytes, as measured by CF. Reported ALONGSIDE the
    /// self-reported `media.bytes`; it never overwrites it.
    pub r2_storage_bytes: Option<i64>,
}

/// The `name` from wrangler.toml — the scriptName filter for
/// workersInvocationsAdaptive. If the worker is renamed, this single spot must be
/// updated too.
const SCRIPT_NAME: &str = "sezgi-worker-rs";

/// The request-count query (the PRIMARY metric) — a constant, kept in one place so a
/// CF schema change only has to be fixed here. Two aliased windows: since 00:00Z today
/// and since the start of the month.
///
/// ⚠️ MAY NEED LIVE TUNING (never verified without a token):
/// - The variable types are lowercase `string`, following CF's documented example (the
///   CF Analytics schema uses its own scalars, NOT the standard GraphQL
///   `String`/`Time`). If CF rejects the query, suspect this first — try the `string!`
///   variant.
/// - The filter field names (`scriptName`, `datetime_geq`) come from CF's
///   workersInvocationsAdaptive example; if the schema evolves, the `errors` block will
///   say so in `wrangler tail`.
/// - `limit` only satisfies CF's mandatory-limit rule; since the sum collapses to a
///   single row, the value itself does not affect the result.
const REQUESTS_QUERY: &str = r#"
query SezgiRequests($accountTag: string, $scriptName: string, $todayStart: string, $monthStart: string) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      today: workersInvocationsAdaptive(
        limit: 1000
        filter: { scriptName: $scriptName, datetime_geq: $todayStart }
      ) {
        sum { requests }
      }
      month: workersInvocationsAdaptive(
        limit: 1000
        filter: { scriptName: $scriptName, datetime_geq: $monthStart }
      ) {
        sum { requests }
      }
    }
  }
}
"#;

/// The R2 storage query (SECONDARY, best-effort) — DELIBERATELY a separate POST: this
/// dataset is adaptively sampled, and the "current storage = max{payloadSize} of the
/// latest observation" pattern still needs live confirmation. If it turns out to be
/// schema-incompatible only this query is lost; it is not in the SAME body as the
/// request counts precisely because a GraphQL validation error sinks the whole query.
/// When something goes wrong r2_storage_bytes simply stays None — never forced.
const R2_QUERY: &str = r#"
query SezgiR2($accountTag: string, $todayStart: string) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      r2: r2StorageAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $todayStart }
      ) {
        max { payloadSize }
      }
    }
  }
}
"#;

/// Read `secret` FIRST, then `var` (the token is expected to be a secret; the account
/// id may well be a var). Missing/empty/whitespace → None, i.e. treated as not
/// configured. This is the ENV layer only — the D1 fallback lives in `resolve_cfg`,
/// where env wins.
fn read_cfg(env: &Env, key: &str) -> Option<String> {
    let raw = env
        .secret(key)
        .map(|s| s.to_string())
        .or_else(|_| env.var(key).map(|v| v.to_string()))
        .ok()?;
    normalize(raw)
}

/// Trim, and map empty to None — env and D1 values are normalized with the SAME rule.
fn normalize(raw: String) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The cf columns of D1 `server_settings` (0024) — the config the owner entered from
/// the app via `PATCH /admin/cf-config`. FAIL-OPEN IS ABSOLUTE: no D1 binding, missing
/// table/column (before the migration), missing row or a query error all yield
/// (None, None), i.e. the source is ignored (env-only, today's behavior; stats NEVER
/// 500s).
async fn read_db_cfg(env: &Env) -> (Option<String>, Option<String>) {
    #[derive(serde::Deserialize)]
    struct Row {
        cf_api_token: Option<String>,
        cf_account_id: Option<String>,
    }
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return (None, None),
    };
    let row: Option<Row> = match db
        .prepare("SELECT cf_api_token, cf_account_id FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // The expected case is a pre-migration "no such column" — it should not
            // vanish silently, but it must not break the endpoint either
            // (fail-open, with a trace).
            console_warn!("cf_analytics: D1 config okunamadı (fail-open): {e:?}");
            return (None, None);
        }
    };
    match row {
        Some(r) => (
            r.cf_api_token.and_then(normalize),
            r.cf_account_id.and_then(normalize),
        ),
        None => (None, None),
    }
}

/// The effective config — per key, **env FIRST, D1 second** (env wins, so a mixed
/// setup works: account id in env, token entered in the UI and stored in D1). If both
/// env keys are set, D1 is NEVER queried — the env-configured fast path is
/// bit-identical to today's behavior.
async fn resolve_cfg(env: &Env) -> (Option<String>, Option<String>) {
    let env_token = read_cfg(env, "CF_API_TOKEN");
    let env_account = read_cfg(env, "CF_ACCOUNT_ID");
    if env_token.is_some() && env_account.is_some() {
        return (env_token, env_account);
    }
    let (db_token, db_account) = read_db_cfg(env).await;
    (env_token.or(db_token), env_account.or(db_account))
}

/// Is a token configured (in env OR D1)? Feeds the `cf_configured` field of
/// `/admin/stats` and the `PATCH /admin/cf-config` response. CHEAP: it does NOT touch
/// the CF network (`fetch` costs two GraphQL POSTs) and only checks whether a token
/// EXISTS. This is the read side of the WRITE-ONLY contract: a bool leaks, never the
/// value.
pub async fn is_configured(env: &Env) -> bool {
    if read_cfg(env, "CF_API_TOKEN").is_some() {
        return true;
    }
    read_db_cfg(env).await.0.is_some()
}

/// Truncate a body for logging so `wrangler tail` stays readable — CF error messages
/// are usually within the first few hundred characters.
fn truncate_for_log(s: &str) -> String {
    const MAX: usize = 600;
    if s.len() <= MAX {
        s.to_string()
    } else {
        // Round down to a char boundary so we never slice mid-UTF-8 and panic.
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}… ({}B)", &s[..end], s.len())
    }
}

/// Today at 00:00Z as ISO 8601, derived from usage.rs `today_utc` ("YYYY-MM-DD") so
/// the window matches the self-reported counters EXACTLY.
fn today_start_utc() -> String {
    format!("{}T00:00:00Z", crate::usage::today_utc())
}

/// The first of the month at 00:00Z as ISO 8601, derived from turn.rs
/// `current_month_utc` ("YYYY-MM") so the window matches the TURN budget EXACTLY.
fn month_start_utc() -> String {
    format!("{}-01T00:00:00Z", crate::turn::current_month_utc())
}

/// One GraphQL POST → the `data.viewer.accounts[0]` node. Every failure layer does
/// `console_warn` + None (fail-open; `tag` tells the log which query it was). Follows
/// fcm.rs's Fetch/RequestInit pattern. The body is taken as TEXT so that on a parse
/// failure the raw body can be logged (evidence for live tuning) — and per the OTK
/// wedge lesson, text + serde_json is the house pattern instead of resp.json.
async fn graphql_account(token: &str, body: String, tag: &str) -> Option<serde_json::Value> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    if headers
        .set("authorization", &format!("Bearer {token}"))
        .is_err()
        || headers.set("content-type", "application/json").is_err()
    {
        console_warn!("cf_analytics[{tag}]: header kurulamadı");
        return None;
    }
    init.with_headers(headers);

    // (2) fetch/network error → swallow, log, return None (stats never 500s).
    let req = match Request::new_with_init("https://api.cloudflare.com/client/v4/graphql", &init) {
        Ok(r) => r,
        Err(e) => {
            console_warn!("cf_analytics[{tag}]: request kurulamadı: {e:?}");
            return None;
        }
    };
    let mut resp = match Fetch::Request(req).send().await {
        Ok(r) => r,
        Err(e) => {
            console_warn!("cf_analytics[{tag}]: fetch hatası: {e:?}");
            return None;
        }
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            console_warn!("cf_analytics[{tag}]: gövde okunamadı: {e:?}");
            return None;
        }
    };

    // (3) HTTP error (401 wrong token / 403 missing permission / 5xx) → log + None.
    if resp.status_code() != 200 {
        console_warn!(
            "cf_analytics[{tag}]: HTTP {} — {}",
            resp.status_code(),
            truncate_for_log(&text)
        );
        return None;
    }

    // (4) JSON parse failure → log + None.
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            console_warn!(
                "cf_analytics[{tag}]: JSON parse-fail: {e} — {}",
                truncate_for_log(&text)
            );
            return None;
        }
    };

    // (5) GraphQL `errors` — where CF speaks up about a schema/filter mismatch.
    // Log it but CONTINUE: `data` may have arrived partially.
    if let Some(errors) = v.get("errors").filter(|e| !e.is_null()) {
        if errors.as_array().map(|a| !a.is_empty()).unwrap_or(true) {
            console_warn!(
                "cf_analytics[{tag}]: GraphQL errors: {}",
                truncate_for_log(&errors.to_string())
            );
        }
    }

    let account = v
        .get("data")
        .and_then(|d| d.get("viewer"))
        .and_then(|w| w.get("accounts"))
        .and_then(|a| a.get(0))
        .cloned();
    if account.is_none() {
        console_warn!(
            "cf_analytics[{tag}]: data.viewer.accounts[0] yok — {}",
            truncate_for_log(&text)
        );
    }
    account
}

/// `<alias>[0].sum.requests` — defensive traversal; any level missing, null or of the
/// wrong type yields None, dropping that one metric while the caller survives.
fn extract_requests(account: &serde_json::Value, alias: &str) -> Option<i64> {
    let v = account.get(alias)?.get(0)?.get("sum")?.get("requests")?;
    // CF returns sums as integers, but accept a float if the schema ever emits one.
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

/// `r2[0].max.payloadSize` — the same defensive pattern.
fn extract_r2_bytes(account: &serde_json::Value) -> Option<i64> {
    let v = account.get("r2")?.get(0)?.get("max")?.get("payloadSize")?;
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

/// Fetch usage from CF Analytics. `None` means no CF, not configured, or an error, and
/// the caller (admin/stats) falls back to the self-reported counters — the fallback arm
/// of the dual logic. The detailed fail-open chain is in the module header.
pub async fn fetch(env: &Env) -> Option<CfUsage> {
    // (0)+(1) Config resolution, env-first with a D1 fallback (`resolve_cfg`). If the
    // token or the account is missing from EVERY source, return None without ever
    // touching the CF network (not configured = self-report, today's behavior).
    let (token, account_tag) = match resolve_cfg(env).await {
        (Some(t), Some(a)) => (t, a),
        _ => return None,
    };

    let today_start = today_start_utc();

    // ── PRIMARY metric: request counts (today + this month) ──────────────────
    let requests_body = serde_json::json!({
        "query": REQUESTS_QUERY,
        "variables": {
            "accountTag": account_tag,
            "scriptName": SCRIPT_NAME,
            "todayStart": today_start,
            "monthStart": month_start_utc(),
        }
    })
    .to_string();
    let requests_account = graphql_account(&token, requests_body, "requests").await;
    let (requests_today, requests_month) = match &requests_account {
        Some(acc) => (
            extract_requests(acc, "today"),
            extract_requests(acc, "month"),
        ),
        None => (None, None),
    };

    // ── SECONDARY: R2 storage (best-effort; separate POST — see the R2_QUERY note) ──
    let r2_body = serde_json::json!({
        "query": R2_QUERY,
        "variables": {
            "accountTag": account_tag,
            "todayStart": today_start,
        }
    })
    .to_string();
    let r2_storage_bytes = match graphql_account(&token, r2_body, "r2").await {
        Some(acc) => extract_r2_bytes(&acc),
        None => None,
    };

    // (8) All None = not a SINGLE real number came back from CF → we are NOT
    // authoritative; return None so stats reports `authoritative:false` and prints the
    // self-reported figures.
    if requests_today.is_none() && requests_month.is_none() && r2_storage_bytes.is_none() {
        console_warn!("cf_analytics: hiç metrik çıkmadı (şema-tuning gerek? — üstteki loglara bak)");
        return None;
    }
    Some(CfUsage {
        requests_today,
        requests_month,
        r2_storage_bytes,
    })
}
