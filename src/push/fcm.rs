//! FCM HTTP v1 — CONTENTLESS wake push (the Signal pattern). It carries NO message
//! content, only `data:{type:"wake"}`. All Google learns is "a push happened, at this
//! time": E2E is preserved and the content is decrypted on the device. That matches the
//! closed-to-the-outside philosophy.
//!
//! Flow: service account (env secret `FCM_SERVICE_ACCOUNT`, JSON) → RS256-signed JWT →
//! Google OAuth2 (`oauth2.googleapis.com/token`, jwt-bearer) → `access_token` (cached
//! module-globally, ~1h) → `fcm/v1/projects/{FCM_PROJECT_ID}/messages:send`. RS256 comes
//! from the pure-Rust `rsa` crate (deterministic PKCS1v15, so no RNG is needed).
//! 404/UNREGISTERED means the token is stale and the caller deletes it from `push_tokens`.
//!
//! Config resolution (owner self-service): per key, **env FIRST, then D1 `server_config`**
//! (the cf_analytics `resolve_cfg` pattern). With env set — our prod uses wrangler.toml
//! `FCM_PROJECT_ID` plus the `FCM_SERVICE_ACCOUNT` secret — D1 is never touched and
//! today's path stays BIT-IDENTICAL. Without env we use whatever the owner entered from
//! the app via `PATCH /admin/fcm-config` and stored in D1; failing that we fall back to the
//! **shared PUSH RELAY** (the default, so self-host installs that never bring their own
//! service account still get zero-config push; see `DEFAULT_PUSH_RELAY_URL` and the
//! `push-relay/` worker). With the relay set to `off` (env `PUSH_RELAY_URL` or D1
//! `push_relay_url`) push becomes a silent no-op — FAIL-OPEN, because FCM is optional and
//! the worker runs perfectly well without it. Details in `resolve_send_mode`.

use std::sync::Mutex;

use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde::Deserialize;
use sha2::Sha256;
use worker::*;

use crate::d1util::d1_text;
use crate::utils::{b64u_encode, now_secs};

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String, // PEM PKCS8 (newlines may arrive `\n`-escaped)
}

struct CachedToken {
    token: String,
    exp: u64, // unix seconds; refresh before this
}

// Module-global OAuth token cache, living as long as the warm isolate. Per Codex: do NOT
// tie it to DO memory. workerd is single-threaded so the Mutex is effectively a no-op, and
// the cache is cleared when the isolate is recycled (the token is simply re-fetched).
//
// NOTE (fcm-config self-service): if the owner enters a NEW service account from the app,
// this cache can keep using the token obtained with the OLD one until it expires (~1h) —
// a config change does not invalidate the cache. That is ACCEPTABLE: isolate lifetimes are
// short (workerd recycles often), and as long as the old token is still valid at Google
// push keeps working; within ~1h at the latest it is renewed with the fresh account.
static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

// ── Config resolution — env-first / D1-fallback (cf_analytics `resolve_cfg` pattern) ──
//
// DELIBERATELY NOT MEMOIZED: instead of the self_provision thread_local pattern we read
// fresh on every send. Push is RARE — it fires only for a message whose recipient is
// offline — and the same `maybe_push_wake` call ALREADY goes to D1 for push_tokens, so one
// extra SELECT is negligible. A thread_local memo, by contrast, would hide config the
// owner just entered from the app for the whole isolate lifetime: the "I saved it but no
// push arrives" trap. The self_provision keys are fixed, whereas this config changes by
// the owner's hand. Reading fresh means save → it takes effect on the FIRST push.
// On an env-configured install (our prod) these functions never reach D1 at all.
//
// SECURITY (the D1-storage trade-off, identical to admin/cf_config.rs):
// FCM_SERVICE_ACCOUNT contains a Google service-account private key. D1 is encrypted at
// rest by CF, but the worker must read it in plaintext to sign the Google OAuth assertion
// — it cannot be encrypted with a key we do not hold. This is the owner's OWN Firebase
// project on their OWN server, and it is not E2E content: push is a contentless wake, so
// even a leaked key cannot open message content, only forge wakes. The value is never
// returned from any endpoint (worker-internal reads only), and a security-conscious owner
// can move it to an env secret, which ALWAYS wins.

/// Trim, then empty → None. env and D1 values are normalized with the SAME discipline
/// (the cf_analytics `normalize` pattern).
fn normalize(raw: String) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Read a single key from D1 `server_config` (the 0025 key-value table). FAIL-OPEN is
/// ABSOLUTE here: missing table (pre-migration), missing row or any D1 error all yield
/// None, and the caller silently no-ops. Push is optional; fcm never fails a request.
async fn read_db_config(db: &D1Database, key: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Row {
        value: String,
    }
    let row: Option<Row> = db
        .prepare("SELECT value FROM server_config WHERE key = ? LIMIT 1")
        .bind(&[d1_text(key)])
        .ok()?
        .first(None)
        .await
        .ok()?;
    normalize(row?.value)
}

/// The shared push relay (Hasan's CF worker) — the DEFAULT push path for self-host
/// installs that do not bring their own service account. The URL is NOT a secret: the
/// relay is token-gated and rate-limited, and the worst case is a contentless wake. If the
/// owner supplies their own service account (via env or D1) the relay is never used at all
/// (see `resolve_send_mode` below).
const DEFAULT_PUSH_RELAY_URL: &str = "https://sezi-push-relay.hsn-salihoglu.workers.dev";

/// Relay URL resolution: env `PUSH_RELAY_URL` → D1 `push_relay_url` → the compiled-in
/// default. Either source set to `off` yields None, i.e. relay disabled — the single switch
/// for an owner who wants push turned off entirely.
async fn resolve_relay_url(env: &Env, db: &D1Database) -> Option<String> {
    let v = match env.var("PUSH_RELAY_URL").ok().and_then(|v| normalize(v.to_string())) {
        Some(v) => Some(v),
        None => read_db_config(db, "push_relay_url").await,
    };
    match v {
        Some(u) if u.eq_ignore_ascii_case("off") => None,
        Some(u) => Some(u),
        None => Some(DEFAULT_PUSH_RELAY_URL.to_string()),
    }
}

/// Firebase project id: the env var FIRST (today's path — our prod stays BIT-IDENTICAL
/// without ever touching D1), then, if absent or empty, D1 `fcm_project_id` as entered by
/// the owner from the app. None means FCM is not configured and the caller silently no-ops
/// (today's behaviour).
async fn resolve_project_id(env: &Env, db: &D1Database) -> Option<String> {
    if let Some(v) = env.var("FCM_PROJECT_ID").ok().and_then(|v| normalize(v.to_string())) {
        return Some(v);
    }
    read_db_config(db, "fcm_project_id").await
}

/// Service-account JSON: the env secret FIRST (today's path), then D1
/// `fcm_service_account`. Content is validated at write time by `PATCH /admin/fcm-config`
/// (valid JSON carrying client_email and private_key).
async fn resolve_service_account(env: &Env, db: &D1Database) -> Option<String> {
    if let Some(v) = env
        .secret("FCM_SERVICE_ACCOUNT")
        .ok()
        .and_then(|s| normalize(s.to_string()))
    {
        return Some(v);
    }
    read_db_config(db, "fcm_service_account").await
}

/// Is FCM configured — backs the `fcm_configured` field of `/admin/stats` and the
/// `PATCH /admin/fcm-config` response. It counts as configured when either (a) the owner's
/// OWN config is complete (project id AND service account, from env or D1) or (b) the
/// shared relay is enabled (the default). This is the read face of a WRITE-ONLY contract:
/// only a bool escapes, never the value. Cheap by design — it never calls out to Google or
/// the relay, it only checks presence — and it fails open to false (no D1 binding means
/// "not configured"; stats must NEVER 500).
pub async fn is_configured(env: &Env) -> bool {
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return false,
    };
    let own = resolve_project_id(env, &db).await.is_some()
        && resolve_service_account(env, &db).await.is_some();
    own || resolve_relay_url(env, &db).await.is_some()
}

/// Service-account JWT → OAuth2 access_token, cached and refreshed with a 60s margin.
async fn get_access_token(env: &Env, db: &D1Database) -> Result<String> {
    let now = now_secs();
    if let Ok(guard) = TOKEN_CACHE.lock() {
        if let Some(c) = guard.as_ref() {
            if c.exp > now + 60 {
                return Ok(c.token.clone());
            }
        }
    }

    // env-first / D1-fallback. None means half-configured (project id present, service
    // account missing) → Err, the same class of behaviour as today's `env.secret(..)?`: the
    // caller logs a console_warn and that message's push is skipped, while the worker keeps
    // running normally.
    let sa_json = resolve_service_account(env, db)
        .await
        .ok_or_else(|| Error::RustError("fcm: service_account yok (env+D1)".into()))?;
    let sa: ServiceAccount = serde_json::from_str(&sa_json)
        .map_err(|e| Error::RustError(format!("fcm: service_account parse: {e}")))?;
    // Inside the JSON string the private_key line breaks may be `\n`-escaped → restore real
    // newlines.
    let pem = sa.private_key.replace("\\n", "\n");

    // --- RS256 JWT (assertion) ---
    let iat = now;
    let exp = now + 3600;
    let header = br#"{"alg":"RS256","typ":"JWT"}"#;
    let claims = serde_json::json!({
        "iss": sa.client_email,
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": iat,
        "exp": exp,
    })
    .to_string();
    let signing_input = format!("{}.{}", b64u_encode(header), b64u_encode(claims.as_bytes()));

    let key = RsaPrivateKey::from_pkcs8_pem(pem.trim())
        .map_err(|e| Error::RustError(format!("fcm: private_key pkcs8 parse: {e}")))?;
    let signing_key = SigningKey::<Sha256>::new(key);
    let sig = signing_key
        .try_sign(signing_input.as_bytes())
        .map_err(|e| Error::RustError(format!("fcm: jwt sign: {e}")))?;
    let jwt = format!("{}.{}", signing_input, b64u_encode(&sig.to_bytes()));

    // --- JWT → access_token (jwt-bearer grant) ---
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={jwt}"
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/x-www-form-urlencoded")?;
    init.with_headers(headers);
    let req = Request::new_with_init("https://oauth2.googleapis.com/token", &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    if resp.status_code() >= 300 {
        return Err(Error::RustError(format!(
            "fcm: oauth token {}",
            resp.status_code()
        )));
    }
    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        expires_in: u64,
    }
    let tr: TokenResp = resp.json().await?;
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        *guard = Some(CachedToken {
            token: tr.access_token.clone(),
            exp: now + tr.expires_in,
        });
    }
    Ok(tr.access_token)
}

/// Send one CONTENTLESS wake push to a device. `Ok(true)` = sent; `Ok(false)` = the token
/// is STALE (UNREGISTERED/invalid, so the caller must delete it from `push_tokens`);
/// `Err` = a transient failure.
async fn send_wake(env: &Env, db: &D1Database, fcm_token: &str, project_id: &str) -> Result<bool> {
    let access_token = get_access_token(env, db).await?;
    let url = format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send");
    // data-ONLY (no `notification` block): this is what makes Android fire
    // onBackgroundMessage even when the app is terminated, and it carries no content.
    // priority=high wakes the device out of doze.
    let payload = serde_json::json!({
        "message": {
            "token": fcm_token,
            "data": { "type": "wake" },
            "android": { "priority": "high" }
        }
    })
    .to_string();
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(payload.into()));
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {access_token}"))?;
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let req = Request::new_with_init(&url, &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    let code = resp.status_code();
    if code == 200 {
        return Ok(true);
    }
    // D-M8: on EVERY non-200 read the body and look for a POSITIVE stale signal via
    // `classify_fcm_send`. An ambiguous or systematic 400 — typically a bug in our own
    // payload or config — must NOT delete the token; only a 404 UNREGISTERED, or a 400 in
    // which FCM points at the token itself, yields Ok(false) = stale.
    let body = resp.text().await.unwrap_or_default();
    match classify_fcm_send(code, &body) {
        FcmSendOutcome::Stale => Ok(false),
        // Sent (200) cannot reach here — we returned early above. Transient means a
        // temporary failure, so the token is KEPT (the caller warns; the next message or
        // alarm retries).
        _ => Err(Error::RustError(format!("fcm: send {code}"))),
    }
}

/// Classification of an FCM `messages:send` response (D-M8). A token is only ever DELETED
/// on a POSITIVE stale signal: 404 + UNREGISTERED, or a 400 in which FCM blames the
/// registration token itself (a `fieldViolations` entry for field `message.token`, or
/// "registration token" appearing in `error.message`). EVERY other non-200 — a bare or
/// ambiguous INVALID_ARGUMENT, a payload/config bug of ours, a 5xx, an empty or malformed
/// body — is `Transient` and the token is KEPT. That is what stops a systematic 400 from
/// wiping the whole token registry and killing push in a way that hides itself.
#[derive(Debug, PartialEq, Eq)]
enum FcmSendOutcome {
    Sent,
    Stale,
    Transient,
}

fn classify_fcm_send(code: u16, body: &str) -> FcmSendOutcome {
    if code == 200 {
        return FcmSendOutcome::Sent;
    }
    if code == 404 && body.contains("UNREGISTERED") {
        return FcmSendOutcome::Stale;
    }
    if code == 400 && body_signals_bad_token(body) {
        return FcmSendOutcome::Stale;
    }
    FcmSendOutcome::Transient
}

/// Does a 400 body POSITIVELY indicate that FCM considers the token invalid? Either
/// (a) some `error.details[].fieldViolations[].field` contains "message.token", or
/// (b) `error.message` contains "registration token". An unparseable or absent body
/// yields false — the conservative answer, which KEEPS the token.
fn body_signals_bad_token(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let err = &v["error"];
    if let Some(msg) = err["message"].as_str() {
        if msg.contains("registration token") {
            return true;
        }
    }
    if let Some(details) = err["details"].as_array() {
        for d in details {
            if let Some(fvs) = d["fieldViolations"].as_array() {
                for fv in fvs {
                    if let Some(field) = fv["field"].as_str() {
                        if field.contains("message.token") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Contentless wake through the relay — the default path for a self-host install without
/// its own service account. The contract is IDENTICAL to `send_wake`: Ok(true) = sent,
/// Ok(false) = STALE (the caller deletes it from push_tokens; the relay forwards FCM's
/// UNREGISTERED signal as `stale:true`), Err = transient (429 / 5xx / network).
async fn send_wake_relay(relay_url: &str, fcm_token: &str) -> Result<bool> {
    let url = format!("{}/wake", relay_url.trim_end_matches('/'));
    let payload = serde_json::json!({ "token": fcm_token }).to_string();
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(payload.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let req = Request::new_with_init(&url, &init)?;
    let mut resp = Fetch::Request(req).send().await?;
    let code = resp.status_code();
    if code == 200 {
        #[derive(Deserialize)]
        struct RelayResp {
            #[serde(default)]
            ok: bool,
            #[serde(default)]
            stale: bool,
        }
        let r: RelayResp = resp.json().await?;
        if r.stale {
            return Ok(false);
        }
        if r.ok {
            return Ok(true);
        }
    }
    Err(Error::RustError(format!("fcm relay: {code}")))
}

/// The push send path: if the owner's OWN config is complete (project id + service
/// account) go DIRECT to FCM — today's path, never touching the relay, so our prod stays
/// BIT-IDENTICAL. Otherwise use the shared RELAY (the default, for zero-config self-host).
/// If that is `off` too, push is disabled.
enum SendMode {
    Direct { project_id: String },
    Relay { url: String },
}

async fn resolve_send_mode(env: &Env, db: &D1Database) -> Option<SendMode> {
    // The own-config path requires BOTH project id and service account; a half-configured
    // install (project id only) falls through to the relay — more useful than the old
    // "no service account → console_warn on every message" behaviour.
    if let Some(project_id) = resolve_project_id(env, db).await {
        if resolve_service_account(env, db).await.is_some() {
            return Some(SendMode::Direct { project_id });
        }
    }
    resolve_relay_url(env, db).await.map(|url| SendMode::Relay { url })
}

/// Recipient is OFFLINE (delivered_live=false) → send a contentless wake to their
/// registered push tokens. `recipient_device_id` Some → that device only; None → ALL of the
/// user's devices (device-blind pending). Best-effort: own config → direct FCM, otherwise
/// the shared relay (the default), and with the relay `off` a silent no-op (push is
/// optional; the worker runs normally). A stale token (`Ok(false)`) is deleted from
/// `push_tokens`.
pub async fn maybe_push_wake(
    env: &Env,
    db: &D1Database,
    recipient_id: &str,
    recipient_device_id: Option<&str>,
) {
    // One verdict line per wake attempt.
    //
    // Every exit from this function used to be silent except a hard `Err`. "Push is switched off",
    // "the device has no token", "the token was stale and has just been deleted" and "it went out
    // fine" were indistinguishable from outside, which is why "notifications do not arrive when the
    // app is closed" had no answer on 2026-07-27: the server correctly logged that it had chosen the
    // FCM-wake path, and then nothing at all. The delivery decision was observable; its OUTCOME was
    // not.
    //
    // `mode` also matters on its own. A self-hosted server with no FCM configuration silently falls
    // back to the shared default relay, so the operator can be pushing through someone else's
    // infrastructure without ever being told. Naming the mode here is what makes that visible.
    let mode = match resolve_send_mode(env, db).await {
        Some(m) => m,
        None => {
            console_log!(
                "[push] user={recipient_id} mode=off -> atlandı (FCM yapılandırılmamış ya da 'off')"
            );
            return;
        }
    };
    let mode_name = match &mode {
        SendMode::Direct { .. } => "direct",
        SendMode::Relay { .. } => "relay",
    };

    #[derive(Deserialize)]
    struct TokRow {
        device_id: String,
        fcm_token: String,
    }
    let query = match recipient_device_id {
        Some(d) => db
            .prepare(
                "SELECT device_id, fcm_token FROM push_tokens WHERE user_id = ? AND device_id = ?",
            )
            .bind(&[d1_text(recipient_id), d1_text(d)]),
        None => db
            .prepare("SELECT device_id, fcm_token FROM push_tokens WHERE user_id = ?")
            .bind(&[d1_text(recipient_id)]),
    };
    let rows: Vec<TokRow> = match query {
        Ok(stmt) => match stmt.all().await {
            Ok(r) => r.results().unwrap_or_default(),
            Err(e) => {
                console_warn!("[push] user={recipient_id} mode={mode_name} token sorgusu FAIL: {e:?}");
                return;
            }
        },
        Err(e) => {
            console_warn!("[push] user={recipient_id} mode={mode_name} token sorgusu FAIL: {e:?}");
            return;
        }
    };
    if rows.is_empty() {
        // Not an error, and the single most useful thing to know: this device never registered, or
        // its token was deleted as stale. Without the line it cannot be told apart from a push that
        // WAS sent and then lost somewhere downstream.
        console_log!(
            "[push] user={recipient_id} mode={mode_name} token=0 -> gonderilmedi (kayitli cihaz yok)"
        );
        return;
    }
    let total = rows.len();
    let (mut ok, mut stale, mut failed) = (0usize, 0usize, 0usize);

    // NOTE (2026-06-26): wake debounce was REVERTED. A 20s per-recipient+device debounce was
    // suppressing LEGITIMATE follow-up messages that arrived just after a drain finished: no
    // wake → no delivery → single tick and no notification, a real field bug. `delivered_live`
    // (message.rs) ALREADY prevents wakes during a drain over an active WS, which made the
    // debounce both redundant and harmful. The real root of the storm was the WEDGE (a resend
    // loop), fixed by Fix-2/3 (coalesce + 5xx retry + boot-401 expedite). So every undelivered
    // message must get its wake — that is what correct delivery requires.
    for row in rows {
        let sent = match &mode {
            SendMode::Direct { project_id } => {
                send_wake(env, db, &row.fcm_token, project_id).await
            }
            SendMode::Relay { url } => send_wake_relay(url, &row.fcm_token).await,
        };
        match sent {
            Ok(true) => ok += 1,
            Ok(false) => {
                stale += 1;
                // Stale token → drop it, so later messages do not retry it for nothing. Logged per
                // device on purpose: the deletion is correct but invisible, and it permanently ends
                // push for that device. "Notifications just stopped" needs a trace to follow, and a
                // bulk deletion after an FCM 400 has bitten this project before.
                console_warn!(
                    "[push] user={recipient_id} cihaz={} token BAYAT -> silindi (bu cihaz artik uyandirilamaz)",
                    row.device_id
                );
                if let Ok(stmt) = db
                    .prepare("DELETE FROM push_tokens WHERE user_id = ? AND device_id = ?")
                    .bind(&[d1_text(recipient_id), d1_text(&row.device_id)])
                {
                    let _ = stmt.run().await;
                }
            }
            Err(e) => {
                failed += 1;
                console_warn!(
                    "[push] user={recipient_id} cihaz={} gonderim HATA: {e:?}",
                    row.device_id
                );
            }
        }
    }
    console_log!(
        "[push] user={recipient_id} mode={mode_name} token={total} ok={ok} bayat={stale} hata={failed}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // D-M8: a bare INVALID_ARGUMENT with NO token signal is Transient. A systematic 400
    // (our own payload/config bug) must not wipe the token registry — that regression is
    // exactly the self-concealing death of push.
    #[test]
    fn dm8_generic_invalid_argument_not_stale() {
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"Request contains an invalid argument."}}"#;
        assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Transient);
    }

    // A payload bug — a field we sent — must not kill the token.
    #[test]
    fn dm8_payload_field_violation_not_stale() {
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"Request contains an invalid argument.","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.android.priority","description":"Invalid value"}]}]}}"#;
        assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Transient);
    }

    // A violation on the token field itself → genuinely stale, so it gets deleted.
    #[test]
    fn dm8_token_field_violation_is_stale() {
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"The registration token is not a valid FCM registration token","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.token","description":"Invalid registration token"}]}]}}"#;
        assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Stale);
    }

    // No `details` at all, only "registration token" in the human-readable message → stale.
    #[test]
    fn dm8_registration_token_message_is_stale() {
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"The registration token is not a valid FCM registration token"}}"#;
        assert_eq!(classify_fcm_send(400, body), FcmSendOutcome::Stale);
    }

    // Empty or malformed body → conservatively KEEP the token (Transient).
    #[test]
    fn dm8_unparseable_body_not_stale() {
        assert_eq!(classify_fcm_send(400, ""), FcmSendOutcome::Transient);
        assert_eq!(classify_fcm_send(400, "{bozuk json"), FcmSendOutcome::Transient);
        assert_eq!(classify_fcm_send(404, ""), FcmSendOutcome::Transient);
    }

    // 404 UNREGISTERED → stale; 200 → sent.
    #[test]
    fn dm8_unregistered_stale_and_200_sent() {
        let body = r#"{"error":{"code":404,"status":"NOT_FOUND","message":"Requested entity was not found.","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#;
        assert_eq!(classify_fcm_send(404, body), FcmSendOutcome::Stale);
        assert_eq!(classify_fcm_send(200, ""), FcmSendOutcome::Sent);
        assert_eq!(classify_fcm_send(200, "anything"), FcmSendOutcome::Sent);
        // 5xx → Transient.
        assert_eq!(classify_fcm_send(503, "unavailable"), FcmSendOutcome::Transient);
    }
}

