//! FCM HTTP v1 — CONTENTLESS wake push (the Signal pattern). It carries NO message
//! content, only `data:{type:"wake"}` — and, for a device that cannot be woken, a fixed generic
//! notification (`style.rs`). All Google learns is "a push happened, at this
//! time": E2E is preserved and the content is decrypted on the device. That matches the
//! closed-to-the-outside philosophy.
//!
//! Flow: service account (env secret `FCM_SERVICE_ACCOUNT`, JSON) → RS256-signed JWT →
//! Google OAuth2 (`oauth2.googleapis.com/token`, jwt-bearer) → `access_token` (cached
//! module-globally, ~1h) → `fcm/v1/projects/{FCM_PROJECT_ID}/messages:send`. RS256 comes
//! from the pure-Rust `rsa` crate (deterministic PKCS1v15, so no RNG is needed).
//! 404/UNREGISTERED means the token is stale and the caller deletes it from `push_tokens`.
//!
//! This file is the two senders — Google directly and the shared push relay. Which one a wake
//! uses is `config.rs`; the wake itself (tokens, verdicts, deletes) is `wake.rs`.

use std::sync::Mutex;

use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde::Deserialize;
use sha2::Sha256;
use worker::*;

use super::style::{fcm_message, relay_body, WakeStyle};
use crate::utils::{b64u_encode, now_secs};

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String, // PEM PKCS8 (newlines may arrive `\n`-escaped)
}

#[derive(serde::Serialize, Deserialize)]
struct CachedToken {
    token: String,
    exp: u64, // unix seconds; refresh before this
}

// Module-global OAuth token cache, living as long as the warm isolate — NOT tied to DO memory.
// workerd is single-threaded, so the Mutex is effectively a no-op.
//
// A config change does not invalidate it: after the owner enters a NEW service account the
// token from the old one may still be used until it expires (~1h). Acceptable — isolates recycle
// often, and an old token Google still accepts keeps push working meanwhile.
static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

/// Where the OAuth token is shared between isolates: the KV namespace the rate limits already use.
///
/// The isolate cache alone was enough while every wake ran in the worker. Since D8 a member's wake
/// runs in that member's inbox DO, and every COLD DO isolate minted its own token — a D1 read, an
/// RSA signature and a call to Google for each — so a class message could mint dozens (the D8
/// review's F5). One KV read now finds the token another isolate minted. The token is a
/// short-lived bearer for sending wakes, in the deployment's own storage beside the service
/// account key that D1 already holds; like the isolate cache, it may outlive a service-account
/// change by up to an hour.
const SHARED_TOKEN_KEY: &str = "fcm:oauth:v1";

/// Service-account JWT → OAuth2 access_token, cached per isolate and shared through KV, refreshed
/// with a 60s margin. `sa_json` is the service account the wake's one config read already holds
/// (`config::read`), so minting costs no D1 read of its own.
async fn get_access_token(env: &Env, sa_json: &str) -> Result<String> {
    let now = now_secs();
    if let Ok(guard) = TOKEN_CACHE.lock() {
        if let Some(c) = guard.as_ref() {
            if c.exp > now + 60 {
                return Ok(c.token.clone());
            }
        }
    }
    let kv = env.kv("RATE_LIMIT").ok();
    if let Some(kv) = &kv {
        if let Ok(Some(c)) = kv.get(SHARED_TOKEN_KEY).json::<CachedToken>().await {
            if c.exp > now + 60 {
                let token = c.token.clone();
                if let Ok(mut guard) = TOKEN_CACHE.lock() {
                    *guard = Some(c);
                }
                return Ok(token);
            }
        }
    }

    let sa: ServiceAccount = serde_json::from_str(sa_json)
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
    let cached = CachedToken { token: tr.access_token.clone(), exp: now + tr.expires_in };
    // Shared until shortly before it expires (KV's shortest TTL is 60 s). Best-effort: without
    // it the next cold isolate simply mints its own.
    if let (Some(kv), Ok(json)) = (&kv, serde_json::to_string(&cached)) {
        if let Ok(put) = kv.put(SHARED_TOKEN_KEY, json) {
            let _ = put.expiration_ttl(tr.expires_in.saturating_sub(120).max(60)).execute().await;
        }
    }
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        *guard = Some(cached);
    }
    Ok(tr.access_token)
}

/// What one direct send came to, as the wake acts on it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectSend {
    Sent,
    /// UNREGISTERED/invalid: the caller deletes the token from `push_tokens`.
    Stale,
    /// Google says this token belongs to ANOTHER Firebase project (`SENDER_ID_MISMATCH`): these
    /// credentials can never wake it. The caller resends through the shared relay (K8).
    SenderMismatch,
    /// Anything else: the token is kept, the wake for it is lost, the next message retries.
    Failed(String),
}

/// Send one CONTENTLESS wake push to a device through the owner's own project.
pub(crate) async fn send_wake(
    env: &Env,
    service_account: &str,
    fcm_token: &str,
    project_id: &str,
    style: WakeStyle,
) -> DirectSend {
    match send_wake_inner(env, service_account, fcm_token, project_id, style).await {
        Ok(d) => d,
        Err(e) => DirectSend::Failed(format!("{e:?}")),
    }
}

async fn send_wake_inner(
    env: &Env,
    service_account: &str,
    fcm_token: &str,
    project_id: &str,
    style: WakeStyle,
) -> Result<DirectSend> {
    let access_token = get_access_token(env, service_account).await?;
    let url = format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send");
    // data-only, or data plus a generic notification for a device that cannot be woken
    // (`style.rs`). Neither carries content.
    let payload = fcm_message(fcm_token, style).to_string();
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
        return Ok(DirectSend::Sent);
    }
    // D-M8: on EVERY non-200 read the body and look for a POSITIVE signal via
    // `classify_fcm_send`. An ambiguous or systematic 400 — typically a bug in our own
    // payload or config — must NOT delete the token; only a 404 UNREGISTERED, or a 400 in
    // which FCM points at the token itself, is stale.
    let body = resp.text().await.unwrap_or_default();
    Ok(match classify_fcm_send(code, &body) {
        FcmSendOutcome::Sent => DirectSend::Sent,
        FcmSendOutcome::Stale => DirectSend::Stale,
        FcmSendOutcome::SenderMismatch => DirectSend::SenderMismatch,
        // A temporary failure, so the token is KEPT (the caller warns; the next message or
        // alarm retries).
        FcmSendOutcome::Transient => DirectSend::Failed(format!("fcm: send {code}")),
    })
}

/// Classification of an FCM `messages:send` response. A token is DELETED only on a POSITIVE stale
/// signal: 404 + UNREGISTERED, or a 400 where FCM blames the registration token itself (a
/// `fieldViolations` entry for `message.token`, or "registration token" in `error.message`). Every
/// other non-200 — an ambiguous INVALID_ARGUMENT, a payload bug of ours, a 5xx, a malformed body —
/// is `Transient` and KEEPS the token, so a systematic 400 cannot wipe the whole registry and kill
/// push silently.
///
/// `SenderMismatch` is the one answer that says "THESE credentials can never reach THIS token"
/// (K8): see `body_signals_sender_mismatch` for why it is the only one.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FcmSendOutcome {
    Sent,
    Stale,
    SenderMismatch,
    Transient,
}

pub(crate) fn classify_fcm_send(code: u16, body: &str) -> FcmSendOutcome {
    if code == 200 {
        return FcmSendOutcome::Sent;
    }
    if code == 404 && body.contains("UNREGISTERED") {
        return FcmSendOutcome::Stale;
    }
    if code == 400 && body_signals_bad_token(body) {
        return FcmSendOutcome::Stale;
    }
    if body_signals_sender_mismatch(body) {
        return FcmSendOutcome::SenderMismatch;
    }
    FcmSendOutcome::Transient
}

/// Does the body carry FCM's own `SENDER_ID_MISMATCH` error code? Read from the structured
/// `error.details[].errorCode` of a `google.firebase.fcm.v1.FcmError`, never from prose.
///
/// Why this code and no other (K8): falling back to the shared relay is right only when the TOKEN
/// was minted by another project — the published app's, which the relay serves — and this is the
/// one FCM answer that says so. The 403 neighbours do not: a bare `PERMISSION_DENIED` (the FCM API
/// disabled in the owner's project, a service account without the messaging role) and a 401
/// `UNAUTHENTICATED` / `THIRD_PARTY_AUTH_ERROR` are faults of the CREDENTIALS, true for every
/// token, the owner's own build's included. Switching a server to the relay on them would take an
/// own-build server's working project away over a fixable IAM slip, and tell its owner the wrong
/// story ("cannot reach the published app"). They stay transient, as before.
fn body_signals_sender_mismatch(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    v["error"]["details"]
        .as_array()
        .is_some_and(|ds| ds.iter().any(|d| d["errorCode"].as_str() == Some("SENDER_ID_MISMATCH")))
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
/// its own service account, and the resend of a wake Google refused for the owner's own project
/// (K8). Ok(true) = sent, Ok(false) = STALE (the caller deletes it from push_tokens; the relay forwards FCM's
/// UNREGISTERED signal as `stale:true`), Err = transient (429 / 5xx / network).
pub(crate) async fn send_wake_relay(relay_url: &str, fcm_token: &str, style: WakeStyle) -> Result<bool> {
    let url = format!("{}/wake", relay_url.trim_end_matches('/'));
    let payload = relay_body(fcm_token, style).to_string();
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

#[cfg(test)]
#[path = "fcm_tests.rs"]
mod tests;
