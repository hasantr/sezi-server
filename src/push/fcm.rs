//! FCM HTTP v1 — İÇERİKSİZ uyandırma push (Signal deseni). Mesaj İÇERİĞİ TAŞIMAZ:
//! yalnız `data:{type:"wake"}`. Google'a giden tek bilgi "bir push oldu + zaman"
//! (E2E korunur; içerik cihazda çözülür). Dışa-KAPALI felsefesiyle uyumlu.
//!
//! Akış: service-account (env secret `FCM_SERVICE_ACCOUNT` JSON) → RS256-imzalı JWT
//! → Google OAuth2 (`oauth2.googleapis.com/token`, jwt-bearer) → `access_token`
//! (module-global cache, ~1sa) → `fcm/v1/projects/{FCM_PROJECT_ID}/messages:send`.
//! RS256 saf-Rust `rsa` (deterministik PKCS1v15 — RNG yok). 404/UNREGISTERED → stale
//! token (caller `push_tokens`'tan siler).

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
    private_key: String, // PEM PKCS8 (\n kaçışlı olabilir)
}

struct CachedToken {
    token: String,
    exp: u64, // unix-secs; bu zamandan önce yenile
}

// Module-global OAuth token cache (warm-isolate ömrü). Codex: DO-memory'ye BAĞLAMA.
// workerd tek-thread → Mutex no-op; isolate geri-dönüşümünde cache sıfırlanır (yeniden alınır).
static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

/// Service-account JWT → OAuth2 access_token (cache'li). 60sn marj ile yeniler.
async fn get_access_token(env: &Env) -> Result<String> {
    let now = now_secs();
    if let Ok(guard) = TOKEN_CACHE.lock() {
        if let Some(c) = guard.as_ref() {
            if c.exp > now + 60 {
                return Ok(c.token.clone());
            }
        }
    }

    let sa_json = env.secret("FCM_SERVICE_ACCOUNT")?.to_string();
    let sa: ServiceAccount = serde_json::from_str(&sa_json)
        .map_err(|e| Error::RustError(format!("fcm: service_account parse: {e}")))?;
    // JSON-string'te private_key satır-sonları `\n` kaçışlı olabilir → gerçek newline'a çevir.
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

/// Bir cihaza İÇERİKSİZ uyandırma push'u. Dönüş: `Ok(true)`=gönderildi, `Ok(false)`=token
/// STALE (UNREGISTERED/geçersiz → caller `push_tokens`'tan silmeli), `Err`=geçici hata.
async fn send_wake(env: &Env, fcm_token: &str, project_id: &str) -> Result<bool> {
    let access_token = get_access_token(env).await?;
    let url = format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send");
    // data-ONLY (notification yok) → Android terminated'da onBackgroundMessage tetiklenir
    // + içerik taşımaz. priority=high → doze'dan uyandırır.
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
    // Stale-token: FCM 404 (UNREGISTERED) ya da 400 (INVALID_ARGUMENT — kayıtsız/biçimsiz token).
    if code == 404 || code == 400 {
        let body = resp.text().await.unwrap_or_default();
        if body.contains("UNREGISTERED") || body.contains("INVALID_ARGUMENT") {
            return Ok(false);
        }
    }
    Err(Error::RustError(format!("fcm: send {code}")))
}

/// Alıcı OFFLINE (delivered_live=false) → kayıtlı push-token'larına içeriksiz wake yolla.
/// `recipient_device_id` Some → yalnız o cihaz; None → kullanıcının TÜM cihazları (device-blind
/// pending). Best-effort: secret/var yoksa sessiz no-op (FCM opsiyonel — kurulmamışsa worker
/// normal çalışır). Stale token (`Ok(false)`) → `push_tokens`'tan sil.
pub async fn maybe_push_wake(
    env: &Env,
    db: &D1Database,
    recipient_id: &str,
    recipient_device_id: Option<&str>,
) {
    // FCM kurulu değil (proje-id/secret yok) → sessiz no-op.
    let project_id = match env.var("FCM_PROJECT_ID") {
        Ok(v) => v.to_string(),
        Err(_) => return,
    };
    if project_id.is_empty() {
        return;
    }

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
            Err(_) => return,
        },
        Err(_) => return,
    };

    // NOT (2026-06-26): wake-debounce GERİ ALINDI. Recipient+device 20sn-debounce, drain bittikten
    // sonra gelen MEŞRU sonraki mesajları bastırıyordu (wake yok → teslim yok → tek-tik + bildirim
    // yok = saha-bug). `delivered_live` (message.rs) ZATEN drain-sırasında [aktif-WS] wake'i önlüyor →
    // debounce redundant + zararlıydı. Storm'un asıl kökü WEDGE'ti (resend-loop) → Fix-2/3 (coalesce +
    // 5xx-retry + boot-401-expedite) ile çözüldü → her undelivered mesaj wake almalı (doğru teslim).
    for row in rows {
        match send_wake(env, &row.fcm_token, &project_id).await {
            Ok(true) => {}
            Ok(false) => {
                // Stale token → temizle (sonraki mesajlarda boşa deneme yok).
                if let Ok(stmt) = db
                    .prepare("DELETE FROM push_tokens WHERE user_id = ? AND device_id = ?")
                    .bind(&[d1_text(recipient_id), d1_text(&row.device_id)])
                {
                    let _ = stmt.run().await;
                }
            }
            Err(e) => {
                console_warn!("fcm: wake send fail user={recipient_id}: {e:?}");
            }
        }
    }
}

