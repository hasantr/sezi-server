//! FCM HTTP v1 — İÇERİKSİZ uyandırma push (Signal deseni). Mesaj İÇERİĞİ TAŞIMAZ:
//! yalnız `data:{type:"wake"}`. Google'a giden tek bilgi "bir push oldu + zaman"
//! (E2E korunur; içerik cihazda çözülür). Dışa-KAPALI felsefesiyle uyumlu.
//!
//! Akış: service-account (env secret `FCM_SERVICE_ACCOUNT` JSON) → RS256-imzalı JWT
//! → Google OAuth2 (`oauth2.googleapis.com/token`, jwt-bearer) → `access_token`
//! (module-global cache, ~1sa) → `fcm/v1/projects/{FCM_PROJECT_ID}/messages:send`.
//! RS256 saf-Rust `rsa` (deterministik PKCS1v15 — RNG yok). 404/UNREGISTERED → stale
//! token (caller `push_tokens`'tan siler).
//!
//! Config çözümü (owner self-service): per-key **env ÖNCE, D1 `server_config`
//! sonra** (cf_analytics `resolve_cfg` deseni). env set (bizim prod:
//! wrangler.toml `FCM_PROJECT_ID` + secret `FCM_SERVICE_ACCOUNT`) → D1'e HİÇ
//! gidilmez, bugünkü yol BİT-AYNI. env yoksa owner'ın `PATCH /admin/fcm-config`
//! ile app'ten girdiği D1 değerleri kullanılır; o da yoksa → push sessiz no-op
//! (FAIL-OPEN — FCM opsiyonel, worker normal çalışır; bugünkü "kurulu değil"
//! davranışı). Ayrıntı `resolve_project_id` / `resolve_service_account`.

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
//
// NOT (fcm-config self-service): owner app'ten YENİ service-account girerse bu
// cache eski SA ile alınmış token'ı süresi dolana dek (~1sa) kullanmaya devam
// edebilir (config-değişimi cache'i düşürmez). KABUL EDİLEBİLİR: izolate ömrü
// kısa (workerd sık geri-dönüştürür) + eski token Google'da geçerli kaldıkça
// push zaten çalışır; en geç ~1sa'de taze SA ile yenilenir.
static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

// ── Config çözümü — env-first / D1-fallback (cf_analytics `resolve_cfg` deseni) ──
//
// MEMOIZE EDİLMEDİ (bilinçli karar; self_provision thread_local deseni yerine
// per-send taze okuma): push gönderimi SEYREK — yalnız alıcı-offline mesaj başı
// tetiklenir ve aynı `maybe_push_wake` çağrısı push_tokens için ZATEN D1'e
// gidiyor → tek ek SELECT ihmal edilebilir. thread_local memoize ise owner'ın
// app'ten YENİ girdiği config'i izolate ömrü boyunca görmezdi ("kaydettim ama
// push gelmiyor" tuzağı — self_provision'daki anahtarlar sabit, bu config ise
// owner eliyle değişiyor). Taze okuma = kaydet → İLK push'ta devreye girer.
// env-set kurulumda (bizim prod) bu fonksiyonlar D1'e HİÇ gitmez (bit-aynı).
//
// GÜVENLİK (D1-saklama trade-off'u — admin/cf_config.rs ile AYNI):
// FCM_SERVICE_ACCOUNT içinde Google service-account private-key'i var; D1
// CF at-rest şifreli, worker Google OAuth imzası için plaintext okumak zorunda
// (decrypt-anahtarı olmayan bir şeyle şifrelenemez). Owner'ın KENDİ Firebase
// projesi, KENDİ sunucusu — E2E içerik DEĞİL (push zaten içeriksiz wake;
// anahtar sızsa bile mesaj içeriği açılamaz, yalnız sahte-wake atılabilir).
// Değer HİÇBİR endpoint'ten dönmez (yalnız worker-içi okuma); güvenlik-bilinçli
// owner env-secret'e taşırsa env HER ZAMAN kazanır.

/// Trim + boş → None (env ve D1 değerleri AYNI disiplinle normalize edilir —
/// cf_analytics `normalize` deseni).
fn normalize(raw: String) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// D1 `server_config` (0025 key-value) tek anahtar oku — FAIL-OPEN MUTLAK:
/// tablo yok (migration öncesi) / satır yok / D1 hatası → None → caller sessiz
/// no-op (push opsiyonel; fcm hiçbir isteği düşürmez).
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

/// Firebase proje-id: env var ÖNCE (bugünkü yol — bizim prod D1'e hiç gitmeden
/// BİT-AYNI), yoksa/boşsa D1 `fcm_project_id` (owner app'ten girdi). None =
/// FCM kurulu değil → caller sessiz no-op (bugünkü davranış).
async fn resolve_project_id(env: &Env, db: &D1Database) -> Option<String> {
    if let Some(v) = env.var("FCM_PROJECT_ID").ok().and_then(|v| normalize(v.to_string())) {
        return Some(v);
    }
    read_db_config(db, "fcm_project_id").await
}

/// Service-account JSON: env secret ÖNCE (bugünkü yol), yoksa D1
/// `fcm_service_account`. İçerik doğrulaması yazım anında (`PATCH
/// /admin/fcm-config` — geçerli JSON + client_email + private_key).
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

/// FCM kurulu mu (proje-id VE service-account ikisi de [env-veya-D1] mevcut) —
/// `/admin/stats` `fcm_configured` alanı + `PATCH /admin/fcm-config` cevabı.
/// WRITE-ONLY sözleşmenin okuma yüzü: değer değil yalnız bool sızar. HAFİF:
/// Google'a ÇIKMAZ, yalnız varlığa bakar; fail-open false (D1 binding yok →
/// kurulmamış say; stats ASLA 500 atmaz).
pub async fn is_configured(env: &Env) -> bool {
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return false,
    };
    resolve_project_id(env, &db).await.is_some()
        && resolve_service_account(env, &db).await.is_some()
}

/// Service-account JWT → OAuth2 access_token (cache'li). 60sn marj ile yeniler.
async fn get_access_token(env: &Env, db: &D1Database) -> Result<String> {
    let now = now_secs();
    if let Ok(guard) = TOKEN_CACHE.lock() {
        if let Some(c) = guard.as_ref() {
            if c.exp > now + 60 {
                return Ok(c.token.clone());
            }
        }
    }

    // env-first/D1-fallback. None = yarı-kurulu (proje-id var, SA yok) → Err —
    // bugünkü `env.secret(..)?` davranış-şekliyle aynı sınıf: caller console_warn
    // basar, o mesajın push'u atlanır (worker normal çalışır).
    let sa_json = resolve_service_account(env, db)
        .await
        .ok_or_else(|| Error::RustError("fcm: service_account yok (env+D1)".into()))?;
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
async fn send_wake(env: &Env, db: &D1Database, fcm_token: &str, project_id: &str) -> Result<bool> {
    let access_token = get_access_token(env, db).await?;
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
/// pending). Best-effort: config (env VEYA owner'ın app'ten girdiği D1) yoksa sessiz no-op
/// (FCM opsiyonel — kurulmamışsa worker normal çalışır). Stale token (`Ok(false)`) →
/// `push_tokens`'tan sil.
pub async fn maybe_push_wake(
    env: &Env,
    db: &D1Database,
    recipient_id: &str,
    recipient_device_id: Option<&str>,
) {
    // FCM kurulu değil (proje-id env'de de D1'de de yok) → sessiz no-op.
    // env-first: bizim prod (wrangler.toml FCM_PROJECT_ID) D1'e hiç gitmez.
    let project_id = match resolve_project_id(env, db).await {
        Some(p) => p,
        None => return,
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
        match send_wake(env, db, &row.fcm_token, &project_id).await {
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

