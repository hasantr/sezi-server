//! `PATCH /admin/fcm-config` — FCM push kurulumu, owner self-service
//! (cf_config.rs desen-ikizi; "herkes kendi sunucusunun admini, her şeyi
//! app'ten yönetir"). İlk kurulum minimum tutuldu (FCM şablondan çıktı) —
//! owner push'u SONRADAN Sezi uygulamasından açar: Firebase'de ücretsiz proje
//! + service-account JSON'u yapıştırır, `wrangler secret put` bilmesi gerekmez.
//!
//! GÜVENLİK SÖZLEŞMESİ (cf_config.rs ile birebir):
//! - **OWNER-ONLY**: `require_owner` — admin YETMEZ (service-account
//!   private-key taşır; yalnız sunucunun sahibi girer/değiştirir).
//! - **WRITE-ONLY**: değerler buradan yalnız YAZILIR; bu endpoint dahil HİÇBİR
//!   endpoint değerleri geri döndürmez. Cevap + `/admin/stats` yalnız
//!   `fcm_configured: bool` (var-mı) taşır — sızıntı yüzeyi sıfır.
//! - Saklama: D1 `server_config` (0025 key-value; CF at-rest şifreli).
//!   Trade-off cf_config'tekiyle AYNI: worker Google OAuth imzası için
//!   plaintext okumak zorunda (decrypt-anahtarı olmayan bir şeyle
//!   şifrelenemez). Owner'ın KENDİ Firebase projesi, KENDİ sunucusu; E2E
//!   içerik DEĞİL (push zaten içeriksiz wake — anahtar sızsa bile mesaj
//!   içeriği açılamaz). env-secret'e taşıyan owner'da env HER ZAMAN kazanır.
//! - Okuma zinciri push/fcm.rs'te: per-key **env ÖNCE, D1 sonra** (env-set
//!   kazanır — bizim prod bit-aynı); ikisi de yok → push sessiz no-op
//!   (FAIL-OPEN, bugünkü "kurulu değil" davranışı).

use crate::auth::middleware::{require_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct FcmConfigBody {
    /// Konvansiyon (cf_config/update_settings deseni): alan YOK → mevcut
    /// korunur; `""` (trim-sonrası boş) → satır-DELETE (temizle → push
    /// no-op'a döner); dolu → set.
    fcm_project_id: Option<String>,
    fcm_service_account: Option<String>,
}

/// Proje-id doğrulaması: Firebase proje ID'leri kısa ([a-z0-9-], 6-30 char);
/// 100 bol pay + kontrol karakteri yok (değer FCM send URL'sine giriyor:
/// `fcm.googleapis.com/v1/projects/{id}/messages:send` — enjeksiyon/DoS koruması).
fn project_id_ok(s: &str) -> bool {
    s.len() <= 100 && !s.chars().any(|c| c.is_control())
}

/// Service-account doğrulaması: ≤16KB (gerçek SA JSON ~2.4KB — bol pay, DoS
/// koruması) + geçerli JSON + fcm.rs'in GERÇEKTE kullandığı iki alan
/// (`ServiceAccount { client_email, private_key }`) dolu-string mevcut.
/// Yanlış dosya (ör. google-services.json — onda bu alanlar yok) burada ERKEN
/// reddedilir ki owner panelde anlasın; push sahada sessizce ölmesin.
fn service_account_ok(s: &str) -> bool {
    if s.len() > 16 * 1024 {
        return false;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return false;
    };
    let has_str = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .is_some_and(|x| !x.trim().is_empty())
    };
    has_str("client_email") && has_str("private_key")
}

pub async fn set_fcm_config(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // OWNER-ONLY — require_admin DEĞİL: service-account güçlü kimlik-bilgisi
    // (Google private-key), yalnız sunucu sahibi yönetir (cf-config sınıfı yetki).
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: FcmConfigBody = req.json().await.unwrap_or_default();
    if body.fcm_project_id.is_none() && body.fcm_service_account.is_none() {
        return json_err(400, "bad_request");
    }
    // Doğrulama yalnız DOLU değerlere — "" (temizle) her zaman geçerli.
    if let Some(v) = body.fcm_project_id.as_deref() {
        let t = v.trim();
        if !t.is_empty() && !project_id_ok(t) {
            return json_err(400, "bad_request");
        }
    }
    if let Some(v) = body.fcm_service_account.as_deref() {
        let t = v.trim();
        if !t.is_empty() && !service_account_ok(t) {
            return json_err(400, "bad_request");
        }
    }

    let db = ctx.env.d1("DB")?;
    apply(&db, "fcm_project_id", body.fcm_project_id).await?;
    apply(&db, "fcm_service_account", body.fcm_service_account).await?;

    // WRITE-ONLY cevap: değerler ASLA dönmez — yalnız "artık kurulu mu"
    // (proje-id VE service-account ikisi de [env-veya-D1] mevcutsa true;
    // fcm.rs env-first zinciriyle tutarlı — D1 temizlense bile env varsa true).
    let fcm_configured = crate::push::fcm::is_configured(&ctx.env).await;
    Response::from_json(&serde_json::json!({ "fcm_configured": fcm_configured }))
}

/// Tek anahtarı uygula. `server_config` key-value olduğundan cf_config'in
/// "SELECT-mevcudu-koru" dansı GEREKMEZ: alan-yok → satıra hiç dokunma (mevcut
/// korunur); "" → DELETE (temizle); dolu → upsert (`ON CONFLICT` yalnız value
/// günceller; created_at ilk-yazım damgası olarak kalır).
async fn apply(db: &D1Database, key: &str, new: Option<String>) -> Result<()> {
    let Some(raw) = new else {
        return Ok(()); // alan gelmedi → mevcut korunur
    };
    let t = raw.trim();
    if t.is_empty() {
        db.prepare("DELETE FROM server_config WHERE key = ?")
            .bind(&[d1_text(key)])?
            .run()
            .await?;
        return Ok(());
    }
    db.prepare(
        "INSERT INTO server_config (key, value, created_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(&[d1_text(key), d1_text(t), d1_int(now_secs() as i64)])?
    .run()
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proje_id_dogrulama() {
        assert!(project_id_ok("sezi-481e9"));
        assert!(project_id_ok("a"));
        // Kontrol karakteri → red (URL-enjeksiyon koruması).
        assert!(!project_id_ok("abc\ndef"));
        assert!(!project_id_ok(&"x".repeat(101)));
        assert!(project_id_ok(&"x".repeat(100)));
    }

    #[test]
    fn service_account_dogrulama() {
        // Geçerli: fcm.rs'in kullandığı iki alan dolu.
        assert!(service_account_ok(
            r#"{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"}"#
        ));
        // JSON değil → red (owner panelde erken anlar).
        assert!(!service_account_ok("bu json degil"));
        // Yanlış dosya (google-services.json'da client_email/private_key yok) → red.
        assert!(!service_account_ok(r#"{"project_info":{"project_id":"x"}}"#));
        // Alanlar var ama boş → red.
        assert!(!service_account_ok(
            r#"{"client_email":"","private_key":""}"#
        ));
        // private_key eksik → red.
        assert!(!service_account_ok(r#"{"client_email":"a@b.c"}"#));
        // 16KB üstü → red (DoS koruması).
        let big = format!(
            r#"{{"client_email":"a@b.c","private_key":"{}"}}"#,
            "k".repeat(17 * 1024)
        );
        assert!(!service_account_ok(&big));
    }
}
