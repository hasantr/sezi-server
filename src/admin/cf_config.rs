//! `PATCH /admin/cf-config` — CF Analytics erişim bilgileri, owner self-service
//! ("herkes kendi sunucusunun admini, her şeyi app'ten yönetir" vizyonu; CLI'sız
//! kurulum: `wrangler secret put` yerine owner token'ı Sezi uygulamasından girer).
//!
//! GÜVENLİK SÖZLEŞMESİ (bu dosyanın varlık sebebi):
//! - **OWNER-ONLY**: `require_owner` — admin YETMEZ (CF API token güçlü
//!   kimlik-bilgisi; yalnız sunucunun sahibi girer/değiştirir).
//! - **WRITE-ONLY**: token buradan yalnız YAZILIR; bu endpoint dahil HİÇBİR
//!   endpoint token değerini geri döndürmez. Cevap + `/admin/stats` yalnız
//!   `cf_configured: bool` (var-mı) taşır — sızıntı yüzeyi sıfır.
//! - Saklama: D1 `server_settings` (CF at-rest şifreli). Worker Bearer için
//!   plaintext okur (operasyonel config; decrypt-anahtarı olmayan bir şeyle
//!   şifrelenemez). E2E içerik DEĞİL → server-kör ilkesini bozmaz (owner'ın
//!   kendi token'ı, kendi sunucusunda).
//! - Okuma zinciri cf_analytics.rs'te: per-key **env-secret ÖNCE, D1 sonra**
//!   (env-set kazanır); ikisi de yok → self-report (FAIL-OPEN, bugünkü davranış).

use crate::auth::middleware::{require_auth, require_owner};
use crate::d1util::{d1_int, d1_opt_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct CfConfigBody {
    /// Konvansiyon (update_settings deseni): alan YOK → mevcut korunur;
    /// `""` (trim-sonrası boş) → NULL (temizle → self-report'a döner);
    /// dolu → set.
    cf_api_token: Option<String>,
    cf_account_id: Option<String>,
}

/// Alan doğrulaması: makul uzunluk + kontrol karakteri yok (CF token ~40,
/// account-id 32 hex karakter; 200 bol pay — header-enjeksiyon/DoS koruması).
fn field_ok(s: &str) -> bool {
    s.len() <= 200 && !s.chars().any(|c| c.is_control())
}

/// Efektif değer: alan gelmemişse mevcut korunur; boş-string → NULL (temizle);
/// dolu → trim'lenmiş yeni değer.
fn effective(new: Option<String>, cur: Option<String>) -> Option<String> {
    match new {
        None => cur,
        Some(v) => {
            let t = v.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
    }
}

pub async fn set_cf_config(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // OWNER-ONLY — require_admin DEĞİL: CF token güçlü kimlik-bilgisi,
    // yalnız sunucu sahibi yönetir (set_role/transfer_ownership sınıfı yetki).
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: CfConfigBody = req.json().await.unwrap_or_default();
    if body.cf_api_token.is_none() && body.cf_account_id.is_none() {
        return json_err(400, "bad_request");
    }
    if body.cf_api_token.as_deref().is_some_and(|v| !field_ok(v))
        || body.cf_account_id.as_deref().is_some_and(|v| !field_ok(v))
    {
        return json_err(400, "bad_request");
    }

    let db = ctx.env.d1("DB")?;
    // Mevcut değerleri oku — alan gelmemişse korunur (update_settings deseni).
    // NOT: bu SELECT yalnız korumak için; değerler HİÇBİR cevaba yazılmaz.
    #[derive(Deserialize)]
    struct CurRow {
        cf_api_token: Option<String>,
        cf_account_id: Option<String>,
    }
    let cur: Option<CurRow> = db
        .prepare("SELECT cf_api_token, cf_account_id FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await?;
    let (cur_token, cur_account) = cur
        .map(|c| (c.cf_api_token, c.cf_account_id))
        .unwrap_or((None, None));
    let new_token = effective(body.cf_api_token, cur_token);
    let new_account = effective(body.cf_account_id, cur_account);

    // Upsert — update_settings deseni. INSERT yolu (satır-yok; 0003 seed'i
    // sayesinde pratikte olmaz) diğer kolonları şema DEFAULT'larına bırakır;
    // ON CONFLICT yalnız cf kolonlarını günceller (name/retention'a DOKUNMAZ).
    let now = now_secs();
    db.prepare(
        "INSERT INTO server_settings (id, cf_api_token, cf_account_id, updated_at)
         VALUES (1, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            cf_api_token = excluded.cf_api_token,
            cf_account_id = excluded.cf_account_id,
            updated_at = excluded.updated_at",
    )
    .bind(&[
        d1_opt_text(new_token.as_deref()),
        d1_opt_text(new_account.as_deref()),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    // WRITE-ONLY cevap: token DEĞERİ asla dönmez — yalnız "artık kurulu mu"
    // (env-secret VEYA D1; env-first zincirle tutarlı — D1 temizlense bile
    // env token'ı varsa true).
    let cf_configured = crate::cf_analytics::is_configured(&ctx.env).await;
    Response::from_json(&serde_json::json!({ "cf_configured": cf_configured }))
}
