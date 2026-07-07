//! Eklenti KODU blob deposu (Faz-4 server-code) — KALICI + grup-kapılı R2 blob.
//!
//! Eklenti kodu (html/bundle) artık wire'da inline taşınmaz (64KB envelope acısı +
//! devasa-web imkânsızdı); server'da kalıcı R2 blob'da ŞİFRELİ durur, cihazlar indirir.
//! Medya hattından (`media/handlers.rs`) AYRI çünkü semantik TERS:
//!   - ack-delete YOK + TTL YOK: kod yıllarca yaşar, her yeni cihaz/üye tekrar indirir.
//!   - IDOR kapatma: R2 anahtarı **room-scope'lu** (`plugin-code/{room}/{id}`) + her erişim
//!     aktif-üyelik + device-revoked kapısından geçer → medya M11 IDOR'u KOPYALANMAZ
//!     (medyada recipient/room ilişkisi serverda yok; burada path room'u var, üyelik kapılı).
//!
//! Server KÖR: blob opak ciphertext (XChaCha20-Poly1305 STREAM, anahtar yalnız grup E2E
//! kanalında — `PluginCodeRefV1.key_b64` Olm/epoch-key korumalı wire'da). Server kodu
//! OKUYAMAZ; bütünlük client'ta `blob_hash` (BLAKE3) + AEAD-tag ile çift-doğrulanır.

use crate::auth::jwt::device_id_from_token;
use crate::auth::middleware::{device_revoked, extract_bearer, require_auth};
use crate::groups::{group_role, is_group_admin};
use crate::respond::json_err;
use worker::*;

/// Eklenti kodu blob tavanı — devasa-web bundle'a yeter (medya 50MB'ın altı), DoS-sınırı.
/// Core assign plaintext tavanı 8 MiB; XChaCha20-STREAM ciphertext'i chunk-başına ~16B tag
/// overhead ekler (8 MiB için ~2KB) → 8 MiB plaintext sınırdaki geçerli kod yüklenebilsin diye
/// 64 KiB pay (Codex#10: aksi sınırdaki kod worker'da 413 yerdi).
const MAX_CODE_SIZE: u64 = 8 * 1024 * 1024 + 64 * 1024;

/// JWT + cihaz-revoked + path param'ları + aktif-üyelik kapısı (ortak ön-koşul).
/// Ok → (user, room, id, role) — `role` PUT'ta admin-kontrolü için.
async fn gate(req: &Request, ctx: &RouteContext<()>) -> std::result::Result<(String, String, String, String), Response> {
    let user_id = require_auth(req, &ctx.env)?;
    // Device-binding + revoked (B6 deseni): çıkarılmış/iptal cihaz token-TTL'i içinde
    // kod çekememeli/yükleyememeli.
    let token_device =
        extract_bearer(req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    let device_id = match token_device {
        Some(d) => d,
        None => return Err(json_err(403, "device_required").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    match device_revoked(&ctx.env, &user_id, &device_id).await {
        Ok(true) => return Err(json_err(401, "device_revoked").unwrap_or_else(|_| Response::empty().unwrap())),
        Ok(false) => {}
        Err(_) => return Err(json_err(500, "revoked_check_failed").unwrap_or_else(|_| Response::empty().unwrap())),
    }
    let room_id = match ctx.param("room") {
        Some(r) => r.clone(),
        None => return Err(json_err(400, "bad_request").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    let blob_id = match ctx.param("id") {
        Some(p) => p.clone(),
        None => return Err(json_err(400, "bad_request").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    // Aktif-üyelik kapısı (IDOR — üye-olmayan kodu çekemez/yükleyemez).
    let db = match ctx.env.d1("DB") {
        Ok(d) => d,
        Err(_) => return Err(json_err(500, "db_unavailable").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    let role = match group_role(&db, &room_id, &user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(json_err(403, "not_member").unwrap_or_else(|_| Response::empty().unwrap())),
        Err(_) => return Err(json_err(500, "role_check_failed").unwrap_or_else(|_| Response::empty().unwrap())),
    };
    Ok((user_id, room_id, blob_id, role))
}

/// `POST /plugin-blob/:room/:id` — eklenti kodu (şifreli) yükle. KALICI. Yalnız aktif üye.
pub async fn put_code(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, blob_id, role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Yalnız admin/owner kod YÜKLER (eklenti atamak admin işidir). Üye yükleyebilseydi
    // kötü-üye legit kodu garbage ile EZER → DoS (client hash-verify code-injection'ı keser
    // ama yükleme-yetkisini sınırlamak DoS-overwrite'ı kapatır). Üye yalnız İNDİRİR (GET).
    if !is_group_admin(&role) {
        return json_err(403, "not_admin");
    }
    // Lite kurulum (R2 OPSİYONEL): eklenti-kod deposu = R2 → binding yoksa server-saklı
    // kod yüklenemez; medya hattıyla AYNI temiz 503 (client nonretryable sayar). Yetki
    // kontrolünden SONRA (önce 403, sonra servis-durumu) ama rate-limit/body'den ÖNCE.
    if !crate::storage::MediaStore::available(&ctx.env) {
        return json_err(503, "media_not_configured");
    }
    // Per-user upload rate-limit (medya-upload deseni; R2 depolama/egress DoS guard).
    // KV binding OPSİYONEL (şablon-diyeti): yoksa limitsiz devam — bkz. ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("pcode:put:{user_id}"), 60, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    // Boyut tavanı (content-length ön-kontrol → büyük gövdeyi okumadan reddet).
    let size: u64 = req
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if size == 0 || size > MAX_CODE_SIZE {
        return json_err(413, "bad_size");
    }
    let bytes = req.bytes().await?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CODE_SIZE {
        return json_err(413, "bad_size");
    }
    let store = crate::storage::MediaStore::from_env(&ctx.env)?;
    store.put_code(&room_id, &blob_id, bytes).await?;
    Response::from_json(&serde_json::json!({ "ok": true, "blob_id": blob_id }))
}

/// `GET /plugin-blob/:room/:id` — eklenti kodu (şifreli) indir. Yalnız aktif üye.
pub async fn get_code(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // İndirme: HER aktif üye (admin-şart değil — üye eklentiyi kullanır).
    let (_user_id, room_id, blob_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Lite kurulum (R2 OPSİYONEL): binding yoksa kod indirilemez → put_code ile simetrik 503.
    if !crate::storage::MediaStore::available(&ctx.env) {
        return json_err(503, "media_not_configured");
    }
    let store = crate::storage::MediaStore::from_env(&ctx.env)?;
    match store.get_code(&room_id, &blob_id).await? {
        Some(bytes) => {
            let mut resp = Response::from_bytes(bytes)?;
            resp.headers_mut()
                .set("content-type", "application/octet-stream")?;
            Ok(resp)
        }
        None => json_err(404, "not_found"),
    }
}
