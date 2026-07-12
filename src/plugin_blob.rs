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
use crate::d1util::{d1_int, d1_text};
use crate::groups::{group_role, is_group_admin};
use crate::respond::json_err;
use crate::utils::now_secs;
use worker::*;

/// Eklenti kodu blob tavanı — devasa-web bundle'a yeter (medya 50MB'ın altı), DoS-sınırı.
/// Core assign plaintext tavanı 8 MiB; XChaCha20-STREAM ciphertext'i chunk-başına ~16B tag
/// overhead ekler (8 MiB için ~2KB) → 8 MiB plaintext sınırdaki geçerli kod yüklenebilsin diye
/// 64 KiB pay (Codex#10: aksi sınırdaki kod worker'da 413 yerdi).
const MAX_CODE_SIZE: u64 = 8 * 1024 * 1024 + 64 * 1024;

/// JWT + cihaz-revoked + path param'ları + aktif-üyelik kapısı (ortak ön-koşul).
/// Ok → (user, room, id, role) — `role` PUT'ta admin-kontrolü için.
///
/// `pub(crate)`: `plugin_media` (üye-PUT'lu kardeş kanal) AYNI kapıyı yeniden
/// kullanır (device-revoked + aktif-üyelik) — admin-kontrolü orada YOK (role atlanır),
/// böylece tek-yerde-tanımlı IDOR/revoke kapısı iki kanalda ayrışamaz.
pub(crate) async fn gate(req: &Request, ctx: &RouteContext<()>) -> std::result::Result<(String, String, String, String), Response> {
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
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
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
    // FAZ 3: priority-overflow + per-depo max_bytes + PUT-fallback. Kalıcı sınıf → dolu
    // = 429 quota_exceeded/server_storage (asla otomatik-silme); tüm denemeler fail = 503.
    let store_id = match router
        .put_new(
            crate::storage::StorageClass::PluginCode,
            &crate::storage::code_key(&room_id, &blob_id),
            bytes,
            "application/octet-stream",
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => return crate::storage::placement_err_response(e),
    };
    // Envanter (plugin_code_objects, migration 0028) — İLK kez eklenti-kodu meta'sı
    // (bugüne dek "nerede" bilinemezdi). BEST-EFFORT: put zaten başarılı; meta-DB hatası
    // upload'ı KIRMAZ (put_code'un meta'sı YOKtu → meta-fail upload'ı hiç etkilemezdi =
    // davranış-değişmez). Eksik satırı günlük bakım backfill'i (R2 list → INSERT OR IGNORE)
    // yakalar. Kota sayaçlarına DAHİL DEĞİL (plan c.3: user_storage/server_stats bit-aynı).
    // ON CONFLICT DO UPDATE: kod overwrite'ında (yeni sürüm) size/store_id tazelenir.
    if let Ok(db) = ctx.env.d1("DB") {
        if let Ok(stmt) = db
            .prepare(
                "INSERT INTO plugin_code_objects (room_id, blob_id, uploader_id, size_bytes, store_id, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(room_id, blob_id) DO UPDATE SET \
                   uploader_id = excluded.uploader_id, size_bytes = excluded.size_bytes, store_id = excluded.store_id",
            )
            .bind(&[
                d1_text(&room_id),
                d1_text(&blob_id),
                d1_text(&user_id),
                d1_int(size as i64),
                d1_text(&store_id),
                d1_int(now_secs() as i64),
            ])
        {
            let _ = stmt.run().await;
        }
    }
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
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Faz 2 çoklu-depo: blob'un depo'sunu meta'dan çöz. plugin_code_objects Faz 1'de
    // YENİ (0028) → ESKİ kod-blob'ları günlük backfill'e kadar meta'SIZ olabilir: meta
    // yok → 'r2-primary' FALLBACK (eski blob hep R2'de; backfill sonrası meta-driven olur).
    // Yeni put_code'lar meta'yı inline yazar → anında meta-driven.
    let store_id = code_store_id(&ctx, &room_id, &blob_id)
        .await
        .unwrap_or_else(|| crate::storage::PRIMARY_STORE_ID.to_string());
    // FAZ 3 (plan f#2): depo erişilemez → 503 storage_backend_unavailable (retryable) +
    // router içinde fırsatçı health-işaret; yok → 404.
    match router
        .get(&store_id, &crate::storage::code_key(&room_id, &blob_id))
        .await
    {
        Ok(Some(obj)) => {
            let mut resp = Response::from_bytes(obj.bytes)?;
            resp.headers_mut()
                .set("content-type", "application/octet-stream")?;
            Ok(resp)
        }
        Ok(None) => json_err(404, "not_found"),
        Err(_) => json_err(503, "storage_backend_unavailable"),
    }
}

/// Kod-blob'un depo'su (plugin_code_objects.store_id) — Faz 2 çoklu-depo GET çözümlemesi.
/// Meta yok / D1-hata → None (çağıran 'r2-primary'ye fallback: eski un-backfill blob hep
/// R2'de). Best-effort: hata GET'i kırmaz, yalnız fallback-depoya düşer.
async fn code_store_id(ctx: &RouteContext<()>, room_id: &str, blob_id: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct StoreRow {
        store_id: String,
    }
    let db = ctx.env.d1("DB").ok()?;
    let row: Option<StoreRow> = db
        .prepare("SELECT store_id FROM plugin_code_objects WHERE room_id = ? AND blob_id = ? LIMIT 1")
        .bind(&[d1_text(room_id), d1_text(blob_id)])
        .ok()?
        .first(None)
        .await
        .ok()?;
    row.map(|r| r.store_id)
}
