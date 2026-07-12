//! Üye-yüklenebilir KALICI eklenti-MEDYA blob kanalı — `plugin_blob` (eklenti KODU)
//! deseninin ÜYE-PUT'lu, büyük-boyutlu kardeşi.
//!
//! İki mevcut kanalın ORTASI (kasıtlı melez):
//!   - `plugin_blob`'dan MİRAS: room-scope R2 anahtarı (IDOR kapalı) + aktif-üyelik +
//!     device-revoked kapısı (ORTAK `plugin_blob::gate`) + KALICI (TTL yok, ack-delete yok).
//!   - `media`'dan MİRAS: 50 MiB tavan + kota+usage muhasebesi (AYNI `check_upload` /
//!     `media_added` / `count_bump` sayaçları → depolama cap'i İKİ kanalın TOPLAMINA uygulanır).
//!
//! `plugin_blob`'dan AYRILAN tek nokta: admin-kapısı YOK. Herhangi bir aktif üye yükler
//! (eklenti-içi kullanıcı-üretimli medya: fotoğraf/dosya). KOD'u yalnız admin yükler
//! (legit kodu ezme-DoS'u kapatmak için); MEDYA kullanıcı-verisi → üye-PUT.
//!
//! Server KÖR: gövde/yanıt opak ciphertext (client E2E şifreler; anahtar grup kanalında).
//! Meta `plugin_media_objects` (0026) — `media_objects`'ten AYRI: `expires_at` YOK
//! (kalıcı; günlük cleanup cron'u bu tabloya DOKUNMAZ) → kota reconcile'ı iki tabloyu
//! da toplar (bkz. `usage::reconcile_storage`).

use crate::d1util::{d1_int, d1_text};
use crate::plugin_blob::gate;
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// Üye eklenti-medyası blob tavanı — `media` kanalıyla AYNI (50 MiB). E2E-ciphertext
/// gövde bu ham-tavana kadar (client zaten plaintext'i altında tutar).
const MAX_PLUGIN_MEDIA_SIZE: u64 = 50 * 1024 * 1024;

/// `POST /plugin-media/:room/:id` — üye eklenti-medyası (şifreli) yükle. KALICI.
/// Auth: o odanın HERHANGİ aktif üyesi (admin ŞART DEĞİL). Kota+usage `media` ile
/// AYNI sayaçlara işlenir. İdempotent: aynı (room,id) tekrar → 200 (re-upload YOK).
pub async fn put_media(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Kapı: aktif-üye + device-revoked (plugin_blob ile ORTAK). `role` ATLANIR —
    // admin şart değil (media gibi herhangi üye yükler); üyelik = gate'in Ok'u zaten kanıtlar.
    let (user_id, room_id, blob_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Lite kurulum (R2 OPSİYONEL): binding yoksa temiz 503 (media/plugin_blob ile simetrik;
    // client nonretryable sayar). Yetki-kapısından SONRA, rate-limit/body'den ÖNCE.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Per-user upload rate-limit — media-upload ile AYNI sabitler (60/5dk) + AYNI altyapı
    // (KV opsiyonel; binding yoksa fail-open limitsiz). R2 depolama/egress DoS guard.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plugmedia:put:{user_id}"), 60, 5 * 60).await {
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
    if size == 0 || size > MAX_PLUGIN_MEDIA_SIZE {
        return json_err(413, "bad_size");
    }
    let db = ctx.env.d1("DB")?;
    // İDEMPOTENT (retry-güvenli): aynı (room,id) zaten varsa 200 döner — client blob_id'yi
    // RASTGELE üretir (metadata-privacy; içerik-adres değil) → çakışma pratikte yalnız retry.
    // Re-upload YOK (50 MiB gövde okunmaz) + kota ÇİFT-SAYILMAZ (check_upload'a hiç girilmez).
    // plugin_blob'un overwrite-idempotent'i + core client'ın "2xx=başarı" sözleşmesiyle uyumlu.
    if let Some(existing) = existing_size(&db, &room_id, &blob_id).await? {
        return Response::from_json(&serde_json::json!({ "id": blob_id, "size": existing }));
    }
    // Kota Faz-1a (ZORLAMA): `media` ile AYNI check_upload (server_stats + user_storage vs
    // owner cap'leri). FAIL-OPEN: cap/sayaç okunamazsa reddetme YOK; NULL cap = sınırsız.
    // Gövde buffer'lanmadan ÖNCE (reddedilecek 50 MiB'ı belleğe almanın anlamı yok).
    if let Some(scope) = crate::quota::check_upload(&db, &user_id, size as i64).await {
        let resp = Response::from_json(&serde_json::json!({ "error": "quota_exceeded", "scope": scope }))?;
        return Ok(resp.with_status(429));
    }
    let bytes = req.bytes().await?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PLUGIN_MEDIA_SIZE {
        return json_err(413, "bad_size");
    }
    // R2-ÖNCE, meta-SONRA (media'nın TERSİ — BİLİNÇLİ): plugin-media'nın TTL/cleanup
    // cron'u YOK. media meta-önce yazar çünkü cleanup D1-tabanlı (R2-önce olsaydı
    // meta'sız blob'u cron HİÇ görmez = öksüz). Burada cleanup HİÇ yok → phantom meta
    // (R2 fail'i sonrası) kalıcı-kota-şişmesi + GET-404 üretirdi. R2 başarılıysa meta
    // yazılır; meta fail → client retry (R2 idempotent-overwrite + meta yeniden-INSERT) self-heal.
    // put_new → yazılan store_id döner (R2-önce/meta-sonra disiplini korunur: meta
    // put'tan SONRA yazılır → phantom-meta yok). Faz 1 tek-depo: store_id='r2-primary'.
    // FAZ 3: priority-overflow + per-depo max_bytes + PUT-fallback (degrade-yazma). Kalıcı
    // sınıf → dolu = 429 quota_exceeded/server_storage; tüm denemeler PUT-fail = 503.
    // R2-önce/meta-sonra disiplini korunur: hata'da meta HİÇ yazılmaz (phantom-meta yok).
    let store_id = match router
        .put_new(
            crate::storage::StorageClass::PluginMedia,
            &crate::storage::plugin_media_key(&room_id, &blob_id),
            bytes,
            "application/octet-stream",
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => return crate::storage::placement_err_response(e),
    };
    // Meta INSERT = kota gerçeğinin kaynağı (reconcile buradan hesaplar). ON CONFLICT
    // DO NOTHING RETURNING → yalnız GERÇEKTEN eklenen satır sayaçlara işlenir: iki
    // eşzamanlı PUT'tan (existence-check'i ikisi de geçse bile) biri kaybeder → çift-sayım yok.
    if insert_meta(&db, &room_id, &blob_id, &user_id, size as i64, &store_id).await? {
        // Kota Faz-0 (SHADOW) + Faz-1c (SALT-SAYIM): media ile AYNI sayaçlar. BEST-EFFORT
        // (sayaç hatası upload'ı KIRMAZ; günlük reconcile drift'i onarır).
        crate::usage::media_added(&db, &user_id, size as i64).await;
        crate::usage::count_bump(&db, "upload_bytes", size as i64).await;
        crate::usage::count_bump(&db, "upload_count", 1).await;
    }
    Response::from_json(&serde_json::json!({ "id": blob_id, "size": size }))
}

/// `GET /plugin-media/:room/:id` — üye eklenti-medyası (şifreli) indir. Aktif üye +
/// device-revoked kapılı (plugin_blob GET deseni). Rate 600/5dk (media-download eş).
pub async fn get_media(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, room_id, blob_id, _role) = match gate(&req, &ctx).await {
        Ok(t) => t,
        Err(resp) => return Ok(resp),
    };
    // Lite kurulum: binding yoksa put ile simetrik 503.
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // Per-user download rate-limit — media-download ile AYNI (600/5dk; R2-egress DoS guard).
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plugmedia:get:{user_id}"), 600, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    // Faz 2 çoklu-depo: blob'un depo'sunu meta'dan çöz (plugin_media_objects.store_id).
    // Migration 0028 store_id kolonuna DEFAULT 'r2-primary' verdi → ESKİ satırlar da dolu;
    // put HER ZAMAN store_id yazar (backfill'siz kanal) → meta yok = blob hiç yüklenmemiş → 404.
    let db = ctx.env.d1("DB")?;
    let store_id = match media_store_id(&db, &room_id, &blob_id).await? {
        Some(s) => s,
        None => return json_err(404, "not_found"),
    };
    // FAZ 3 (plan f#2): depo erişilemez → 503 storage_backend_unavailable + fırsatçı
    // health-işaret (router içinde); yok → 404.
    match router
        .get(
            &store_id,
            &crate::storage::plugin_media_key(&room_id, &blob_id),
        )
        .await
    {
        Ok(Some(obj)) => {
            let bytes = obj.bytes;
            // Kota Faz-1c (SALT-SAYIM): yalnız BAŞARILI indirme günlük sayaçlara — media ile
            // AYNI. bytes zaten elde (ekstra sorgu yok). BEST-EFFORT (sayaç hatası indirmeyi kırmaz).
            let n = bytes.len() as i64;
            crate::usage::count_bump(&db, "download_count", 1).await;
            crate::usage::count_bump(&db, "download_bytes", n).await;
            let mut resp = Response::from_bytes(bytes)?;
            let headers = resp.headers_mut();
            headers.set("content-type", "application/octet-stream")?;
            headers.set("cache-control", "private, no-store")?;
            Ok(resp)
        }
        Ok(None) => json_err(404, "not_found"),
        Err(_) => json_err(503, "storage_backend_unavailable"),
    }
}

/// Blob'un depo'su (plugin_media_objects.store_id) — Faz 2 çoklu-depo GET çözümlemesi.
/// Meta yok → None (blob hiç yüklenmemiş → çağıran 404). Tek-depoda hep 'r2-primary'.
async fn media_store_id(db: &D1Database, room_id: &str, blob_id: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct StoreRow {
        store_id: String,
    }
    let row: Option<StoreRow> = db
        .prepare("SELECT store_id FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? LIMIT 1")
        .bind(&[d1_text(room_id), d1_text(blob_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.store_id))
}

/// (room,id) meta satırı VAR MI? Varsa `size_bytes` döner (idempotent-PUT kısa-devresi).
async fn existing_size(db: &D1Database, room_id: &str, blob_id: &str) -> Result<Option<i64>> {
    #[derive(Deserialize)]
    struct SizeRow {
        size_bytes: i64,
    }
    let row: Option<SizeRow> = db
        .prepare("SELECT size_bytes FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? LIMIT 1")
        .bind(&[d1_text(room_id), d1_text(blob_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.size_bytes))
}

/// Meta'yı yaz; GERÇEKTEN eklendi mi döner. `ON CONFLICT DO NOTHING RETURNING` →
/// yarış-güvenli çift-sayım koruması (kaybeden izolat 0 satır alır → sayaç bump ATLANIR).
async fn insert_meta(
    db: &D1Database,
    room_id: &str,
    blob_id: &str,
    uploader_id: &str,
    size: i64,
    store_id: &str,
) -> Result<bool> {
    #[derive(Deserialize)]
    struct IdRow {
        #[allow(dead_code)]
        blob_id: String,
    }
    let now = now_secs() as i64;
    let res = db
        .prepare(
            "INSERT INTO plugin_media_objects (room_id, blob_id, uploader_id, size_bytes, store_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(room_id, blob_id) DO NOTHING \
             RETURNING blob_id",
        )
        .bind(&[
            d1_text(room_id),
            d1_text(blob_id),
            d1_text(uploader_id),
            d1_int(size),
            d1_text(store_id),
            d1_int(now),
        ])?
        .all()
        .await?;
    Ok(res.results::<IdRow>().map(|r| !r.is_empty()).unwrap_or(false))
}
