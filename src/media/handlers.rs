use crate::auth::middleware::require_auth;
use crate::d1util::{d1_int, d1_text};
use crate::respond::{json_err, json_err_msg};
use crate::utils::now_secs;
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

const MAX_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB

pub async fn upload(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };

    // Lite kurulum (R2 OPSİYONEL): MEDIA binding'i yoksa medya hattı kapalı → EN BAŞTA
    // (auth'tan sonra, rate-limit/kota/D1'den ÖNCE) temiz 503. D1-insert'e HİÇ girilmez:
    // binding'siz kurulumda öksüz meta satırı oluşmaz, sayaçlar şişmez. Client tarafı
    // "media_not_configured"ı nonretryable sayar (op_result.rs) — owner dashboard'dan
    // binding ekleyene dek her deneme 503 kalacağı için retry anlamsız.
    if !crate::storage::MediaStore::available(&ctx.env) {
        return json_err(503, "media_not_configured");
    }

    // S2 (Fable HIGH — kota/DoS): per-user upload rate-limit. Sürekli 50MB upload
    // R2 depolama + CF egress faturasını şişirebiliyordu (turn.rs bütçe-bekçisi
    // medyada yok). KV sliding-window (auth redeem/verify ile AYNI altyapı). 60
    // upload / 5dk: meşru medya-paylaşımının çok üstü, otomatik-abuse'ü keser.
    let kv = ctx.env.kv("RATE_LIMIT")?;
    if !crate::ratelimit::check_rate_limit(&kv, &format!("media:upload:{user_id}"), 60, 5 * 60)
        .await?
    {
        return json_err(429, "rate_limited");
    }

    let size_str = req.headers().get("content-length").ok().flatten();
    let size: u64 = match size_str.and_then(|s| s.parse().ok()) {
        Some(n) if n > 0 && n <= MAX_SIZE => n,
        Some(_) => return json_err_msg(413, "bad_size", &MAX_SIZE.to_string()),
        None => return json_err(411, "content_length_required"),
    };

    // Kota Faz-1a (ZORLAMA): owner cap koyduysa ve used+size aşıyorsa 429.
    // FAIL-OPEN: cap/sayaç okunamazsa reddetme YOK (quota.rs); NULL cap = sınırsız
    // → default kurulumda davranış değişmez. Body buffer'lanmadan ÖNCE kontrol
    // (reddedilecek 50MiB'ı belleğe almanın anlamı yok).
    let db = ctx.env.d1("DB")?;
    if let Some(scope) = crate::quota::check_upload(&db, &user_id, size as i64).await {
        let resp = Response::from_json(
            &serde_json::json!({ "error": "quota_exceeded", "scope": scope }),
        )?;
        return Ok(resp.with_status(429));
    }

    let content_type = req
        .headers()
        .get("content-type")
        .ok()
        .flatten()
        .unwrap_or_else(|| "application/octet-stream".into());

    // Body'i bytes olarak al (50 MiB üst sınır)
    let bytes = req.bytes().await?;

    let id = Uuid::new_v4().to_string();
    let now = now_secs();
    // Saklama penceresi owner-ayarlı (server_settings.retention_days); /capabilities
    // ilanı ile AYNI kaynak → "şu kadar tutulur" beyanı gerçek davranışla tutarlı.
    let retention_days =
        crate::server::handlers::fetch_retention_days(&ctx.env).await as u64;

    // D1 metasını R2 PUT'tan ÖNCE yaz (correctness): PUT sonra başarısız olursa
    // meta expiry'de cleanup'lanır (indirme 404; öksüz kalmaz). PUT-önce-INSERT
    // olsaydı INSERT fail → R2'de blob iz bırakır, cleanup D1-tabanlı olduğu için
    // onu HİÇ görmez → kalıcı öksüz-blob.
    db.prepare(
        "INSERT INTO media_objects (blob_id, uploader_id, size_bytes, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&id),
        d1_text(&user_id),
        d1_int(size as i64),
        d1_int(now as i64),
        d1_int((now + retention_days * 24 * 3600) as i64),
    ])?
    .run()
    .await?;

    // Kota Faz-0 (SHADOW — yalnız sayım, zorlama YOK): depolama sayaçlarını artır.
    // media_objects INSERT'i sayaç gerçeğinin kaynağı (günlük reconcile de oradan
    // hesaplar) → hook INSERT'in hemen ardında; R2 PUT sonradan başarısız olsa da
    // meta expiry-cleanup'ta silinir ve sayaç orada geri düşer (tutarlı). BEST-EFFORT:
    // sayaç hatası upload'ı ASLA kırmaz (usage.rs logla-devam).
    crate::usage::media_added(&db, &user_id, size as i64).await;

    // Kota Faz-1c (SALT-SAYIM): günlük hacim sayaçları (/admin/stats "BUGÜN"
    // bölümü). media_added ile aynı disiplin — BEST-EFFORT, upload'ı KIRMAZ.
    crate::usage::count_bump(&db, "upload_bytes", size as i64).await;
    crate::usage::count_bump(&db, "upload_count", 1).await;

    // Tek choke-point (crate::storage) üzerinden R2'ye yaz.
    let store = crate::storage::MediaStore::from_env(&ctx.env)?;
    store.put(&id, bytes, &content_type).await?;

    Response::from_json(&serde_json::json!({ "id": id, "size": size }))
}

#[derive(Deserialize)]
struct MediaRow {
    size_bytes: i64,
    expires_at: i64,
}

#[derive(Deserialize)]
struct OwnerRow {
    uploader_id: String,
    // Kota Faz-0: ack-silmede sayaç-düşümü için boyut da çekilir.
    size_bytes: i64,
}

/// POST /media/:id/ack — recipient indirip cache'lediğini onaylar; server
/// R2 blob'u + D1 metasını ANINDA siler. Vizyonun "burada unutulmak
/// varsayılan" felsefesi: medya server'da iz bırakmaz. Ack hiç gelmezse
/// 30 gün TTL ile temizlenir (fallback).
///
/// Idempotent: tekrar çağrılırsa 204 döner (R2.delete + DELETE no-op).
pub async fn ack(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let uid = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    // S1 (Fable HIGH — media-IDOR / ack-delete): silmeyi YALNIZ yükleyen tetikler.
    // blob_id Megolm manifest'iyle TÜM grup üyelerinde olduğundan, sahiplik-kapısı
    // YOKKEN kötü üye (veya ilk-indiren alıcı) `POST /media/:id/ack` ile paylaşılan
    // medyayı diğerleri indirmeden KALICI silebiliyordu. Yükleyen-dışı çağrı → 204
    // no-op (sessiz; "var mı/yok mu" sızmaz): medya retention TTL'inde temizlenir
    // (client ack'i zaten fire-and-forget kullanır + TTL fallback bekler).
    let db = ctx.env.d1("DB")?;
    let owner: Option<OwnerRow> = db
        .prepare("SELECT uploader_id, size_bytes FROM media_objects WHERE blob_id = ? LIMIT 1")
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let row = match owner {
        Some(o) if o.uploader_id == uid => o, // yetkili: yükleyen → sil
        _ => return crate::respond::no_content(), // yok VEYA yükleyen-değil → 204 no-op
    };
    // Önce R2 blob'u sil (correctness): gerçek R2 hatası propagate edilir → D1
    // metası KORUNUR (öksüz-blob önlenir; sonraki ack/cleanup yeniden dener).
    // R2 delete idempotent → yoksa hata vermez, tekrar 204. Başarınca D1 meta sil.
    // Lite kurulum kenarı: binding YOKSA (R2 sonradan dashboard'dan KAPATILMIŞ
    // olabilir — meta satırları D1'de kalmış) R2-delete ATLANIR ama D1-meta silme
    // DEVAM eder: blob'a zaten erişilemez, metayı bırakmak yalnız sayaç/cron
    // kirliliği üretir. (Binding geri gelirse o blob R2'de öksüz kalabilir —
    // kabul edilen kenar; ack-delete zaten best-effort + TTL fallback'li.)
    if crate::storage::MediaStore::available(&ctx.env) {
        let store = crate::storage::MediaStore::from_env(&ctx.env)?;
        store.delete(&id).await?;
    }
    db.prepare("DELETE FROM media_objects WHERE blob_id = ?")
        .bind(&[d1_text(&id)])?
        .run()
        .await?;
    // Kota Faz-0 (SHADOW, best-effort): silinen medyayı depolama sayaçlarından düş
    // (0-clamp). Sayaç hatası ack'i kırmaz; günlük reconcile drift'i onarır.
    crate::usage::media_removed(&db, &[(row.uploader_id, row.size_bytes)]).await;
    crate::respond::no_content()
}

/// GET /media/:id — opak (E2E-şifreli) blob indir.
///
/// ⚠️ M11 (IDOR — KISMÎ): Şu an `require_auth`'lu HERHANGİ kullanıcı, `blob_id`'yi
/// bilirse BAŞKASININ medyasını indirebilir. TAM "uploader VEYA meşru-alıcı" kapısı
/// BU SCHEMA İLE KURULAMAZ: `media_objects` yalnız `uploader_id` tutar; alıcı/oda/grup
/// ilişkisi SUNUCUDA YOK — yalnız E2E Megolm manifest'inde (client-side) yaşar. Sunucu
/// "kimler meşru alıcı" bilgisine sahip değil → uploader-only kapı her meşru alıcı
/// indirmesini kırar. Gerçek fix recipient/room ilişkisini upload'ta kaydetmeyi
/// (yeni kolon/tablo + client değişimi + migration) gerektirir (scope-dışı: yalnız
/// worker-rs, core/mobile'a dokunma). Mitigasyon: (1) blob OPAK ciphertext — anahtar
/// yalnız E2E kanalında, indiren çözemez; (2) süre-dolmuş blob 404 (pencere daraltma,
/// aşağıda). Bkz rapor: tam IDOR fix ayrı epic.
pub async fn download(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let uid = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // Lite kurulum (R2 OPSİYONEL): binding yoksa indirme de kapalı → upload ile
    // simetrik 503 (rate-limit/D1'e girmeden erken çıkış).
    if !crate::storage::MediaStore::available(&ctx.env) {
        return json_err(503, "media_not_configured");
    }
    // W12 (media-hardening, 2026-07-02): per-user DOWNLOAD rate-limit — upload 60/5dk kapılıyken
    // download SINIRSIZDI = asimetri. Download = R2-EGRESS yolu → sınırsız indirme CF-egress
    // faturasını şişirir (upload-guard'ın koruduğu AYNI maliyetin asıl kaynağı; turn.rs-tarzı
    // bütçe medyada yok). 600/5dk = meşru galeri-görüntüleme burst'ünün üstünde (sliding-window
    // burst-toleranslı), runaway/egress-DoS keser. KV-hata fail-open (2026-06-28 dersi).
    // NOT: bu M11-IDOR'u ÇÖZMEZ (o = recipient/room-binding cross-layer epic); egress-DoS savunması.
    let kv = ctx.env.kv("RATE_LIMIT")?;
    if !crate::ratelimit::check_rate_limit(&kv, &format!("media:download:{uid}"), 600, 5 * 60).await? {
        return json_err(429, "rate_limited");
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let meta: Option<MediaRow> = db
        .prepare("SELECT size_bytes, expires_at FROM media_objects WHERE blob_id = ? LIMIT 1")
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let meta = match meta {
        Some(m) => m,
        None => return json_err(404, "not_found"),
    };
    // M11 (kısmî defense-in-depth — IDOR penceresi daraltma): süresi GEÇMİŞ blob'u
    // sunma. Cleanup yalnız günlük cron (lib.rs) olduğundan, expires_at<now bir blob
    // ~24 saat boyunca R2'de kalıp indirilebiliyordu → retention-sonrası maruziyet.
    // Süre-dolmuş kaydı 404 ver (legit alıcı retention İÇİNDE indirir → kırılmaz).
    // NOT: bu TAM IDOR fix'i DEĞİL (bkz aşağıdaki not + rapor); yalnız pencereyi
    // retention sınırına çeker.
    if (meta.expires_at as u64) < now_secs() {
        return json_err(404, "not_found");
    }
    // Tek choke-point (crate::storage) üzerinden oku.
    let store = crate::storage::MediaStore::from_env(&ctx.env)?;
    let obj = match store.get(&id).await? {
        Some(o) => o,
        None => return json_err(404, "not_found_r2"),
    };

    // Kota Faz-1c (SALT-SAYIM): günlük indirme sayaçları — yalnız BAŞARILI
    // indirme (R2 get tamam) sayılır; bytes = D1 metasındaki size_bytes (hazır,
    // ekstra sorgu yok). BEST-EFFORT: sayaç hatası indirmeyi KIRMAZ.
    crate::usage::count_bump(&db, "download_count", 1).await;
    crate::usage::count_bump(&db, "download_bytes", meta.size_bytes).await;

    let headers = Headers::new();
    headers.set("content-type", &obj.content_type)?;
    headers.set("content-length", &meta.size_bytes.to_string())?;
    headers.set("cache-control", "private, no-store")?;

    let resp = Response::from_bytes(obj.bytes)?.with_headers(headers);
    Ok(resp)
}
