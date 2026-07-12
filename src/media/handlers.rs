use crate::auth::middleware::require_auth;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
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
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }

    // S2 (Fable HIGH — kota/DoS): per-user upload rate-limit. Sürekli 50MB upload
    // R2 depolama + CF egress faturasını şişirebiliyordu (turn.rs bütçe-bekçisi
    // medyada yok). KV sliding-window (auth redeem/verify ile AYNI altyapı). 60
    // upload / 5dk: meşru medya-paylaşımının çok üstü, otomatik-abuse'ü keser.
    // KV binding OPSİYONEL (şablon-diyeti): yoksa limitsiz devam — bkz. ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("media:upload:{user_id}"), 60, 5 * 60)
        .await
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

    // IDOR kapısı (audit #2): uploader hedefi ilan eder → download bunu kapılar.
    // scope_kind='peer' (1:1, scope_id=karşı user_id) | 'room' (grup, scope_id=
    // group_id). İlansız (eski client) → NULL → yalnız uploader indirebilir
    // (fail-closed). Header'lar client tarafından set edilir (core upload_media).
    let scope_kind = req.headers().get("x-sezi-scope-kind").ok().flatten();
    let scope_id = req.headers().get("x-sezi-scope-id").ok().flatten();
    // Doğrulama: kind ∈ {peer,room} + id boş-değil; aksi ikisi de NULL (fail-closed).
    let (scope_kind, scope_id) = match (scope_kind.as_deref(), scope_id.as_deref()) {
        (Some(k), Some(i)) if (k == "peer" || k == "room") && !i.is_empty() => {
            (Some(k.to_string()), Some(i.to_string()))
        }
        _ => (None, None),
    };

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
    // store_id: migration 0028 DEFAULT'u ('r2-primary') mevcut satırları doğru işaretler
    // → tek-depoda INSERT'te belirtmeye gerek yok. content_type: harici backend'lerde
    // tip-güvencesi için D1'de saklanır (Faz 1'de okuma-yolu hâlâ backend'in beyanını
    // kullanır — davranış-değişmez; Faz 3 D1-öncelik).
    db.prepare(
        "INSERT INTO media_objects (blob_id, uploader_id, size_bytes, created_at, expires_at, content_type, scope_kind, scope_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&id),
        d1_text(&user_id),
        d1_int(size as i64),
        d1_int(now as i64),
        d1_int((now + retention_days * 24 * 3600) as i64),
        d1_text(&content_type),
        d1_opt_text(scope_kind.as_deref()),
        d1_opt_text(scope_id.as_deref()),
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

    // Tek choke-point (crate::storage StorageRouter) üzerinden yaz → yazılan store_id döner.
    // FAZ 3: priority-overflow + per-depo max_bytes + PUT-fallback (degrade-yazma). Tümü
    // dolu → 429 quota_exceeded/server_storage; tüm denemeler PUT-fail → 503 upload_failed.
    let store_id = match router
        .put_new(
            crate::storage::StorageClass::Media,
            &crate::storage::media_key(&id),
            bytes,
            &content_type,
        )
        .await
    {
        Ok(sid) => sid,
        Err(e) => {
            // ROLLBACK (2026-07-10 audit HIGH): put_new'un HİÇBİR varyantı (AllFull/
            // AllFailed/NoActive) blob YAZMAZ → meta-önce satırı + kota sayaçları HAYALİ
            // kalır. Eski davranış "expiry-cleanup düşürür" idi ama bu ~30 GÜN sürer;
            // o pencerede reconcile satırı GERÇEK sayıp kullanıcıyı kendi kotasından
            // kilitleyebilir (depo-dolu senaryosu). Anında geri al: satırı sil + sayacı
            // düş (media_removed 0-clamp'li). Best-effort — asıl hata-yanıtı korunur;
            // rollback hatası olsa bile expiry-cleanup yine son-savunma.
            db.prepare("DELETE FROM media_objects WHERE blob_id = ?")
                .bind(&[d1_text(&id)])?
                .run()
                .await
                .ok();
            crate::usage::media_removed(&db, &[(user_id.clone(), size as i64)]).await;
            return crate::storage::placement_err_response(e);
        }
    };
    // Meta INSERT store_id='r2-primary' DEFAULT'uyla girdi; put_new farklı depoya
    // yazdıysa (Faz 2+ overflow/fallback) tek UPDATE düzeltir — meta-önce disiplini
    // bozulmaz (PUT-fail'de expiry-cleanup satırı zaten süpürür). Faz 1 tek-depo:
    // store_id hep 'r2-primary' == DEFAULT → UPDATE HİÇ koşmaz (ek D1-yazımı yok = bit-aynı).
    if store_id != crate::storage::PRIMARY_STORE_ID {
        db.prepare("UPDATE media_objects SET store_id = ? WHERE blob_id = ?")
            .bind(&[d1_text(&store_id), d1_text(&id)])?
            .run()
            .await?;
    }

    Response::from_json(&serde_json::json!({ "id": id, "size": size }))
}

#[derive(Deserialize)]
struct MediaRow {
    size_bytes: i64,
    expires_at: i64,
    // Takılabilir-depolama: blob hangi depoda → router.get o depoya yönlendirir
    // (tek-depo Faz 1: hep 'r2-primary').
    store_id: String,
    // IDOR kapısı (audit #2): uploader HER ZAMAN indirir; scope alıcıları da.
    uploader_id: String,
    scope_kind: Option<String>,
    scope_id: Option<String>,
}

#[derive(Deserialize)]
struct OwnerRow {
    uploader_id: String,
    // Kota Faz-0: ack-silmede sayaç-düşümü için boyut da çekilir.
    size_bytes: i64,
    // Takılabilir-depolama: blob hangi depoda → router.delete o depoya yönlendirir
    // (tek-depo Faz 1: hep 'r2-primary').
    store_id: String,
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
        .prepare("SELECT uploader_id, size_bytes, store_id FROM media_objects WHERE blob_id = ? LIMIT 1")
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
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if router.any_available() {
        // FAZ 3 (plan f#3): depo-hatası → fırsatçı health-işaret + Err propagate → D1 meta
        // KALIR (öksüz-blob önlenir; sonraki ack/TTL yeniden dener). Tekil silme → tek
        // health-yazımı (batch değil; router.delete kendi işaretini yapmaz → burada yapılır).
        if let Err(e) = router
            .delete(&row.store_id, &crate::storage::media_key(&id))
            .await
        {
            crate::storage::write_health(
                &ctx.env,
                &row.store_id,
                false,
                Some(&e.to_string().chars().take(120).collect::<String>()),
            )
            .await;
            return Err(e);
        }
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
/// IDOR kapısı (audit #2 — ÇÖZÜLDÜ 2026-07-10, migration 0029): upload'ta ilan
/// edilen `scope_kind`/`scope_id` ile download kapılanır (uploader her zaman;
/// peer→karşı-taraf; room→aktif-üye; NULL→yalnız-uploader). Katmanlı savunma:
/// (1) scope-gate (aşağıda), (2) blob_id = tahmin-edilemez capability (yalnız
/// E2E-manifest'te), (3) blob OPAK ciphertext (indiren çözemez), (4) süre-dolmuş
/// blob 404 (retention-sonrası pencere kapatma).
pub async fn download(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let uid = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // Lite kurulum (R2 OPSİYONEL): binding yoksa indirme de kapalı → upload ile
    // simetrik 503 (rate-limit/D1'e girmeden erken çıkış).
    let router = crate::storage::StorageRouter::from_env(&ctx.env).await?;
    if !router.any_available() {
        return json_err(503, "media_not_configured");
    }
    // W12 (media-hardening, 2026-07-02): per-user DOWNLOAD rate-limit — upload 60/5dk kapılıyken
    // download SINIRSIZDI = asimetri. Download = R2-EGRESS yolu → sınırsız indirme CF-egress
    // faturasını şişirir (upload-guard'ın koruduğu AYNI maliyetin asıl kaynağı; turn.rs-tarzı
    // bütçe medyada yok). 600/5dk = meşru galeri-görüntüleme burst'ünün üstünde (sliding-window
    // burst-toleranslı), runaway/egress-DoS keser. KV-hata fail-open (2026-06-28 dersi).
    // NOT: bu M11-IDOR'u ÇÖZMEZ (o = recipient/room-binding cross-layer epic); egress-DoS savunması.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("media:download:{uid}"), 600, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let meta: Option<MediaRow> = db
        .prepare("SELECT size_bytes, expires_at, store_id, uploader_id, scope_kind, scope_id FROM media_objects WHERE blob_id = ? LIMIT 1")
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let meta = match meta {
        Some(m) => m,
        None => return json_err(404, "not_found"),
    };
    // IDOR kapısı (audit #2, 2026-07-10): blob_id zaten E2E-manifest'te taşınan
    // capability (tahmin-edilemez UUID) — ama server-yetkisi olmadan blob_id'yi
    // ELE GEÇİREN (log/ayrılmış-üye) çekebiliyordu. Artık scope-gate:
    //   • uploader → HER ZAMAN (kendi blob'u; çoklu-cihaz kendi indirir).
    //   • scope 'peer' → yalnız karşı taraf (1:1).
    //   • scope 'room' → yalnız AKTİF grup üyesi (ayrılınca erişim biter).
    //   • scope NULL (ilansız/eski) → yalnız uploader (fail-closed).
    // 404 (403 değil) → blob'un VARLIĞINI sızdırma (enumerate-savunma).
    if uid != meta.uploader_id {
        let allowed = match (meta.scope_kind.as_deref(), meta.scope_id.as_deref()) {
            (Some("peer"), Some(peer)) => uid == peer,
            (Some("room"), Some(room)) => {
                crate::groups::group_role(&db, room, &uid)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
            }
            _ => false,
        };
        if !allowed {
            return json_err(404, "not_found");
        }
    }
    // M11 (kısmî defense-in-depth — IDOR penceresi daraltma): süresi GEÇMİŞ blob'u
    // sunma. Cleanup yalnız günlük cron (lib.rs) olduğundan, expires_at<now bir blob
    // ~24 saat boyunca R2'de kalıp indirilebiliyordu → retention-sonrası maruziyet.
    // Süre-dolmuş kaydı 404 ver (legit alıcı retention İÇİNDE indirir → kırılmaz).
    // NOT: bu TAM IDOR fix'i DEĞİL (bkz aşağıdaki not + rapor); yalnız pencereyi
    // retention sınırına çeker.
    if (meta.expires_at as u64) < now_secs() {
        return json_err(404, "not_found");
    }
    // Tek choke-point (crate::storage StorageRouter) üzerinden oku (blob'un depo'sundan).
    // FAZ 3 (plan f#2): depo erişilemez → 503 storage_backend_unavailable (retryable) +
    // router içinde fırsatçı health-işaret ZATEN yapıldı; yok (None) → 404 not_found_r2.
    let obj = match router.get(&meta.store_id, &crate::storage::media_key(&id)).await {
        Ok(Some(o)) => o,
        Ok(None) => return json_err(404, "not_found_r2"),
        Err(_) => return json_err(503, "storage_backend_unavailable"),
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
