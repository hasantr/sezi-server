//! `GET /admin/stats` — sunucu kullanım istatistikleri (kota epic **Faz 0**
//! SHADOW-MODE; **Faz 1c** genişletme; **Faz 3** CF Analytics dual-logic).
//! Admin/owner-gated tek-bakış özeti: üye/davet sayıları + medya depolama
//! (server_stats sayacı) + retention ilanı + video-arama (TURN) aylık
//! kullanımı + günlük medya hacmi. Yalnız RAPOR — bu endpoint hiçbir limit
//! zorlamaz.
//!
//! Faz 3 dual-logic: CF_API_TOKEN kuruluysa istek sayıları CF GraphQL
//! Analytics'ten (fatura-doğru, `authoritative:true`); değilse/hatada
//! self-report sayaçlar aynen çalışır (`authoritative:false` — VPS/standalone
//! yolu). cf_analytics.rs her katmanda fail-open.
//!
//! Yeni sayaç tabloları (0022/0009) henüz migrate edilmemişse fail-open 0 döner
//! (turn.rs sayaç-okuma deseni) — stats-lite her zaman çalışır.

use crate::auth::middleware::{require_admin, require_auth};
use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct CountRow {
    n: i64,
}

#[derive(Deserialize)]
struct TurnUsageRow {
    issued: i64,
}

#[derive(Deserialize)]
struct MediaStatsRow {
    media_bytes: i64,
    media_count: i64,
}

#[derive(Deserialize)]
struct CapsRow {
    max_storage_bytes: Option<i64>,
    max_user_storage_bytes: Option<i64>,
}

pub async fn stats(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let now = now_secs();

    // Üye sayıları (list_users ile aynı tablo: users). admins = yükseltilmiş
    // roller, owner DAHİL (owner her admin işini yapar — middleware ile tutarlı).
    let members: i64 = db
        .prepare("SELECT COUNT(*) AS n FROM users")
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);
    let admins: i64 = db
        .prepare("SELECT COUNT(*) AS n FROM users WHERE role IN ('admin','owner')")
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);
    // Bekleyen davetler: kullanılmamış + süresi geçmemiş (list_invites tablosu;
    // used/expired satırlar zaten aksiyon-değersiz + cron temizler).
    let invites: i64 = db
        .prepare("SELECT COUNT(*) AS n FROM invite_tokens WHERE used = 0 AND expires_at > ?")
        .bind(&[d1_int(now as i64)])?
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);

    // Medya depolama — server_stats SHADOW sayacı (0022; upload/ack/cron hook'ları
    // + günlük reconcile besler). Tablo/satır yok veya hata → 0 (fail-open).
    let media = db
        .prepare("SELECT media_bytes, media_count FROM server_stats WHERE id = 1 LIMIT 1")
        .first::<MediaStatsRow>(None)
        .await
        .ok()
        .flatten();
    let (media_bytes, media_count) = media
        .map(|m| (m.media_bytes, m.media_count))
        .unwrap_or((0, 0));

    // Retention — /capabilities ilanıyla AYNI kaynak (ilan = davranış disiplini).
    let media_days = crate::server::handlers::fetch_retention_days(&ctx.env).await;
    let message_days = crate::server::handlers::fetch_message_retention_days(&ctx.env).await;

    // Faz 3 — CF Analytics dual-logic. `fetch` fail-open: token/account yok
    // (env VE D1'de — VPS/standalone ya da hiç girilmedi) → HIZLI None (CF
    // ağına çıkmaz, bugünkü davranış bit-aynı); CF hata/parse-fail →
    // console_warn + None. None = self-report koluna düş; stats ASLA 500 atmaz.
    let cf = crate::cf_analytics::fetch(&ctx.env).await;

    // v6: cf_configured — owner UI'ı "token girilmiş mi" bilir (env-secret VEYA
    // owner'ın app'ten girdiği D1 değeri). WRITE-ONLY SÖZLEŞME: token DEĞERİ bu
    // endpoint dahil HİÇBİR yerden dönmez; yalnız bu bool. `is_configured`
    // hafif (CF ağına çıkmaz; fail-open false). `authoritative`den farkı:
    // token girili ama CF hatalıysa configured=true + authoritative=false
    // (UI "bağlı ama veri gelmiyor" ayrımını yapabilir).
    let cf_configured = crate::cf_analytics::is_configured(&ctx.env).await;

    // requests_today — CF varsa CF'nin fatura-doğru sayısı; yoksa self-report
    // usage_counters 'requests' (per-istek D1-sayım pahalı → satır yazılmaz →
    // 0-stub). Wire tipi HER ZAMAN sayı (null asla) — eski client'ın i64
    // parse'ı kırılmaz (CF-var-ama-bugün-parse-None ucunda da self-report'a
    // düşer, alan-bazlı fail-open).
    let requests_today_self = crate::usage::read_today(&db, "requests").await;
    let requests_today = cf
        .as_ref()
        .and_then(|c| c.requests_today)
        .unwrap_or(requests_today_self);
    // requests_month — YENİ alan (v4): yalnız CF verebilir (self-report aylık
    // sayaç yok) → CF yoksa null (client Option; '—' basar).
    let requests_month = cf.as_ref().and_then(|c| c.requests_month);
    // CF'nin ölçtüğü R2 depolama — self-report `media.bytes`'ın YANINA (onu
    // değiştirmez; karşılaştırma/mutabakat için). CF yoksa null.
    let storage_cf_bytes = cf.as_ref().and_then(|c| c.r2_storage_bytes);

    // Video-arama (TURN) — bu ayın kimlik-üretim sayacı (turn.rs bütçe-bekçisi
    // `turn_usage` tablosu, 0009) + ilan edilen tavan (bekçiyle AYNI kaynak:
    // turn::monthly_cap). Fail-open: tablo yok / D1 hatası → 0 (stats 500 atmaz).
    let turn_issued: i64 = match db
        .prepare("SELECT issued FROM turn_usage WHERE month = ? LIMIT 1")
        .bind(&[d1_text(&crate::turn::current_month_utc())])
    {
        Ok(stmt) => stmt
            .first::<TurnUsageRow>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.issued)
            .unwrap_or(0),
        Err(_) => 0,
    };
    let turn_cap = crate::turn::monthly_cap(&ctx.env);

    // Günlük medya hacmi (Faz 1c) — media/handlers.rs count_bump hook'ları
    // besler; read_today fail-open (tablo/satır yok → 0).
    let upload_bytes_today = crate::usage::read_today(&db, "upload_bytes").await;
    let upload_count_today = crate::usage::read_today(&db, "upload_count").await;
    let download_count_today = crate::usage::read_today(&db, "download_count").await;
    let download_bytes_today = crate::usage::read_today(&db, "download_bytes").await;

    // Aylık medya hacmi (v5, aylık-detay) — usage_counters gün satırlarının
    // bu-ay SUM'u (read_month, ay-prefix LIKE; TURN bütçesiyle aynı ay
    // penceresi). read_month fail-open (tablo yok / D1 hatası → 0).
    let upload_bytes_month = crate::usage::read_month(&db, "upload_bytes").await;
    let upload_count_month = crate::usage::read_month(&db, "upload_count").await;
    let download_count_month = crate::usage::read_month(&db, "download_count").await;
    let download_bytes_month = crate::usage::read_month(&db, "download_bytes").await;

    // Kota cap'leri (Faz 1a) — server_settings NULLABLE kolonları. NULL =
    // sınırsız; hata/satır-yok/migration-eksik → null (fail-open, stats 500 atmaz).
    let caps = db
        .prepare(
            "SELECT max_storage_bytes, max_user_storage_bytes \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first::<CapsRow>(None)
        .await
        .ok()
        .flatten();
    let (max_storage, max_user_storage) = caps
        .map(|c| (c.max_storage_bytes, c.max_user_storage_bytes))
        .unwrap_or((None, None));

    Response::from_json(&serde_json::json!({
        "members": members,
        "admins": admins,
        "invites": invites,
        "media": { "bytes": media_bytes, "count": media_count },
        "retention": { "media_days": media_days, "message_days": message_days },
        "requests_today": requests_today,
        "caps": {
            "max_storage_bytes": max_storage,
            "max_user_storage_bytes": max_user_storage,
        },
        // Faz 1c: video-arama (TURN) aylık kullanım + günlük medya hacmi.
        // Mevcut alanlar AYNEN korunur (eski client v2 alanlarını okumaya
        // devam eder; yeni bloklar additive).
        "turn": { "issued_month": turn_issued, "cap": turn_cap },
        "today": {
            "upload_bytes": upload_bytes_today,
            "upload_count": upload_count_today,
            "download_count": download_count_today,
            "download_bytes": download_bytes_today,
        },
        // Aylık-detay (v5, additive): "BU AY" kartı için bu ayın medya hacmi
        // (usage_counters SUM'u). requests_month (CF-only) top-level'da,
        // TURN issued_month turn bloğunda ZATEN var — burada tekrarlanmaz.
        "month": {
            "upload_bytes": upload_bytes_month,
            "upload_count": upload_count_month,
            "download_count": download_count_month,
            "download_bytes": download_bytes_month,
        },
        // Faz 3 (v4, additive): dual-logic sözleşme alanları. `backend` = bu
        // binary'nin çalıştığı yer (VPS/standalone port ileride "standalone"
        // gönderecek); `authoritative` true = rakamlar CF faturasıyla birebir
        // (GraphQL Analytics), false = self-report (token yok / CF hatası).
        // `storage_cf_bytes` CF-ölçümü; self-report media.bytes'ı DEĞİŞTİRMEZ.
        "backend": "cf",
        "authoritative": cf.is_some(),
        "requests_month": requests_month,
        "storage_cf_bytes": storage_cf_bytes,
        // v6 (additive): token var-mı bool'u — DEĞERİ ASLA (write-only sözleşme).
        "cf_configured": cf_configured,
        "version": 6,
    }))
}
