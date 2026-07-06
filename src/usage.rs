//! Kullanım sayaçları — kota epic **Faz 0, SHADOW-MODE** (yalnız sayım; ZORLAMA YOK).
//!
//! turn.rs bütçe-bekçisi (turn_usage) deseninin depolamaya genelleştirilmişi:
//! `user_storage` (per-user canlı byte sayacı) + `server_stats` (sunucu-geneli medya
//! byte/adet, tek satır id=1) + `usage_counters` (gün-anahtarlı genel sayaçlar).
//!
//! **BEST-EFFORT disiplini:** sayaç yazımındaki HİÇBİR hata gerçek op'u
//! (upload/ack/cron-cleanup) kırmaz — loglanır (PII'siz, 80-char kırpık) ve devam
//! edilir. Drift kabul edilir: günlük cron `reconcile_storage` sayaçları
//! `media_objects` gerçeğinden yeniden-hesaplar (self-heal). Kota REDDİ yok —
//! zorlama Faz 1'in işi; burada hiçbir istek reddedilmez (shadow).

use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;
use serde::Deserialize;
use std::collections::HashMap;
use wasm_bindgen::JsValue;
use worker::*;

/// Sayaç-hata logu — PII sızdırmaz (lib.rs cleanup deseni: ilk 80 char).
fn log_fail(what: &str, e: Error) {
    let msg = e.to_string();
    let truncated: String = msg.chars().take(80).collect();
    console_warn!("usage: {} fail: {}", what, truncated);
}

/// Tek statement'ı best-effort çalıştır: bind/run hatası → logla + sessiz devam
/// (çağıran gerçek op hiç etkilenmez).
async fn run_best_effort(db: &D1Database, what: &str, sql: &str, binds: &[JsValue]) {
    match db.prepare(sql).bind(binds) {
        Ok(stmt) => {
            if let Err(e) = stmt.run().await {
                log_fail(what, e);
            }
        }
        Err(e) => log_fail(what, e),
    }
}

/// Medya upload'ını sayaçlara işle: `user_storage.bytes += size` +
/// `server_stats.media_bytes += size, media_count += 1`. BEST-EFFORT (hata
/// upload'ı KIRMAZ). media_objects INSERT'i sayaç gerçeğinin kaynağı (reconcile
/// de oradan hesaplar) → çağrı INSERT'in hemen ardında yapılır.
pub async fn media_added(db: &D1Database, uploader_id: &str, size: i64) {
    let now = now_secs() as i64;
    run_best_effort(
        db,
        "user_storage add",
        "INSERT INTO user_storage (user_id, bytes) VALUES (?, ?) \
         ON CONFLICT(user_id) DO UPDATE SET bytes = bytes + excluded.bytes",
        &[d1_text(uploader_id), d1_int(size)],
    )
    .await;
    run_best_effort(
        db,
        "server_stats add",
        "INSERT INTO server_stats (id, media_bytes, media_count, updated_at) VALUES (1, ?, 1, ?) \
         ON CONFLICT(id) DO UPDATE SET media_bytes = media_bytes + excluded.media_bytes, \
         media_count = media_count + 1, updated_at = excluded.updated_at",
        &[d1_int(size), d1_int(now)],
    )
    .await;
}

/// Medya silme (ack / cron-expire) sayaç-düşümü. `(uploader_id, size_bytes)`
/// listesi alır (cron 500'e kadar satırı toplu siler) → per-user toplar,
/// `MAX(0, ...)` ile 0'da CLAMP'ler. BEST-EFFORT (hata silmeyi kırmaz).
pub async fn media_removed(db: &D1Database, removed: &[(String, i64)]) {
    if removed.is_empty() {
        return;
    }
    let now = now_secs() as i64;
    let mut per_user: HashMap<&str, i64> = HashMap::new();
    let mut total: i64 = 0;
    for (uploader_id, size) in removed {
        *per_user.entry(uploader_id.as_str()).or_insert(0) += size;
        total += size;
    }
    for (uploader_id, bytes) in per_user {
        run_best_effort(
            db,
            "user_storage sub",
            "UPDATE user_storage SET bytes = MAX(0, bytes - ?) WHERE user_id = ?",
            &[d1_int(bytes), d1_text(uploader_id)],
        )
        .await;
    }
    run_best_effort(
        db,
        "server_stats sub",
        "UPDATE server_stats SET media_bytes = MAX(0, media_bytes - ?), \
         media_count = MAX(0, media_count - ?), updated_at = ? WHERE id = 1",
        &[d1_int(total), d1_int(removed.len() as i64), d1_int(now)],
    )
    .await;
}

/// Günlük authoritative reconcile — best-effort sayaçlardaki drift'i
/// `media_objects` gerçeğinden yeniden-hesaplayarak onar (self-heal).
/// `db.batch` = tek D1 transaction → tutarlı anlık-görüntü; tam yeniden-kurulum
/// (DELETE+INSERT-SELECT) upsert-SELECT parse-ambiguity'sinden de kaçınır.
/// Günlük cron'dan çağrılır (lib.rs scheduled); hata orada loglanır, cron kırılmaz.
pub async fn reconcile_storage(env: &Env) -> Result<()> {
    let db = env.d1("DB")?;
    let now = now_secs() as i64;
    db.batch(vec![
        db.prepare("DELETE FROM user_storage"),
        db.prepare(
            "INSERT INTO user_storage (user_id, bytes) \
             SELECT uploader_id, COALESCE(SUM(size_bytes), 0) FROM media_objects \
             GROUP BY uploader_id",
        ),
        db.prepare("DELETE FROM server_stats WHERE id = 1"),
        db.prepare(
            "INSERT INTO server_stats (id, media_bytes, media_count, updated_at) \
             SELECT 1, COALESCE(SUM(size_bytes), 0), COUNT(*), ? FROM media_objects",
        )
        .bind(&[d1_int(now)])?,
    ])
    .await?;
    Ok(())
}

/// Gün-anahtarlı genel sayaç artışı (kota epic **Faz 1c**, SALT-SAYIM) —
/// `usage_counters` bugünkü `(day, kind)` satırına `+by` upsert. `media_added`
/// deseninin genelleştirilmişi: BEST-EFFORT (hata çağıran gerçek op'u —
/// upload/download — ASLA kırmaz; logla-devam). Hook'lar: media upload
/// (`upload_bytes`/`upload_count`) + download (`download_count`/
/// `download_bytes`); /admin/stats `read_today` ile okur.
pub async fn count_bump(db: &D1Database, kind: &str, by: i64) {
    run_best_effort(
        db,
        "count_bump",
        "INSERT INTO usage_counters (day, kind, count) VALUES (?, ?, ?) \
         ON CONFLICT(day, kind) DO UPDATE SET count = count + excluded.count",
        &[d1_text(&today_utc()), d1_text(kind), d1_int(by)],
    )
    .await;
}

/// `usage_counters` bugünkü `kind` satırını oku (yoksa/hatada 0 — fail-open,
/// turn.rs sayaç-okuma deseni: tablo migrate edilmemişse bile stats 500 atmaz).
/// Faz 1c'den beri `count_bump` hook'ları besler (upload/download hacmi);
/// `requests` kind'ı hâlâ stub (istek-sayımı → Faz 3 CF Analytics).
pub async fn read_today(db: &D1Database, kind: &str) -> i64 {
    #[derive(Deserialize)]
    struct Row {
        count: i64,
    }
    match db
        .prepare("SELECT count FROM usage_counters WHERE day = ? AND kind = ? LIMIT 1")
        .bind(&[d1_text(&today_utc()), d1_text(kind)])
    {
        Ok(stmt) => stmt
            .first::<Row>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.count)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// `usage_counters` bu ayın `kind` toplamını oku (aylık-detay raporu) — gün
/// satırlarının SUM'u; ay penceresi turn.rs `current_month_utc` anahtarından
/// türetilir (day "YYYY-MM-DD" → prefix "YYYY-MM%", TURN bütçesiyle
/// pencere-uyumlu). Fail-open: bind/first hatası ya da tablo yok → 0
/// (read_today deseni; stats 500 atmaz). /admin/stats "month" bloğunu besler.
pub async fn read_month(db: &D1Database, kind: &str) -> i64 {
    #[derive(Deserialize)]
    struct Row {
        total: i64,
    }
    match db
        .prepare(
            "SELECT COALESCE(SUM(count), 0) AS total FROM usage_counters \
             WHERE kind = ? AND day LIKE ?",
        )
        .bind(&[
            d1_text(kind),
            d1_text(&format!("{}%", crate::turn::current_month_utc())),
        ]) {
        Ok(stmt) => stmt
            .first::<Row>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.total)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// epoch → "YYYY-MM-DD" (UTC). turn.rs `current_month_utc` civil-from-days
/// algoritmasının (Howard Hinnant) gün-versiyonu — chrono'suz; usage_counters
/// gün anahtarı.
///
/// `pub(crate)`: cf_analytics (Faz 3) bugün-00:00Z CF-sorgu penceresini AYNI
/// gün anahtarından türetir (self-report sayaç ile CF rakamı pencere-uyumlu).
pub(crate) fn today_utc() -> String {
    let secs = now_secs() as i64;
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}
