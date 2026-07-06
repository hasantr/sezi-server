//! Lazy-maintenance — cron-bağımsız bakım (kesin-çözüm paketi 2026-07-06).
//!
//! SAHA GEREKÇESİ: CF free-planında hesap-başına cron-tetikleyici limiti var —
//! aynı hesaba kurulan İKİNCİ sezi-server `wrangler deploy`in schedules adımında
//! "account-plan-limits" hatası alıyor ve CRON'SUZ kalıyor → günlük-GC +
//! 2dk fanout-drain HİÇ çalışmıyor (retry-kuyruğu birikir, expired-media/token
//! temizliği durur). Çözüm: bakım görevleri istek-sırtında (piggyback) da
//! koşabilsin — cron yalnızca "bakımı taze tutan" bir yol olsun, TEK yol değil.
//!
//! ŞABLON-UYUM NOTU: şablon-kurulumda `wrangler.toml` [triggers] YOK
//! (hesap-cron-limiti) → bakım tamamen lazy-yoldan; cron'lu kurulumda damgalar
//! taze kaldığından lazy uyur. (Monorepo-prod `wrangler.toml` [triggers]'a
//! DOKUNULMADI — orada cron çalışır, bu modül sessiz kalır.)
//!
//! MEKANİZMA — `server_config` (0025 key-value) iki zaman-damgası:
//!   - `maint_drain_at`  = son fanout-drain bakımının epoch-sn'si
//!   - `maint_daily_at`  = son günlük-GC'nin epoch-sn'si
//!
//! `scheduled()` HER koşuşta kendi damgasını tazeler → cron çalışan kurulumda
//! damga hiç eskimez → lazy-yol HİÇ tetiklenmez (prod bit-aynı). Cron'suz
//! kurulumda damga eskir → ilk uygun istek `ctx.wait_until` ile bakımı
//! arka-planda koşar (yanıt gecikmez).
//!
//! MALİYET DİSİPLİNİ: istek-başı EK D1-OKUMASI YOK — izolat-içi `thread_local`
//! son-kontrol-zamanı ile D1'e en fazla ~60sn'de bir bakılır; o bakış da
//! `wait_until` içinde (istek kritik-yolunda sıfır ek gecikme).
//!
//! YARIŞ-DARALTMA (kazanan-deseni): damga stale görülünce ÖNCE
//! `UPDATE ... WHERE CAST(value AS INTEGER) <= stale-eşik RETURNING key`
//! ile damga ileri itilir — D1 UPDATE'i serialize eder, yalnız İLK kazanan
//! satır döndürür; kaybeden izolat işi atlar. Kazanamama = başka izolat
//! zaten koşuyor → görev tekilleşir. (Görevlerin kendisi de eşzamanlılığa
//! dayanıklı — aşağıdaki fonksiyon yorumlarına bakınız — kazanan-deseni
//! sadece gereksiz çift-işi keser.)

use std::cell::Cell;

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use crate::d1util::d1_int;
use crate::d1util::d1_text;
use crate::utils::now_secs;

/// İzolat-içi D1-bakış gaz-kelebeği: istek-başına damga-SELECT'i atmamak için
/// en fazla bu aralıkta bir kez D1'e bakılır (WASM izolatı tek-thread →
/// thread_local = izolat-memoize; self_provision ile aynı desen).
const CHECK_EVERY_SECS: u64 = 60;

/// Lazy drain eşiği. Cron aralığı 120sn ama eşik BİLİNÇLİ 300sn (2.5×):
/// CF scheduled-event'leri saniye-hassas değil — cron birkaç sn/dk gecikebilir.
/// Eşik = tam 120sn olsaydı cron'lu PROD'da "damga 120sn'yi yeni geçti, cron
/// birazdan koşacak" penceresinde lazy düzenli tetiklenirdi (çift-drain zararsız
/// ama "cron'lu kurulumda lazy uyur" sözleşmesi bozulurdu). 2.5× jitter payı =
/// lazy yalnız cron GERÇEKTEN ölüyse uyanır; cron'suz kurulumda drain kadansı
/// trafik varken ~5dk (retry-kuyruğu backoff'lu tampon — yeterli).
const DRAIN_LAZY_AFTER_SECS: i64 = 300;

/// Lazy günlük-GC eşiği: 24s + 1s pay (aynı jitter gerekçesi — günlük cron
/// "0 4 * * *" damgası tam 86400sn'de tazelenir; paysız eşik sınırda yarışırdı).
const DAILY_LAZY_AFTER_SECS: i64 = 90_000;

// Sözleşme-kilidi (derleme-zamanı): lazy eşikleri cron kadanslarının (drain
// "*/2 * * * *"=120sn, günlük "0 4 * * *"=86400sn) ALTINA inmemeli — inerse
// cron'lu prod'da lazy düzenli uyanır (çift-koşum zararsız ama "prod bit-aynı"
// sözleşmesi bozulur).
const _: () = assert!(DRAIN_LAZY_AFTER_SECS >= 2 * 120);
const _: () = assert!(DAILY_LAZY_AFTER_SECS > 86_400);

const KEY_DRAIN: &str = "maint_drain_at";
const KEY_DAILY: &str = "maint_daily_at";

thread_local! {
    /// Son D1 damga-kontrol zamanı (epoch-sn; 0 = izolat hiç bakmadı).
    static LAST_CHECK: Cell<u64> = const { Cell::new(0) };
}

// ── fetch-yolu girişi ───────────────────────────────────────────────────────

/// `#[event(fetch)]` girişinden (ensure_ready ardından) çağrılır. İstek kritik
/// yolundaki maliyeti: `Date.now()` + thread_local karşılaştırma (D1'siz,
/// await'siz). Gaz-kelebeği açıksa damga-kontrol + olası bakım TAMAMEN
/// `ctx.wait_until` arka-planında koşar → yanıt gecikmez. BEST-EFFORT: her
/// hata loglanır-yutulur, istek asla etkilenmez.
pub fn maybe_run_lazy(env: &Env, ctx: &Context) {
    let now = now_secs();
    let due = LAST_CHECK.with(|c| {
        if throttle_due(c.get(), now, CHECK_EVERY_SECS) {
            // Bayrağı HEMEN ileri al (tek-thread → yarışsız): aynı izolatın
            // ardışık istekleri 60sn boyunca D1'e hiç bakmaz.
            c.set(now);
            true
        } else {
            false
        }
    });
    if !due {
        return;
    }
    let env = env.clone();
    ctx.wait_until(async move { check_and_run(env).await });
}

/// Damgaları oku → stale görevler için kazanan-desenini dene → kazanılanı koş.
/// Sıra: önce drain (sık/ucuz), sonra günlük-GC (nadir/ağır).
async fn check_and_run(env: Env) {
    let Ok(db) = env.d1("DB") else { return };
    let now = now_secs() as i64;
    let (drain_at, daily_at) = match read_stamps(&db).await {
        Ok(v) => v,
        // D1 geçici hatası → sonraki gaz-kelebeği penceresinde yeniden.
        Err(_) => return,
    };
    if is_due(now, drain_at, DRAIN_LAZY_AFTER_SECS)
        && claim(&db, KEY_DRAIN, now, now - DRAIN_LAZY_AFTER_SECS).await
    {
        console_log!(
            "maintenance: lazy drain (damga {}sn eski — cron'suz kurulum ya da cron gecikti)",
            now - drain_at
        );
        crate::messages::handlers::drain_fanout_retry(&env).await;
    }
    if is_due(now, daily_at, DAILY_LAZY_AFTER_SECS)
        && claim(&db, KEY_DAILY, now, now - DAILY_LAZY_AFTER_SECS).await
    {
        console_log!(
            "maintenance: lazy gunluk-GC (damga {}sn eski)",
            now - daily_at
        );
        run_daily(&env).await;
    }
}

// ── damga okuma / kazanan-deseni ────────────────────────────────────────────

/// İki damgayı TEK SELECT'te oku (epoch-sn; satır-yok/bozuk-değer → 0 =
/// "çok eski" → ilk uygun istekte bir kez koşar + damgalanır).
async fn read_stamps(db: &D1Database) -> Result<(i64, i64)> {
    #[derive(Deserialize)]
    struct Row {
        key: String,
        value: String,
    }
    let rows: Vec<Row> = db
        .prepare("SELECT key, value FROM server_config WHERE key IN (?, ?)")
        .bind(&[d1_text(KEY_DRAIN), d1_text(KEY_DAILY)])?
        .all()
        .await?
        .results()?;
    let mut drain_at = 0i64;
    let mut daily_at = 0i64;
    for r in rows {
        let v = parse_stamp(Some(&r.value));
        match r.key.as_str() {
            KEY_DRAIN => drain_at = v,
            KEY_DAILY => daily_at = v,
            _ => {}
        }
    }
    Ok((drain_at, daily_at))
}

/// Kazanan-deseni: damgayı işten ÖNCE ileri it — `UPDATE ... WHERE
/// CAST(value AS INTEGER) <= stale-eşik RETURNING key` yalnız hâlâ-stale
/// satırda 1 satır döndürür (D1 UPDATE'leri serialize eder → eşzamanlı iki
/// izolattan yalnız biri kazanır, kaybeden görevi atlar). Satır yoksa (ilk
/// boot) önce `INSERT OR IGNORE value='0'` ile açılır → '0' her eşiğin
/// altında = claim'lenebilir. Hata → false (best-effort; iş koşulmaz,
/// sonraki pencerede yeniden denenir).
async fn claim(db: &D1Database, key: &str, now: i64, stale_cutoff: i64) -> bool {
    // Satırı garanti et (ilk boot). Idempotent + yalnız stale-şüphesinde koşar.
    if let Ok(stmt) = db
        .prepare("INSERT OR IGNORE INTO server_config (key, value, created_at) VALUES (?, '0', ?)")
        .bind(&[d1_text(key), d1_int(now)])
    {
        let _ = stmt.run().await;
    }
    #[derive(Deserialize)]
    struct KeyRow {
        #[allow(dead_code)]
        key: String,
    }
    let Ok(stmt) = db
        .prepare(
            "UPDATE server_config SET value = ?
             WHERE key = ? AND CAST(value AS INTEGER) <= ?
             RETURNING key",
        )
        .bind(&[d1_text(&now.to_string()), d1_text(key), d1_int(stale_cutoff)])
    else {
        return false;
    };
    match stmt.all().await {
        Ok(res) => res.results::<KeyRow>().map(|r| r.len() == 1).unwrap_or(false),
        Err(_) => false,
    }
}

// ── cron-yolu damgalama ─────────────────────────────────────────────────────

/// `scheduled()` her koşuşta çağırır (drain sonrası) → cron çalışan kurulumda
/// `maint_drain_at` hep taze kalır = lazy-drain hiç uyanmaz. Best-effort.
pub(crate) async fn stamp_drain(env: &Env) {
    if let Ok(db) = env.d1("DB") {
        stamp(&db, KEY_DRAIN).await;
    }
}

/// `scheduled()` günlük dalı sonunda çağırır → lazy günlük-GC uyur. Best-effort.
pub(crate) async fn stamp_daily(env: &Env) {
    if let Ok(db) = env.d1("DB") {
        stamp(&db, KEY_DAILY).await;
    }
}

async fn stamp(db: &D1Database, key: &str) {
    let now = now_secs() as i64;
    if let Ok(stmt) = db
        .prepare("INSERT OR REPLACE INTO server_config (key, value, created_at) VALUES (?, ?, ?)")
        .bind(&[d1_text(key), d1_text(&now.to_string()), d1_int(now)])
    {
        let _ = stmt.run().await;
    }
}

// ── günlük bakım seti (cron + lazy ORTAK gövde) ─────────────────────────────

/// Günlük-GC seti — `scheduled()` günlük dalıyla BİT-AYNI (gövde lib.rs'ten
/// buraya saf-taşındı; cron da lazy de AYNI fonksiyonu çağırır → davranış
/// ayrışamaz). Hepsi idempotent/eşzamanlılık-dayanıklı: cleanup DELETE'leri
/// ikinci koşumda 0 satır etkiler; gc_fanout_retry cutoff-DELETE; reconcile
/// gerçeği yeniden hesaplar (last-writer aynı değeri yazar).
pub(crate) async fn run_daily(env: &Env) {
    if let Err(e) = cleanup_expired(env).await {
        // Debug-format kullanılmaz: error içinde SQL parametre/binding
        // (user_id, email vb.) sızabiliyor. İlk 80 char yeter — hata
        // kategorisi görünür, PII görünmez.
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("cleanup error: {}", truncated);
    }
    crate::messages::handlers::gc_fanout_retry(env).await;
    // Kota Faz-0 (SHADOW): günlük authoritative reconcile — best-effort depolama
    // sayaçlarındaki (user_storage/server_stats) drift'i media_objects gerçeğinden
    // yeniden-hesapla (self-heal). Hata bakımın kalanını kırmaz — logla-devam.
    if let Err(e) = crate::usage::reconcile_storage(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("usage reconcile error: {}", truncated);
    }
}

#[derive(Deserialize)]
struct ExpiredMediaRow {
    blob_id: String,
    // Kota Faz-0 (SHADOW): silinen blob'un sayaç-düşümü için boyut + yükleyen.
    size_bytes: i64,
    uploader_id: String,
}

/// Süresi dolmuş kalıntıların temizliği (lib.rs'ten saf-taşındı, davranış
/// değişmedi). Recipient ack atınca medya zaten anında silinir; bu fallback
/// "kimse almadı, 30 gün geçti" senaryosu için. Ayrıca expired invite_tokens
/// ve verification_codes da temizlenir (D1 büyümesin).
async fn cleanup_expired(env: &Env) -> Result<()> {
    let now = now_secs() as i64;
    let db = env.d1("DB")?;

    // 1) expired media: R2 + D1 sil
    let rows: Vec<ExpiredMediaRow> = db
        .prepare("SELECT blob_id, size_bytes, uploader_id FROM media_objects WHERE expires_at < ? LIMIT 500")
        .bind(&[d1_int(now)])?
        .all()
        .await?
        .results()?;

    if !rows.is_empty() {
        // Tek choke-point (crate::storage) üzerinden; R2-bağımlılığı tek yerde.
        // Lite kurulum (R2-binding'siz): blob-delete ATLANIR ama D1-meta silme +
        // sayaç-düşümü DEVAM eder — aksi halde `from_env`in `?`sı temizliği her
        // koşumda Err'letir ve SONRAKİ temizlik adımları (invite/verification GC)
        // atlanırdı. (Meta satırı yalnız R2-sonradan-kaldırıldı kenarında var
        // olabilir; upload Lite'ta D1-insert'ten önce 503'lenir.)
        if crate::storage::MediaStore::available(env) {
            let store = crate::storage::MediaStore::from_env(env)?;
            for row in &rows {
                let _ = store.delete(&row.blob_id).await; // best-effort günlük temizlik
            }
        }
        let placeholders: String =
            (0..rows.len()).map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "DELETE FROM media_objects WHERE blob_id IN ({})",
            placeholders
        );
        let binds: Vec<JsValue> = rows
            .iter()
            .map(|r| JsValue::from_str(&r.blob_id))
            .collect();
        db.prepare(&sql).bind(&binds)?.run().await?;
        console_log!("cleanup: {} expired media blobs removed", rows.len());
        // Kota Faz-0 (SHADOW, best-effort): süresi dolup silinen medyayı depolama
        // sayaçlarından düş (0-clamp; hata temizliği kırmaz, günlük reconcile onarır).
        let removed: Vec<(String, i64)> = rows
            .iter()
            .map(|r| (r.uploader_id.clone(), r.size_bytes))
            .collect();
        crate::usage::media_removed(&db, &removed).await;
    }

    // 2) expired invite tokens (used veya süresi dolmuş)
    db.prepare(
        "DELETE FROM invite_tokens WHERE expires_at < ? OR used = 1",
    )
    .bind(&[d1_int(now)])?
    .run()
    .await?;

    // 3) expired verification codes
    db.prepare("DELETE FROM verification_codes WHERE expires_at < ?")
        .bind(&[d1_int(now)])?
        .run()
        .await?;

    // 4) revoked / expired refresh tokens
    db.prepare(
        "DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1",
    )
    .bind(&[d1_int(now)])?
    .run()
    .await?;

    // 5) süresi dolmuş link istekleri (M2-S3.2; consume zaten satırı siler →
    //    'consumed' durumu persist edilmez, lazy-GC + bu temizlik expired'ları toplar)
    db.prepare("DELETE FROM link_requests WHERE expires_at < ?")
        .bind(&[d1_int(now)])?
        .run()
        .await?;

    Ok(())
}

// ── Saf yardımcılar (unit-testli) ───────────────────────────────────────────

/// `server_config.value` (TEXT) → epoch-sn. Satır-yok/boş/bozuk/negatif → 0
/// ("çok eski" = ilk uygun istekte koşar). Claim'in SQL tarafı
/// (`CAST(value AS INTEGER)`) bozuk-metni de 0'a CAST'ler → iki taraf tutarlı.
fn parse_stamp(v: Option<&str>) -> i64 {
    v.and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0)
        .max(0)
}

/// Damga eşiği aştı mı? Gelecekteki damga (saat-kayması) → due DEĞİL
/// (saturating: negatif fark 0 sayılır; bozuk-gelecek-damga sonsuz kilitlemez —
/// cron/lazy her başarılı koşumda damgayı şimdiye çeker).
fn is_due(now: i64, stamp_at: i64, after: i64) -> bool {
    now.saturating_sub(stamp_at) >= after
}

/// İzolat-içi gaz-kelebeği: hiç bakılmadıysa (0) ya da pencere geçtiyse bak.
/// `now < last` (saat geri kaydı) → saturating 0 → bakma (pencere yeniden dolana
/// dek); izolat kısa-ömürlü, kalıcı-kilit riski yok.
fn throttle_due(last: u64, now: u64, every: u64) -> bool {
    last == 0 || now.saturating_sub(last) >= every
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stamp_bozuk_ve_eksik_sifira_duser() {
        assert_eq!(parse_stamp(None), 0);
        assert_eq!(parse_stamp(Some("")), 0);
        assert_eq!(parse_stamp(Some("abc")), 0);
        assert_eq!(parse_stamp(Some("12.5")), 0);
        assert_eq!(parse_stamp(Some("-99")), 0, "negatif damga 0'a clamp");
        assert_eq!(parse_stamp(Some("1780000000")), 1_780_000_000);
        assert_eq!(parse_stamp(Some(" 42 ")), 42, "trim'li parse");
    }

    #[test]
    fn is_due_esik_sinirlari() {
        // Damga=0 (satır yok / ilk boot) → her zaman due.
        assert!(is_due(1_780_000_000, 0, DRAIN_LAZY_AFTER_SECS));
        // Tam eşik → due (>=).
        assert!(is_due(1000 + DRAIN_LAZY_AFTER_SECS, 1000, DRAIN_LAZY_AFTER_SECS));
        // Eşiğin 1sn altı → değil.
        assert!(!is_due(1000 + DRAIN_LAZY_AFTER_SECS - 1, 1000, DRAIN_LAZY_AFTER_SECS));
        // Gelecekteki damga (saat-kayması) → değil (saturating).
        assert!(!is_due(1000, 2000, DRAIN_LAZY_AFTER_SECS));
    }

    #[test]
    fn is_due_gunluk_esik() {
        let t0 = 1_780_000_000i64;
        assert!(!is_due(t0 + 86_400, t0, DAILY_LAZY_AFTER_SECS), "24s = pay içinde, uyur");
        assert!(is_due(t0 + 90_000, t0, DAILY_LAZY_AFTER_SECS), "25s → due");
    }

    #[test]
    fn throttle_ilk_bakis_ve_pencere() {
        assert!(throttle_due(0, 5, CHECK_EVERY_SECS), "izolat ilk istekte bakar");
        assert!(!throttle_due(100, 100 + CHECK_EVERY_SECS - 1, CHECK_EVERY_SECS));
        assert!(throttle_due(100, 100 + CHECK_EVERY_SECS, CHECK_EVERY_SECS));
        // Saat geri kaydı → bakma (underflow yok).
        assert!(!throttle_due(200, 150, CHECK_EVERY_SECS));
    }
}
