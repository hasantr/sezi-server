//! CF GraphQL Analytics — FATURA-DOĞRU kullanım rakamları (kota epic **Faz 3**).
//! `/admin/stats` self-report sayaçlarının (Faz 1c) yanına Cloudflare'ın kendi
//! ölçtüğü istek sayısı (workersInvocationsAdaptive) + R2 depolama
//! (r2StorageAdaptiveGroups) eklenir → "authoritative" dual-logic.
//!
//! ⚠️ FAIL-OPEN MUTLAK (bu modül CANLI test edilemeden yazıldı — CF_API_TOKEN
//! henüz yok): HER hata yolu `None` döner → stats self-report'a düşer, endpoint
//! ASLA 500 atmaz, mevcut alanlar ASLA bozulmaz. Zincir:
//!   0. Config çözümü per-key **env-secret/var ÖNCE, D1 `server_settings`
//!      sonra** (0024; owner `PATCH /admin/cf-config` ile app'ten girer —
//!      env-set kazanır: account-id env'de + token UI'dan-D1'de karışık
//!      kurulum çalışır). D1 okuma FAIL-OPEN: tablo/kolon yok (migration
//!      öncesi) ya da D1 hatası → o kaynak yok sayılır (env-only, bugünkü
//!      davranış). İki env key de set ise D1'e HİÇ gidilmez.
//!   1. Token/account HİÇBİR kaynakta yok ya da boş → erken None (CF ağına
//!      hiç çıkılmaz — VPS/standalone ya da token-kurulmamış CF = bugünkü
//!      davranış BİT-AYNI).
//!   2. fetch/ağ hatası → `console_warn` + o sorgu None.
//!   3. HTTP status != 200 → `console_warn` (status + gövde) + o sorgu None.
//!   4. Gövde JSON parse-fail → `console_warn` (ham gövde, kısaltılmış) + None.
//!   5. GraphQL `errors` dolu → `console_warn` (CF'nin hata mesajı — token
//!      gelince `wrangler tail`'de görülür) + yine de data parse denenir
//!      (kısmi başarı mümkün).
//!   6. Alan-bazlı SAVUNMACI parse: her metrik bağımsız `.get(..).and_then(..)`
//!      zinciri — eksik/null/şema-değişti → o metrik None, diğerleri yaşar.
//!   7. İstek-sayısı ve R2 sorguları AYRI POST'lar: R2 alt-sorgusu şema-uyumsuz
//!      çıkarsa (validation hatası TÜM sorguyu düşürürdü) asıl metrik olan
//!      istek sayıları ETKİLENMEZ.
//!   8. TÜM metrikler None → None (hiç CF verisi yok = authoritative DEĞİL).
//!
//! Kurulum: CF dashboard → API token (Account Analytics: Read) → ya owner
//! Sezi uygulamasından girer (Sunucu kullanımı → CF Analytics; D1'e yazılır,
//! WRITE-ONLY — hiçbir endpoint geri döndürmez) ya da CLI ile
//! `wrangler secret put CF_API_TOKEN` + `CF_ACCOUNT_ID` (var ya da secret).

use worker::*;

/// CF'nin ölçtüğü kullanım. Her alan bağımsız Option — sorgunun bir parçası
/// şema-uyumsuz çıkarsa diğerleri yine gelir (alan-bazlı fail-open).
pub struct CfUsage {
    /// Bugün (UTC 00:00'dan beri) worker istek sayısı — CF faturasıyla birebir.
    pub requests_today: Option<i64>,
    /// Bu ay (ay-başı UTC'den beri) worker istek sayısı.
    pub requests_month: Option<i64>,
    /// R2 depolama (payload byte) — CF'nin ölçtüğü; self-report `media.bytes`'ın
    /// YANINA konur, onu değiştirmez.
    pub r2_storage_bytes: Option<i64>,
}

/// wrangler.toml `name` — workersInvocationsAdaptive scriptName filtresi.
/// Worker yeniden adlandırılırsa burası da güncellenmeli (tek yer).
const SCRIPT_NAME: &str = "sezgi-worker-rs";

/// İstek-sayısı sorgusu (ASIL metrik) — SABİT, tek yer (CF şema değişirse
/// yalnız burası oynar). Alias'lı iki pencere: bugün-00:00Z'den + ay-başından.
///
/// ⚠️ CANLI-TUNING GEREKEBİLİR (token olmadan doğrulanamadı):
/// - Değişken tipleri CF'nin dokümante örneğine göre lowercase `string`
///   (CF Analytics şeması standart GraphQL `String`/`Time` DEĞİL kendi
///   skalerlerini kullanır); CF reddederse ilk şüphe burası (`string!`
///   varyantını dene).
/// - Filtre alan adları (`scriptName`, `datetime_geq`) CF dokümanındaki
///   workersInvocationsAdaptive örneğine göre; şema evrilirse `errors`
///   bloğu `wrangler tail`'de görülür.
/// - `limit` CF'nin zorunlu-limit kuralı için; sum tek satıra katlandığından
///   değerin kendisi sonucu değiştirmez.
const REQUESTS_QUERY: &str = r#"
query SezgiRequests($accountTag: string, $scriptName: string, $todayStart: string, $monthStart: string) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      today: workersInvocationsAdaptive(
        limit: 1000
        filter: { scriptName: $scriptName, datetime_geq: $todayStart }
      ) {
        sum { requests }
      }
      month: workersInvocationsAdaptive(
        limit: 1000
        filter: { scriptName: $scriptName, datetime_geq: $monthStart }
      ) {
        sum { requests }
      }
    }
  }
}
"#;

/// R2 depolama sorgusu (İKİNCİL, best-effort) — BİLEREK ayrı POST: bu dataset
/// adaptif-örneklidir ve "anlık depolama = son gözlem max{payloadSize}" deseni
/// canlıda doğrulanmalı. Şema-uyumsuz çıkarsa yalnız bu sorgu düşer (GraphQL
/// validation hatası tüm sorguyu düşürdüğünden istek-sayısıyla AYNI gövdeye
/// konmadı). Sorun çıkarsa r2_storage_bytes None kalır, zorlanmaz.
const R2_QUERY: &str = r#"
query SezgiR2($accountTag: string, $todayStart: string) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      r2: r2StorageAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $todayStart }
      ) {
        max { payloadSize }
      }
    }
  }
}
"#;

/// `secret` ÖNCE, `var` sonra oku (token=secret beklenir; account-id var da
/// olabilir). Yok/boş/whitespace → None (kurulmamış say). Yalnız ENV katmanı —
/// D1 fallback `resolve_cfg`'de (env-set kazanır).
fn read_cfg(env: &Env, key: &str) -> Option<String> {
    let raw = env
        .secret(key)
        .map(|s| s.to_string())
        .or_else(|_| env.var(key).map(|v| v.to_string()))
        .ok()?;
    normalize(raw)
}

/// Trim + boş → None (env ve D1 değerleri AYNI disiplinle normalize edilir).
fn normalize(raw: String) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// D1 `server_settings` cf kolonları (0024) — owner'ın `PATCH /admin/cf-config`
/// ile app'ten girdiği config. FAIL-OPEN MUTLAK: D1 binding yok / tablo-kolon
/// yok (migration öncesi) / satır yok / sorgu hatası → (None, None) = o kaynak
/// yok sayılır (env-only, bugünkü davranış; stats ASLA 500 atmaz).
async fn read_db_cfg(env: &Env) -> (Option<String>, Option<String>) {
    #[derive(serde::Deserialize)]
    struct Row {
        cf_api_token: Option<String>,
        cf_account_id: Option<String>,
    }
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return (None, None),
    };
    let row: Option<Row> = match db
        .prepare("SELECT cf_api_token, cf_account_id FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // Beklenen durum migration-öncesi "no such column" — sessiz düşmesin
            // ama endpoint de kırılmasın (fail-open + iz).
            console_warn!("cf_analytics: D1 config okunamadı (fail-open): {e:?}");
            return (None, None);
        }
    };
    match row {
        Some(r) => (
            r.cf_api_token.and_then(normalize),
            r.cf_account_id.and_then(normalize),
        ),
        None => (None, None),
    }
}

/// Efektif config — per-key **env ÖNCE, D1 sonra** (env-set kazanır; karışık
/// kurulum: account-id env'de + token UI'dan-D1'de çalışır). İki env key de
/// set ise D1'e HİÇ gidilmez (env-kurulu hızlı-yol bugünkü davranışla BİT-AYNI).
async fn resolve_cfg(env: &Env) -> (Option<String>, Option<String>) {
    let env_token = read_cfg(env, "CF_API_TOKEN");
    let env_account = read_cfg(env, "CF_ACCOUNT_ID");
    if env_token.is_some() && env_account.is_some() {
        return (env_token, env_account);
    }
    let (db_token, db_account) = read_db_cfg(env).await;
    (env_token.or(db_token), env_account.or(db_account))
}

/// Token kurulu mu (env VEYA D1) — `/admin/stats` `cf_configured` alanı +
/// `PATCH /admin/cf-config` cevabı için. HAFİF: CF ağına ÇIKMAZ (`fetch`
/// 2 GraphQL POST = pahalı); yalnız token VARLIĞINA bakar. WRITE-ONLY
/// sözleşmenin okuma yüzü: değer değil yalnız bool sızar.
pub async fn is_configured(env: &Env) -> bool {
    if read_cfg(env, "CF_API_TOKEN").is_some() {
        return true;
    }
    read_db_cfg(env).await.0.is_some()
}

/// Log gövdesini kısalt — `wrangler tail` okunur kalsın (CF hata mesajları
/// genelde ilk birkaç yüz karakterde).
fn truncate_for_log(s: &str) -> String {
    const MAX: usize = 600;
    if s.len() <= MAX {
        s.to_string()
    } else {
        // char-sınırına yuvarla (UTF-8 ortasından kesme → panic olmasın).
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}… ({}B)", &s[..end], s.len())
    }
}

/// Bugün 00:00Z — usage.rs `today_utc` ("YYYY-MM-DD", self-report sayaçlarla
/// AYNI gün penceresi) → ISO8601.
fn today_start_utc() -> String {
    format!("{}T00:00:00Z", crate::usage::today_utc())
}

/// Ay başı 00:00Z — turn.rs `current_month_utc` ("YYYY-MM", TURN bütçesiyle
/// AYNI ay penceresi) → ISO8601.
fn month_start_utc() -> String {
    format!("{}-01T00:00:00Z", crate::turn::current_month_utc())
}

/// Tek GraphQL POST → `data.viewer.accounts[0]` düğümü. Her hata katmanı
/// `console_warn` + None (fail-open; `tag` log'da hangi sorgu olduğunu söyler).
/// fcm.rs Fetch/RequestInit deseni; gövde TEXT alınır → parse-fail'de ham
/// gövde loglanabilir (canlı tuning kanıtı) + OTK-wedge dersi (resp.json
/// yerine text+serde_json evde-desen).
async fn graphql_account(token: &str, body: String, tag: &str) -> Option<serde_json::Value> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    if headers
        .set("authorization", &format!("Bearer {token}"))
        .is_err()
        || headers.set("content-type", "application/json").is_err()
    {
        console_warn!("cf_analytics[{tag}]: header kurulamadı");
        return None;
    }
    init.with_headers(headers);

    // (2) fetch/ağ hatası → yut + logla + None (stats 500 atmaz).
    let req = match Request::new_with_init("https://api.cloudflare.com/client/v4/graphql", &init) {
        Ok(r) => r,
        Err(e) => {
            console_warn!("cf_analytics[{tag}]: request kurulamadı: {e:?}");
            return None;
        }
    };
    let mut resp = match Fetch::Request(req).send().await {
        Ok(r) => r,
        Err(e) => {
            console_warn!("cf_analytics[{tag}]: fetch hatası: {e:?}");
            return None;
        }
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            console_warn!("cf_analytics[{tag}]: gövde okunamadı: {e:?}");
            return None;
        }
    };

    // (3) HTTP hatası (401 token-yanlış / 403 izin-eksik / 5xx) → logla + None.
    if resp.status_code() != 200 {
        console_warn!(
            "cf_analytics[{tag}]: HTTP {} — {}",
            resp.status_code(),
            truncate_for_log(&text)
        );
        return None;
    }

    // (4) JSON parse-fail → logla + None.
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            console_warn!(
                "cf_analytics[{tag}]: JSON parse-fail: {e} — {}",
                truncate_for_log(&text)
            );
            return None;
        }
    };

    // (5) GraphQL `errors` — CF şema/filtre uyuşmazlığında burada konuşur.
    // Logla ama DEVAM et: data kısmi gelmiş olabilir.
    if let Some(errors) = v.get("errors").filter(|e| !e.is_null()) {
        if errors.as_array().map(|a| !a.is_empty()).unwrap_or(true) {
            console_warn!(
                "cf_analytics[{tag}]: GraphQL errors: {}",
                truncate_for_log(&errors.to_string())
            );
        }
    }

    let account = v
        .get("data")
        .and_then(|d| d.get("viewer"))
        .and_then(|w| w.get("accounts"))
        .and_then(|a| a.get(0))
        .cloned();
    if account.is_none() {
        console_warn!(
            "cf_analytics[{tag}]: data.viewer.accounts[0] yok — {}",
            truncate_for_log(&text)
        );
    }
    account
}

/// `<alias>[0].sum.requests` — savunmacı gezinme; herhangi bir seviye
/// eksik/null/yanlış-tip → None (o metrik düşer, çağıran yaşar).
fn extract_requests(account: &serde_json::Value, alias: &str) -> Option<i64> {
    let v = account.get(alias)?.get(0)?.get("sum")?.get("requests")?;
    // CF sum'ları tam sayı döner ama şema float verirse de kabul et (savunmacı).
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

/// `r2[0].max.payloadSize` — aynı savunmacı desen.
fn extract_r2_bytes(account: &serde_json::Value) -> Option<i64> {
    let v = account.get("r2")?.get(0)?.get("max")?.get("payloadSize")?;
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

/// CF Analytics'ten kullanım çek. `None` = CF yok/kurulmamış/hata → çağıran
/// (admin/stats) self-report sayaçlara düşer (dual-logic'in fallback kolu).
/// Ayrıntılı fail-open zinciri modül başlığında.
pub async fn fetch(env: &Env) -> Option<CfUsage> {
    // (0)+(1) Config çözümü env-first/D1-fallback (`resolve_cfg`); token ya da
    // account HİÇBİR kaynakta yoksa CF ağına hiç çıkmadan None (kurulmamış =
    // self-report, bugünkü davranış).
    let (token, account_tag) = match resolve_cfg(env).await {
        (Some(t), Some(a)) => (t, a),
        _ => return None,
    };

    let today_start = today_start_utc();

    // ── ASIL metrik: istek sayıları (bugün + bu ay) ──────────────────────────
    let requests_body = serde_json::json!({
        "query": REQUESTS_QUERY,
        "variables": {
            "accountTag": account_tag,
            "scriptName": SCRIPT_NAME,
            "todayStart": today_start,
            "monthStart": month_start_utc(),
        }
    })
    .to_string();
    let requests_account = graphql_account(&token, requests_body, "requests").await;
    let (requests_today, requests_month) = match &requests_account {
        Some(acc) => (
            extract_requests(acc, "today"),
            extract_requests(acc, "month"),
        ),
        None => (None, None),
    };

    // ── İKİNCİL: R2 depolama (best-effort; ayrı POST — bkz. R2_QUERY notu) ──
    let r2_body = serde_json::json!({
        "query": R2_QUERY,
        "variables": {
            "accountTag": account_tag,
            "todayStart": today_start,
        }
    })
    .to_string();
    let r2_storage_bytes = match graphql_account(&token, r2_body, "r2").await {
        Some(acc) => extract_r2_bytes(&acc),
        None => None,
    };

    // (8) Hepsi None = CF'den TEK gerçek rakam yok → authoritative DEĞİLİZ;
    // None dön ki stats `authoritative:false` + self-report bassın.
    if requests_today.is_none() && requests_month.is_none() && r2_storage_bytes.is_none() {
        console_warn!("cf_analytics: hiç metrik çıkmadı (şema-tuning gerek? — üstteki loglara bak)");
        return None;
    }
    Some(CfUsage {
        requests_today,
        requests_month,
        r2_storage_bytes,
    })
}
