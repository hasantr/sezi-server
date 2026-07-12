//! `StorageRouter` — yerleştirme + çözümleme. **Handler'lar YALNIZ bununla konuşur**
//! (tek choke-point; `MediaStore`'un yerini alır).
//!
//! FAZ 2 (2026-07-08): `from_env` D1 `storage_backends`'i yükler → çoklu-depo çözümleme.
//!   - **İzolat-içi 60sn config-cache** (maintenance.rs CHECK_EVERY_SECS deseni): cache'lenen
//!     yalnız D1 config-anlık-görüntüsü (düz veri; JsValue/binding DEĞİL) → sıcak-yolda
//!     istek-başına D1-roundtrip yok. Canlı `BlobStore` tutamaçları (R2 binding / S3Store)
//!     istek-başına ucuzca yeniden kurulur (binding-lookup ağa çıkmaz; S3Store = struct).
//!   - `/admin/storage` mutasyonu kendi izolatının cache'ini `invalidate_storage_cache` ile
//!     ANINDA düşürür; diğer izolatlar ≤60sn'de yakalar (plan f#12 — pencere zararsız).
//!
//! TEK-DEPO DAVRANIŞ-DEĞİŞMEZLİĞİ: hiç S3 kaydı yokken (yalnız migration 0028 default'u
//! `r2-primary`) okuma/yazma bugünküyle BİREBİR R2'ye çözülür. D1 okunamazsa/tablo-yoksa
//! → fallback tek `r2-primary` (binding varsa aktif; Lite'ta any_available=false).
//!
//! FAZ 3 (2026-07-08): put_new priority-overflow + per-depo max_bytes zorlaması +
//! PUT-hata'da sıradaki uygun depoya düş (degrade-yazma) + fırsatçı health-işaretleme
//! (put/get Err → last_health_ok=0). `readonly`/`disabled` yerleştirmede DIŞLANIR
//! (readonly: okuma/silme sürer). `storage_orphans` cleanup + drain → maintenance.rs / Faz 4.

use std::cell::RefCell;

use serde::Deserialize;
use worker::*;

use super::health::write_health;
use super::{build_store, BlobObject, BlobStore, StorageClass, PRIMARY_STORE_ID};
use crate::utils::now_secs;

/// İzolat-içi config-cache TTL (maintenance.rs `CHECK_EVERY_SECS` ile aynı kadans).
const CACHE_TTL_SECS: u64 = 60;

/// `put_new` yerleştirme sonucu HTTP-hatası (çağıran `placement_err_response` ile eşler).
pub enum PlacementError {
    /// Aktif depo(lar) VAR ama hepsi `max_bytes` dolu → 429 `quota_exceeded/server_storage`
    /// (client bu kota-sözleşmesini ZATEN tanır — op_result nonretryable). Plan f#5.
    AllFull,
    /// Aktif+sığan depo(lar) denendi ama HEPSİ PUT-hatası verdi (degrade tükendi) →
    /// 503 `upload_failed` (retryable op). Plan f#1.
    AllFailed,
    /// Hiç yazılabilir (`active`) depo yok (hepsi readonly/disabled) → 503 `upload_failed`.
    /// Normalde `any_available` kapısı önce yakalar; readonly-only kenar için.
    NoActive,
}

/// `PlacementError` → HTTP yanıtı (üç upload handler'ı ORTAK kullanır → eşleme tek-yerde).
pub fn placement_err_response(e: PlacementError) -> Result<Response> {
    match e {
        PlacementError::AllFull => {
            let resp = Response::from_json(
                &serde_json::json!({ "error": "quota_exceeded", "scope": "server_storage" }),
            )?;
            Ok(resp.with_status(429))
        }
        PlacementError::AllFailed | PlacementError::NoActive => {
            crate::respond::json_err(503, "upload_failed")
        }
    }
}

/// D1 `storage_backends` satırının düz-veri anlık görüntüsü (cache'lenebilir: JsValue yok).
/// Canlı `BlobStore` bundan istek-başına kurulur.
#[derive(Clone, Deserialize)]
struct StoreConfig {
    store_id: String,
    kind: String, // 'r2_binding' | 's3'  (Faz 6: 'webdav')
    state: String,
    priority: i64,
    max_bytes: Option<i64>,
    // Faz 3: per-depo tavan zorlaması için yerleştirme-anı kullanım tahmini (best-effort;
    // günlük reconcile + media_added/removed besler; ≤60sn cache bayat olabilir — soft cap).
    #[serde(default)]
    used_bytes: i64,
    config_json: String,
}

struct CachedConfig {
    fetched_at: u64,
    stores: Vec<StoreConfig>,
}

thread_local! {
    /// Son D1 config-anlık-görüntüsü (izolat-memoize; WASM tek-thread → RefCell yarışsız).
    static CONFIG_CACHE: RefCell<Option<CachedConfig>> = const { RefCell::new(None) };
}

/// `/admin/storage` mutasyonundan (POST/PATCH/DELETE) sonra çağrılır → BU izolatın
/// config-cache'ini düşür (bir sonraki `from_env` D1'den taze yükler). Diğer izolatlar
/// ≤60sn'de kendi TTL'leriyle yakalar (plan f#12).
pub fn invalidate_storage_cache() {
    CONFIG_CACHE.with(|c| *c.borrow_mut() = None);
}

/// Router içindeki bir deponun kimlik/politika meta'sı (D1'den yüklenir).
pub struct StoreMeta {
    pub store_id: String,
    pub state: String,
    // Yerleştirme SQL'de zaten priority-sıralı geliyor → router okumaz; Faz 4 drain
    // hedef-seçimi / panel-teşhis tüketecek (envanterde tutuluyor).
    #[allow(dead_code)]
    pub priority: i64,
    /// NULL = sınırsız; doluysa yerleştirmede `used_bytes + size <= max_bytes` zorlanır.
    pub max_bytes: Option<i64>,
    /// Yerleştirme-anı kullanım tahmini (best-effort; cache'den — soft cap).
    pub used_bytes: i64,
}

/// Priority-sıralı depo listesi. Handler'lar `put_new/get/delete/any_available`
/// üzerinden konuşur; hangi backend olduğunu bilmez.
pub struct StorageRouter {
    /// Fırsatçı health-işaretlemesi için (put/get Err → last_health_ok=0; best-effort).
    env: Env,
    stores: Vec<(StoreMeta, BlobStore)>,
}

impl StorageRouter {
    /// Router'ı kur: config-cache taze ise ondan, değilse D1 `storage_backends`'ten
    /// yükle (izolat-cache'e yaz) → priority-sıralı canlı `BlobStore`'ları kur.
    pub async fn from_env(env: &Env) -> Result<Self> {
        let now = now_secs();
        // 1. Cache'i SENKRON oku (await-öncesi borrow'u bırak; clone-out).
        let cached: Option<Vec<StoreConfig>> = CONFIG_CACHE.with(|c| {
            let g = c.borrow();
            match g.as_ref() {
                Some(cc) if now.saturating_sub(cc.fetched_at) < CACHE_TTL_SECS => {
                    Some(cc.stores.clone())
                }
                _ => None,
            }
        });
        // 2. Bayat/boş ise D1'den yükle + cache'le.
        let configs = match cached {
            Some(v) => v,
            None => {
                let v = load_configs(env).await;
                CONFIG_CACHE.with(|c| {
                    *c.borrow_mut() = Some(CachedConfig {
                        fetched_at: now,
                        stores: v.clone(),
                    })
                });
                v
            }
        };
        // 3. Canlı BlobStore'ları kur (ucuz: binding-lookup + S3Store struct).
        let stores = build_stores(env, configs);
        Ok(StorageRouter {
            env: env.clone(),
            stores,
        })
    }

    /// Medya deposu YAPILANDIRILMIŞ MI? — okuma/yazma yapılabilecek en az bir depo var mı.
    /// FAZ 3: `disabled` depolar SAYILMAZ (tamamen kapalı); `active/readonly/draining`
    /// sayılır (en azından okuma sürer). Lite+B2 kurulumda (R2-binding yok, S3 aktif) →
    /// true → capabilities `media=true` (plan f#11). Hiç non-disabled depo yok → 503
    /// `media_not_configured` (plan f#10, Lite bit-aynı).
    pub fn any_available(&self) -> bool {
        self.stores.iter().any(|(m, _)| m.state != "disabled")
    }

    /// Yeni blob yerleştir → yazılan store_id döner (çağıran meta satırına yazar).
    /// FAZ 3 POLİTİKA (plan c.4/f): priority-sıralı `active` depolar içinde
    /// `used_bytes + size <= max_bytes` SIĞAN İLK depoya yaz; PUT-hata verirse fırsatçı
    /// health-işaret + SIRADAKİ uygun depoya düş (degrade-yazma). Tümü dolu → `AllFull`
    /// (→ 429 quota); denenenlerin tümü PUT-fail → `AllFailed` (→ 503); hiç active yok →
    /// `NoActive`. Tek r2-primary'de (max_bytes NULL) = ilk depoya yaz → BİT-AYNI.
    pub async fn put_new(
        &self,
        _class: StorageClass,
        key: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> std::result::Result<String, PlacementError> {
        let size = bytes.len() as i64;
        let plan = classify_placement(
            self.stores.iter().map(|(m, _)| PlacementSlot {
                state: &m.state,
                max_bytes: m.max_bytes,
                used_bytes: m.used_bytes,
            }),
            size,
        );
        let candidates = match plan {
            Placement::Candidates(idxs) => idxs,
            Placement::AllFull => return Err(PlacementError::AllFull),
            Placement::NoActive => return Err(PlacementError::NoActive),
        };
        // Sığan aktif depoları priority-sırasında dene; ilk başaran kazanır.
        // PUT-hata → fırsatçı health-işaret + sıradakine düş (degrade-yazma).
        for idx in candidates {
            let (meta, store) = &self.stores[idx];
            match store.put(key, bytes.clone(), content_type).await {
                Ok(()) => return Ok(meta.store_id.clone()),
                Err(e) => {
                    write_health(&self.env, &meta.store_id, false, Some(&short(&e))).await;
                    console_warn!("storage: put fail {} → fallback: {e:?}", meta.store_id);
                }
            }
        }
        Err(PlacementError::AllFailed)
    }

    /// store_id'ye kayıtlı depodan oku. Bilinmeyen store_id → Err (blob'un depo'su bu
    /// izolatın cache'inde yoksa: yeni-eklenmiş depo penceresi ≤60sn — plan f#12; ya da
    /// config-parse-fail'li depo — plan f#9 → 503 degrade). Gerçek depo-hatası → fırsatçı
    /// health-işaret + Err (çağıran 503 `storage_backend_unavailable`, retryable — plan f#2).
    pub async fn get(&self, store_id: &str, key: &str) -> Result<Option<BlobObject>> {
        let store = self.resolve(store_id)?;
        match store.get(key).await {
            Ok(v) => Ok(v),
            Err(e) => {
                write_health(&self.env, store_id, false, Some(&short(&e))).await;
                Err(e)
            }
        }
    }

    /// store_id'ye kayıtlı depodan sil (idempotent — BlobStore::delete sözleşmesi).
    /// Fırsatçı health-işaret BURADA YAPILMAZ: delete hem tekil (ack) hem TOPLU
    /// (cleanup ≤500 / orphan-retry ≤50) yoldan çağrılır → per-satır health-yazımı
    /// batch'i şişirir. Toplu-yol kendi agregeli health-işaretini yapar (maintenance.rs);
    /// tekil ack-yolu Err'i çağırana propagate eder (meta KALIR → retry — plan f#3).
    pub async fn delete(&self, store_id: &str, key: &str) -> Result<()> {
        self.resolve(store_id)?.delete(key).await
    }

    fn resolve(&self, store_id: &str) -> Result<&BlobStore> {
        self.stores
            .iter()
            .find(|(m, _)| m.store_id == store_id)
            .map(|(_, s)| s)
            .ok_or_else(|| Error::RustError(format!("unknown_store:{store_id}")))
    }
}

/// `worker::Error` → 120-char kısa metin (health `last_health_err`: secret'sız, kırpık).
fn short(e: &Error) -> String {
    e.to_string().chars().take(120).collect()
}

// ── Yerleştirme politikası (SAF — unit-testli; worker türlerinden bağımsız) ──────

/// Bir deponun yerleştirme-anı görünümü (state + tavan/kullanım).
struct PlacementSlot<'a> {
    state: &'a str,
    max_bytes: Option<i64>,
    used_bytes: i64,
}

/// Yerleştirme sınıflaması (put_new'in saf çekirdeği).
#[derive(Debug, PartialEq)]
enum Placement {
    /// Denenecek depo INDEKSLERİ (priority-sırasında; PUT-fallback için tümü).
    Candidates(Vec<usize>),
    /// Aktif depo var ama HİÇBİRİ sığmıyor (hepsi max_bytes dolu) → 429 quota.
    AllFull,
    /// Hiç `active` depo yok (hepsi readonly/disabled) → 503.
    NoActive,
}

/// Priority-sıralı depo dilimlerinden yerleştirme adaylarını seç. `active` VE
/// (`max_bytes` NULL || `used_bytes + size <= max_bytes`) olan depoların indeksleri
/// giriş sırasında (= priority-sıralı) döner. Overflow: birinci dolu → ikinciye düşer.
fn classify_placement<'a>(
    slots: impl Iterator<Item = PlacementSlot<'a>>,
    size: i64,
) -> Placement {
    let mut candidates = Vec::new();
    let mut any_active = false;
    for (idx, s) in slots.enumerate() {
        if s.state != "active" {
            continue; // readonly/draining/disabled → yerleştirmede dışla (plan f#6)
        }
        any_active = true;
        let fits = match s.max_bytes {
            None => true,
            Some(cap) => s.used_bytes.saturating_add(size) <= cap,
        };
        if fits {
            candidates.push(idx);
        }
    }
    if !candidates.is_empty() {
        Placement::Candidates(candidates)
    } else if any_active {
        Placement::AllFull // aktif var ama hiçbiri sığmadı
    } else {
        Placement::NoActive
    }
}

/// D1 `storage_backends`'i priority-sıralı yükle. HATA-DAYANIKLI: tablo yok / D1
/// hatası / satır yok → fallback tek `r2-primary` (bugünkü tek-depo davranışı
/// korunur; binding varsa aktif, Lite'ta build_stores boş → any_available false).
async fn load_configs(env: &Env) -> Vec<StoreConfig> {
    let Ok(db) = env.d1("DB") else {
        return fallback_configs();
    };
    let rows: Vec<StoreConfig> = match db
        .prepare(
            "SELECT store_id, kind, state, priority, max_bytes, used_bytes, config_json \
             FROM storage_backends ORDER BY priority ASC",
        )
        .all()
        .await
    {
        Ok(res) => res.results().unwrap_or_default(),
        Err(_) => return fallback_configs(),
    };
    if rows.is_empty() {
        return fallback_configs();
    }
    rows
}

/// Fallback: yalnız `r2-primary` (migration/tablo-yok penceresi + D1-hatası → bugünkü
/// tek-depo davranışıyla bit-aynı). `disabled` durumundaki r2-primary'yi de kapsamaz —
/// D1 okunamıyorsa en güvenli varsayım: R2 binding'i aktif dene.
fn fallback_configs() -> Vec<StoreConfig> {
    vec![StoreConfig {
        store_id: PRIMARY_STORE_ID.to_string(),
        kind: "r2_binding".to_string(),
        state: "active".to_string(),
        priority: 0,
        max_bytes: None,
        used_bytes: 0,
        config_json: "{}".to_string(),
    }]
}

/// Config anlık-görüntüsünden canlı `BlobStore`'ları kur. Kurulamayan depo ATLANIR
/// (fırsatçı degrade): r2_binding + MEDIA-binding yok (Lite) → atla; s3 config-parse
/// fail → logla+atla (blob'u o depoda olan get → resolve Err → 503, plan f#9).
/// `disabled` depolar da yüklenir (okuma/silme çalışsın; put_new active filtreler).
fn build_stores(env: &Env, configs: Vec<StoreConfig>) -> Vec<(StoreMeta, BlobStore)> {
    let mut out = Vec::new();
    for cfg in configs {
        match build_store(env, &cfg.kind, &cfg.config_json) {
            Ok(store) => out.push((
                StoreMeta {
                    store_id: cfg.store_id,
                    state: cfg.state,
                    priority: cfg.priority,
                    max_bytes: cfg.max_bytes,
                    used_bytes: cfg.used_bytes,
                },
                store,
            )),
            Err(e) => {
                // Lite (binding_missing) sessiz-normal; s3-parse-fail owner-hatası → warn.
                if cfg.kind != "r2_binding" {
                    console_warn!("storage: '{}' kurulamadı ({}): {e}", cfg.store_id, cfg.kind);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(state: &str, max: Option<i64>, used: i64) -> PlacementSlot<'_> {
        PlacementSlot {
            state,
            max_bytes: max,
            used_bytes: used,
        }
    }

    #[test]
    fn tek_active_sinirsiz_ilk_depo() {
        // Tek r2-primary (max NULL) → daima ilk aday (bit-aynı davranış).
        let p = classify_placement([slot("active", None, 0)].into_iter(), 100);
        assert_eq!(p, Placement::Candidates(vec![0]));
    }

    #[test]
    fn overflow_dolu_depo_atlanir_sonrakine_duser() {
        // idx0 dolu (0+100 > 10), idx1 sığar → yalnız idx1 aday (plan f#5 overflow).
        let p = classify_placement(
            [slot("active", Some(10), 0), slot("active", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::Candidates(vec![1]));
    }

    #[test]
    fn iki_sigan_depo_ikisi_de_aday_priority_sirasinda() {
        // İkisi de sığar → ikisi aday (PUT-fallback için); giriş(=priority) sırası korunur.
        let p = classify_placement(
            [slot("active", Some(1000), 0), slot("active", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::Candidates(vec![0, 1]));
    }

    #[test]
    fn tavan_tam_sinirda_sigar() {
        // used + size == cap → SIĞAR (<=).
        let p = classify_placement([slot("active", Some(100), 0)].into_iter(), 100);
        assert_eq!(p, Placement::Candidates(vec![0]));
        // used + size == cap+1 → SIĞMAZ.
        let p = classify_placement([slot("active", Some(99), 0)].into_iter(), 100);
        assert_eq!(p, Placement::AllFull);
    }

    #[test]
    fn readonly_ve_disabled_yerlestirmede_dislanir() {
        // readonly + disabled tek başına → NoActive (plan f#6: readonly yazma-dışı).
        let p = classify_placement(
            [slot("readonly", None, 0), slot("disabled", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::NoActive);
        // readonly(0) atlanır, active(1) sığar → yalnız idx1 (readonly okuma sürer, yazma değil).
        let p = classify_placement(
            [slot("readonly", None, 0), slot("active", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::Candidates(vec![1]));
    }

    #[test]
    fn tum_active_dolu_allfull() {
        // İki active ama ikisi de dolu → AllFull (→ 429 quota, plan f#5).
        let p = classify_placement(
            [slot("active", Some(10), 5), slot("active", Some(20), 20)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::AllFull);
    }

    #[test]
    fn hic_depo_yok_noactive() {
        let p = classify_placement(std::iter::empty(), 100);
        assert_eq!(p, Placement::NoActive);
    }
}
