//! Medya blob deposu — tek choke-point + BACKEND SOYUTLAMASI.
//!
//! Takılabilir-Depolama epic Faz 1-2 (2026-07-08): `storage.rs` tek-dosya enum'u
//! (`MediaStore`) → iki-katmanlı modül klasörü:
//!   - `BlobStore` (backend tutamacı, ANAHTAR-tabanlı put/get/delete + probe) — `r2.rs`/`s3.rs`.
//!   - `StorageRouter` (yerleştirme/çözümleme; handler'lar YALNIZ bununla konuşur) — `router.rs`.
//!   - `s3.rs` = Faz 2 S3-uyumlu adaptör (SigV4 imzalı workerd fetch; B2/MinIO/ikinci-R2).
//!
//! TÜM blob get/put/delete BURADAN geçer; hiçbir handler doğrudan `env.bucket("MEDIA")`
//! çağırmaz. Tek-depo (`r2-primary`, hiç S3 kaydı yokken) davranışı BUGÜNKÜYLE BİREBİR:
//! router D1 `storage_backends`'i 60sn izolat-cache'le yükler; yalnız r2-primary satırı
//! varsa okuma/yazma R2'ye çözülür. Faz 2 = D1-config + çoklu-depo çözümleme + S3 adaptörü;
//! Faz 3 = yerleştirme politikası (priority/overflow/max_bytes/fallback) + health;
//! Faz 4 = drain/taşıma motoru (`drain.rs`: draining depo → kalan depolara, otomatik disabled).
//!
//! Neden enum, `trait`+`dyn` değil: workers-rs WASM'ı `!Send` → `async_trait(?Send)` /
//! boxed-dyn sürtünmesi. Sabit-küçük backend kümesi için enum-dispatch daha hafif.
//!
//! ANAHTAR-ŞEMASI ARTIK backend'in değil bu modülün malı (`media_key`/`code_key`/
//! `plugin_media_key`): her backend AYNI anahtarı kullanır → depolar arası taşıma =
//! kopyala, anahtar değişmez (Faz 4 drain ön-koşulu).

pub mod drain;
mod health;
pub mod maint;
mod r2;
mod router;
mod s3;

pub use health::{probe_all, write_health};
pub use r2::R2Store;
pub use router::{invalidate_storage_cache, placement_err_response, StorageRouter};
pub use s3::{validate_config as validate_s3_config, S3Config, S3Store};

/// Faz 1 tek-depo kimliği — migration 0028 default'u ('r2-primary'). Meta satırları
/// (media_objects/plugin_media_objects/plugin_code_objects) bu store_id'yi taşır;
/// tek-depo modunda TÜM okuma/yazma buraya çözülür. Faz 2+ çoklu-depo: 's3-<8hex>'.
pub const PRIMARY_STORE_ID: &str = "r2-primary";

/// Depodan çekilen blob: ham bytes + content-type.
pub struct BlobObject {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// Yerleştirme sınıfı — v1'de politika sınıf-agnostik (hepsi aynı priority-sırasına
/// düşer); API'de taşınır ki Faz 2+ sınıf-pinleme (örn. plugin-code hep r2'de) ekleyebilsin.
pub enum StorageClass {
    Media,
    PluginMedia,
    PluginCode,
}

/// Tek backend tutamacı. ANAHTAR-tabanlı (anahtar-şeması bu modülde: `media_key` vb.).
/// Faz 2: `S3(S3Store)` varyantı bağlandı (`s3.rs` + `sigv4.rs`).
pub enum BlobStore {
    R2(R2Store),
    S3(S3Store),
}

impl BlobStore {
    /// Blob'u yaz (content-type backend metadata'sına işlenir). İdempotent-overwrite.
    pub async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> worker::Result<()> {
        match self {
            BlobStore::R2(s) => s.put(key, bytes, content_type).await,
            BlobStore::S3(s) => s.put(key, bytes, content_type).await,
        }
    }

    /// Blob'u oku; yoksa `None`.
    pub async fn get(&self, key: &str) -> worker::Result<Option<BlobObject>> {
        match self {
            BlobStore::R2(s) => s.get(key).await,
            BlobStore::S3(s) => s.get(key).await,
        }
    }

    /// Blob'u sil. İDEMPOTENT ŞART (olmayan anahtar → Ok); gerçek depo hatası propagate
    /// (D1 meta silinmesin → öksüz-blob önlenir — mevcut R2 disiplini).
    pub async fn delete(&self, key: &str) -> worker::Result<()> {
        match self {
            BlobStore::R2(s) => s.delete(key).await,
            BlobStore::S3(s) => s.delete(key).await,
        }
    }

    /// Canlı-doğrulama (plan e): `probe/<uuid>` anahtarına PUT→GET→(bit-doğrula)→DELETE.
    /// Backend-agnostik (aynı put/get/delete choke-point'i) → R2 binding'i de S3
    /// kimlik-bilgisi de aynı round-trip'le sınanır. Cleanup DELETE best-effort
    /// (probe verdi/vermedi fark etmez; artık iz bırakmasın). Bit-uyuşmazlık → Err.
    pub async fn probe(&self) -> worker::Result<()> {
        let key = format!("probe/{}", uuid::Uuid::new_v4());
        let payload = b"sezi-probe".to_vec();
        self.put(&key, payload.clone(), "application/octet-stream")
            .await?;
        let got = self.get(&key).await;
        let _ = self.delete(&key).await; // best-effort temizlik
        match got? {
            Some(o) if o.bytes == payload => Ok(()),
            Some(_) => Err(worker::Error::RustError("probe: bit-uyuşmazlık".into())),
            None => Err(worker::Error::RustError("probe: yazılan blob okunamadı".into())),
        }
    }
}

// ── Anahtar-şeması (backend-agnostik; her depo AYNI anahtarı kullanır) ────────

/// Efemer kullanıcı-medyası anahtarı (ack+TTL'li). `media_objects` meta.
pub fn media_key(blob_id: &str) -> String {
    format!("media/{blob_id}")
}

/// Eklenti KODU blob anahtarı — KALICI + room-scope'lu (IDOR: `/plugin-blob/:room/:id`
/// path'i üyelik-doğrulı; başka odanın blob_id'sini bilse bile prefix açık değil).
pub fn code_key(room_id: &str, blob_id: &str) -> String {
    format!("plugin-code/{room_id}/{blob_id}")
}

/// Üye-yüklenebilir eklenti-MEDYA anahtarı — KALICI + room-scope'lu (koddan AYRI namespace).
pub fn plugin_media_key(room_id: &str, blob_id: &str) -> String {
    format!("plugin-media/{room_id}/{blob_id}")
}

/// Tek deponun canlı `BlobStore` tutamacını kur — `kind`+`config_json`'dan. Router
/// (build_stores), günlük health-probe (health::probe_all) ve elle-probe endpoint'i
/// (admin/storage.rs) ORTAK kullanır → depo-kurma davranışı üç yolda ayrışamaz.
///   - `r2_binding` → MEDIA binding (yok = Lite → `Err("binding_missing")` → depo atlanır).
///   - `s3` → `config_json` parse (bozuk → `Err(kısa-neden)`; o depoya blob → get 503, plan f#9).
///
/// Hata METNİ kısa + secret'sız (health `last_health_err`'e yazılabilir).
pub(crate) fn build_store(
    env: &worker::Env,
    kind: &str,
    config_json: &str,
) -> std::result::Result<BlobStore, String> {
    match kind {
        "r2_binding" => env
            .bucket("MEDIA")
            .map(|b| BlobStore::R2(R2Store::new(b)))
            .map_err(|_| "binding_missing".to_string()),
        "s3" => S3Store::from_config_json(config_json)
            .map(BlobStore::S3)
            .map_err(|e| e.to_string().chars().take(120).collect()),
        other => Err(format!("unsupported_kind:{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anahtar-şeması mevcut R2Store::key/code_key/plugin_media_key ile BİT-AYNI olmalı
    /// (davranış-değişmezlik: taşınan blob'lar aynı anahtardan okunur/yazılır).
    #[test]
    fn anahtar_semasi_mevcut_ile_bit_ayni() {
        assert_eq!(media_key("abc"), "media/abc");
        assert_eq!(code_key("room1", "blob1"), "plugin-code/room1/blob1");
        assert_eq!(plugin_media_key("room1", "blob1"), "plugin-media/room1/blob1");
    }
}
