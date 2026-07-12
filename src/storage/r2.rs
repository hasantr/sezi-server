//! Cloudflare R2 backend — `MediaStore::R2Store`'un (2026-07-06) ANAHTAR-tabanlı hâli.
//!
//! Faz 1 saf-taşıma: eski `R2Store` kanal-başına (media/code/plugin-media) ayrı metot +
//! iç-anahtar hesaplıyordu; artık anahtar-şeması `storage::{media_key,code_key,
//! plugin_media_key}`de → burada TEK put/get/delete, çağıran hazır anahtarı geçer.
//! Davranış birebir korunur (aynı R2 çağrıları, aynı content-type disiplini).
//!
//! **CF-kilit yalnız burada** — taşınabilir-sunucu geçişinde (VPS/Pi) yeni backend
//! struct'ı yazılır (`s3.rs` gibi), `BlobStore` enum'una varyant eklenir; handler değişmez.

use worker::*;

use super::BlobObject;

pub struct R2Store {
    bucket: Bucket,
}

impl R2Store {
    /// MEDIA binding'inden kur. Binding-lookup UCUZ (ağa çıkmaz); router `from_env`
    /// binding yoksa bu depoyu HİÇ eklemez (any_available=false → 503 media_not_configured).
    pub fn new(bucket: Bucket) -> Self {
        R2Store { bucket }
    }

    /// Blob'u yaz — content-type R2 http_metadata'sına işlenir. İdempotent-overwrite
    /// (aynı anahtara tekrar PUT üstüne yazar).
    pub async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<()> {
        self.bucket
            .put(key, bytes)
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_string()),
                ..Default::default()
            })
            .execute()
            .await?;
        Ok(())
    }

    /// Blob'u oku; yoksa `None`. content-type R2 metadata'sından (yoksa octet-stream).
    pub async fn get(&self, key: &str) -> Result<Option<BlobObject>> {
        let Some(obj) = self.bucket.get(key).execute().await? else {
            return Ok(None);
        };
        let Some(body) = obj.body() else {
            return Ok(None);
        };
        let bytes = body.bytes().await?;
        let content_type = obj
            .http_metadata()
            .content_type
            .unwrap_or_else(|| "application/octet-stream".into());
        Ok(Some(BlobObject { bytes, content_type }))
    }

    /// Blob'u sil. R2 delete idempotent (yok ise hata VERMEZ) → ack/cleanup tekrarında
    /// güvenli. GERÇEK R2 hatası (outage) propagate edilir ki çağıran D1 metasını
    /// silmesin → öksüz-blob (D1-kayıtsız R2 objesi, cleanup hiç görmez) önlenir.
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.bucket.delete(key).await?;
        Ok(())
    }
}
