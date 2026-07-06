//! Medya blob deposu — tek choke-point + BACKEND SOYUTLAMASI (2026-07-06 trait-first).
//!
//! TÜM blob get/put/delete BURADAN geçer; hiçbir handler doğrudan `env.bucket("MEDIA")`
//! çağırmaz. `MediaStore` artık bir **ENUM (backend seçici)**: bugün yalnız R2, ama
//! ikinci backend (S3 · GDrive · kişisel-sunucu · yerel-FS) eklemek = yeni bir varyant
//! + match kolu; **ÇAĞRI YERLERİ DEĞİŞMEZ** + kota-sayacı `put/delete`i sarabilir.
//!
//! Neden enum, `trait`+`dyn` değil: workers-rs WASM'ı `!Send` → `async_trait(?Send)` /
//! boxed-dyn sürtünmesi. Sabit-küçük backend kümesi için enum-dispatch daha hafif
//! (ek-crate yok, monomorfize, çağrı yerleri temiz). Backend leştiği yer yine tek nokta.
//!
//! CF-kilit yalnız `R2Store`'da yoğunlaşır (taşınabilir-sunucu geçişinde tek yer).
//! blob_id→depo-anahtarı eşlemesi de backend'e özgü (R2Store içinde `media/{id}`).

use worker::*;

/// Depodan çekilen blob: ham bytes + content-type.
pub struct BlobObject {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// Medya deposu — backend-agnostik seam. `from_env` yapılandırılmış backend'i seçer
/// (şimdilik tek: R2). Kota-sayacı ve çağıranlar bu tipe konuşur; hangi backend
/// olduğunu bilmez.
pub enum MediaStore {
    R2(R2Store),
}

impl MediaStore {
    /// Yapılandırılmış backend'e bağlan. Bugün R2 `MEDIA` binding'i; ileride config
    /// (server_settings / env) hangi backend olduğunu belirler → burada dallanır.
    pub fn from_env(env: &Env) -> Result<Self> {
        Ok(MediaStore::R2(R2Store {
            bucket: env.bucket("MEDIA")?,
        }))
    }

    /// Blob'u yaz (content-type backend metadata'sına işlenir).
    pub async fn put(&self, blob_id: &str, bytes: Vec<u8>, content_type: &str) -> Result<()> {
        match self {
            MediaStore::R2(s) => s.put(blob_id, bytes, content_type).await,
        }
    }

    /// Blob'u oku; yoksa `None`.
    pub async fn get(&self, blob_id: &str) -> Result<Option<BlobObject>> {
        match self {
            MediaStore::R2(s) => s.get(blob_id).await,
        }
    }

    /// Blob'u sil (backend'e göre idempotent olmalı).
    pub async fn delete(&self, blob_id: &str) -> Result<()> {
        match self {
            MediaStore::R2(s) => s.delete(blob_id).await,
        }
    }

    /// Eklenti KODU blob'u yaz (medyadan AYRI, room-scope'lu namespace).
    pub async fn put_code(&self, room_id: &str, blob_id: &str, bytes: Vec<u8>) -> Result<()> {
        match self {
            MediaStore::R2(s) => s.put_code(room_id, blob_id, bytes).await,
        }
    }

    /// Eklenti kodu blob'u oku (ham ciphertext); yoksa `None`.
    pub async fn get_code(&self, room_id: &str, blob_id: &str) -> Result<Option<Vec<u8>>> {
        match self {
            MediaStore::R2(s) => s.get_code(room_id, blob_id).await,
        }
    }
}

/// Cloudflare R2 backend. **CF-kilit yalnız burada** — taşınabilir-sunucu geçişinde
/// (VPS/Pi: yerel-FS/S3) yeni bir backend struct'ı yazılır, `MediaStore` enum'una
/// varyant eklenir; hiçbir handler değişmez.
pub struct R2Store {
    bucket: Bucket,
}

impl R2Store {
    fn key(blob_id: &str) -> String {
        format!("media/{blob_id}")
    }

    /// Eklenti kodu blob anahtarı (Faz-4 server-code). Medyadan AYRI namespace +
    /// **room-scope'lu** → grup-kapısı IDOR'unu kapatır: bir üye yalnız KENDİ odasının
    /// (`/plugin-blob/:room/:id` path'i üyelik-doğrulı) prefix'inden çekebilir; başka
    /// odanın blob_id'sini bilse bile `plugin-code/{başka-oda}/{id}` ona açık değil.
    fn code_key(room_id: &str, blob_id: &str) -> String {
        format!("plugin-code/{room_id}/{blob_id}")
    }

    /// Eklenti kodu blob'unu yaz — KALICI (medyanın aksine TTL/ack-delete YOK; kod
    /// yıllarca yaşar, her yeni cihaz/üye indirir). İçerik E2E ŞİFRELİ ciphertext
    /// (XChaCha20 STREAM); server opak görür. Idempotent (aynı (room,id) PUT'u üzerine yazar).
    async fn put_code(&self, room_id: &str, blob_id: &str, bytes: Vec<u8>) -> Result<()> {
        self.bucket
            .put(Self::code_key(room_id, blob_id), bytes)
            .http_metadata(HttpMetadata {
                content_type: Some("application/octet-stream".to_string()),
                ..Default::default()
            })
            .execute()
            .await?;
        Ok(())
    }

    async fn get_code(&self, room_id: &str, blob_id: &str) -> Result<Option<Vec<u8>>> {
        let Some(obj) = self
            .bucket
            .get(Self::code_key(room_id, blob_id))
            .execute()
            .await?
        else {
            return Ok(None);
        };
        let Some(body) = obj.body() else {
            return Ok(None);
        };
        Ok(Some(body.bytes().await?))
    }

    async fn put(&self, blob_id: &str, bytes: Vec<u8>, content_type: &str) -> Result<()> {
        self.bucket
            .put(Self::key(blob_id), bytes)
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_string()),
                ..Default::default()
            })
            .execute()
            .await?;
        Ok(())
    }

    async fn get(&self, blob_id: &str) -> Result<Option<BlobObject>> {
        let Some(obj) = self.bucket.get(Self::key(blob_id)).execute().await? else {
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

    /// Blob'u sil. R2 delete idempotent (yok ise hata VERMEZ) → ack/cleanup
    /// tekrarında güvenli. GERÇEK R2 hatası (outage) propagate edilir ki çağıran
    /// D1 metasını silmesin → öksüz-blob (D1-kayıtsız R2 objesi, cleanup hiç görmez)
    /// önlenir.
    async fn delete(&self, blob_id: &str) -> Result<()> {
        self.bucket.delete(Self::key(blob_id)).await?;
        Ok(())
    }
}
