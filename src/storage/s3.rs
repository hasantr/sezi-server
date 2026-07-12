//! S3-uyumlu (SigV4) backend — **Faz 2 gerçek implementasyon** (2026-07-08).
//!
//! Bir implementasyonla en geniş aday kümesini açar: Backblaze B2 (kılavuz-önerilen),
//! ikinci R2 bucket (S3-endpoint), MinIO/VPS, iDrive e2, Wasabi. Plan
//! PLUGGABLE_STORAGE_PLAN.md (b) NET v1 kararı.
//!
//! İmzalama çekirdeği `crate::sigv4` (Faz 0'da MinIO'ya karşı uçtan-uca doğrulandı):
//!   - Gövde-hash'li imza (UNSIGNED-PAYLOAD DEĞİL) — SHA-256 ucuz, B2+MinIO kabul eder.
//!   - `Host` header SET EDİLMEZ — workerd URL'den türetir; imzacı authority'yi URL'den
//!     PORT DAHİL imzalar (Faz 0 workerd-fetch notu) → imza-host ↔ istek-host birebir.
//!   - Yalnız `authorization` / `x-amz-date` / `x-amz-content-sha256` (+ opsiyonel imzalı
//!     `x-amz-storage-class`) set edilir; `content-type` imzasız gönderilir (S3 imzasız
//!     başlıkları yok sayar → uyumlu).
//!
//! Adapter sözleşmesi (BlobStore doc + conformance): delete idempotent (204/404→Ok),
//! get yok→None (404→None), put idempotent-overwrite. v1 = **path-style** (endpoint/bucket/key);
//! `force_path_style=false` config'te kabul edilir ama v1 daima path-style kurar (MinIO şart,
//! B2 destekler) — virtual-hosted Faz 6+.

use serde::{Deserialize, Serialize};
use worker::*;

use super::BlobObject;

fn default_true() -> bool {
    true
}

/// `storage_backends.config_json` şeması (plan c.2). Secret İÇERİR
/// (`secret_access_key`) → WRITE-ONLY: hiçbir endpoint bu struct'ı geri döndürmez.
#[derive(Serialize, Deserialize, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default = "default_true")]
    pub force_path_style: bool,
    #[serde(default)]
    pub storage_class: Option<String>,
}

/// S3-uyumlu depo (Faz 2). `config_json`'dan kurulur; imzalama `crate::sigv4`.
pub struct S3Store {
    endpoint: String, // normalize: trailing '/' yok
    region: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    prefix: String, // boş olabilir; doluysa anahtar-öneki (owner trailing '/'ten sorumlu)
    storage_class: Option<String>,
}

impl S3Store {
    /// Doğrulanmış config'ten kur (endpoint trailing-slash normalize edilir).
    pub fn from_config(cfg: S3Config) -> Self {
        S3Store {
            endpoint: cfg.endpoint.trim().trim_end_matches('/').to_string(),
            region: cfg.region.trim().to_string(),
            bucket: cfg.bucket.trim().to_string(),
            access_key_id: cfg.access_key_id.trim().to_string(),
            secret_access_key: cfg.secret_access_key.trim().to_string(),
            prefix: cfg.prefix,
            storage_class: cfg.storage_class.filter(|s| !s.trim().is_empty()),
        }
    }

    /// D1 `config_json`'dan kur (router build-yolu). Parse hatası → Err (router o
    /// depoyu ATLAR = fırsatçı health-degrade; blob'u o depoda olan get → 503).
    pub fn from_config_json(json: &str) -> Result<Self> {
        let cfg: S3Config = serde_json::from_str(json)
            .map_err(|e| Error::RustError(format!("s3 config parse: {e}")))?;
        Ok(Self::from_config(cfg))
    }

    /// `prefix + key` (prefix boşsa key). Anahtar-şeması `storage::media_key` vb.
    fn full_key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}{}", self.prefix, key)
        }
    }

    /// Path-style obje URL'i: `{endpoint}/{bucket}/{full_key}` (imzacı path'i
    /// uri-encode eder → '/' korunur, özel char %XY). Query yok.
    fn object_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.endpoint, self.bucket, self.full_key(key))
    }

    /// İmzalı workerd fetch. `signed_extra` = SignedHeaders'a girecek EK başlıklar
    /// (küçük-harf ad; değerleri imzalanır VE request'e set edilir); `unsigned` =
    /// imzasız gönderilecek başlıklar (S3 yok sayar-veya-metadata: content-type).
    /// `host` HİÇBİR yerde set edilmez (workerd URL'den türetir; imzacı da URL'den).
    async fn signed_request(
        &self,
        method_str: &str,
        url: &str,
        body: Option<Vec<u8>>,
        signed_extra: &[(String, String)],
        unsigned: &[(String, String)],
    ) -> Result<Response> {
        let payload = body.as_deref().unwrap_or(&[]);
        let payload_hash = crate::sigv4::sha256_hex(payload);
        let datetime = amz_now();
        let extra_refs: Vec<(&str, &str)> = signed_extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let sig = crate::sigv4::sign_request(
            method_str,
            url,
            &extra_refs,
            &payload_hash,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            "s3",
            &datetime,
        )
        .map_err(|e| Error::RustError(format!("sigv4: {e}")))?;

        let headers = Headers::new();
        headers.set("authorization", &sig.authorization)?;
        headers.set("x-amz-date", &sig.x_amz_date)?;
        headers.set("x-amz-content-sha256", &sig.x_amz_content_sha256)?;
        for (k, v) in signed_extra {
            headers.set(k, v)?;
        }
        for (k, v) in unsigned {
            headers.set(k, v)?;
        }

        let mut init = RequestInit::new();
        init.with_method(method_from_str(method_str));
        init.with_headers(headers);
        if let Some(b) = body {
            init.with_body(Some(js_sys::Uint8Array::from(&b[..]).into()));
        }
        let req = Request::new_with_init(url, &init)?;
        Fetch::Request(req).send().await
    }

    /// Blob'u yaz (idempotent-overwrite). content-type imzasız header; storage_class
    /// (varsa) imzalı `x-amz-storage-class`. 2xx → Ok, diğer → Err (gövde kırpık).
    pub async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<()> {
        let url = self.object_url(key);
        let mut signed: Vec<(String, String)> = Vec::new();
        if let Some(sc) = &self.storage_class {
            signed.push(("x-amz-storage-class".to_string(), sc.clone()));
        }
        let unsigned = vec![("content-type".to_string(), content_type.to_string())];
        let mut resp = self
            .signed_request("PUT", &url, Some(bytes), &signed, &unsigned)
            .await?;
        let code = resp.status_code();
        if (200..300).contains(&code) {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(Error::RustError(format!(
                "s3 put {code}: {}",
                truncate(&body, 200)
            )))
        }
    }

    /// Blob'u oku; yok (404) → None. content-type response header'ından (yoksa
    /// octet-stream). 2xx-dışı/404-dışı → Err.
    pub async fn get(&self, key: &str) -> Result<Option<BlobObject>> {
        let url = self.object_url(key);
        let mut resp = self.signed_request("GET", &url, None, &[], &[]).await?;
        let code = resp.status_code();
        if code == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&code) {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::RustError(format!(
                "s3 get {code}: {}",
                truncate(&body, 200)
            )));
        }
        let content_type = resp
            .headers()
            .get("content-type")
            .ok()
            .flatten()
            .unwrap_or_else(|| "application/octet-stream".into());
        let bytes = resp.bytes().await?;
        Ok(Some(BlobObject { bytes, content_type }))
    }

    /// Blob'u sil — İDEMPOTENT: 2xx (S3=204) VEYA 404 → Ok. Gerçek hata (403/5xx)
    /// → Err (çağıran D1-meta silmesin → öksüz-blob önlenir; mevcut R2 disiplini).
    pub async fn delete(&self, key: &str) -> Result<()> {
        let url = self.object_url(key);
        let mut resp = self.signed_request("DELETE", &url, None, &[], &[]).await?;
        let code = resp.status_code();
        if (200..300).contains(&code) || code == 404 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(Error::RustError(format!(
                "s3 delete {code}: {}",
                truncate(&body, 200)
            )))
        }
    }
}

/// `YYYYMMDDTHHMMSSZ` — şimdi (workerd `js_sys::Date`; SAF-imzacı bunu tüketir).
/// Host'ta (cargo test) ÇAĞRILMAZ (S3 metotları workerd-only) → js-runtime yok sorunu olmaz.
fn amz_now() -> String {
    let iso = js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_default();
    crate::sigv4::amz_date_from_iso(&iso)
}

fn method_from_str(m: &str) -> Method {
    match m {
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        _ => Method::Get,
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Kontrol-karakteri yok (header-enjeksiyon/DoS koruması; cf_config `field_ok` emsali).
fn no_ctrl(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

/// POST/PATCH öncesi alan-doğrulama (cf_config `field_ok` deseni). `allow_http`
/// = ENV!=prod (dev/MinIO); prod'da `http://` endpoint reddedilir. Hata → sabit
/// alan-kodu (client hangi alanın hatalı olduğunu görür; secret DEĞERİ sızmaz).
pub fn validate_config(cfg: &S3Config, allow_http: bool) -> std::result::Result<(), &'static str> {
    let ep = cfg.endpoint.trim();
    let is_https = ep.starts_with("https://");
    let is_http = ep.starts_with("http://");
    if !is_https && !is_http {
        return Err("endpoint_scheme");
    }
    if is_http && !allow_http {
        return Err("endpoint_http_forbidden");
    }
    if ep.len() > 300 || !no_ctrl(ep) {
        return Err("endpoint_invalid");
    }
    let r = cfg.region.trim();
    if r.is_empty() || r.len() > 64 || !no_ctrl(r) {
        return Err("region_invalid");
    }
    let b = cfg.bucket.trim();
    if b.is_empty() || b.len() > 128 || !no_ctrl(b) {
        return Err("bucket_invalid");
    }
    let ak = cfg.access_key_id.trim();
    if ak.is_empty() || ak.len() > 256 || !no_ctrl(ak) {
        return Err("access_key_invalid");
    }
    let sk = cfg.secret_access_key.trim();
    if sk.is_empty() || sk.len() > 512 || !no_ctrl(sk) {
        return Err("secret_invalid");
    }
    if cfg.prefix.len() > 256 || !no_ctrl(&cfg.prefix) {
        return Err("prefix_invalid");
    }
    if let Some(sc) = &cfg.storage_class {
        if sc.len() > 64 || !no_ctrl(sc) {
            return Err("storage_class_invalid");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_cfg() -> S3Config {
        S3Config {
            endpoint: "https://s3.us-west-004.backblazeb2.com".into(),
            region: "us-west-004".into(),
            bucket: "sezi-media".into(),
            access_key_id: "key".into(),
            secret_access_key: "secret".into(),
            prefix: String::new(),
            force_path_style: true,
            storage_class: None,
        }
    }

    #[test]
    fn object_url_path_style_ve_prefix() {
        let s = S3Store::from_config(valid_cfg());
        assert_eq!(
            s.object_url("media/abc"),
            "https://s3.us-west-004.backblazeb2.com/sezi-media/media/abc"
        );
        // prefix uygulanır + endpoint trailing-slash normalize.
        let mut c = valid_cfg();
        c.endpoint = "http://127.0.0.1:9000/".into();
        c.prefix = "sezi/".into();
        let s = S3Store::from_config(c);
        assert_eq!(s.full_key("media/x"), "sezi/media/x");
        assert_eq!(s.object_url("media/x"), "http://127.0.0.1:9000/sezi-media/sezi/media/x");
    }

    #[test]
    fn config_json_roundtrip_defaults() {
        // Minimal JSON (opsiyonel alanlar yok) → serde default'ları dolar.
        let json = r#"{"endpoint":"https://x","region":"r","bucket":"b","access_key_id":"k","secret_access_key":"s"}"#;
        let s = S3Store::from_config_json(json).expect("parse");
        assert_eq!(s.prefix, "");
        assert!(s.storage_class.is_none());
        // Bozuk JSON → Err (router atlar).
        assert!(S3Store::from_config_json("not json").is_err());
    }

    #[test]
    fn validate_config_https_ok_http_kilitli() {
        assert!(validate_config(&valid_cfg(), false).is_ok());
        // http → prod'da red, dev'de ok.
        let mut c = valid_cfg();
        c.endpoint = "http://127.0.0.1:9000".into();
        assert_eq!(validate_config(&c, false), Err("endpoint_http_forbidden"));
        assert!(validate_config(&c, true).is_ok());
        // scheme yok → red.
        let mut c = valid_cfg();
        c.endpoint = "127.0.0.1".into();
        assert_eq!(validate_config(&c, true), Err("endpoint_scheme"));
    }

    #[test]
    fn validate_config_bos_alanlar_red() {
        let mut c = valid_cfg();
        c.bucket = "  ".into();
        assert_eq!(validate_config(&c, false), Err("bucket_invalid"));
        let mut c = valid_cfg();
        c.secret_access_key = String::new();
        assert_eq!(validate_config(&c, false), Err("secret_invalid"));
        let mut c = valid_cfg();
        c.access_key_id = "a\nb".into();
        assert_eq!(validate_config(&c, false), Err("access_key_invalid"));
    }

    #[test]
    fn storage_class_bos_none_a_duser() {
        let mut c = valid_cfg();
        c.storage_class = Some("".into());
        let s = S3Store::from_config(c);
        assert!(s.storage_class.is_none(), "boş storage_class → None (imzasız)");
    }
}
