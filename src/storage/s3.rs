//! S3-compatible (SigV4) backend — **the real Faz 2 implementation** (2026-07-08).
//!
//! One implementation unlocks the widest set of candidates: Backblaze B2 (the recommended
//! option), a second R2 bucket (via its S3 endpoint), MinIO/VPS, iDrive e2, Wasabi. The v1
//! decision in PLUGGABLE_STORAGE_PLAN.md (b).
//!
//! Signing core: `crate::sigv4` (verified end-to-end against MinIO in Faz 0):
//!   - Body-hash signatures, NOT UNSIGNED-PAYLOAD — SHA-256 is cheap and both B2 and MinIO
//!     accept it.
//!   - The `Host` header is never SET — workerd derives it from the URL, and the signer signs
//!     the authority from the same URL INCLUDING the port (see the Faz 0 workerd-fetch note),
//!     so the signed host and the request host match exactly.
//!   - Only `authorization` / `x-amz-date` / `x-amz-content-sha256` are set (plus an optional
//!     signed `x-amz-storage-class`); `content-type` is sent unsigned, which S3 tolerates
//!     because it ignores unsigned headers.
//!
//! Adapter contract (BlobStore doc + conformance): delete is idempotent (204/404→Ok), a missing
//! get is None (404→None), put is an idempotent overwrite. v1 is **path-style**
//! (endpoint/bucket/key); `force_path_style=false` is accepted in the config but v1 always
//! builds path-style URLs (required by MinIO, supported by B2) — virtual-hosted is Faz 6+.

use serde::{Deserialize, Serialize};
use worker::*;

use super::BlobObject;

fn default_true() -> bool {
    true
}

/// Schema of `storage_backends.config_json` (plan c.2). CONTAINS a secret
/// (`secret_access_key`) → WRITE-ONLY: no endpoint ever returns this struct.
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

/// S3-compatible backend (Faz 2). Built from `config_json`; signing via `crate::sigv4`.
pub struct S3Store {
    endpoint: String, // normalized: no trailing '/'
    region: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    prefix: String, // may be empty; when set it prefixes the key (the owner owns the trailing '/')
    storage_class: Option<String>,
}

impl S3Store {
    /// Build from a validated config (the endpoint's trailing slash is normalized away).
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

    /// Build from D1 `config_json` (the router's build path). A parse error → Err, on which the
    /// router SKIPS this backend (opportunistic health degrade; a get for a blob stored there
    /// becomes a 503).
    pub fn from_config_json(json: &str) -> Result<Self> {
        let cfg: S3Config = serde_json::from_str(json)
            .map_err(|e| Error::RustError(format!("s3 config parse: {e}")))?;
        Ok(Self::from_config(cfg))
    }

    /// `prefix + key` (just key when the prefix is empty). Keys come from
    /// `storage::media_key` and friends.
    fn full_key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}{}", self.prefix, key)
        }
    }

    /// Path-style object URL: `{endpoint}/{bucket}/{full_key}` (the signer uri-encodes the path,
    /// keeping '/' and percent-encoding the rest). No query string.
    fn object_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.endpoint, self.bucket, self.full_key(key))
    }

    /// Signed workerd fetch. `signed_extra` = EXTRA headers that join SignedHeaders (lowercase
    /// names; their values are both signed and set on the request); `unsigned` = headers sent
    /// without being signed (S3 either ignores them or stores them as metadata, as with
    /// content-type). `host` is never set anywhere — workerd derives it from the URL and so does
    /// the signer.
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

    /// Write a blob (idempotent overwrite). content-type goes out as an unsigned header;
    /// storage_class (when configured) as a signed `x-amz-storage-class`. 2xx → Ok, anything
    /// else → Err with a truncated body.
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

    /// Read a blob; missing (404) → None. content-type comes from the response header, falling
    /// back to octet-stream. Anything that is neither 2xx nor 404 → Err.
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

    /// Delete a blob — IDEMPOTENT: 2xx (S3 returns 204) OR 404 → Ok. A real failure (403/5xx) →
    /// Err, so the caller keeps the D1 meta row and no orphaned blob is created (the established
    /// R2 discipline).
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

/// Current time as `YYYYMMDDTHHMMSSZ` (from workerd's `js_sys::Date`; fed to the pure signer).
/// Never called on the host (`cargo test`) because the S3 methods are workerd-only, so the
/// absent JS runtime is not a problem.
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

/// No control characters (header-injection / DoS guard; same rule as cf_config's `field_ok`).
fn no_ctrl(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

/// Field validation before a POST/PATCH (the cf_config `field_ok` pattern). `allow_http` means
/// ENV != prod (dev/MinIO); in prod an `http://` endpoint is rejected. Errors are fixed field
/// codes, so the client learns WHICH field is wrong without leaking any secret VALUE.
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
        // The prefix is applied and the endpoint's trailing slash is normalized away.
        let mut c = valid_cfg();
        c.endpoint = "http://127.0.0.1:9000/".into();
        c.prefix = "sezi/".into();
        let s = S3Store::from_config(c);
        assert_eq!(s.full_key("media/x"), "sezi/media/x");
        assert_eq!(s.object_url("media/x"), "http://127.0.0.1:9000/sezi-media/sezi/media/x");
    }

    #[test]
    fn config_json_roundtrip_defaults() {
        // Minimal JSON (no optional fields) → serde fills in the defaults.
        let json = r#"{"endpoint":"https://x","region":"r","bucket":"b","access_key_id":"k","secret_access_key":"s"}"#;
        let s = S3Store::from_config_json(json).expect("parse");
        assert_eq!(s.prefix, "");
        assert!(s.storage_class.is_none());
        // Malformed JSON → Err (the router skips the backend).
        assert!(S3Store::from_config_json("not json").is_err());
    }

    #[test]
    fn validate_config_https_ok_http_kilitli() {
        assert!(validate_config(&valid_cfg(), false).is_ok());
        // http → rejected in prod, allowed in dev.
        let mut c = valid_cfg();
        c.endpoint = "http://127.0.0.1:9000".into();
        assert_eq!(validate_config(&c, false), Err("endpoint_http_forbidden"));
        assert!(validate_config(&c, true).is_ok());
        // No scheme → rejected.
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
