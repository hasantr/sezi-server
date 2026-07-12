//! AWS Signature Version 4 imzalama — **SAF RUST** (yalnız `hmac` + `sha2` + `hex`,
//! hepsi mevcut bağımlılık). WebCrypto/subtle YOK → host'ta (`cargo test`) da koşar,
//! workerd/wasm'da da. Takılabilir-Depolama epic'inin S3-uyumlu adaptörünün (B2 /
//! ikinci-R2 / MinIO / iDrive e2 / Wasabi) tohumu; `PLUGGABLE_STORAGE_PLAN.md` Faz 0/2.
//!
//! UNSIGNED-PAYLOAD KULLANILMAZ: `x-amz-content-sha256` gövde-hash'li imza (blob zaten
//! bellekte; SHA-256 ucuz). B2 ve MinIO ikisi de gövde-hash'li imzayı kabul eder.
//!
//! İmza zinciri (AWS spec birebir):
//!   1. CanonicalRequest = method\n uri\n query\n headers\n signedHeaders\n payloadHash
//!   2. StringToSign     = "AWS4-HMAC-SHA256"\n datetime\n scope\n SHA256(CanonicalRequest)
//!   3. SigningKey       = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
//!   4. Signature        = hex(HMAC(SigningKey, StringToSign))
//!   5. Authorization    = AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…
//!
//! Kanonik-URI kodlaması S3 için TEK kez (diğer servisler iki kez); bu modül S3-yolunu
//! (tek kodlama) hedefler → `sign_request` service="s3" ile çağrılır.
//!
//! NOT: Bu API henüz çağrılmıyor (Faz 0'da yalnız geçici dev-route tüketiyordu; o kaldırıldı).
//! Faz 2'de `storage/s3.rs` bunu tüketecek. O zamana dek cdylib'de "never used" olmasın diye
//! modül-düzeyi `allow(dead_code)` — Faz 2 wiring'inde kaldırılır.
#![allow(dead_code)]

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// İmza için gereken üç başlık (çağıran bunları request'e SET eder; `host` SET EDİLMEZ
/// — workerd URL'den türetir ve imzalanan değerle birebir örtüşür).
pub struct SigV4Headers {
    pub authorization: String,
    pub x_amz_date: String,
    pub x_amz_content_sha256: String,
}

/// İmzalama hatası (URL ayrıştırma). Kripto adımları hata VERMEZ (HMAC her anahtar
/// uzunluğunu kabul eder).
#[derive(Debug)]
pub enum SigV4Error {
    BadUrl(String),
}

impl std::fmt::Display for SigV4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigV4Error::BadUrl(u) => write!(f, "sigv4: geçersiz URL: {u}"),
        }
    }
}

/// SHA-256 → küçük-harf hex. Gövde-hash (`x-amz-content-sha256`) + kanonik-request hash.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// HMAC-SHA256(key, data) → 32 bayt.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC her anahtar uzunluğunu kabul eder");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 3986 URI-encode (AWS UriEncode). Ayrılmamış (`A-Za-z0-9-_.~`) DIŞINDA her bayt
/// `%XY` (BÜYÜK hex). `encode_slash=false` → path segmentleri için `/` korunur;
/// `true` → query anahtar/değerleri için `/` de kodlanır. Boşluk her zaman `%20`.
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push(nibble_hex(b >> 4));
                out.push(nibble_hex(b & 0x0f));
            }
        }
    }
    out
}

fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

/// Kanonik başlık değeri: baş/son boşluk kırp + iç ardışık boşlukları teke indir
/// (AWS spec; tırnaksız değerler). host/tarih/hex-hash gibi basit değerlerde no-op.
fn canonical_header_value(v: &str) -> String {
    let trimmed = v.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_space = false;
    for c in trimmed.chars() {
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

/// Kanonik query string: `a=b&c=d` → her anahtar/değer URI-encode (slash dahil),
/// encode edilmiş ANAHTARA göre sırala, `&` ile birleştir. Değersiz anahtar → `k=`.
fn canonical_query(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (uri_encode(k, true), uri_encode(v, true)),
            None => (uri_encode(kv, true), String::new()),
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// İmzalama anahtarı zinciri: kDate → kRegion → kService → kSigning.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// `scheme://host[:port]/path?query` → (host[:port], path, query). Minimal, bağımlılıksız
/// (worker::Url'ü çekmeden host-testte de koşsun). userinfo yok sayılır; path boşsa `/`.
fn parse_url(url: &str) -> Result<(String, String, String), SigV4Error> {
    let after_scheme = url
        .split_once("://")
        .map(|(_, r)| r)
        .ok_or_else(|| SigV4Error::BadUrl(url.to_string()))?;
    let (authority, rest) = match after_scheme.find(['/', '?']) {
        Some(idx) => after_scheme.split_at(idx),
        None => (after_scheme, ""),
    };
    if authority.is_empty() {
        return Err(SigV4Error::BadUrl(url.to_string()));
    }
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, q),
        None => (rest, ""),
    };
    let path = if path.is_empty() { "/" } else { path };
    Ok((authority.to_string(), path.to_string(), query.to_string()))
}

/// İmza sonucu. `authorization` üretim yolunda kullanılır; ara adımlar
/// (`signature`/`canonical_request`/`string_to_sign`) bilinen-vektör testlerinde +
/// ileride imza-uyuşmazlığı teşhisinde okunur (S3 imza-hatasında hangi string uyuşmadı).
struct SignParts {
    authorization: String,
    signature: String,
    canonical_request: String,
    string_to_sign: String,
}

/// Çekirdek imzalayıcı: verilen (küçük-harf-adlı) başlık kümesini imzalar. `headers`
/// = (ad, ham-değer); ad küçük-harf olmalı. `host`/`x-amz-date`/`x-amz-content-sha256`
/// dahil TÜM imzalanacak başlıklar burada verilir. Test bunu doğrudan çağırır
/// (bilinen-vektör) → S3-özel başlık enjeksiyonundan bağımsız.
#[allow(clippy::too_many_arguments)]
fn sign(
    method: &str,
    canonical_uri: &str,
    canonical_query_str: &str,
    mut headers: Vec<(String, String)>,
    payload_hash: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    datetime: &str,
) -> SignParts {
    // Başlıkları ada göre sırala (küçük-harf, bayt sırası).
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // --- 1. CanonicalRequest ---
    let mut canonical = String::new();
    canonical.push_str(method);
    canonical.push('\n');
    canonical.push_str(canonical_uri);
    canonical.push('\n');
    canonical.push_str(canonical_query_str);
    canonical.push('\n');
    for (name, value) in &headers {
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&canonical_header_value(value));
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed_headers);
    canonical.push('\n');
    canonical.push_str(payload_hash);

    // --- 2. StringToSign ---
    let date = &datetime[..8]; // YYYYMMDD
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );

    // --- 3+4. SigningKey + Signature ---
    let key = signing_key(secret_key, date, region, service);
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

    // --- 5. Authorization ---
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    SignParts {
        authorization,
        signature,
        canonical_request: canonical,
        string_to_sign,
    }
}

/// S3-uyumlu imza. `url` tam URL; `extra_headers` imzalanacak EK başlıklar
/// (küçük-harf ad; host/x-amz-date/x-amz-content-sha256 OTOMATİK eklenir). `datetime`
/// = `YYYYMMDDTHHMMSSZ` (bkz `amz_date_from_iso`). Dönüş: request'e SET edilecek 3 başlık.
///
/// `host` başlığı DÖNÜŞTE YOK — bilerek: workerd `Host`'u URL'den türetir (fetch'te
/// elle set edilemez) ve imzaladığımız değerle örtüşür.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    method: &str,
    url: &str,
    extra_headers: &[(&str, &str)],
    payload_sha256_hex: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    datetime: &str,
) -> Result<SigV4Headers, SigV4Error> {
    let (host, path, query) = parse_url(url)?;
    let canonical_uri = uri_encode(&path, false);
    let canonical_q = canonical_query(&query);

    let mut headers: Vec<(String, String)> = vec![
        ("host".to_string(), host),
        ("x-amz-content-sha256".to_string(), payload_sha256_hex.to_string()),
        ("x-amz-date".to_string(), datetime.to_string()),
    ];
    for (k, v) in extra_headers {
        headers.push((k.to_ascii_lowercase(), v.to_string()));
    }

    let parts = sign(
        method,
        &canonical_uri,
        &canonical_q,
        headers,
        payload_sha256_hex,
        access_key,
        secret_key,
        region,
        service,
        datetime,
    );

    Ok(SigV4Headers {
        authorization: parts.authorization,
        x_amz_date: datetime.to_string(),
        x_amz_content_sha256: payload_sha256_hex.to_string(),
    })
}

/// JS `toISOString()` ("2015-08-30T12:36:00.000Z") → AMZ basic ("20150830T123600Z").
/// `-`/`:` atılır, kesir-saniye ve trailing Z düşürülüp tek `Z` eklenir. SAF (test'li);
/// çağıran zaman kaynağını (js_sys::Date) verir → bu fonksiyon host'ta da koşar.
pub fn amz_date_from_iso(iso: &str) -> String {
    let mut s: String = iso
        .chars()
        .take_while(|c| *c != '.' && *c != 'Z' && *c != 'z')
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    s.push('Z');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // AWS SigV4 test suite — `get-vanilla` (yayınlanmış bilinen-vektör).
    // Credential=AKIDEXAMPLE, Secret=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
    // region=us-east-1, service=service, 20150830T123600Z, GET / (boş gövde).
    const VEC_KEY: &str = "AKIDEXAMPLE";
    const VEC_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const VEC_DATETIME: &str = "20150830T123600Z";

    #[test]
    fn bos_govde_sha256_bilinen_deger() {
        // SHA-256("") — RFC/AWS'de her yerde geçen sabit.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn get_vanilla_kanonik_request_stringi() {
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), VEC_DATETIME.to_string()),
        ];
        let parts = sign(
            "GET",
            "/",
            "",
            headers,
            &sha256_hex(b""),
            VEC_KEY,
            VEC_SECRET,
            "us-east-1",
            "service",
            VEC_DATETIME,
        );
        let expected = "GET\n\
                        /\n\
                        \n\
                        host:example.amazonaws.com\n\
                        x-amz-date:20150830T123600Z\n\
                        \n\
                        host;x-amz-date\n\
                        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(parts.canonical_request, expected);
    }

    #[test]
    fn get_vanilla_string_to_sign_ve_imza() {
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), VEC_DATETIME.to_string()),
        ];
        let parts = sign(
            "GET",
            "/",
            "",
            headers,
            &sha256_hex(b""),
            VEC_KEY,
            VEC_SECRET,
            "us-east-1",
            "service",
            VEC_DATETIME,
        );
        // Kanonik-request hash (AWS dokümanı get-vanilla).
        let expected_sts = "AWS4-HMAC-SHA256\n\
                            20150830T123600Z\n\
                            20150830/us-east-1/service/aws4_request\n\
                            bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63";
        assert_eq!(parts.string_to_sign, expected_sts);
        // Nihai imza — bilinen-vektör (aws-sig-v4-test-suite `get-vanilla`).
        assert_eq!(
            parts.signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert!(parts.authorization.contains(
            "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"
        ));
        assert!(parts.authorization.contains("SignedHeaders=host;x-amz-date"));
    }

    #[test]
    fn uri_encode_kenarlari() {
        assert_eq!(uri_encode("/", false), "/");
        assert_eq!(uri_encode("/", true), "%2F");
        assert_eq!(uri_encode(" ", true), "%20");
        assert_eq!(uri_encode("a~b.c-d_e", true), "a~b.c-d_e"); // ayrılmamışlar korunur
        assert_eq!(uri_encode("foo/bar baz", false), "foo/bar%20baz");
        assert_eq!(uri_encode("foo/bar", true), "foo%2Fbar");
        assert_eq!(uri_encode("+=&", true), "%2B%3D%26");
    }

    #[test]
    fn canonical_query_sirali_ve_encode() {
        assert_eq!(canonical_query(""), "");
        assert_eq!(canonical_query("b=2&a=1"), "a=1&b=2");
        assert_eq!(canonical_query("prefix=a/b&marker="), "marker=&prefix=a%2Fb");
    }

    #[test]
    fn amz_date_iso_donusum() {
        assert_eq!(amz_date_from_iso("2015-08-30T12:36:00.000Z"), "20150830T123600Z");
        assert_eq!(amz_date_from_iso("2015-08-30T12:36:00Z"), "20150830T123600Z");
    }

    #[test]
    fn sign_request_s3_basliklari_uretir() {
        let payload_hash = sha256_hex(b"hello");
        let out = sign_request(
            "PUT",
            "http://127.0.0.1:9000/sezi-faz0/obj",
            &[],
            &payload_hash,
            "minioadmin",
            "minioadmin",
            "us-east-1",
            "s3",
            "20260708T101112Z",
        )
        .expect("imza");
        assert_eq!(out.x_amz_date, "20260708T101112Z");
        assert_eq!(out.x_amz_content_sha256, payload_hash);
        assert!(out.authorization.starts_with("AWS4-HMAC-SHA256 Credential=minioadmin/20260708/us-east-1/s3/aws4_request"));
        // S3 imzasında host + content-sha256 + date imzalanır.
        assert!(out
            .authorization
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }
}
