//! AWS Signature Version 4 signing — **PURE RUST** (only `hmac` + `sha2` + `hex`, all already
//! dependencies). No WebCrypto/subtle, so it runs on the host (`cargo test`) as well as under
//! workerd/wasm. This is the seed of the Pluggable-Storage epic's S3-compatible adapter (B2 /
//! second R2 / MinIO / iDrive e2 / Wasabi); `PLUGGABLE_STORAGE_PLAN.md` Faz 0/2.
//!
//! UNSIGNED-PAYLOAD IS NOT USED: signatures carry the body hash in `x-amz-content-sha256` (the
//! blob is already in memory and SHA-256 is cheap). Both B2 and MinIO accept body-hash signing.
//!
//! Signature chain (verbatim from the AWS spec):
//!   1. CanonicalRequest = method\n uri\n query\n headers\n signedHeaders\n payloadHash
//!   2. StringToSign     = "AWS4-HMAC-SHA256"\n datetime\n scope\n SHA256(CanonicalRequest)
//!   3. SigningKey       = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
//!   4. Signature        = hex(HMAC(SigningKey, StringToSign))
//!   5. Authorization    = AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…
//!
//! The canonical URI is encoded ONCE for S3 (other services encode twice); this module targets
//! the S3 path (single encoding), so `sign_request` is called with service="s3".
//!
//! CONSUMER: `storage/s3.rs` (wired up in Faz 2) signs every S3 request through here — every put,
//! get and delete.
//!
//! There is deliberately NO module-level `allow(dead_code)`. There used to be, carried over from
//! Faz 0 when nothing called this module yet, and its own note said it would go away "at Faz 2
//! wiring" — Faz 2 landed and it stayed. In a crypto module a blanket allow is the wrong trade: it
//! would equally silence a signing step that quietly stopped being called. Removing it surfaced
//! exactly three items, the `SignParts` diagnostic fields, which the known-vector tests read; the
//! allow now sits on those three fields and nothing else.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The three headers a signed request needs (the caller SETs these; `host` is deliberately NOT
/// set — workerd derives it from the URL and it matches the signed value exactly).
pub struct SigV4Headers {
    pub authorization: String,
    pub x_amz_date: String,
    pub x_amz_content_sha256: String,
}

/// Signing failure (URL parsing). The crypto steps cannot fail — HMAC accepts a key of any
/// length.
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

/// SHA-256 → lowercase hex. Used for the body hash (`x-amz-content-sha256`) and the
/// canonical-request hash.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// HMAC-SHA256(key, data) → 32 bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC her anahtar uzunluğunu kabul eder");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 3986 URI-encode (AWS UriEncode). Every byte outside the unreserved set
/// (`A-Za-z0-9-_.~`) becomes `%XY` in UPPERCASE hex. `encode_slash=false` keeps `/` intact for
/// path segments; `true` encodes it too, for query keys/values. A space is always `%20`.
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

/// Canonical header value: trim the ends and collapse runs of inner spaces to one (AWS spec, for
/// unquoted values). A no-op for simple values like host, date or a hex hash.
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

/// Canonical query string: for `a=b&c=d`, URI-encode every key/value (slashes included), sort by
/// the ENCODED key and join with `&`. A key with no value becomes `k=`.
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

/// The signing-key chain: kDate → kRegion → kService → kSigning.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// `scheme://host[:port]/path?query` → (host[:port], path, query). Minimal and dependency-free so
/// it also runs in host tests without pulling in worker::Url. userinfo is ignored; an empty path
/// becomes `/`.
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

/// Signing result. `authorization` is what production uses; the intermediates
/// (`signature`/`canonical_request`/`string_to_sign`) are read by the known-vector tests and are
/// there for diagnosing a signature mismatch (which string disagreed when S3 rejects a signature).
struct SignParts {
    authorization: String,
    // Read only from the test module, so the `lib` build (where `cfg(test)` is off) sees them as
    // dead. The allow is scoped to these three fields ON PURPOSE: this file used to carry a
    // module-wide `#![allow(dead_code)]` for them, which in a crypto module means any future dead
    // code is silenced too — including a signing step that stopped being called.
    #[cfg_attr(not(test), allow(dead_code))]
    signature: String,
    #[cfg_attr(not(test), allow(dead_code))]
    canonical_request: String,
    #[cfg_attr(not(test), allow(dead_code))]
    string_to_sign: String,
}

/// Core signer: signs exactly the header set it is handed. `headers` = (name, raw value) with
/// lowercase names; EVERY header to be signed is passed in here, `host`/`x-amz-date`/
/// `x-amz-content-sha256` included. The known-vector tests call this directly, independently of
/// the S3-specific header injection.
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
    // Sort the headers by name (lowercase, byte order).
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

/// S3-compatible signing. `url` is the full URL; `extra_headers` are ADDITIONAL headers to sign
/// (lowercase names — host/x-amz-date/x-amz-content-sha256 are added AUTOMATICALLY). `datetime` is
/// `YYYYMMDDTHHMMSSZ` (see `amz_date_from_iso`). Returns the 3 headers to SET on the request.
///
/// `host` is deliberately absent from the return value: workerd derives `Host` from the URL (it
/// cannot be set by hand on a fetch) and that is exactly the value we signed.
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

/// JS `toISOString()` ("2015-08-30T12:36:00.000Z") → AMZ basic format ("20150830T123600Z"):
/// drop `-`/`:`, drop the fractional seconds and the trailing Z, then append a single `Z`. PURE
/// and unit-tested; the caller supplies the clock (js_sys::Date), so this also runs on the host.
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

    // AWS SigV4 test suite — `get-vanilla` (the published known vector).
    // Credential=AKIDEXAMPLE, Secret=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
    // region=us-east-1, service=service, 20150830T123600Z, GET / (empty body).
    const VEC_KEY: &str = "AKIDEXAMPLE";
    const VEC_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const VEC_DATETIME: &str = "20150830T123600Z";

    #[test]
    fn bos_govde_sha256_bilinen_deger() {
        // SHA-256("") — the constant that shows up all over the RFC/AWS docs.
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
        // Canonical-request hash (AWS docs, get-vanilla).
        let expected_sts = "AWS4-HMAC-SHA256\n\
                            20150830T123600Z\n\
                            20150830/us-east-1/service/aws4_request\n\
                            bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63";
        assert_eq!(parts.string_to_sign, expected_sts);
        // Final signature — known vector (aws-sig-v4-test-suite `get-vanilla`).
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
        assert_eq!(uri_encode("a~b.c-d_e", true), "a~b.c-d_e"); // unreserved bytes are kept
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
        // An S3 signature covers host + content-sha256 + date.
        assert!(out
            .authorization
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }
}
