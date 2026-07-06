use crate::utils::{b64u_decode, b64u_encode, now_secs};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use worker::{Env, Error, Result};

const ACCESS_TTL_SEC: u64 = 15 * 60;
const KID: &str = "sezgi-1";

/// PKCS8-PEM → SigningKey. env-secret yolu ve self-provision yolu AYNI
/// parser'dan geçer (self_provision üretim-roundtrip unit-testi bunu çağırır →
/// üretilen anahtarın format uyumu kanıtlı). `\\n` replace: wrangler secret'a
/// tek-satır kaçışlı PEM girilmiş olabilir (bkz .dev.vars.example); gerçek
/// newline'lı PEM'de no-op.
pub(crate) fn parse_signing_pem(raw: &str) -> Result<SigningKey> {
    let pkcs8 = raw.replace("\\n", "\n");
    SigningKey::from_pkcs8_pem(&pkcs8)
        .map_err(|e| Error::RustError(format!("jwt: pkcs8 parse: {}", e)))
}

fn load_signing_key(env: &Env) -> Result<SigningKey> {
    // Self-host Faz A çözüm zinciri: 1) env secret ÖNCE (bugünkü davranış
    // BİT-AYNI; env-set HER ZAMAN kazanır — güvenlik-bilinçli owner anahtarı
    // secret'a taşıyabilir), 2) yoksa self-provision cache (boot-guard'ın
    // D1 `server_config`'ten çözdüğü/ürettiği PEM — hot-path'te D1-roundtrip
    // YOK, izolate-memoize; bkz. src/self_provision.rs).
    let raw = match env.secret("JWT_SIGNING_KEY") {
        Ok(s) => s.to_string(),
        Err(_) => crate::self_provision::cached_jwt_pem().ok_or_else(|| {
            Error::RustError("jwt: signing key yok (env secret yok + self-provision hazir degil)".into())
        })?,
    };
    parse_signing_pem(&raw)
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

#[derive(Serialize, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    iat: u64,
    exp: u64,
    // M2-S1: opsiyonel cihaz adresleme claim'i. `skip_serializing_if` →
    // device_id verilmeyen token'larda alan HİÇ yazılmaz (eski wire birebir);
    // `default` → eski token'lar (claim'siz) AYNEN parse olur (geriye-uyum).
    // S1'de YAZILIR ama henüz TÜKETİLMEZ (auth user_id düzeyinde kalır).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

pub fn sign_access_token(env: &Env, user_id: &str, device_id: Option<&str>) -> Result<String> {
    let signing = load_signing_key(env)?;
    let issuer = env.var("JWT_ISSUER")?.to_string();
    let now = now_secs();
    let header = JwtHeader {
        alg: "EdDSA",
        typ: "JWT",
        kid: KID,
    };
    let claims = JwtClaims {
        iss: issuer,
        sub: user_id.to_string(),
        iat: now,
        exp: now + ACCESS_TTL_SEC,
        device_id: device_id.map(|s| s.to_string()),
    };
    let header_b64 = b64u_encode(serde_json::to_string(&header)?.as_bytes());
    let claims_b64 = b64u_encode(serde_json::to_string(&claims)?.as_bytes());
    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let sig = signing.sign(signing_input.as_bytes());
    let sig_b64 = b64u_encode(&sig.to_bytes());
    Ok(format!("{}.{}", signing_input, sig_b64))
}

pub fn verify_access_token(env: &Env, token: &str) -> Result<String> {
    let signing = load_signing_key(env)?;
    let verifying = signing.verifying_key();
    let issuer = env.var("JWT_ISSUER")?.to_string();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::RustError("jwt: bad format".into()));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64u_decode(parts[2])
        .map_err(|e| Error::RustError(format!("jwt: sig decode: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(Error::RustError("jwt: sig length".into()));
    }
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|e| Error::RustError(format!("jwt: sig invalid: {}", e)))?;
    let claims_json = b64u_decode(parts[1])
        .map_err(|e| Error::RustError(format!("jwt: claims decode: {}", e)))?;
    let claims: JwtClaims = serde_json::from_slice(&claims_json)?;
    if claims.iss != issuer {
        return Err(Error::RustError("jwt: bad iss".into()));
    }
    let now = now_secs();
    if claims.exp <= now {
        return Err(Error::RustError("jwt: expired".into()));
    }
    Ok(claims.sub)
}

/// M2-S1: doğrulanmış token'dan opsiyonel `device_id` claim'ini döner.
///
/// `verify_access_token`'ın imzasını/dönüş-tipini bozmamak için (6 çağıran;
/// blast-radius S2'de açılmadı) onun yanında ayrı helper. Tam doğrulama yapar
/// (imza + iss + exp); claim yoksa veya token eski/claim'siz ise `None`.
/// S1'de device_id YAZILIR; S2'de `ws_upgrade` WS attachment'ı için TÜKETİLİR.
pub fn device_id_from_token(env: &Env, token: &str) -> Result<Option<String>> {
    let signing = load_signing_key(env)?;
    let verifying = signing.verifying_key();
    let issuer = env.var("JWT_ISSUER")?.to_string();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::RustError("jwt: bad format".into()));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64u_decode(parts[2])
        .map_err(|e| Error::RustError(format!("jwt: sig decode: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(Error::RustError("jwt: sig length".into()));
    }
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|e| Error::RustError(format!("jwt: sig invalid: {}", e)))?;
    let claims_json = b64u_decode(parts[1])
        .map_err(|e| Error::RustError(format!("jwt: claims decode: {}", e)))?;
    let claims: JwtClaims = serde_json::from_slice(&claims_json)?;
    if claims.iss != issuer {
        return Err(Error::RustError("jwt: bad iss".into()));
    }
    let now = now_secs();
    if claims.exp <= now {
        return Err(Error::RustError("jwt: expired".into()));
    }
    Ok(claims.device_id)
}

#[derive(Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub x: String,
    pub alg: &'static str,
    pub kid: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
}

pub fn public_jwk(env: &Env) -> Result<Jwk> {
    let signing = load_signing_key(env)?;
    let pubkey_bytes = signing.verifying_key().to_bytes();
    Ok(Jwk {
        kty: "OKP",
        crv: "Ed25519",
        x: b64u_encode(&pubkey_bytes),
        alg: "EdDSA",
        kid: KID,
        use_: "sig",
    })
}
