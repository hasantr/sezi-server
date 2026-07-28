use crate::utils::{b64u_decode, b64u_encode, now_secs};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use worker::{Env, Error, Result};

const ACCESS_TTL_SEC: u64 = 15 * 60;
const KID: &str = "sezgi-1";

/// Slim template: the code default for `JWT_ISSUER` when the env var is absent, so
/// the `[vars]` line can be dropped from the template wrangler.toml to keep the
/// deploy screen simple; deployments that set it (prod) behave bit-identically. All
/// three paths — sign, verify and the device_id claim — read the issuer through this
/// one helper, so minting and checking can never drift apart.
const DEFAULT_ISSUER: &str = "sezi-server";

fn issuer(env: &Env) -> String {
    crate::utils::var_or(env, "JWT_ISSUER", DEFAULT_ISSUER)
}

/// PKCS8 PEM → SigningKey. The env-secret path and the self-provision path go
/// through the SAME parser (the self_provision generation round-trip unit test calls
/// this, which proves a generated key is format-compatible). The `\\n` replacement
/// covers a PEM pasted into a wrangler secret as a single escaped line (see
/// .dev.vars.example); for a PEM with real newlines it is a no-op.
pub(crate) fn parse_signing_pem(raw: &str) -> Result<SigningKey> {
    let pkcs8 = raw.replace("\\n", "\n");
    SigningKey::from_pkcs8_pem(&pkcs8)
        .map_err(|e| Error::RustError(format!("jwt: pkcs8 parse: {}", e)))
}

fn load_signing_key(env: &Env) -> Result<SigningKey> {
    // Resolution chain: 1) the env secret FIRST, but ONLY if it is non-empty and
    //    parses — so a security-conscious owner's real key wins and prod stays
    //    bit-identical; 2) otherwise the self-provision cache (a valid PEM resolved
    //    from, or generated into, D1).
    // CRITICAL (2026-07-07 free-account incident): the deploy-button runtime can
    // return `Ok("")` for a secret that was never set. The old code parsed that empty
    // string and 500'd with "PEM label invalid" without ever reaching
    // self-provision. Now an empty or unparseable env secret is ignored and the valid
    // self-provisioned key is used.
    if let Ok(s) = env.secret("JWT_SIGNING_KEY") {
        let raw = s.to_string();
        if !raw.trim().is_empty() {
            if let Ok(k) = parse_signing_pem(&raw) {
                return Ok(k);
            }
            // An env secret exists but does not parse → fall through to self-provision.
        }
    }
    let raw = crate::self_provision::cached_jwt_pem().ok_or_else(|| {
        Error::RustError("jwt: no signing key (env secret empty/invalid and self-provision not ready)".into())
    })?;
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
    // M2-S1: optional device-addressing claim. `skip_serializing_if` means the field
    // is omitted entirely from tokens minted without a device_id (identical to the
    // old wire format), and `default` means older claim-less tokens still parse
    // (backwards compatibility). Since S2 the claim is also CONSUMED — see
    // `device_id_from_token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

pub fn sign_access_token(env: &Env, user_id: &str, device_id: Option<&str>) -> Result<String> {
    let signing = load_signing_key(env)?;
    let issuer = issuer(env);
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
    let issuer = issuer(env);
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

/// M2-S1: returns the optional `device_id` claim from a verified token.
///
/// It lives beside `verify_access_token` rather than changing that function's
/// signature or return type, so the blast radius of S2 stayed small. It performs the
/// full verification (signature + iss + exp) and returns `None` when the claim is
/// absent or the token is an older, claim-less one. Written since S1; consumed since
/// S2 — the WS upgrade path attaches it to the socket, and the send/keys/plugin/push
/// routes use it for per-device checks.
pub fn device_id_from_token(env: &Env, token: &str) -> Result<Option<String>> {
    let signing = load_signing_key(env)?;
    let verifying = signing.verifying_key();
    let issuer = issuer(env);
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
