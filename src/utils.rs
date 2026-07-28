use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use worker::{Date, Env};

pub fn now_ms() -> u64 {
    Date::now().as_millis()
}

pub fn now_secs() -> u64 {
    now_ms() / 1000
}

pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Mobile, the Rust core and TS leftovers can each send a different variant:
    // standard (+/=), standard-no-pad, url-safe (-_=), url-safe-no-pad. To tolerate
    // all of them we normalise: url-safe → the standard alphabet, pad with '=' when
    // padding is missing, then do a STANDARD decode.
    let cleaned: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let pad_len = (4 - cleaned.len() % 4) % 4;
    let mut padded = cleaned;
    for _ in 0..pad_len {
        padded.push('=');
    }
    STANDARD.decode(&padded)
}

pub fn b64u_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64u_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

pub fn random_b64u(n: usize) -> String {
    b64u_encode(&random_bytes(n))
}

/// TEMPLATE DIET (a simpler deploy screen): returns the code default when the env var
/// is absent, so the `[vars]` block can be deleted from wrangler.toml. Installations
/// that DO set the env (prod) behave bit-identically — the env always wins.
pub fn var_or(env: &Env, key: &str, default: &str) -> String {
    env.var(key)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| default.to_string())
}
