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

/// The text of a string binding — a `[vars]` entry, a secret, a `.dev.vars` line, or on bare
/// workerd a `fromEnvironment` binding — or `None` when there is no such binding or it is not a
/// string. EVERY read of a string binding goes through here, never `Env::var`/`Env::secret`.
///
/// The reason is the self-host relay on bare workerd (`scripts/workerd_config.py`): a
/// `fromEnvironment` binding whose system variable is unset is `null`, and `Env::var` /
/// `Env::secret` cast it through `Object::from(null).constructor()`, which throws inside the wasm
/// and hangs the request (measured 2026-10-15: an unset `JWT_SIGNING_KEY` made every request a
/// 500). On Cloudflare a binding is a string or absent, so nothing changes there: an empty string
/// stays an empty string, and every caller keeps its own rule for it.
pub fn env_text(env: &Env, key: &str) -> Option<String> {
    js_sys::Reflect::get(env, &wasm_bindgen::JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string())
}

/// TEMPLATE DIET (a simpler deploy screen): returns the code default when the env var
/// is absent, so the `[vars]` block can be deleted from wrangler.toml. Installations
/// that DO set the env (prod) behave bit-identically — the env always wins.
pub fn var_or(env: &Env, key: &str, default: &str) -> String {
    env_text(env, key).unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
#[path = "utils_env_tests.rs"]
mod env_tests;
