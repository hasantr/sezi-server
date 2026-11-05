//! The FCM JWT's RS256 signature, made by the platform's WebCrypto (`crypto.subtle`) rather than
//! in Rust. Until 2026-11-05 it was the pure-Rust `rsa` crate, whose private-key operation has
//! the Marvin timing side channel (RUSTSEC-2023-0071) with no fixed release; workerd's WebCrypto
//! signs with BoringSSL.
//!
//! RSASSA-PKCS1-v1_5 over SHA-256 is deterministic, so this produces exactly the bytes the old
//! path did; the known answer is in `fcm_jwt_tests.rs`. Nothing here runs on the host — a native
//! test has no `crypto.subtle` — and the module depends on nothing of the relay's own, so it can
//! be compiled into a wasm test harness on its own.

use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

const ALGORITHM: &str = "RSASSA-PKCS1-v1_5";

/// The global scope's `crypto.subtle` — a worker's, a Durable Object's, or Node's in a test.
fn subtle() -> Result<SubtleCrypto, String> {
    let crypto = Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
        .map_err(|e| format!("fcm: no crypto global: {e:?}"))?;
    if crypto.is_undefined() || crypto.is_null() {
        return Err("fcm: no crypto global".to_string());
    }
    let subtle = Reflect::get(&crypto, &JsValue::from_str("subtle"))
        .map_err(|e| format!("fcm: no crypto.subtle: {e:?}"))?;
    if subtle.is_undefined() || subtle.is_null() {
        return Err("fcm: no crypto.subtle".to_string());
    }
    // Not `dyn_into`: an `instanceof SubtleCrypto` check depends on the runtime exposing that
    // constructor, which the spec does not require of every global scope.
    Ok(subtle.unchecked_into())
}

/// Import a PKCS#8 RSA private key (DER, `fcm_jwt::pkcs8_der`) for RS256 signing only. Not
/// extractable: once imported, the key's bytes cannot be read back out of the `CryptoKey`.
pub(crate) async fn import_signing_key(pkcs8_der: &[u8]) -> Result<CryptoKey, String> {
    let algorithm = Object::new();
    set(&algorithm, "name", ALGORITHM)?;
    set(&algorithm, "hash", "SHA-256")?;
    let usages = Array::of1(&JsValue::from_str("sign"));
    let data = Uint8Array::from(pkcs8_der);
    let promise = subtle()?
        .import_key_with_object("pkcs8", &data, &algorithm, false, &usages)
        .map_err(|e| format!("fcm: importKey: {e:?}"))?;
    let key = JsFuture::from(promise).await.map_err(|e| format!("fcm: importKey: {e:?}"))?;
    Ok(key.unchecked_into())
}

/// The RS256 signature of `data` under `key`.
pub(crate) async fn sign(key: &CryptoKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let promise = subtle()?
        .sign_with_str_and_u8_array(ALGORITHM, key, data)
        .map_err(|e| format!("fcm: sign: {e:?}"))?;
    let sig = JsFuture::from(promise).await.map_err(|e| format!("fcm: sign: {e:?}"))?;
    Ok(Uint8Array::new(&sig).to_vec())
}

fn set(obj: &Object, key: &str, value: &str) -> Result<(), String> {
    Reflect::set(obj, &JsValue::from_str(key), &JsValue::from_str(value))
        .map(|_| ())
        .map_err(|e| format!("fcm: algorithm {key}: {e:?}"))
}
