//! In-flight transfer registry, so a running transfer can be cancelled from outside.
//!
//! A transport task registers a token under its own key and selects on it; the FFI surface's
//! `attachment_cancel(key)` fires that token, and the task falls out of its `tokio::select!`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Re-exported so callers cannot accidentally name a `CancellationToken` from a different
/// `tokio-util`: the token this module hands out is selected on in the root crate's chunk loops, so
/// the two must be the same type.
pub use tokio_util::sync::CancellationToken;

static INFLIGHT: OnceLock<Mutex<HashMap<String, CancellationToken>>> = OnceLock::new();

fn inflight() -> &'static Mutex<HashMap<String, CancellationToken>> {
    INFLIGHT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A transport task registers a token under its own key and selects on the returned token; it calls
/// [`unregister`] when it finishes.
pub fn register(key: &str) -> CancellationToken {
    let token = CancellationToken::new();
    inflight()
        .lock()
        .unwrap()
        .insert(key.to_string(), token.clone());
    token
}

pub fn unregister(key: &str) {
    inflight().lock().unwrap().remove(key);
}

/// Cancel the token registered under `key` and drop it from the map; the transport task holding it
/// then falls out of its `tokio::select!`. Idempotent — cancelling an unknown or already-cancelled
/// key is a no-op.
pub fn cancel(key: &str) {
    if let Some(token) = inflight().lock().unwrap().remove(key) {
        token.cancel();
    }
}

#[cfg(test)]
fn inflight_has(key: &str) -> bool {
    inflight().lock().unwrap().contains_key(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The tests share the global INFLIGHT map: each one uses its own unique key and asserts only on
    // that key. `cargo test` runs them in parallel, so NEVER assert `assert_eq!(count, N)` — the
    // counts would interfere. Use `inflight_has(key)`.

    #[test]
    fn cancel_token_lifecycle() {
        let key = "attach-progress-test-cancel";
        let token = register(key);
        assert!(!token.is_cancelled());
        assert!(inflight_has(key));

        cancel(key);
        assert!(token.is_cancelled());
        assert!(!inflight_has(key));

        // Idempotent
        cancel(key);
    }

    #[test]
    fn unregister_drops_token() {
        let key = "attach-progress-test-unreg";
        let _t = register(key);
        assert!(inflight_has(key));
        unregister(key);
        assert!(!inflight_has(key));
    }
}
