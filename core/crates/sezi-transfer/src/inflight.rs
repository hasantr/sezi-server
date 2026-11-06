//! In-flight transfer registry, so a running transfer can be cancelled from outside.
//!
//! A transport task registers a token under its own key and selects on it; the FFI surface's
//! `attachment_cancel(key)` fires that token, and the task falls out of its `tokio::select!`.
//!
//! Several transfers may be registered under one key at once — a cancel followed at once by a
//! retry, while the first is still winding down; a file seeded for two of my devices — so each
//! [`Registration`] is its own entry, removed only by its own drop, and [`cancel`] fires every one
//! (TRF-1, 2026-11-06). Until then a key held ONE token: a second registration replaced it, and
//! the first transfer's unregister-by-key then removed the second's, which no cancel reached after.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Re-exported so callers cannot accidentally name a `CancellationToken` from a different
/// `tokio-util`: the token this module hands out is selected on in the root crate's chunk loops, so
/// the two must be the same type.
pub use tokio_util::sync::CancellationToken;

type Registry = HashMap<String, Vec<(u64, CancellationToken)>>;

static INFLIGHT: OnceLock<Mutex<Registry>> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn inflight() -> std::sync::MutexGuard<'static, Registry> {
    // A poisoned registry is still a registry: every write to it is a single insert or removal.
    INFLIGHT.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|e| e.into_inner())
}

/// One transfer's place in the registry, for as long as it lives. Derefs to its token, which the
/// transport selects on; dropping it takes out this transfer's entry and no other.
pub struct Registration {
    key: String,
    id: u64,
    token: CancellationToken,
}

impl std::ops::Deref for Registration {
    type Target = CancellationToken;

    fn deref(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut map = inflight();
        if let Some(entries) = map.get_mut(&self.key) {
            entries.retain(|(id, _)| *id != self.id);
            if entries.is_empty() {
                map.remove(&self.key);
            }
        }
    }
}

/// A transport task registers under its own key and selects on the returned registration's
/// token; the registration ends when it is dropped, on every exit path.
pub fn register(key: &str) -> Registration {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let token = CancellationToken::new();
    inflight().entry(key.to_string()).or_default().push((id, token.clone()));
    Registration { key: key.to_string(), id, token }
}

/// Cancel every transfer registered under `key` and drop them from the map; each transport task
/// then falls out of its `tokio::select!`. Idempotent — cancelling an unknown or already-cancelled
/// key is a no-op.
pub fn cancel(key: &str) {
    let entries = inflight().remove(key).unwrap_or_default();
    for (_, token) in entries {
        token.cancel();
    }
}

#[cfg(test)]
fn inflight_has(key: &str) -> bool {
    inflight().contains_key(key)
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

    /// TRF-1: a cancel and an immediate retry put a second transfer under the key while the first
    /// is still winding down. The first one's end must not take the second's token with it, or the
    /// retried transfer can never be cancelled.
    #[test]
    fn an_older_transfer_ending_leaves_the_newer_cancellable() {
        let key = "attach-progress-test-retry";
        let old = register(key);
        let new = register(key);
        drop(old); // the old runner ends
        cancel(key);
        assert!(new.is_cancelled(), "the retried transfer is reached by the cancel");
    }

    /// Two transfers under one key (a file seeded for two of my devices): a cancel reaches both.
    #[test]
    fn a_cancel_reaches_every_transfer_under_the_key() {
        let key = "attach-progress-test-two";
        let a = register(key);
        let b = register(key);
        cancel(key);
        assert!(a.is_cancelled() && b.is_cancelled());
        assert!(!inflight_has(key));
    }

    #[test]
    fn dropping_the_registration_frees_the_key() {
        let key = "attach-progress-test-unreg";
        let t = register(key);
        assert!(inflight_has(key));
        drop(t);
        assert!(!inflight_has(key));
    }
}
