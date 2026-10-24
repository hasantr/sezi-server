//! Passphrase → key derivation, and a memo of what it already derived.
//!
//! # Why there is a cache in front of a KDF
//!
//! Argon2id is slow **on purpose** (19 MiB, two passes — 100–330 ms per call on a phone), and that
//! cost is not negotiable: it is what resists brute-forcing the passphrase against a stolen
//! database. Computing the SAME answer repeatedly is negotiable. Attaching a server derives three
//! times, and two of those salts are identical across servers (the identity store is one global
//! row, `PICKLE_SALT` is a constant), so four servers cost twelve derivations and about a second
//! at every cold start to produce eight distinct keys.
//!
//! The memo takes nothing away from the security property. The KDF exists to make *guessing* a
//! passphrase expensive, and anyone who can read this cache is already inside a process holding
//! the passphrase itself and every key derived from it.
//!
//! # The lifetime is the point
//!
//! Entries live exactly as long as the keys the kernel holds in `ServerCtx` and no longer;
//! [`clear_cache`] is what makes that true. Without that call the cache would outlive a logout,
//! which is the one way this could be worse than deriving every time.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use sezi_error::{Error, Result};

/// Derived keys, indexed by a hash of what produced them.
///
/// The KEY of this map is `blake3(passphrase ‖ salt)` rather than the passphrase, so the
/// passphrase itself is never copied into a process-global. The VALUE is the derived key, which
/// is the thing worth caching and the thing `ServerCtx` already holds in the clear.
fn cache() -> &'static Mutex<HashMap<[u8; 32], [u8; 32]>> {
    static CACHE: OnceLock<Mutex<HashMap<[u8; 32], [u8; 32]>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A device has one passphrase and a handful of salts — one global, one per server. Sixteen is
/// far more than that and still small enough that dropping the lot on overflow is free.
const MAX_ENTRIES: usize = 16;

/// Derives a 32-byte pickle/encryption key from a passphrase with Argon2id.
/// The shared key derivation for the Identity and for session pickles.
///
/// Memoized — see the module docs. Every caller in the workspace must route through here: a
/// second local copy of these four lines bypasses the memo, which is how the redundant work
/// arose in the first place.
pub fn derive_pickle_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(passphrase.as_bytes());
    // A length prefix, so that ("ab", "c") and ("a", "bc") cannot collide into one entry. With a
    // per-server random salt that is not a realistic accident, but a cache that can return the
    // wrong key is not a thing to leave to chance.
    hasher.update(&(passphrase.len() as u64).to_le_bytes());
    hasher.update(salt);
    let index: [u8; 32] = hasher.finalize().into();

    if let Ok(map) = cache().lock() {
        if let Some(hit) = map.get(&index) {
            return Ok(*hit);
        }
    }

    let mut out = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Crypto(format!("argon2: {e}")))?;

    if let Ok(mut map) = cache().lock() {
        if map.len() >= MAX_ENTRIES {
            map.clear();
        }
        map.insert(index, out);
    }
    Ok(out)
}

/// Forget every derived key. Call this wherever the kernel's own key material goes away.
///
/// A poisoned lock is ignored rather than propagated: this is a cache, and failing to clear it is
/// not worth turning a shutdown into an error. It cannot leave a *stale* entry behind either —
/// entries are keyed by their inputs, so the worst case is memory that outlives its usefulness.
pub fn clear_cache() {
    if let Ok(mut map) = cache().lock() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Argon2 rejects a salt under 8 bytes, which the first draft of these tests did not know and
    // every production salt satisfies (16 random bytes, or the 15-byte PICKLE_SALT). Kept as
    // named constants so a future test cannot reintroduce a too-short one by accident.
    const SALT_A: &[u8] = b"salt-aaaaaaaaaaa";
    const SALT_B: &[u8] = b"salt-bbbbbbbbbbb";

    #[test]
    fn the_memo_returns_what_argon2_would_have() {
        clear_cache();
        let cold = derive_pickle_key("hunter2", SALT_A).unwrap();
        let warm = derive_pickle_key("hunter2", SALT_A).unwrap();
        assert_eq!(cold, warm, "a cache hit must equal the derivation");
        clear_cache();
        let again = derive_pickle_key("hunter2", SALT_A).unwrap();
        assert_eq!(cold, again, "clearing must not change the answer");
    }

    #[test]
    fn different_inputs_are_different_entries() {
        clear_cache();
        let a = derive_pickle_key("hunter2", SALT_A).unwrap();
        let b = derive_pickle_key("hunter2", SALT_B).unwrap();
        let c = derive_pickle_key("hunter3", SALT_A).unwrap();
        assert_ne!(a, b, "the salt must reach the index");
        assert_ne!(a, c, "the passphrase must reach the index");
    }

    #[test]
    fn a_split_between_passphrase_and_salt_is_not_a_collision() {
        // Both calls hash the same bytes in the same order, split differently. Without the
        // length prefix in the index they would land on one entry and the second call would be
        // served the first one's key — a cache returning the wrong key, silently.
        clear_cache();
        let one = derive_pickle_key("ab", b"cdefghij").unwrap();
        let two = derive_pickle_key("a", b"bcdefghij").unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn overflow_drops_entries_without_dropping_correctness() {
        clear_cache();
        let first = derive_pickle_key("pw", b"saltnum-00").unwrap();
        for i in 1..=MAX_ENTRIES {
            derive_pickle_key("pw", format!("saltnum-{i:02}").as_bytes()).unwrap();
        }
        assert_eq!(
            first,
            derive_pickle_key("pw", b"saltnum-00").unwrap(),
            "an evicted entry is re-derived, not lost"
        );
    }
}
