//! The short, typeable invite code — `K7QM-4827` under the projector QR (migration 0043).
//!
//! **The grammar, which the client parses too** (this module is the authority for it; a client
//! that disagrees with it is the bug):
//!
//! - Eight symbols from [`ALPHABET`]: the digits 2–9 and the capital letters without I, L, O and U
//!   — no symbol that reads as another on a wall or in a hurried hand (0/O, 1/I/L, U/V).
//! - Shown as two groups of four joined by a hyphen (`K7QM-4827`).
//! - Typed in any case, with or without the hyphen, with spaces anywhere: [`normalize`] uppercases
//!   and drops `-` and whitespace, then requires exactly eight alphabet symbols.
//! - The projector's URL form is `<base>/<CODE>` — the server's base URL with the display form as
//!   its one path segment, e.g. `https://sezi.kampus.edu.tr/K7QM-4827`. The client splits it into
//!   the base it attaches to and the code it sends to `POST /auth/redeem` as `token`.
//!
//! **Entropy.** 30^8 ≈ 6.6·10^11, about 39 bits. That is far below the 144-bit bearer token, and
//! deliberately so — it has to be typed. What makes it enough is that a guess has to be made
//! online: redeem refuses a caller after a handful of MISSES per address per window
//! (`auth::invite`), every code dies with its invite (30 days at most), and a hit costs nothing
//! extra to detect. At 30 misses per five minutes an address gets ~8 600 guesses a day; against
//! fifty live codes that is one expected hit per address in roughly 4 000 years.
//!
//! **Storage.** Raw in `invite_tokens.code` (the admin list shows it again, and the row is
//! TTL-bounded like the token beside it) and as `code_hash` = SHA-256 of a domain-separated
//! canonical form, which is the indexed lookup key. Hashing a 39-bit code protects nothing by
//! itself — the raw code sits in the same row — so the hash is an index, not a secret.

use crate::auth::hashing::sha256_hex;
use crate::utils::random_bytes;

/// 30 symbols: 2–9 and A–Z without I, L, O, U.
pub(crate) const ALPHABET: &[u8; 30] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Symbols in a code.
pub(crate) const CODE_LEN: usize = 8;

/// A fresh code in canonical form (eight symbols, no hyphen). Rejection sampling keeps every
/// symbol equally likely: 240 is the largest multiple of 30 that fits in a byte.
pub(crate) fn generate() -> String {
    let mut out = String::with_capacity(CODE_LEN);
    while out.len() < CODE_LEN {
        for b in random_bytes(16) {
            if b < 240 && out.len() < CODE_LEN {
                out.push(ALPHABET[(b % 30) as usize] as char);
            }
        }
    }
    out
}

/// What a person typed → the canonical code, or `None` when it is not one. Anything longer than a
/// code with generous spacing is refused before it is scanned, so a 24-character bearer token is
/// never mistaken for a code (it is too long), and a code is never mistaken for a token (redeem
/// tries this first).
pub(crate) fn normalize(input: &str) -> Option<String> {
    if input.len() > 16 {
        return None;
    }
    let canonical: String = input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (canonical.len() == CODE_LEN && canonical.bytes().all(|b| ALPHABET.contains(&b)))
        .then_some(canonical)
}

/// The display form: `K7QM-4827`.
pub(crate) fn display(canonical: &str) -> String {
    if canonical.len() != CODE_LEN {
        return canonical.to_string();
    }
    format!("{}-{}", &canonical[..4], &canonical[4..])
}

/// The lookup key stored in `invite_tokens.code_hash`. Domain-separated so it can never equal a
/// `token_hash`, which is the SHA-256 of a bearer token.
pub(crate) fn code_hash(canonical: &str) -> String {
    sha256_hex(&format!("sezi-invite-code:{canonical}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_code_is_eight_unambiguous_symbols() {
        for _ in 0..200 {
            let code = generate();
            assert_eq!(code.len(), CODE_LEN);
            assert!(code.bytes().all(|b| ALPHABET.contains(&b)), "{code}");
            assert_eq!(normalize(&code).as_deref(), Some(code.as_str()));
            assert_eq!(normalize(&display(&code)).as_deref(), Some(code.as_str()));
        }
        assert!(!ALPHABET.iter().any(|b| b"01ILOU".contains(b)));
    }

    #[test]
    fn typing_is_forgiving_about_case_spaces_and_the_hyphen() {
        for typed in [
            "K7QM-4827",
            "k7qm4827",
            " k7qm 4827 ",
            "K7QM - 4827",
            "k7-qm-48-27",
        ] {
            assert_eq!(normalize(typed).as_deref(), Some("K7QM4827"), "{typed:?}");
        }
        assert_eq!(display("K7QM4827"), "K7QM-4827");
    }

    #[test]
    fn what_is_not_a_code_is_refused() {
        for bad in [
            "K7QM-482",                 // seven symbols
            "K7QM-48270",               // nine
            "K0QM-4827",                // a zero
            "KIQM-4827",                // an I
            "K7QM_4827",                // an underscore is not a separator
            "abcdefghijklmnopqrstuvwx", // a bearer token's length
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_code_hash_never_collides_with_a_token_hash() {
        assert_ne!(code_hash("K7QM4827"), sha256_hex("K7QM4827"));
        assert_eq!(code_hash("K7QM4827").len(), 64);
    }
}
