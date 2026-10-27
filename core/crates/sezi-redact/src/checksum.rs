//! The checksums of tier 1 (§4.3). Public so the H2 parser, the H4 validator and the tests use
//! the same arithmetic as the masker.

/// T.C. kimlik no: 11 digits, the first not 0;
/// d10 = ((d1+d3+d5+d7+d9)·7 − (d2+d4+d6+d8)) mod 10, d11 = (d1+…+d10) mod 10.
pub fn tckn_valid(s: &str) -> bool {
    let Some(d) = digits::<11>(s) else { return false };
    if d[0] == 0 {
        return false;
    }
    let odd = d[0] + d[2] + d[4] + d[6] + d[8];
    let even = d[1] + d[3] + d[5] + d[7];
    let d10 = (odd * 7 - even).rem_euclid(10);
    let d11 = d[..10].iter().sum::<i32>() % 10;
    d10 == d[9] && d11 == d[10]
}

/// Vergi kimlik no (10 digits), the algorithm GİB's own form validation uses and every public
/// implementation repeats: for i in 1..=9, t = (dᵢ + 10 − i) mod 10; add 9 when t = 9, else
/// (t · 2^(10−i)) mod 9; the check digit is (10 − sum mod 10) mod 10. A wrong checksum never
/// leaks a number — ten bare digits fall to the `NUMARA` net — it only changes the label.
pub fn vkn_valid(s: &str) -> bool {
    let Some(d) = digits::<10>(s) else { return false };
    let mut sum = 0;
    for (i, &di) in d.iter().take(9).enumerate() {
        let t = (di + 10 - (i as i32 + 1)) % 10;
        sum += if t == 9 { 9 } else { (t * (1 << (9 - i))) % 9 };
    }
    (10 - sum % 10) % 10 == d[9]
}

/// ISO 13616 mod-97, for any country; spaces are ignored and letters may be either case.
pub fn iban_valid(s: &str) -> bool {
    let c: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).map(|c| c.to_ascii_uppercase()).collect();
    if c.len() < 15 || c.len() > 34 || !c.iter().all(char::is_ascii_alphanumeric) {
        return false;
    }
    if !(c[0].is_ascii_uppercase() && c[1].is_ascii_uppercase() && c[2].is_ascii_digit() && c[3].is_ascii_digit()) {
        return false;
    }
    iban_mod97(c[4..].iter().chain(c[..4].iter()).copied()) == 1
}

/// The remainder mod 97 of an IBAN body read as digits (A = 10 … Z = 35).
pub fn iban_mod97(chars: impl Iterator<Item = char>) -> u32 {
    let mut r: u32 = 0;
    for ch in chars {
        let v = ch.to_digit(36).unwrap_or(0);
        r = if v >= 10 { (r * 100 + v) % 97 } else { (r * 10 + v) % 97 };
    }
    r
}

/// Luhn (payment cards).
pub fn luhn_valid(s: &str) -> bool {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0;
    for (i, b) in s.bytes().rev().enumerate() {
        let mut x = u32::from(b - b'0');
        if i % 2 == 1 {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
    }
    sum % 10 == 0
}

fn digits<const N: usize>(s: &str) -> Option<[i32; N]> {
    let b = s.as_bytes();
    if b.len() != N || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut d = [0i32; N];
    for (x, &c) in d.iter_mut().zip(b) {
        *x = i32::from(c - b'0');
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // The well-known test TCKN, and ISO 13616's own worked examples.
        assert!(tckn_valid("10000000146"));
        assert!(!tckn_valid("10000000147"));
        assert!(!tckn_valid("01234567890"));
        assert!(iban_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_valid("TR33 0006 1005 1978 6457 8413 26"));
        assert!(!iban_valid("TR34 0006 1005 1978 6457 8413 26"));
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn vkn_check_digit_is_unique() {
        // Exactly one of the ten possible last digits passes for any nine-digit body.
        for body in ["123456789", "000000001", "987654321", "555555555"] {
            let ok = (0..10).filter(|d| vkn_valid(&format!("{body}{d}"))).count();
            assert_eq!(ok, 1, "{body}");
        }
    }
}
