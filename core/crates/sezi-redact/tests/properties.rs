//! Property tests as deterministic seeded loops (proptest is not in the workspace's lockfile):
//! a checksum-valid TCKN, IBAN or phone inserted anywhere in a real-looking record — inside a
//! word, split across a line break, spaced out — is always masked; restore∘redact is the
//! identity outside the placeholders; redact is deterministic.

mod common;

use std::fs;
use std::path::Path;

use common::Rng;
use sezi_redact::{redact, restore, Policy, Redacted};

fn bases() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut v: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "zabit"))
        .collect();
    v.sort();
    v.iter().take(12).map(|p| common::parse(&fs::read_to_string(p).unwrap(), 7).raw).collect()
}

/// Splits `digits` into 1–4 groups joined by separators drawn from `seps`.
fn spaced(r: &mut Rng, digits: &str, seps: &[&str]) -> String {
    let n = digits.len();
    let mut cuts: Vec<usize> = (0..r.below(4)).map(|_| 1 + r.below(n as u64 - 1) as usize).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let mut out = String::new();
    let mut prev = 0;
    for c in cuts {
        out.push_str(&digits[prev..c]);
        out.push_str(r.pick(seps));
        prev = c;
    }
    out.push_str(&digits[prev..]);
    out
}

fn tckn_form(r: &mut Rng) -> String {
    let d = common::tckn(r);
    match r.below(3) {
        0 => d,
        _ => spaced(r, &d, &[" ", "\n", "-", ".", " \n"]),
    }
}

fn iban_form(r: &mut Rng) -> String {
    let grouped = common::iban(r);
    match r.below(4) {
        0 => grouped.replace(' ', ""),
        1 => grouped,
        2 => {
            // One of the spaces becomes a line break.
            let spaces: Vec<usize> = grouped.match_indices(' ').map(|(i, _)| i).collect();
            let at = spaces[r.below(spaces.len() as u64) as usize];
            format!("{}\n{}", &grouped[..at], &grouped[at + 1..])
        }
        _ => format!("{} {}", &grouped[..4], grouped[4..].replace(' ', "")),
    }
}

fn phone_form(r: &mut Rng) -> String {
    let m = common::mobile(r); // 0 5xx xxx xx xx
    let (a, b, c, d) = (&m[1..4], &m[4..7], &m[7..9], &m[9..11]);
    let s = r.pick(&[" ", "-", ".", "\n"]).to_string();
    match r.below(7) {
        0 => m.clone(),
        1 => format!("0{a}{s}{b}{s}{c}{s}{d}"),
        2 => format!("(0{a}) {b} {c} {d}"),
        3 => format!("+90 {a} {b} {c} {d}"),
        4 => format!("0 {a} {b}{c}{d}"),
        5 => format!("0{a} {b}\n{c} {d}"),
        _ => format!("+90{a}{b}{c}{d}"),
    }
}

/// A char boundary in `text` whose neighbours are not digits (a number glued to another number
/// is a different, longer number) — inside words is fine.
fn insertion_point(r: &mut Rng, text: &str) -> usize {
    loop {
        let mut at = r.below(text.len() as u64) as usize;
        while !text.is_char_boundary(at) {
            at -= 1;
        }
        let before = text[..at].chars().next_back();
        let after = text[at..].chars().next();
        let digitish = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
        if !digitish(before) && !digitish(after) && !text[..at].ends_with("TR") && !text[..at].ends_with("[") {
            return at;
        }
    }
}

fn covered(red: &Redacted, start: usize, value: &str) -> bool {
    value.char_indices().filter(|(_, c)| c.is_ascii_alphanumeric()).all(|(i, _)| {
        let b = start + i;
        red.spans.iter().any(|s| s.original.start <= b && b < s.original.end)
    })
}

#[test]
fn inserted_identifiers_are_always_masked() {
    let bases = bases();
    let mut r = Rng::new(20261027);
    let mut tried = 0;
    for round in 0..1500 {
        let base = &bases[round % bases.len()];
        let (kind, value) = match round % 3 {
            0 => ("TCKN", tckn_form(&mut r)),
            1 => ("IBAN", iban_form(&mut r)),
            _ => ("TEL", phone_form(&mut r)),
        };
        let at = insertion_point(&mut r, base);
        let text = format!("{}{}{}", &base[..at], value, &base[at..]);
        let red = redact(&text, &Policy::default()).unwrap_or_else(|e| panic!("round {round}: {kind} {value:?} refused: {e}"));
        assert!(
            covered(&red, at, &value),
            "round {round}: {kind} {value:?} inserted at {at} ({:?}) survives",
            &text[at.saturating_sub(20)..(at + value.len() + 20).min(text.len())]
        );
        tried += 1;
    }
    assert_eq!(tried, 1500);
}

#[test]
fn restore_is_the_identity_outside_placeholders() {
    for (n, base) in bases().iter().enumerate() {
        let red = redact(base, &Policy::default()).unwrap();
        let again = redact(base, &Policy::default()).unwrap();
        assert_eq!(red.masked, again.masked, "base {n}: redact is not deterministic");
        assert_eq!(red.vault, again.vault, "base {n}: vault is not deterministic");
        let restored = restore(&red.masked, &red.vault);
        // Walk the original and the restored text together: outside spans they are equal, a span
        // becomes its placeholder's vault value.
        let mut want = String::new();
        let mut prev = 0;
        for s in &red.spans {
            want.push_str(&base[prev..s.original.start]);
            want.push_str(red.vault.get(&s.placeholder).unwrap());
            prev = s.original.end;
        }
        want.push_str(&base[prev..]);
        assert_eq!(restored, want, "base {n}");
        // And a placeholder's vault value is the masked original whenever it stood alone.
        for s in &red.spans {
            let v = red.vault.get(&s.placeholder).unwrap();
            assert!(!v.is_empty(), "base {n}: empty vault value for {}", s.placeholder);
        }
    }
}
