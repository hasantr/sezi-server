//! Test helpers: a seeded generator of checksum-valid FAKE identifiers, the golden fixture format,
//! and coverage arithmetic. Nothing here is, or may become, real data.
#![allow(dead_code)]

use std::collections::HashMap;
use std::ops::Range;

use sezi_redact::checksum::{iban_mod97, luhn_valid, tckn_valid, vkn_valid};
use sezi_redact::Redacted;

/// xorshift64* — deterministic on every platform, no dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn digit(&mut self) -> u8 {
        self.below(10) as u8
    }

    pub fn digits(&mut self, n: usize) -> String {
        (0..n).map(|_| char::from(b'0' + self.digit())).collect()
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

/// A checksum-valid, made-up T.C. kimlik no.
pub fn tckn(r: &mut Rng) -> String {
    let mut d = [0i32; 11];
    d[0] = 1 + r.below(9) as i32;
    for x in d.iter_mut().take(9).skip(1) {
        *x = r.digit() as i32;
    }
    d[9] = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])).rem_euclid(10);
    d[10] = d[..10].iter().sum::<i32>() % 10;
    let s: String = d.iter().map(|x| char::from(b'0' + *x as u8)).collect();
    assert!(tckn_valid(&s));
    s
}

/// A checksum-valid, made-up VKN.
pub fn vkn(r: &mut Rng) -> String {
    let body = r.digits(9);
    let s = (0..10).map(|c| format!("{body}{c}")).find(|s| vkn_valid(s)).expect("one check digit fits");
    s
}

/// A mod-97-valid, made-up Turkish IBAN, printed in groups of four.
pub fn iban(r: &mut Rng) -> String {
    let body = format!("{}0{}", r.digits(5), r.digits(16));
    let rem = iban_mod97(body.chars().chain("TR00".chars()));
    let check = 98 - rem;
    let compact = format!("TR{check:02}{body}");
    compact.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ")
}

/// A Luhn-valid, made-up 16-digit card number in groups of four.
pub fn card(r: &mut Rng) -> String {
    let body = format!("4{}", r.digits(14));
    let s = (0..10).map(|c| format!("{body}{c}")).find(|s| luhn_valid(s)).unwrap();
    s.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ")
}

/// A made-up Turkish mobile number, digits only.
pub fn mobile(r: &mut Rng) -> String {
    format!("05{}{}", r.below(6) + 30, r.digits(7))
}

/// One annotated value of a fixture.
#[derive(Clone, Debug)]
pub struct Item {
    pub tag: String,
    pub range: Range<usize>,
    pub text: String,
    /// `{{KISI?:…}}`: reported, not gated (a name no anchor points at — §4.7's NER question).
    pub gated: bool,
}

pub struct Fixture {
    pub raw: String,
    pub items: Vec<Item>,
}

/// `{{CAT:text}}` marks a value that must be masked; `{{CAT?:text}}` one that should be;
/// `{{TCKN:@a}}` (also VKN, IBAN, KART, TEL) generates a checksum-valid fake bound to the name
/// `a` within the file. Lines starting with `#!` are comments.
pub fn parse(src: &str, seed: u64) -> Fixture {
    let mut rng = Rng::new(seed);
    let mut bound: HashMap<String, String> = HashMap::new();
    let body: String = src.lines().filter(|l| !l.starts_with("#!")).map(|l| format!("{l}\n")).collect();
    let mut raw = String::new();
    let mut items = Vec::new();
    let mut rest = body.as_str();
    while let Some(open) = rest.find("{{") {
        raw.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = after.find("}}").expect("unclosed {{");
        let inner = &after[..close];
        let (tag, value) = inner.split_once(':').expect("{{CAT:value}}");
        let (tag, gated) = match tag.strip_suffix('?') {
            Some(t) => (t, false),
            None => (tag, true),
        };
        let text = if let Some(name) = value.strip_prefix('@') {
            let key = format!("{tag}@{name}");
            bound
                .entry(key)
                .or_insert_with(|| match tag {
                    "TCKN" => tckn(&mut rng),
                    "VKN" => vkn(&mut rng),
                    "IBAN" => iban(&mut rng),
                    "KART" => card(&mut rng),
                    "TEL" => mobile(&mut rng),
                    other => panic!("no generator for {other}"),
                })
                .clone()
        } else {
            value.to_string()
        };
        let start = raw.len();
        raw.push_str(&text);
        items.push(Item { tag: tag.to_string(), range: start..raw.len(), text, gated });
        rest = &after[close + 2..];
    }
    raw.push_str(rest);
    Fixture { raw, items }
}

/// Is every non-space byte of `r` inside one of the masked spans?
pub fn covered(red: &Redacted, raw: &str, r: &Range<usize>) -> bool {
    let spans: Vec<&Range<usize>> = red.spans.iter().map(|s| &s.original).collect();
    raw[r.clone()].char_indices().all(|(i, c)| {
        let b = r.start + i;
        c.is_whitespace() || spans.iter().any(|s| s.start <= b && b < s.end)
    })
}

/// The masking category that covers most of `r`.
pub fn covering_tag(red: &Redacted, r: &Range<usize>) -> Option<&'static str> {
    red.spans
        .iter()
        .filter(|s| s.original.start < r.end && r.start < s.original.end)
        .max_by_key(|s| s.original.end.min(r.end) - s.original.start.max(r.start))
        .map(|s| s.placeholder.category.tag())
}

/// Turkish matching key, as the crate folds (kept separate on purpose: the tests should not
/// trust the code they test).
pub fn key(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            'I' | 'ı' | 'İ' | 'î' | 'Î' => vec!['i'],
            'Ş' | 'ş' => vec!['s'],
            'Ğ' | 'ğ' => vec!['g'],
            'Ü' | 'ü' | 'û' | 'Û' => vec!['u'],
            'Ö' | 'ö' => vec!['o'],
            'Ç' | 'ç' => vec!['c'],
            'Â' | 'â' => vec!['a'],
            c => c.to_lowercase().collect(),
        })
        .collect()
}

/// The words of a text as keys (letters only).
pub fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphabetic()).filter(|w| !w.is_empty()).map(key).collect()
}
