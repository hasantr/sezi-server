//! Tier 1 and the phone pattern: numbers read across the ways people write them (§4.3).
//!
//! Digit groups are chained across one short separator (a space, a hyphen, a dot, a line break,
//! a parenthesis), and every contiguous run of groups is tried against each rule. That is what
//! catches `123 456 789 01`, `0532-123-45-67` or a TCKN broken over a line. Phone and card
//! numbers also have to match a known GROUP SHAPE, so that a date and a time ("24.10.2026 10")
//! never pass for a phone.

use crate::category::Category;
use crate::checksum::{luhn_valid, tckn_valid, vkn_valid};
use crate::span::Cand;
use crate::token::{Doc, Kind};

pub fn scan(doc: &Doc, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let mut i = 0;
    while i < toks.len() {
        if toks[i].kind != Kind::Num {
            i += 1;
            continue;
        }
        let mut chain = vec![i];
        let mut j = i;
        while j + 1 < toks.len() && toks[j + 1].kind == Kind::Num && chain_gap(doc.gap(j)) {
            j += 1;
            chain.push(j);
        }
        scan_chain(doc, &chain, out);
        i = j + 1;
    }
    iban(doc, out);
}

/// What may separate two digit groups of one number: spaces and up to two line breaks (a text
/// layer pads a positioned run with a column of spaces, or a blank line, as easily as with one),
/// parentheses, and at most one of `. - / · _`. Wider than a writer would ever space ONE number,
/// on purpose: a join that is not a number only has to fail a checksum or a group shape.
fn chain_gap(g: &str) -> bool {
    let n = g.chars().count();
    (1..=16).contains(&n)
        && g.chars().all(|c| matches!(c, ' ' | '-' | '.' | '\n' | '(' | ')' | '/' | '·' | '_'))
        && g.matches('\n').count() <= 2
        && g.matches(['.', '-', '/', '·', '_']).count() <= 1
}

fn scan_chain(doc: &Doc, chain: &[usize], out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    for a in 0..chain.len() {
        let mut d = String::new();
        let mut lens: Vec<usize> = Vec::new();
        for b in a..chain.len() {
            let t = &toks[chain[b]];
            d.push_str(&t.key);
            lens.push(t.chars);
            if d.len() > 19 {
                break;
            }
            let (s, e) = (toks[chain[a]].s, t.e);
            if d.len() == 11 && tckn_valid(&d) {
                out.push(Cand::new(s, e, Category::Tckn, d.clone()));
            }
            if d.len() == 10 && ((lens.len() == 1 && vkn_valid(&d)) || vkn_context(doc, chain[a])) {
                out.push(Cand::new(s, e, Category::Vkn, d.clone()));
            }
            if (13..=19).contains(&d.len()) && card_shape(&lens) && luhn_valid(&d) {
                out.push(Cand::new(s, e, Category::Kart, d.clone()));
            }
            if phone(&d, &lens) {
                let s = phone_start(doc, s, e);
                out.push(Cand::new(s, e, Category::Tel, d[d.len() - 10..].to_string()));
            }
        }
    }
}

/// "VKN", "V.K.N." or a word starting with "vergi" within the ~40 bytes before the number.
fn vkn_context(doc: &Doc, first: usize) -> bool {
    let start = doc.toks[first].s;
    let mut k = first;
    while k > 0 {
        k -= 1;
        let t = &doc.toks[k];
        if start - t.e > 40 {
            break;
        }
        if t.kind == Kind::Word && (t.key == "vkn" || t.key.starts_with("vergi")) {
            return true;
        }
        if t.kind == Kind::Word && t.key == "n" && k >= 2 && doc.is(k - 1, "k") && doc.is(k - 2, "v") {
            return true;
        }
    }
    false
}

/// Turkish numbers: 10 digits starting 2–5 (area or mobile code) or 8 (0850/0800 lines),
/// optionally after `0`, `90` or `+90`, written whole or as 3-3-2-2, 3-3-4 or 3-7.
fn phone(d: &str, lens: &[usize]) -> bool {
    let b = d.as_bytes();
    let area = |c: u8| (b'2'..=b'5').contains(&c) || c == b'8';
    let national = |l: &[usize]| matches!(l, [10] | [3, 3, 2, 2] | [3, 3, 4] | [3, 7]);
    let after_area = |l: &[usize]| matches!(l, [3, 2, 2] | [3, 4] | [7]);
    match d.len() {
        10 => area(b[0]) && national(lens),
        11 => {
            b[0] == b'0'
                && area(b[1])
                && (lens == [11] || (lens[0] == 1 && national(&lens[1..])) || (lens[0] == 4 && after_area(&lens[1..])))
        }
        12 => {
            d.starts_with("90")
                && area(b[2])
                && (lens == [12] || (lens[0] == 2 && national(&lens[1..])) || (lens[0] == 5 && after_area(&lens[1..])))
        }
        _ => false,
    }
}

/// A `+` before the number, or a `(` whose `)` is inside it, belongs to the phone.
fn phone_start(doc: &Doc, s: usize, e: usize) -> usize {
    let text = doc.text();
    match text[..s].chars().next_back() {
        Some('+') => s - 1,
        Some('(') if text[s..e].contains(')') => s - 1,
        _ => s,
    }
}

fn card_shape(lens: &[usize]) -> bool {
    match lens {
        [_] => true,
        [4, 6, 5] | [4, 6, 4] => true,
        [init @ .., last] if init.len() >= 2 => init.iter().all(|&l| l == 4) && (1..=4).contains(last),
        _ => false,
    }
}

/// `TR` + 24 digits, spaces and line breaks allowed. The shape is masked even when mod-97 fails:
/// a mistyped IBAN is still somebody's account. `TR` may be glued to the word before it.
fn iban(doc: &Doc, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    for i in 0..toks.len().saturating_sub(1) {
        let t = &toks[i];
        if t.kind != Kind::Word || !doc.t(i).to_ascii_uppercase().ends_with("TR") {
            continue;
        }
        let g = doc.gap(i);
        if !(g.is_empty() || g == " ") || toks[i + 1].kind != Kind::Num {
            continue;
        }
        let mut digits = String::new();
        let mut j = i + 1;
        let mut last = j;
        while j < toks.len() && toks[j].kind == Kind::Num {
            digits.push_str(&toks[j].key);
            last = j;
            if digits.len() >= 24 {
                break;
            }
            if !chain_gap(doc.gap(j)) {
                break;
            }
            j += 1;
        }
        if digits.len() < 20 {
            continue;
        }
        let end = last;
        let s = t.e - 2;
        let ident = format!("TR{}", &digits[..digits.len().min(24)]);
        out.push(Cand::new(s, toks[end].e, Category::Iban, ident));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cats(text: &str) -> Vec<(Category, String)> {
        let d = Doc::new(text);
        let mut v = Vec::new();
        scan(&d, &mut v);
        v.into_iter().map(|c| (c.cat, d.text()[c.s..c.e].to_string())).collect()
    }

    #[test]
    fn numbers_in_their_usual_dress() {
        assert!(cats("TC 10000000146 no").contains(&(Category::Tckn, "10000000146".into())));
        assert!(cats("TC 100 000\n001 46").iter().any(|c| c.0 == Category::Tckn));
        assert!(cats("Tel: 0532 123 45 67").contains(&(Category::Tel, "0532 123 45 67".into())));
        assert!(cats("+90 (532) 123-45-67").iter().any(|c| c.0 == Category::Tel && c.1.starts_with('+')));
        assert!(cats("IBAN:TR33 0006 1005 1978 6457 8413 26.").iter().any(|c| c.0 == Category::Iban));
        assert!(cats("kart 4111 1111 1111 1111").iter().any(|c| c.0 == Category::Kart));
    }

    #[test]
    fn dates_and_amounts_are_not_phones() {
        assert!(cats("24.10.2026 10:30 tarihinde 3.000,00 TL").is_empty());
        assert!(cats("2024/123 Esas").is_empty());
    }
}
