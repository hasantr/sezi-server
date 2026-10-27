//! Postal addresses (§4.3): from an address keyword, out over the words that make up the address,
//! to the end of the line or an `İlçe/İL` closing, absorbing a postcode.
//!
//! The left edge matters as much as the right: "Kızılay Mah." starts at "Kızılay". The walk left
//! takes Capitalized words and numbers and stops at a separator (" - ", ",", ":") or a lowercase
//! word, so "davalının Kızılay Mah." stays "davalının [ADRES_1]". With no separator a party's name
//! may be swallowed into the address; it is masked either way.

use crate::category::Category;
use crate::fold::{self, Case};
use crate::span::Cand;
use crate::token::{Doc, Kind};
use crate::vocab;

/// Whole-word keywords.
const FULL: &[&str] = &[
    "mahallesi", "mahalle", "caddesi", "cadde", "sokak", "sokagi", "bulvari", "bulvar", "apartmani", "sitesi",
    "koyu", "mevkii", "mevki", "kumeevleri", "mahallesinde", "caddesinde", "sokaginda",
];

/// Abbreviations (normally followed by a dot).
const ABBR: &[&str] = &["mah", "mh", "cad", "cd", "sok", "sk", "bulv", "blv", "apt", "sit"];

/// Words that continue an address once it has started.
const CONT: &[&str] = &[
    "no", "numara", "d", "daire", "kat", "k", "blok", "b", "a", "c", "ic", "kapi", "pk", "posta", "kodu", "ilce",
    "il", "bina", "giris", "bl", "dis", "yeni", "eski", "osb", "org", "organize", "sanayi", "san", "bolgesi",
    "is", "merkezi", "carsisi", "plaza", "pasaji", "hani", "kume", "evleri", "yolu", "uzeri", "karsisi",
];

pub fn scan(doc: &Doc, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let mut i = 0;
    while i < toks.len() {
        if !is_trigger(doc, i) {
            i += 1;
            continue;
        }
        let s = left_edge(doc, i);
        let e = right_edge(doc, i);
        let (sb, eb) = (toks[s].s, toks[e].e);
        out.push(Cand::new(sb, eb, Category::Adres, fold::key(&doc.text()[sb..eb])));
        i = e + 1;
    }
}

/// The value of an "ADRES :" label, to the end of its line.
pub fn label_value(doc: &Doc, first: usize, last: usize, out: &mut Vec<Cand>) {
    let (sb, eb) = (doc.toks[first].s, doc.toks[last].e);
    out.push(Cand::new(sb, eb, Category::Adres, fold::key(&doc.text()[sb..eb])));
}

pub fn is_keyword(key: &str) -> bool {
    FULL.contains(&key) || ABBR.contains(&key)
}

fn upperish(doc: &Doc, i: usize) -> bool {
    let t = &doc.toks[i];
    t.kind == Kind::Num || matches!(t.case, Case::Cap | Case::Upper)
}

fn is_trigger(doc: &Doc, i: usize) -> bool {
    let t = &doc.toks[i];
    if t.kind != Kind::Word || t.suffix {
        return false;
    }
    let key = t.key.as_str();
    // "Gazi caddesi", and a numbered street in lowercase: "7. cadde", "3. sokak".
    let numbered = |p: usize| doc.toks[p].kind == Kind::Num && doc.toks[p].chars <= 4 && doc.gap(p) == ". ";
    let left_ok = i > 0
        && doc.toks[i - 1].line == t.line
        && ((doc.gap(i - 1) == " " && upperish(doc, i - 1)) || numbered(i - 1));
    if ABBR.contains(&key) {
        return doc.gap(i).starts_with('.') || matches!(t.case, Case::Cap | Case::Upper);
    }
    if FULL.contains(&key) {
        return matches!(t.case, Case::Cap | Case::Upper) || left_ok;
    }
    // "Çankaya/ANKARA" or "ANKARA/Çankaya" with no keyword at all.
    closing_pair(doc, i)
}

/// Token `i` and the next one form `District/PROVINCE` (either order).
fn closing_pair(doc: &Doc, i: usize) -> bool {
    let toks = &doc.toks;
    if i + 1 >= toks.len() || doc.gap(i) != "/" {
        return false;
    }
    let (a, b) = (&toks[i], &toks[i + 1]);
    a.kind == Kind::Word
        && b.kind == Kind::Word
        && matches!(a.case, Case::Cap | Case::Upper)
        && matches!(b.case, Case::Cap | Case::Upper)
        && (vocab::is_province(&a.key) || vocab::is_province(&b.key))
}

fn left_edge(doc: &Doc, i: usize) -> usize {
    let toks = &doc.toks;
    let mut s = i;
    let mut taken = 0;
    while s > 0 && taken < 6 {
        let p = s - 1;
        let g = doc.gap(p);
        if toks[p].line != toks[s].line || !matches!(g, " " | "." | ". ") {
            break;
        }
        let t = &toks[p];
        if !(t.kind == Kind::Num || part_of_address(doc, p, s == i && ABBR.contains(&toks[i].key.as_str()))) {
            break;
        }
        s = p;
        taken += 1;
    }
    s
}

fn right_edge(doc: &Doc, i: usize) -> usize {
    let toks = &doc.toks;
    if closing_pair(doc, i) {
        return i + 1;
    }
    let mut e = i;
    let mut j = i + 1;
    while j < toks.len() && j - i < 24 {
        let g = doc.gap(j - 1);
        let t = &toks[j];
        let wrap = g.contains('\n');
        if wrap {
            // An address may wrap once onto a line that starts with its own continuation.
            let starts_cont = t.kind == Kind::Num || CONT.contains(&t.key.as_str()) || is_keyword(&t.key) || closing_pair(doc, j);
            if g.matches('\n').count() > 1 || !starts_cont || line_has_label(doc, t.line) {
                break;
            }
        } else if !addr_gap(g) {
            break;
        }
        if t.suffix {
            break;
        }
        let before_keyword = j + 1 < toks.len() && is_keyword(&toks[j + 1].key) && matches!(doc.gap(j), " " | "\n");
        let ok = t.kind == Kind::Num
            || CONT.contains(&t.key.as_str())
            || is_keyword(&t.key)
            || part_of_address(doc, j, before_keyword && ABBR.contains(&toks[j + 1].key.as_str()))
            || (before_keyword && t.kind == Kind::Word && !vocab::is_role(&t.key));
        if !ok {
            break;
        }
        e = j;
        if closing_pair(doc, j) {
            e = j + 1;
            break;
        }
        // A province closes the address — unless it names a street ("Ankara Cad.").
        if t.kind == Kind::Word && vocab::is_province(&t.key) && !before_keyword {
            break;
        }
        j += 1;
    }
    // A postcode right after the closing.
    if e + 1 < toks.len() && toks[e + 1].kind == Kind::Num && toks[e + 1].chars == 5 && doc.gap(e) == " " {
        e += 1;
    }
    e
}

/// A word that may stand in an address: a Capitalized name ("Kızılay", "Gazi"), never a role or
/// court word — except right before a keyword, where "Cumhuriyet Mah." and "Adalet Sok." are
/// street names. `street` also lets a lowercase word through there ("kızılay mah.").
fn part_of_address(doc: &Doc, p: usize, street: bool) -> bool {
    let t = &doc.toks[p];
    if t.kind != Kind::Word || t.suffix || vocab::is_role(&t.key) {
        return false;
    }
    let next = doc.toks.get(p + 1);
    let next_is_keyword = next.is_some_and(|n| is_keyword(&n.key));
    let next_is_part = next.is_some_and(|n| CONT.contains(&n.key.as_str()) && matches!(n.case, Case::Cap | Case::Upper));
    let capital = matches!(t.case, Case::Cap | Case::Upper);
    if (next_is_keyword || next_is_part) && (capital || (street && !vocab::is_common(&t.key))) {
        return true;
    }
    capital && (!vocab::is_vocab(&t.key) || vocab::is_province(&t.key) || CONT.contains(&t.key.as_str()))
}

/// Separators inside an address: "Gazi Cad. No:5 D:3", "5/3", "Gazi Cad., No: 5".
fn addr_gap(g: &str) -> bool {
    matches!(g, " " | "." | ". " | ":" | ": " | " : " | "/" | " / " | ", " | "," | "-" | " :" | ".:" | ". :" | "\'" )
        || (g.len() <= 3 && g.chars().all(|c| c == ' '))
}

/// A line that begins with a header label ("DAVALI : …") is a new field, not an address wrap.
fn line_has_label(doc: &Doc, line: usize) -> bool {
    let r = doc.line_toks(line);
    r.clone().take(4).any(|i| doc.gap(i).contains(':') && doc.toks[i].kind == Kind::Word && matches!(doc.toks[i].case, Case::Upper))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(text: &str) -> Vec<String> {
        let d = Doc::new(text);
        let mut v = Vec::new();
        scan(&d, &mut v);
        v.into_iter().map(|c| d.text()[c.s..c.e].to_string()).collect()
    }

    #[test]
    fn header_and_body_addresses() {
        assert_eq!(
            addrs("DAVACI : AHMET YILMAZ - Kızılay Mah. Gazi Cad. No:5 D:3 Çankaya/ANKARA 06420"),
            ["Kızılay Mah. Gazi Cad. No:5 D:3 Çankaya/ANKARA 06420"]
        );
        assert_eq!(
            addrs("davalının Kızılay Mahallesi Gazi Caddesi No:5 Çankaya/Ankara adresine tebligat"),
            ["Kızılay Mahallesi Gazi Caddesi No:5 Çankaya/Ankara"]
        );
        assert_eq!(addrs("Keçiören/ANKARA nüfusuna kayıtlı"), ["Keçiören/ANKARA"]);
        assert_eq!(addrs("kızılay mah. gazi cad. no 5"), ["kızılay mah. gazi cad. no 5"]);
        assert!(addrs("internet sitesi üzerinden").is_empty());
    }
}
