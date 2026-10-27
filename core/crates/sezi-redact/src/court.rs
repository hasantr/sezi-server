//! The record's own esas no (`[ESAS]`) and its court's city and number (`[MAHKEME]`) — §4.3.
//! The court TYPE stays in the text ("[MAHKEME] ASLİYE HUKUK MAHKEMESİ") and is returned as
//! typed data, because the model needs it and the runner decides the criminal path on it.

use crate::category::Category;
use crate::fold;
use crate::span::Cand;
use crate::token::{ws_gap, Doc, Kind};
use crate::vocab;

/// Words that make up a court's type, before "Mahkemesi" / "Hakimliği".
const TYPE_WORDS: &[&str] = &[
    "asliye", "hukuk", "ceza", "agir", "sulh", "is", "aile", "ticaret", "tuketici", "icra", "iflas", "kadastro",
    "cocuk", "idare", "vergi", "fikri", "sinai", "haklar", "deniz", "denizcilik", "infaz", "trafik", "bolge",
    "adliye", "istinaf", "ihtisas", "ve", "genel", "ozel", "kosullu", "yetkili",
];

const MAX_HEADER_LINES: usize = 30;

pub struct Court {
    /// City words' keys (may be empty).
    city: Vec<String>,
    /// The number before the type, e.g. "3" (may be absent).
    number: Option<String>,
    /// The first type word's key, to recognise the court again in the body.
    first_type: String,
    /// The type as written, title-cased: "Asliye Hukuk".
    pub type_title: String,
    pub criminal: bool,
}

/// The court from the header (the first "… Mahkemesi" / "… Hakimliği" in the first lines).
pub fn find(doc: &Doc) -> Option<Court> {
    let toks = &doc.toks;
    for i in 0..toks.len() {
        if toks[i].line >= MAX_HEADER_LINES {
            break;
        }
        if !matches!(toks[i].key.as_str(), "mahkemesi" | "hakimligi") {
            continue;
        }
        if let Some(c) = parse_at(doc, i) {
            return Some(c);
        }
    }
    None
}

/// The court named by a hint string (the H2 parser's result), e.g. "Ankara 3. Asliye Hukuk Mahkemesi".
pub fn from_hint(hint: &str) -> Option<Court> {
    let d = Doc::new(hint);
    (0..d.toks.len())
        .filter(|&i| matches!(d.toks[i].key.as_str(), "mahkemesi" | "hakimligi"))
        .find_map(|i| parse_at(&d, i))
}

fn parse_at(doc: &Doc, at: usize) -> Option<Court> {
    let toks = &doc.toks;
    let mut j = at;
    while j > 0 && toks[j - 1].kind == Kind::Word && TYPE_WORDS.contains(&toks[j - 1].key.as_str()) && ws_gap(doc.gap(j - 1)) {
        j -= 1;
    }
    if j == at {
        return None;
    }
    let type_text: Vec<&str> = (j..at).map(|k| doc.t(k)).collect();
    let type_title = fold::title(&type_text.join(" "));
    let criminal = (j..at).any(|k| toks[k].key == "ceza");
    let first_type = toks[j].key.clone();
    let mut number = None;
    let mut k = j;
    if k > 0 && toks[k - 1].kind == Kind::Num && toks[k - 1].chars <= 3 && doc.gap(k - 1).starts_with('.') {
        number = Some(toks[k - 1].key.clone());
        k -= 1;
    }
    let mut city = Vec::new();
    while k > 0 && city.len() < 3 {
        let p = k - 1;
        let t = &toks[p];
        let g = doc.gap(p);
        // "ANKARA BATI", "İSTANBUL ANADOLU": a courthouse's side of the city is part of its name.
        let district = matches!(t.key.as_str(), "bati" | "dogu" | "anadolu" | "kuzey" | "guney" | "merkez");
        let structural = vocab::is_vocab(&t.key) && !vocab::is_province(&t.key) && !district;
        if t.kind != Kind::Word || t.chars < 2 || !ws_gap(g) || structural || TYPE_WORDS.contains(&t.key.as_str()) {
            break;
        }
        if matches!(fold::case_of(doc.t(p)), fold::Case::Lower) {
            break;
        }
        city.insert(0, t.key.clone());
        k = p;
        // A province ends the walk: "ANKARA" is the city, "T.C." before it is not.
        if vocab::is_province(&t.key) {
            break;
        }
    }
    Some(Court { city, number, first_type, type_title, criminal })
}

/// Every place the court is named with its city or number: city + number + type, number + type,
/// or (no number) city + type. The span covers the city and the number with its dot.
pub fn mark(doc: &Doc, court: &Court, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    if court.city.is_empty() && court.number.is_none() {
        return;
    }
    let mut i = 0;
    while i < toks.len() {
        // The span starts at a city (when it is known and matches here) or at the number.
        let after_city = if !court.city.is_empty() && matches_seq(doc, i, &court.city) { i + court.city.len() } else { i };
        let mut k = after_city;
        let numbered = match &court.number {
            Some(n) => k < toks.len() && toks[k].kind == Kind::Num && toks[k].key == *n && doc.gap(k).starts_with('.'),
            None => false,
        };
        if numbered {
            k += 1;
        }
        let named = numbered || (court.number.is_none() && after_city > i);
        if named && k < toks.len() && toks[k].key == court.first_type {
            let e = if numbered { toks[k - 1].e + 1 } else { toks[k - 1].e };
            out.push(Cand::new(toks[i].s, e, Category::Mahkeme, "mahkeme"));
            i = k;
            continue;
        }
        i += 1;
    }
}

fn matches_seq(doc: &Doc, i: usize, keys: &[String]) -> bool {
    keys.iter().enumerate().all(|(n, key)| {
        let k = i + n;
        k < doc.toks.len() && doc.toks[k].key == *key && (n == 0 || ws_gap(doc.gap(k - 1)))
    })
}

/// The record's own esas no as "yyyy/n" (leading zeros of n dropped): from an "ESAS NO :" label,
/// else from the first "yyyy/n Esas" or "yyyy/n E." in the header lines.
pub fn find_esas(doc: &Doc) -> Option<String> {
    let toks = &doc.toks;
    for i in 0..toks.len() {
        if toks[i].line >= MAX_HEADER_LINES {
            break;
        }
        // "ESAS NO :", and a Sulh Ceza Hakimliği's "DEĞİŞİK İŞ NO :".
        let label = toks[i].key == "esas" || (toks[i].key == "degisik" && doc.is(i + 1, "is"));
        if !label {
            continue;
        }
        let i = if toks[i].key == "degisik" { i + 1 } else { i };
        let mut k = i + 1;
        while k < toks.len() && matches!(toks[k].key.as_str(), "no" | "numarasi" | "nosu") {
            k += 1;
        }
        if k > i + 1 || doc.gap(i).contains(':') {
            if let Some(v) = esas_at(doc, k) {
                return Some(v);
            }
        }
    }
    for i in 0..toks.len() {
        if toks[i].line >= MAX_HEADER_LINES {
            break;
        }
        if let Some(v) = esas_at(doc, i) {
            let after = i + 2;
            if doc.is(after, "esas") || (doc.is(after, "e") && doc.gap(after).starts_with('.')) {
                return Some(v);
            }
        }
    }
    None
}

/// `yyyy/n` starting at token `i` (with `/` or ` / ` between), normalized.
pub fn esas_at(doc: &Doc, i: usize) -> Option<String> {
    let toks = &doc.toks;
    let a = toks.get(i)?;
    let b = toks.get(i + 1)?;
    if a.kind != Kind::Num || b.kind != Kind::Num || a.chars != 4 || b.chars > 6 {
        return None;
    }
    if doc.gap(i).trim() != "/" || doc.gap(i).len() > 3 {
        return None;
    }
    Some(normalize(&a.key, &b.key))
}

pub fn normalize(year: &str, n: &str) -> String {
    let n = n.trim_start_matches('0');
    format!("{year}/{}", if n.is_empty() { "0" } else { n })
}

/// A hint like "2024/123 Esas" → "2024/123".
pub fn esas_from_hint(hint: &str) -> Option<String> {
    let d = Doc::new(hint);
    (0..d.toks.len()).find_map(|i| esas_at(&d, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_line_header() {
        let d = Doc::new("T.C.\nANKARA\n3. ASLİYE HUKUK MAHKEMESİ\nESAS NO : 2024/0123 Esas\n");
        let c = find(&d).unwrap();
        assert_eq!(c.type_title, "Asliye Hukuk");
        assert_eq!(c.city, ["ankara"]);
        assert_eq!(c.number.as_deref(), Some("3"));
        assert!(!c.criminal);
        assert_eq!(find_esas(&d).as_deref(), Some("2024/123"));
        let mut v = Vec::new();
        mark(&d, &c, &mut v);
        assert_eq!(v.len(), 1);
        assert_eq!(&d.text()[v[0].s..v[0].e], "ANKARA\n3.");
    }

    #[test]
    fn one_line_header_and_body_mentions() {
        let d = Doc::new("İSTANBUL 12. AĞIR CEZA MAHKEMESİ\nİstanbul 12. Ağır Ceza Mahkemesince ... 12. Ağır Ceza");
        let c = find(&d).unwrap();
        assert!(c.criminal);
        let mut v = Vec::new();
        mark(&d, &c, &mut v);
        let got: Vec<&str> = v.iter().map(|c| &d.text()[c.s..c.e]).collect();
        assert_eq!(got, ["İSTANBUL 12.", "İstanbul 12.", "12."]);
    }
}
