//! Residual nets (§4.5) — fail closed: over-masking is the safe error. They only look at what no
//! earlier recognizer took.

use crate::category::Category;
use crate::fold::{self, Case};
use crate::given_names;
use crate::names::is_title;
use crate::span::{Cand, Intervals};
use crate::token::{space_gap, ws_gap, Doc, Kind};
use crate::vocab;

pub fn scan(doc: &Doc, covered: &Intervals, out: &mut Vec<Cand>) {
    let mut people = Vec::new();
    given_pairs(doc, covered, &mut people);
    companies(doc, &mut people);
    let covered = covered.merged(people.iter());
    out.extend(people);
    caps_runs(doc, &covered, out);
    long_digits(doc, &covered, out);
    registry_numbers(doc, &covered, out);
}

fn free(covered: &Intervals, doc: &Doc, i: usize) -> bool {
    !covered.overlaps(doc.toks[i].s, doc.toks[i].e)
}

fn plain_word(doc: &Doc, i: usize) -> bool {
    let t = &doc.toks[i];
    t.kind == Kind::Word && !t.suffix && t.chars >= 2 && !vocab::is_vocab(&t.key) && !vocab::is_role(&t.key) && !is_title(&t.key)
}

/// A Capitalized pair (or triple) whose first word is a given name → `[KISI_n]`; in lowercase
/// text only for given names that are not also everyday words.
fn given_pairs(doc: &Doc, covered: &Intervals, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        if t.kind != Kind::Word || t.suffix || !given_names::is_given(&t.key) {
            i += 1;
            continue;
        }
        // A given name already masked — it is also a party's ("Mehmet" of MEHMET DEMİRCAN) — still
        // opens a pair: "Mehmet Kurtoğlu" is another person, and the surname must not go out alone.
        let first_free = free(covered, doc, i);
        let capital = matches!(t.case, Case::Cap | Case::Upper);
        let next_ok = |j: usize| {
            j < toks.len()
                && (ws_gap(doc.gap(j - 1)) || doc.gap(j - 1) == "-")
                && plain_word(doc, j)
                && if capital { matches!(toks[j].case, Case::Cap | Case::Upper) } else { toks[j].case == Case::Lower && !vocab::is_common(&toks[j].key) && toks[j].chars >= 3 }
        };
        if !capital && (t.case != Case::Lower || given_names::is_ambiguous(&t.key)) {
            i += 1;
            continue;
        }
        // ...but only with a free word beside it on its own line: "Baba Adı : MAHMUT⏎Ana Adı" is a
        // label on the next line, not a surname.
        let pair_of_masked = || free(covered, doc, i + 1) && space_gap(doc.gap(i));
        if !next_ok(i + 1) || (!first_free && !pair_of_masked()) {
            // "Kenan Bey", "Ayşe Hanım": the given name alone is the person.
            let honorific = toks.get(i + 1).is_some_and(|n| matches!(n.key.as_str(), "bey" | "hanim" | "efendi" | "beyin" | "hanimin"));
            if first_free && capital && honorific && ws_gap(doc.gap(i)) {
                out.push(Cand::new(t.s, t.e, Category::Kisi, format!("g:{}", t.key)));
            }
            i += 1;
            continue;
        }
        let mut last = i;
        let mut j = i + 1;
        // "Ayşe Yılmaz" where "Yılmaz" is already a harvested name: mask "Ayşe" on its own.
        while j < toks.len() && j - i < 3 && next_ok(j) && free(covered, doc, j) {
            last = j;
            if toks.get(j + 1).is_some_and(|n| n.suffix) {
                break;
            }
            j += 1;
        }
        let (s, e) = (t.s, toks[last].e);
        out.push(Cand::new(s, e, Category::Kisi, format!("g:{}", fold::key(&doc.text()[s..e]))));
        i = last + 1;
    }
}

/// A run of Capitalized words that ends in a company form, wherever it stands ("… ile Anadolu
/// Kervan Bankası A.Ş. Talas şubesinden") → `[SIRKET_n]`, anchored or not.
fn companies(doc: &Doc, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let capital_word = |k: usize| {
        let t = &toks[k];
        t.kind == Kind::Word && !t.suffix && matches!(t.case, Case::Cap | Case::Upper) && !vocab::is_role(&t.key) && !is_title(&t.key)
    };
    let mut i = 0;
    while i < toks.len() {
        let run_start = capital_word(i) && !(i > 0 && capital_word(i - 1) && ws_gap(doc.gap(i - 1)));
        if run_start {
            if let Some(end) = crate::names::company_end(doc, i) {
                let e = toks[end].e + usize::from(doc.next_char(end) == Some('.') && toks[end].chars <= 4);
                out.push(Cand::new(toks[i].s, e, Category::Sirket, format!("c:{}", fold::key(&doc.text()[toks[i].s..e]))));
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
}

/// Runs of 2+ all-caps words: every maximal stretch of words in them that is not court
/// vocabulary and not yet masked → `[AD_n]`.
fn caps_runs(doc: &Doc, covered: &Intervals, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let caps = |i: usize| toks[i].kind == Kind::Word && toks[i].case == Case::Upper && toks[i].chars >= 2;
    let mut i = 0;
    while i < toks.len() {
        if !caps(i) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j + 1 < toks.len() && caps(j + 1) && ws_gap(doc.gap(j)) && !toks[j + 1].suffix {
            j += 1;
        }
        if j > i {
            let flagged = |k: usize| plain_word(doc, k) && free(covered, doc, k);
            let mut k = i;
            while k <= j {
                if !flagged(k) {
                    k += 1;
                    continue;
                }
                let mut m = k;
                while m < j && flagged(m + 1) {
                    m += 1;
                }
                let (s, e) = (toks[k].s, toks[m].e);
                out.push(Cand::new(s, e, Category::Ad, fold::key(&doc.text()[s..e])));
                k = m + 1;
            }
        }
        i = j + 1;
    }
}

const AMOUNT: &[&str] = &["tl", "ytl", "lira", "try", "usd", "eur", "euro", "avro", "dolar", "kurus", "krs"];

/// Any digit run of 7+ that is not an amount, and any spaced-out group of 3+ numbers totalling
/// 9+ digits, not masked yet → `[NUMARA_n]`.
fn long_digits(doc: &Doc, covered: &Intervals, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let amount_after = |i: usize| {
        toks.get(i + 1).is_some_and(|n| AMOUNT.contains(&n.key.as_str())) || doc.gap(i).trim_start().starts_with('₺')
    };
    let mut i = 0;
    while i < toks.len() {
        if toks[i].kind != Kind::Num {
            i += 1;
            continue;
        }
        let mut j = i;
        while j + 1 < toks.len() && toks[j + 1].kind == Kind::Num && matches!(doc.gap(j), " " | "-") {
            j += 1;
        }
        let total: usize = (i..=j).map(|k| toks[k].chars).sum();
        if j - i >= 2 && total >= 9 && (i..=j).all(|k| free(covered, doc, k)) && !amount_after(j) {
            out.push(Cand::new(toks[i].s, toks[j].e, Category::Numara, (i..=j).map(|k| toks[k].key.as_str()).collect::<String>()));
        } else {
            for k in i..=j {
                if toks[k].chars >= 7 && free(covered, doc, k) && !amount_after(k) {
                    out.push(Cand::new(toks[k].s, toks[k].e, Category::Numara, toks[k].key.clone()));
                }
            }
        }
        i = j + 1;
    }
}

/// Civil-registry numbers (nüfus: cilt, hane, aile sıra, sıra, kütük) → `[NUMARA_n]`.
fn registry_numbers(doc: &Doc, covered: &Intervals, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    for i in 0..toks.len() {
        if !matches!(toks[i].key.as_str(), "cilt" | "hane" | "kutuk" | "sira" | "birey") {
            continue;
        }
        for j in i + 1..(i + 4).min(toks.len()) {
            let t = &toks[j];
            if t.kind == Kind::Num {
                if free(covered, doc, j) && !doc.gap(j).starts_with(['.', '/']) {
                    out.push(Cand::new(t.s, t.e, Category::Numara, t.key.clone()));
                }
                break;
            }
            if !matches!(t.key.as_str(), "no" | "nosu" | "numarasi" | "sira" | "kayitli") {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(text: &str) -> Vec<(Category, String)> {
        let d = Doc::new(text);
        let mut v = Vec::new();
        scan(&d, &Intervals::default(), &mut v);
        v.into_iter().map(|c| (c.cat, d.text()[c.s..c.e].to_string())).collect()
    }

    #[test]
    fn residual_nets() {
        assert_eq!(nets("komşusu Hasan Kılıç'ın evine"), [(Category::Kisi, "Hasan Kılıç".into())]);
        assert_eq!(nets("GEREĞİ DÜŞÜNÜLDÜ"), []);
        assert_eq!(nets("TANIK BEYANI OSMAN KURT"), [(Category::Kisi, "OSMAN KURT".into())]);
        assert_eq!(nets("TANIK BEYANI KURTULUŞ KARA"), [(Category::Ad, "KURTULUŞ KARA".into())]);
        assert_eq!(nets("hesap 1234567 ve 3.000.000 TL, 12345678 TL"), [(Category::Numara, "1234567".into())]);
        assert_eq!(nets("Cilt No: 12 Hane No: 345"), [(Category::Numara, "12".into()), (Category::Numara, "345".into())]);
        assert_eq!(nets("tanık ahmet kara geldi; deniz kenarı"), [(Category::Kisi, "ahmet kara".into())]);
    }
}
