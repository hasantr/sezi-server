//! Names (§4.4): harvested from header role lines and body anchors, then propagated — every
//! harvested name is masked everywhere it appears, whole or token by token.
//!
//! | file | does |
//! |---|---|
//! | `header.rs` | `DAVACI : AHMET YILMAZ - …` label lines, their continuations, `ADRES :` values |
//! | `anchors.rs` | `Av. X`, `davalı vekili X`, `tanık X`, `X oğlu`, `baba adı X`, `X adlı` in the body |
//! | `propagate.rs` | one record per distinct name, and every occurrence of it as a candidate |

pub mod anchors;
pub mod header;
pub mod propagate;

use crate::category::Category;
use crate::fold::Case;
use crate::token::{ws_gap, Doc, Kind};
use crate::vocab;

/// One harvested name: tokens `first..=last` of the document.
#[derive(Clone, Debug)]
pub struct Harvest {
    pub cat: Category,
    pub first: usize,
    pub last: usize,
}

/// Titles skipped before a name: `Av.`, `Dr.`, `Prof. Dr.`, `Stj. Av.`…
pub fn is_title(key: &str) -> bool {
    matches!(
        key,
        "av" | "avukat" | "stj" | "stajyer" | "dr" | "prof" | "doc" | "uzm" | "op" | "yrd" | "mim" | "muh" | "smmm"
            | "ymm" | "sayin" | "bay" | "bayan" | "ogr" | "gor" | "arastirma" | "gorevlisi" | "mali" | "musavir"
            | "muhendis" | "mimar" | "uzman" | "hekim" | "doktor" | "pedagog" | "psikolog"
    )
}

/// Skips titles (and their dots) from token `i`; returns the first token after them.
pub fn skip_titles(doc: &Doc, mut i: usize) -> usize {
    while i < doc.toks.len() && doc.toks[i].kind == Kind::Word && is_title(&doc.toks[i].key) {
        let g = doc.gap(i);
        if !(g.starts_with('.') || g.starts_with(' ')) {
            break;
        }
        i += 1;
    }
    i
}

/// A run of 1–`max` Capitalized or all-caps words from token `i`, separated by spaces (one line
/// break allowed — a name split across lines), stopping at a role or court word, a punctuation
/// mark, or after a word that carries an apostrophe suffix. Returns its last token.
pub fn name_run(doc: &Doc, i: usize, max: usize) -> Option<usize> {
    let toks = &doc.toks;
    let mut last = None;
    let mut j = i;
    while j < toks.len() && j - i < max {
        let t = &toks[j];
        if t.kind != Kind::Word || t.suffix || t.chars < 2 || !matches!(t.case, Case::Cap | Case::Upper) {
            break;
        }
        if vocab::is_vocab(&t.key) || vocab::is_role(&t.key) || is_title(&t.key) {
            break;
        }
        // A hyphen glued on both sides joins a double surname ("Ak-Karaoğlan"); a spaced one
        // (" - ") separates the name from what follows it.
        if j > i && !ws_gap(doc.gap(j - 1)) && doc.gap(j - 1) != "-" {
            break;
        }
        // A name may continue on the next line, but not into the next header field
        // ("Ana Adı : GÜLİZAR⏎Doğum Yeri ve Tarihi : …").
        if j > i && toks[j].line != toks[j - 1].line && header::find_label(doc, toks[j].line).is_some_and(|(f, _, _)| f == j) {
            break;
        }
        last = Some(j);
        if toks.get(j + 1).is_some_and(|n| n.suffix) {
            break;
        }
        j += 1;
    }
    last
}

/// When the words from `i` end in a company form ("… Ltd. Şti.", "… A.Ş.", "… Kooperatifi"),
/// the index of the form's last token. Up to eight words are looked at, generic ones included
/// ("Deniz İnşaat Ticaret Ltd. Şti.").
pub fn company_end(doc: &Doc, i: usize) -> Option<usize> {
    let toks = &doc.toks;
    let mut j = i;
    while j < toks.len() && j - i < 9 {
        let t = &toks[j];
        if t.kind != Kind::Word {
            return None;
        }
        if let Some(end) = company_form(doc, j) {
            return (end >= i).then_some(end);
        }
        let g = doc.gap(j);
        let ok = matches!(t.case, Case::Cap | Case::Upper) || t.key == "ve";
        if !ok || !(ws_gap(g) || g == "." || g == ". " || g == " & " || g == "-") {
            return None;
        }
        j += 1;
    }
    None
}

/// A company form starting at token `j`; returns its last token.
fn company_form(doc: &Doc, j: usize) -> Option<usize> {
    let k = |n: usize| doc.toks.get(j + n).map(|t| t.key.as_str());
    match k(0)? {
        "ltd" if k(1) == Some("sti") => Some(j + 1),
        "limited" | "anonim" if k(1) == Some("sirketi") => Some(j + 1),
        "a" if k(1) == Some("s") && doc.gap(j).starts_with('.') => Some(j + 1),
        "as" if matches!(doc.toks[j].case, Case::Upper | Case::Mixed) || doc.t(j) == "Aş" => Some(j),
        "kooperatifi" | "vakfi" | "dernegi" | "holding" | "sendikasi" => Some(j),
        "sirketi" | "sti" => Some(j),
        _ => None,
    }
}

/// Whether a name with these token keys is a company (by its form).
pub fn typed(doc: &Doc, first: usize, last: usize) -> Category {
    if (first..=last).any(|j| company_form(doc, j).is_some_and(|e| e <= last)) {
        Category::Sirket
    } else {
        Category::Kisi
    }
}
