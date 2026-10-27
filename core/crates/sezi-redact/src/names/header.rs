//! Header role lines (§4.4): for `DAVACI`, `VEKİLİ`, `SANIK`, `TANIK`, `HAKİM`… the value after
//! `:` is a party. UYAP prints them one per line; `pdftotext` may put the label and `: value` on
//! adjacent lines, and a list of parties continues on lines of its own ("2- …", "Av. …").

use super::{company_end, name_run, skip_titles, Harvest};
use crate::address;
use crate::category::Category;
use crate::fold::Case;
use crate::span::{Cand, Intervals};
use crate::token::{space_gap, Doc, Kind};
use crate::vocab;

/// Officials and other labels that name a person, beside [`vocab::is_role`].
const OFFICIAL: &[&str] = &[
    "hakim", "hakimi", "uye", "baskan", "baskani", "katip", "katibi", "savci", "savcisi", "avukat", "avukati",
    "eden", "olunan", "cocuk", "cocuklar", "cocugu", "kucuk", "taraf", "mudafileri", "isci", "isveren",
    "istenen", "adayi", "kisitli", "alicisi",
];

/// First words of a value that is not a name.
const NOT_A_NAME: &[&str] = &[
    "yok", "hazir", "hazirdir", "gelmedi", "gelmediler", "katilmadi", "katildi", "belirtilmemis", "mevcut",
    "bulunmamaktadir", "istinabe", "kendisi", "asaleten", "bulunmadi", "atanmadi",
];

/// Words that end a value ("AHMET YILMAZ T.C. …", "… TEL: …").
const STOP: &[&str] = &[
    "t", "tc", "kimlik", "vkn", "vergi", "tel", "telefon", "gsm", "cep", "adres", "adresi", "mernis", "eposta",
    "kep", "iban", "hesap", "dogumlu", "oglu", "kizi", "uyruklu", "sicil", "baro", "barosu",
];

enum Label {
    Person { upper: bool },
    Address,
    Other,
}

/// A label at the start of `line`: (its last token, the first value token), when the line reads
/// `WORDS : value` — or `WORDS` alone with `: value` on the next line.
pub fn find_label(doc: &Doc, line: usize) -> Option<(usize, usize, usize)> {
    let r = doc.line_toks(line);
    let toks = &doc.toks;
    for k in r.clone().take(6) {
        let t = &toks[k];
        if t.kind == Kind::Num && k == r.start {
            return None;
        }
        let g = doc.gap(k);
        if g.contains(':') {
            let before_colon = &g[..g.find(':').unwrap_or(0)];
            if before_colon.matches('\n').count() > 1 || k + 1 >= toks.len() || g.matches('\n').count() > 1 {
                return None;
            }
            return Some((r.start, k, k + 1));
        }
        // "DAVACI (3. KİŞİ) :", "C. SAVCISI :", "FER'İ MÜDAHİL :"
        if !(space_gap(g) || matches!(g, "." | ". " | "'" | "-" | " (" | "(" | ") " | ")" | "/")) {
            return None;
        }
    }
    None
}

/// The label tokens of `line` when they name a party or an address: the header scan reads that
/// value, so the body anchors leave the label's own role words alone.
pub fn role_label(doc: &Doc, line: usize) -> Option<(usize, usize)> {
    let (f, l, _) = find_label(doc, line)?;
    (!matches!(classify(doc, f, l), Label::Other)).then_some((f, l))
}

fn classify(doc: &Doc, first: usize, last: usize) -> Label {
    // The role is outside the parentheses: "DAVACI (3. KİŞİ)", "KARŞI TARAF (ALACAKLI)".
    let mut depth = 0i32;
    let mut words: Vec<&str> = Vec::new();
    for k in first..=last {
        if depth == 0 && doc.toks[k].kind == Kind::Word {
            words.push(doc.toks[k].key.as_str());
        }
        let g = doc.gap(k);
        depth += g.matches('(').count() as i32 - g.matches(')').count() as i32;
    }
    let Some(&end) = words.last() else { return Label::Other };
    if matches!(end, "adres" | "adresi" | "adresleri" | "ikametgah" | "ikametgahi" | "ikamet") {
        return Label::Address;
    }
    let upper = (first..=last).all(|k| doc.toks[k].kind == Kind::Num || doc.toks[k].case == Case::Upper || doc.toks[k].chars == 1);
    let parent = end == "adi" && words.iter().any(|w| matches!(*w, "baba" | "ana" | "anne"));
    if words.iter().any(|w| matches!(*w, "tarihi" | "no" | "numarasi" | "sayisi" | "nosu")) && !parent {
        return Label::Other;
    }
    if parent || vocab::is_role(end) || OFFICIAL.contains(&end) {
        Label::Person { upper }
    } else {
        Label::Other
    }
}

pub fn scan(doc: &Doc, blocked: &Intervals, out: &mut Vec<Harvest>, cands: &mut Vec<Cand>) {
    let mut line = 0;
    while line < doc.n_lines() {
        let Some((lf, ll, v)) = find_label(doc, line) else {
            line += 1;
            continue;
        };
        let vline = doc.toks[v].line;
        let vend = doc.line_toks(vline).end;
        match classify(doc, lf, ll) {
            Label::Address => address::label_value(doc, v, vend - 1, cands),
            Label::Other => {}
            Label::Person { upper } => {
                segments(doc, v, vend, blocked, upper, out);
                // Continuation lines: "2- AYŞE VELİ - …", "Av. CAN ÖZ - …".
                let mut next = vline + 1;
                while next < doc.n_lines() {
                    let r = doc.line_toks(next);
                    if r.is_empty() || find_label(doc, next).is_some() {
                        break;
                    }
                    let t = &doc.toks[r.start];
                    let enumerated = t.kind == Kind::Num && t.chars <= 2 && doc.gap(r.start).trim_start().starts_with(['-', ')', '.']);
                    let lawyer = t.kind == Kind::Word && matches!(t.key.as_str(), "av" | "avukat");
                    if !(enumerated || lawyer) {
                        break;
                    }
                    segments(doc, r.start, r.end, blocked, upper, out);
                    next += 1;
                }
                line = next.max(vline + 1);
                continue;
            }
        }
        line = vline + 1;
    }
}

/// One or more parties on one line: "1- ALİ VELİ 2- AYŞE VELİ".
fn segments(doc: &Doc, from: usize, end: usize, blocked: &Intervals, upper: bool, out: &mut Vec<Harvest>) {
    let mut i = from;
    while i < end {
        let start = skip_enumerator(doc, i, end);
        if let Some(h) = collect(doc, start, end, blocked, upper) {
            let after = h.last + 1;
            out.push(h);
            i = after;
        } else {
            i = start + 1;
        }
        // Move to the next enumerator on this line, if any.
        while i < end && !is_enumerator(doc, i) {
            i += 1;
        }
    }
}

fn is_enumerator(doc: &Doc, i: usize) -> bool {
    let t = &doc.toks[i];
    t.kind == Kind::Num && t.chars <= 2 && doc.gap(i).trim_start().starts_with(['-', ')']) && doc.gap(i).len() <= 3
}

fn skip_enumerator(doc: &Doc, i: usize, end: usize) -> usize {
    if i < end && (is_enumerator(doc, i) || (doc.toks[i].kind == Kind::Num && doc.gap(i).starts_with('.') && doc.toks[i].chars <= 2)) {
        i + 1
    } else {
        i
    }
}

fn collect(doc: &Doc, from: usize, end: usize, blocked: &Intervals, upper_label: bool) -> Option<Harvest> {
    let toks = &doc.toks;
    let i = skip_titles(doc, from);
    if i >= end || toks[i].kind != Kind::Word || NOT_A_NAME.contains(&toks[i].key.as_str()) {
        return None;
    }
    let titled = i > from;
    let first_case = toks[i].case;
    if !upper_label {
        // A body line ("Tanık: Olay günü …") is a speech, not a header: only a full Capitalized
        // name, or one behind a title, counts.
        let last = name_run(doc, i, 4)?;
        if !titled && last == i {
            return None;
        }
        if (i..=last).any(|k| vocab::is_common(&toks[k].key)) {
            return None;
        }
        let cat = if company_end(doc, i).is_some() { Category::Sirket } else { Category::Kisi };
        let last = if cat == Category::Sirket { company_end(doc, i)? } else { last };
        return Some(Harvest { cat, first: i, last });
    }
    let mut last = None;
    let mut n = 0;
    let mut j = i;
    while j < end && n < 8 {
        let t = &toks[j];
        if t.kind != Kind::Word || t.suffix || blocked.overlaps(t.s, t.e) {
            break;
        }
        if STOP.contains(&t.key.as_str()) || address::is_keyword(&t.key) || (n > 0 && vocab::is_role(&t.key)) {
            break;
        }
        if n > 0 {
            let g = doc.gap(j - 1);
            let abbrev = matches!(g, "." | ". ") && toks[j - 1].chars <= 4;
            if !(space_gap(g) || abbrev || g == "-" || g == " & ") {
                break;
            }
        }
        let stop = match first_case {
            Case::Upper | Case::Cap => t.case == Case::Lower,
            Case::Lower => vocab::is_common(&t.key) || vocab::is_vocab(&t.key) || n >= 3,
            Case::Mixed => false,
        };
        if stop {
            break;
        }
        last = Some(j);
        n += 1;
        j += 1;
    }
    let mut last = last?;
    // "SOSYAL GÜVENLİK KURUMU" is an institution; "ADALET SAVCI" is a witness whose given name
    // happens to be a court word.
    if (i..=last).all(|k| vocab::is_vocab(&toks[k].key)) && !crate::given_names::is_given(&toks[i].key) {
        return None;
    }
    if let Some(ce) = company_end(doc, i).filter(|&ce| ce <= last) {
        return Some(Harvest { cat: Category::Sirket, first: i, last: ce });
    }
    last = last.min(i + 4);
    // "DAVACI : AHMET⏎ YILMAZ - …": a lone word at the end of the line takes the next line's
    // capitals with it.
    if last == i && last + 1 == end && first_case == Case::Upper {
        let nl = toks[i].line + 1;
        if nl < doc.n_lines() && find_label(doc, nl).is_none() {
            let mut k = doc.line_toks(nl).start;
            let stop = doc.line_toks(nl).end;
            while k < stop && k - last <= 3 {
                let t = &toks[k];
                let joinable = t.kind == Kind::Word
                    && t.case == Case::Upper
                    && t.chars >= 2
                    && !vocab::is_vocab(&t.key)
                    && !address::is_keyword(&t.key)
                    && !blocked.overlaps(t.s, t.e)
                    && (k == doc.line_toks(nl).start || space_gap(doc.gap(k - 1)));
                if !joinable {
                    break;
                }
                last = k;
                k += 1;
            }
        }
    }
    Some(Harvest { cat: Category::Kisi, first: i, last })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<(Category, String)> {
        let d = Doc::new(text);
        let mut h = Vec::new();
        let mut c = Vec::new();
        scan(&d, &Intervals::default(), &mut h, &mut c);
        h.into_iter().map(|h| (h.cat, d.text()[d.toks[h.first].s..d.toks[h.last].e].to_string())).collect()
    }

    #[test]
    fn labels() {
        let n = names(
            "DAVACI          : AHMET YILMAZ - Kızılay Mah.\nVEKİLİ          : Av. AYŞE KAYA\n\
             DAVALI          : DENİZ İNŞAAT TİCARET LTD. ŞTİ. - Ankara\nDAVA            : ALACAK\n\
             DAVALILAR : 1- ALİ VELİ 2- ZEHRA VELİ\n           3- CAN VELİ\nTANIK\n: SELİN\n AKSOY\n\
             C. SAVCISI : Katılmadı\nDavacı vekili: dilekçemizi tekrar ederiz",
        );
        let want = [
            (Category::Kisi, "AHMET YILMAZ"),
            (Category::Kisi, "AYŞE KAYA"),
            (Category::Sirket, "DENİZ İNŞAAT TİCARET LTD. ŞTİ"),
            (Category::Kisi, "ALİ VELİ"),
            (Category::Kisi, "ZEHRA VELİ"),
            (Category::Kisi, "CAN VELİ"),
            (Category::Kisi, "SELİN\n AKSOY"),
        ];
        let got: Vec<(Category, &str)> = n.iter().map(|(c, s)| (*c, s.as_str())).collect();
        assert_eq!(got, want);
    }
}
