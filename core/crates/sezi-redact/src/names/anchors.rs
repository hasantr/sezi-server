//! Body anchors (§4.4): a name run after `Av.`, after a role ("davalı vekili", "tanık",
//! "bilirkişi Dr."), before "oğlu"/"kızı" (the father's and mother's names are personal data too),
//! after "baba adı"/"ana adı", and before "adlı"/"isimli".

use super::{company_end, is_title, name_run, Harvest};
use crate::category::Category;
use crate::fold::Case;
use crate::span::Intervals;
use crate::token::{ws_gap, Doc, Kind};
use crate::vocab;

pub fn scan(doc: &Doc, blocked: &Intervals, out: &mut Vec<Harvest>) {
    let mut found = Vec::new();
    scan_into(doc, blocked, &mut found);
    // "Davacı vekili Av. X" anchors X three times over; keep it once.
    found.sort_by_key(|h| (h.first, h.last));
    found.dedup_by_key(|h| (h.first, h.last));
    out.extend(found);
}

fn scan_into(doc: &Doc, blocked: &Intervals, out: &mut Vec<Harvest>) {
    let toks = &doc.toks;
    let free = |a: usize, b: usize| !blocked.overlaps(toks[a].s, toks[b].e);
    // A role word inside a header label ("VASİ ADAYI :") is the label's, not an anchor; the
    // header scan reads the value.
    let mut in_label = vec![false; toks.len()];
    for line in 0..doc.n_lines() {
        if let Some((f, l)) = super::header::role_label(doc, line) {
            in_label[f..=l].iter_mut().for_each(|x| *x = true);
        }
    }
    for i in 0..toks.len() {
        let t = &toks[i];
        if t.kind != Kind::Word {
            continue;
        }
        let key = t.key.as_str();
        let lawyer = matches!(key, "av" | "avukat") && (key == "avukat" || doc.gap(i).starts_with('.'));
        if !in_label[i] && (vocab::is_role(key) || lawyer || (is_title(key) && doc.gap(i).starts_with('.'))) {
            if let Some(h) = after_role(doc, i) {
                if free(h.first, h.last) {
                    out.push(h);
                }
            }
        }
        if matches!(key, "oglu" | "kizi") && !t.suffix {
            for p in parents(doc, i) {
                if free(p, p) {
                    out.push(Harvest { cat: Category::Kisi, first: p, last: p });
                }
            }
        }
        if matches!(key, "baba" | "ana" | "anne") && doc.is(i + 1, "adi") {
            let j = i + 2;
            if j < toks.len() && doc.gap(i + 1).chars().all(|c| c == ' ' || c == ':') {
                if let Some(last) = name_run(doc, j, 2).filter(|&l| free(j, l)) {
                    out.push(Harvest { cat: Category::Kisi, first: j, last });
                }
            }
        }
        if matches!(key, "babasi" | "annesi" | "esi" | "kardesi" | "oglu" | "kizi") && i + 1 < toks.len() && ws_gap(doc.gap(i)) {
            if let Some(last) = name_run(doc, i + 1, 3).filter(|&l| free(i + 1, l) && l > i + 1) {
                out.push(Harvest { cat: Category::Kisi, first: i + 1, last });
            }
        }
        if matches!(key, "adli" | "isimli" | "isminde" | "adinda" | "adindaki") && i > 0 && ws_gap(doc.gap(i - 1)) {
            let mut f = i;
            while f > 0 && i - f < 4 && ws_gap(doc.gap(f - 1)) && is_name_word(doc, f - 1) {
                f -= 1;
            }
            if f < i && free(f, i - 1) {
                out.push(Harvest { cat: Category::Kisi, first: f, last: i - 1 });
            }
        }
    }
}

fn is_name_word(doc: &Doc, k: usize) -> bool {
    let t = &doc.toks[k];
    t.kind == Kind::Word
        && !t.suffix
        && t.chars >= 2
        && matches!(t.case, Case::Cap | Case::Upper)
        && !vocab::is_vocab(&t.key)
        && !vocab::is_role(&t.key)
        && !is_title(&t.key)
}

/// The name after a role word (and any further role words and titles): "davacı vekili Av. Ayşe
/// Kaya", "tanık Mehmet Kara", "davalı Deniz Ltd. Şti.". A role word must be followed by plain
/// spaces; a title may be followed by its dot.
fn after_role(doc: &Doc, i: usize) -> Option<Harvest> {
    let toks = &doc.toks;
    let mut j = i;
    let mut lawyer = false;
    loop {
        let t = &toks[j];
        let titled = is_title(&t.key);
        lawyer |= matches!(t.key.as_str(), "av" | "avukat");
        let g = doc.gap(j);
        let gap_ok = if titled { g.starts_with('.') || g == " " } else { ws_gap(g) };
        if !gap_ok || j + 1 >= toks.len() {
            return None;
        }
        j += 1;
        let n = &toks[j];
        if n.kind == Kind::Word && (vocab::is_role(&n.key) || is_title(&n.key)) && !n.suffix {
            continue;
        }
        break;
    }
    let n = &toks[j];
    if n.kind != Kind::Word || n.suffix {
        return None;
    }
    if matches!(n.case, Case::Cap | Case::Upper) && !vocab::is_vocab(&n.key) {
        if let Some(end) = company_end(doc, j) {
            return Some(Harvest { cat: Category::Sirket, first: j, last: end });
        }
    }
    if let Some(last) = name_run(doc, j, 4) {
        return Some(Harvest { cat: Category::Kisi, first: j, last });
    }
    // "av. ayşe kaya": after a lawyer's title the next one or two words are the name, whatever
    // their case.
    if lawyer && n.case == Case::Lower {
        let ok = |k: usize| {
            toks.get(k).is_some_and(|t| {
                t.kind == Kind::Word && t.chars >= 2 && !vocab::is_common(&t.key) && !vocab::is_vocab(&t.key) && !vocab::is_role(&t.key)
            })
        };
        if ok(j) {
            let last = if ok(j + 1) && ws_gap(doc.gap(j)) && !toks[j + 1].suffix { j + 1 } else { j };
            return Some(Harvest { cat: Category::Kisi, first: j, last });
        }
    }
    None
}

/// "Mehmet oğlu", "Mehmet ve Ayşe oğlu", "AHMET ve AYŞE kızı".
fn parents(doc: &Doc, i: usize) -> Vec<usize> {
    let mut v = Vec::new();
    if i == 0 || !ws_gap(doc.gap(i - 1)) || !is_name_word(doc, i - 1) {
        return v;
    }
    let p = i - 1;
    if p >= 2 && doc.is(p - 1, "ve") && ws_gap(doc.gap(p - 1)) && ws_gap(doc.gap(p - 2)) && is_name_word(doc, p - 2) {
        v.push(p - 2);
    }
    v.push(p);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<String> {
        let d = Doc::new(text);
        let mut h = Vec::new();
        scan(&d, &Intervals::default(), &mut h);
        h.into_iter().map(|h| d.text()[d.toks[h.first].s..d.toks[h.last].e].to_string()).collect()
    }

    #[test]
    fn anchors() {
        assert_eq!(names("Davacı vekili Av. Ayşe Kaya geldi."), ["Ayşe Kaya"]);
        assert_eq!(names("davalı Deniz İnşaat Ltd. Şti. vekili"), ["Deniz İnşaat Ltd. Şti"]);
        assert_eq!(names("Davacı tanığı Mehmet\nKara'nın beyanı"), ["Mehmet\nKara"]);
        assert_eq!(names("Ali ve Fatma oğlu, 1980 doğumlu"), ["Ali", "Fatma"]);
        assert_eq!(names("Baba Adı: HASAN"), ["HASAN"]);
        assert_eq!(names("Hasan Kılıç adlı şahıs"), ["Hasan Kılıç"]);
        assert_eq!(names("av. selin aksoy geldi"), ["selin aksoy"]);
        assert!(names("davacı asil gelmedi, davalı Kurum vekili Mahkememize").is_empty());
    }
}
