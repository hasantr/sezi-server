//! Propagation (§4.4): each harvested name is masked everywhere — the full string, and each of its
//! tokens of 3 or more letters alone (surnames recur alone), with Turkish case folding and with a
//! suffix after an apostrophe left outside the mask (`[KISI_1]'ın`) or, without an apostrophe,
//! a known case ending ("Yılmazın" → `[KISI_1]ın`).
//!
//! Numbering: every occurrence of one harvested name is that name's placeholder; a lone token is
//! too, when exactly one harvested name contains it. A surname two parties share gets a
//! placeholder of its own, so the model is never told which of them "Yılmaz" was. A GIVEN name
//! alone is never the harvested person's placeholder: it is masked as a person of its own and
//! restores to itself, since "Ayşe" alone is as likely someone else as AYŞE KARAKAYA.

use std::collections::{HashMap, HashSet};

use super::{is_title, typed, Harvest};
use crate::category::Category;
use crate::given_names;
use crate::span::Cand;
use crate::token::{ws_gap, Doc, Kind};
use crate::vocab;

pub struct NameRec {
    pub cat: Category,
    keys: Vec<String>,
    /// The original text of the first harvest: what the vault restores.
    pub display: String,
}

impl NameRec {
    /// Is `key` only the given-name part of this person — not their surname (the last word), and
    /// either their first word or a known given name among the words before the surname ("Emre"
    /// of "Yunus Emre Battalgazili")? A middle word that is no given name is left to the person:
    /// it is likelier a surname the harvest ran past ("Enes İznikli SEGBİS").
    fn is_given_part(&self, key: &str) -> bool {
        let Some((last, before)) = self.keys.split_last() else { return false };
        self.cat == Category::Kisi
            && last != key
            && before.iter().enumerate().any(|(i, k)| k == key && (i == 0 || given_names::is_given(key)))
    }
}

pub struct Names {
    pub recs: Vec<NameRec>,
    full: HashMap<String, Vec<usize>>,
    single: HashMap<String, Vec<usize>>,
}

impl Names {
    /// Every key that is masked alone wherever it stands; the leak check looks for survivors.
    pub fn single_keys(&self) -> HashSet<&str> {
        self.single.keys().map(String::as_str).collect()
    }

    pub fn ident(id: usize) -> String {
        format!("n#{id}")
    }
}

pub fn build(doc: &Doc, orig: &str, harvest: &[Harvest], known: &[String]) -> Names {
    let mut names = Names { recs: Vec::new(), full: HashMap::new(), single: HashMap::new() };
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut add = |names: &mut Names, cat: Category, keys: Vec<String>, display: String| {
        if keys.is_empty() {
            return;
        }
        let joined = keys.join(" ");
        if seen.contains_key(&joined) {
            return;
        }
        let id = names.recs.len();
        seen.insert(joined, id);
        names.full.entry(keys[0].clone()).or_default().push(id);
        let person_like = given_names::is_given(&keys[0]);
        for k in &keys {
            let alone = k.chars().count() >= 3
                && !is_title(k)
                && match cat {
                    Category::Sirket => !vocab::is_company_generic(k) && !vocab::is_vocab(k),
                    _ => person_like || !vocab::is_vocab(k),
                };
            if alone {
                let ids = names.single.entry(k.clone()).or_default();
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        names.recs.push(NameRec { cat, keys, display });
    };
    let mut found: Vec<(Category, Vec<String>, String)> = Vec::new();
    for h in harvest {
        let keys: Vec<String> = (h.first..=h.last).filter(|&k| doc.toks[k].kind == Kind::Word).map(|k| doc.toks[k].key.clone()).collect();
        let (s, e) = (doc.view.orig(doc.toks[h.first].s), doc.view.orig(doc.toks[h.last].e));
        found.push((h.cat, keys, orig[s..e].to_string()));
    }
    for k in known {
        let d = Doc::new(k);
        let words: Vec<usize> = (0..d.toks.len()).filter(|&i| d.toks[i].kind == Kind::Word && !is_title(&d.toks[i].key)).collect();
        if let (Some(&f), Some(&l)) = (words.first(), words.last()) {
            let keys = words.iter().map(|&i| d.toks[i].key.clone()).collect();
            found.push((typed(&d, f, l), keys, k.trim().to_string()));
        }
    }
    // "Sanık Topaloğlu" anchors a part of "ERDAL TOPALOĞLU": it is the same person, not a new
    // one. A part is dropped when a longer name contains it; the lone surname then reaches the
    // longer name through the single-token index (or its own placeholder when two names share it).
    let contains = |long: &[String], short: &[String]| long.len() > short.len() && long.windows(short.len()).any(|w| w == short);
    let reachable = |k: &[String]| k.iter().all(|w| w.chars().count() >= 3);
    let keep: Vec<bool> = found.iter().map(|(_, k, _)| !(reachable(k) && found.iter().any(|(_, l, _)| contains(l, k)))).collect();
    for ((cat, keys, display), keep) in found.into_iter().zip(keep) {
        if keep {
            add(&mut names, cat, keys, display);
        }
    }
    names
}

/// How the words of one name may be separated where it recurs.
fn name_gap(g: &str) -> bool {
    ws_gap(g) || matches!(g, "." | ". " | "-" | " & " | ".\n")
}

fn match_full(doc: &Doc, i: usize, keys: &[String]) -> Option<usize> {
    let toks = &doc.toks;
    let mut j = i;
    let mut n = 0;
    while n < keys.len() {
        let t = toks.get(j)?;
        if t.kind != Kind::Word || t.key != keys[n] || (n > 0 && (t.suffix || !name_gap(doc.gap(j - 1)))) {
            return None;
        }
        n += 1;
        j += 1;
    }
    Some(j - 1)
}

pub fn apply(doc: &Doc, names: &Names, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        if t.kind != Kind::Word || t.suffix {
            i += 1;
            continue;
        }
        let best = names
            .full
            .get(&t.key)
            .into_iter()
            .flatten()
            .filter_map(|&id| match_full(doc, i, &names.recs[id].keys).map(|last| (id, last)))
            .max_by_key(|&(id, last)| (last, std::cmp::Reverse(id)));
        if let Some((id, last)) = best {
            let mut e = toks[last].e;
            // "… LTD. ŞTİ." / "… A.Ş.": the abbreviation's dot is part of the name.
            if names.recs[id].cat == Category::Sirket && doc.next_char(last) == Some('.') && toks[last].chars <= 4 {
                e += 1;
            }
            out.push(Cand::new(t.s, e, names.recs[id].cat, Names::ident(id)));
            i = last + 1;
            continue;
        }
        if let Some(ids) = names.single.get(&t.key) {
            let mut c = single(names, ids, t.s, t.e, &t.key);
            // A company by its short name takes its generic words along: "Mavikuş Sigorta".
            if c.cat == Category::Sirket {
                let mut j = i;
                while j + 1 < toks.len()
                    && name_gap(doc.gap(j))
                    && toks[j + 1].kind == Kind::Word
                    && !toks[j + 1].suffix
                    && matches!(toks[j + 1].case, crate::fold::Case::Cap | crate::fold::Case::Upper)
                    && vocab::is_company_generic(&toks[j + 1].key)
                {
                    j += 1;
                }
                if j > i {
                    c.e = toks[j].e + usize::from(doc.next_char(j) == Some('.') && toks[j].chars <= 4);
                    out.push(c);
                    i = j + 1;
                    continue;
                }
            }
            out.push(c);
        } else if let Some((stem_len, ids)) = stem_match(names, &t.key) {
            let e = stem_end(doc.t(i), stem_len) + t.s;
            out.push(single(names, ids, t.s, e, &t.key[..t.key.char_indices().nth(stem_len).map_or(t.key.len(), |(b, _)| b)]));
        }
        i += 1;
    }
}

fn single(names: &Names, ids: &[usize], s: usize, e: usize, key: &str) -> Cand {
    if let [id] = ids {
        let rec = &names.recs[*id];
        // A given name alone is not evidence of the person it was harvested with: given names are
        // few and shared, and restoring "Ayşe" as "AYŞE KARAKAYA" would put a party's name where
        // the record spoke of someone else. It is masked as a person of its own (`g:`, as the
        // given-name net does), and comes back as itself.
        if rec.is_given_part(key) {
            return Cand::new(s, e, Category::Kisi, format!("g:{key}"));
        }
        Cand::new(s, e, rec.cat, Names::ident(*id))
    } else {
        let cat = if ids.iter().any(|&id| names.recs[id].cat == Category::Kisi) { Category::Kisi } else { Category::Sirket };
        Cand::new(s, e, cat, format!("t:{key}"))
    }
}

/// A token that is a propagated name of 4+ letters plus a known case ending.
fn stem_match<'a>(names: &'a Names, key: &str) -> Option<(usize, &'a [usize])> {
    let chars: Vec<(usize, char)> = key.char_indices().collect();
    if chars.len() < 5 || vocab::is_vocab(key) {
        return None;
    }
    for len in (4..chars.len()).rev() {
        let b = chars[len].0;
        if let Some(ids) = names.single.get(&key[..b]) {
            if vocab::is_name_suffix(&key[b..]) {
                return Some((len, ids));
            }
        }
    }
    None
}

/// The byte length of a word's first `n` key characters (marks travel with their letter).
fn stem_end(word: &str, n: usize) -> usize {
    let mut seen = 0;
    for (b, c) in word.char_indices() {
        if crate::fold::key_char(c).is_some() {
            if seen == n {
                return b;
            }
            seen += 1;
        }
    }
    word.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagates_whole_tokens_and_stems() {
        let text = "DAVACI AHMET YILMAZ\nYılmaz'ın beyanı; ahmet yilmaz; yılmazın; AYŞE YILMAZ";
        let d = Doc::new(text);
        let h = vec![
            Harvest { cat: Category::Kisi, first: 1, last: 2 },
            Harvest { cat: Category::Kisi, first: 9, last: 10 },
        ];
        let names = build(&d, text, &h, &[]);
        let mut c = Vec::new();
        apply(&d, &names, &mut c);
        let got: Vec<(&str, &str)> = c.iter().map(|c| (&d.text()[c.s..c.e], c.ident.as_str())).collect();
        assert_eq!(
            got,
            [
                ("AHMET YILMAZ", "n#0"),
                ("Yılmaz", "t:yilmaz"),
                ("ahmet yilmaz", "n#0"),
                ("yılmaz", "t:yilmaz"),
                ("AYŞE YILMAZ", "n#1"),
            ]
        );
        assert_eq!(names.recs[0].display, "AHMET YILMAZ");
    }
}
