//! Once a value is masked anywhere, it is masked everywhere.
//!
//! Most recognizers find a value wherever it stands (a TCKN is a TCKN on any line), but some need
//! context: a sicil number on the judge's line, a code near "doğrulama", a name in a run of
//! capitals, a number after "Cilt No". The same digits or words elsewhere would slip through. So
//! after the first pass every masked value's token sequence is looked for again and masked with the
//! same placeholder. The leak check uses the same sequences, which keeps the two consistent: a
//! vault value that still occurs in the masked text is a leak, never a false alarm.

use std::collections::{HashMap, HashSet};

use crate::category::Category;
use crate::given_names;
use crate::span::{Cand, Cluster};
use crate::token::{Doc, Kind};
use crate::vocab;

/// The keys of the tokens overlapping `[s, e)`.
pub fn keys_of(doc: &Doc, s: usize, e: usize) -> Vec<String> {
    let k = doc.toks.partition_point(|t| t.e <= s);
    doc.toks[k..].iter().take_while(|t| t.s < e).map(|t| t.key.clone()).collect()
}

/// Whether a sequence is distinctive enough to look for everywhere: several tokens, or one number
/// of 5+ digits, or one word of 3+ letters that is not court vocabulary. A bare birth year is not
/// ("1985" is also a statute's year).
pub fn eligible(cat: Category, keys: &[String]) -> bool {
    match keys {
        [] => false,
        [_] if cat == Category::Dogum => false,
        [k] if k.bytes().all(|b| b.is_ascii_digit()) => k.len() >= 5,
        [k] => k.chars().count() >= 3 && !vocab::is_vocab(k) && !vocab::is_common(k),
        _ => true,
    }
}

/// What to look for again once a value of `cat` with these token keys is masked: the whole
/// sequence, and for a person or a company each distinctive word of it alone (a surname recurs
/// alone; "İnşaat" of a company does not identify it).
pub fn seqs_for(cat: Category, keys: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    if eligible(cat, keys) {
        out.push(keys.to_vec());
    }
    if matches!(cat, Category::Kisi | Category::Sirket) && keys.len() > 1 {
        // "ADALET SAVCI": a person whose given name is a court word keeps every word (as the
        // name propagation does).
        let person_like = cat == Category::Kisi && given_names::is_given(&keys[0]);
        for k in keys {
            let one = std::slice::from_ref(k);
            let distinct = cat == Category::Kisi || !vocab::is_company_generic(k);
            let wordy = person_like && k.chars().count() >= 3 && !crate::names::is_title(k);
            if distinct && !k.bytes().all(|b| b.is_ascii_digit()) && (wordy || eligible(cat, one)) && !out.iter().any(|s| s == one) {
                out.push(one.to_vec());
            }
        }
    }
    out
}

/// The longest value looked for again, in tokens. Every recognizer finds a longer one where it
/// stands anyway; without a bound, one long masked run ("1 1 1 …" over a whole page) is compared
/// against itself at every token, which is quadratic in the record.
pub const MAX_SEQ_TOKENS: usize = 32;

/// Every occurrence of a sequence: (first token, last token, sequence index). A sequence given
/// more than once is reported under its first index only — a record full of one repeated value
/// must not cost a comparison per copy at every token.
pub fn find_all(doc: &Doc, seqs: &[Vec<String>]) -> Vec<(usize, usize, usize)> {
    let mut seen: HashSet<&[String]> = HashSet::new();
    let mut firsts: HashSet<&str> = HashSet::new();
    let mut single: HashMap<&str, usize> = HashMap::new();
    let mut by_two: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (n, s) in seqs.iter().enumerate() {
        if s.is_empty() || s.len() > MAX_SEQ_TOKENS || !seen.insert(s.as_slice()) {
            continue;
        }
        firsts.insert(s[0].as_str());
        match s.as_slice() {
            [one] => {
                single.entry(one.as_str()).or_insert(n);
            }
            [a, b, ..] => by_two.entry((a.as_str(), b.as_str())).or_default().push(n),
            [] => {}
        }
    }
    let toks = &doc.toks;
    let mut out = Vec::new();
    for i in 0..toks.len() {
        if toks[i].suffix && toks[i].kind == Kind::Word {
            continue;
        }
        let key = toks[i].key.as_str();
        if !firsts.contains(key) {
            // A one-word value with a case ending and no apostrophe ("yılmazın") is that value too
            // — but a court word is never a name plus an ending ("ASLİYE" is not "Aslı"+"ye").
            if toks[i].kind == Kind::Word && !vocab::is_vocab(key) {
                if let Some(n) = stems(key).find_map(|stem| single.get(stem).copied()) {
                    out.push((i, i, n));
                }
            }
            continue;
        }
        if let Some(&n) = single.get(key) {
            out.push((i, i, n));
        }
        let Some(next) = toks.get(i + 1).filter(|_| near(doc.gap(i))) else { continue };
        for &n in by_two.get(&(key, next.key.as_str())).into_iter().flatten() {
            let seq = &seqs[n];
            let fits = seq.iter().enumerate().skip(2).all(|(m, key)| {
                let j = i + m;
                j < toks.len() && toks[j].key == *key && near(doc.gap(j - 1))
            });
            if fits {
                out.push((i, i + seq.len() - 1, n));
            }
        }
    }
    out
}

/// Every way to read `key` as a stem of 4+ letters plus a case ending, longest stem first.
fn stems(key: &str) -> impl Iterator<Item = &str> {
    let idx: Vec<usize> = key.char_indices().map(|(b, _)| b).collect();
    let cuts: Vec<usize> = idx.into_iter().skip(4).rev().filter(|&b| vocab::is_name_suffix(&key[b..])).collect();
    cuts.into_iter().map(move |b| &key[..b])
}

fn near(g: &str) -> bool {
    g.chars().count() <= 4 && g.matches('\n').count() <= 1
}

/// Candidates for every further occurrence of an already masked value, same category and ident.
pub fn occurrences(doc: &Doc, clusters: &[Cluster]) -> Vec<Cand> {
    let mut seqs = Vec::new();
    let mut owner = Vec::new();
    for (n, c) in clusters.iter().enumerate() {
        for seq in seqs_for(c.cat, &keys_of(doc, c.s, c.e)) {
            seqs.push(seq);
            owner.push(n);
        }
    }
    let inside = |s: usize, e: usize| {
        let k = clusters.partition_point(|c| c.e <= s);
        clusters.get(k).is_some_and(|c| c.s <= s && e <= c.e)
    };
    let mut out = Vec::new();
    for (a, b, n) in find_all(doc, &seqs) {
        let (s, e) = (doc.toks[a].s, doc.toks[b].e);
        if !inside(s, e) {
            let c = &clusters[owner[n]];
            out.push(Cand::new(s, e, c.cat, c.ident.clone()));
        }
    }
    out
}
