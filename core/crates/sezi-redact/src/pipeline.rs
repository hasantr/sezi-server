//! The order of the work (§4.2), and how clusters become placeholders.

use std::collections::HashMap;

use crate::category::{placeholders_in, Category, Placeholder, MAX_PLACEHOLDER_N};
use crate::names::{self, propagate::Names};
use crate::span::{resolve, Cand, Cluster, Intervals};
use crate::token::Doc;
use crate::vault::Vault;
use crate::{address, court, digits, leak, nets, patterns, spread};
use crate::{Counts, Kept, MaskedSpan, Policy, RedactError, Redacted};

/// How many times a leak finding is masked and the text checked again before refusing.
const LEAK_ROUNDS: usize = 4;

pub fn run(orig: &str, policy: &Policy) -> Result<Redacted, RedactError> {
    let doc = Doc::new(orig);
    let mut forced: Vec<Cand> = Vec::new();
    for round in 0..LEAK_ROUNDS {
        let (out, names) = pass(&doc, orig, policy, &forced)?;
        let found = leak::findings(&out.masked, &out.vault, &names.single_keys());
        let Some(&(_, _, first)) = found.first() else { return Ok(out) };
        if round + 1 == LEAK_ROUNDS {
            return Err(RedactError::Leak(first));
        }
        // Mask what the check found, in the original's coordinates, and run again.
        for (ms, me, cat) in found {
            let (os, oe) = (to_original(&out.spans, ms, false), to_original(&out.spans, me, true));
            let (s, e) = (doc.view.norm_of(os), doc.view.norm_of(oe));
            forced.push(Cand::new(s, e, cat, format!("f:{}", crate::fold::key(&orig[os..oe]))));
        }
    }
    unreachable!("the last round returns")
}

/// A byte offset of the masked text → the original's. Inside a placeholder it is the masked
/// span's start (or, for an `end`, its end).
fn to_original(spans: &[MaskedSpan], m: usize, end: bool) -> usize {
    let k = spans.partition_point(|s| s.masked.start <= m);
    match k.checked_sub(1).map(|i| &spans[i]) {
        None => m,
        Some(s) if m < s.masked.end => {
            if end {
                s.original.end
            } else {
                s.original.start
            }
        }
        Some(s) => s.original.end + (m - s.masked.end),
    }
}

fn pass(doc: &Doc, orig: &str, policy: &Policy, forced: &[Cand]) -> Result<(Redacted, Names), RedactError> {
    let mut cands = forced.to_vec();
    literal_placeholders(doc, &mut cands);

    // Tiers 1–2.
    digits::scan(doc, &mut cands);
    let found_court = court::find(doc);
    let hint_court = policy.court.as_deref().and_then(court::from_hint);
    let mut kept = Kept::default();
    for c in found_court.iter().chain(hint_court.iter()) {
        court::mark(doc, c, &mut cands);
    }
    if let Some(c) = found_court.as_ref().or(hint_court.as_ref()) {
        kept = Kept { court_type: Some(c.type_title.clone()), criminal: c.criminal };
    }
    let esas = policy.esas_no.as_deref().and_then(court::esas_from_hint).or_else(|| court::find_esas(doc));
    patterns::scan(doc, esas.as_deref(), &mut cands);
    address::scan(doc, &mut cands);

    // Tier 3: harvest, then propagate. A name stops at a tier-1/2 hit, but not at an address —
    // an address' left edge may have taken the name with it, and the name must still be known.
    let blocked = Intervals::of(cands.iter().filter(|c| c.cat != Category::Adres));
    let mut harvest = Vec::new();
    names::header::scan(doc, &blocked, &mut harvest, &mut cands);
    names::anchors::scan(doc, &blocked, &mut harvest);
    let names = names::propagate::build(doc, orig, &harvest, &policy.known_names);
    names::propagate::apply(doc, &names, &mut cands);

    // Tier 4 over what is left.
    let covered = Intervals::of(cands.iter());
    nets::scan(doc, &covered, &mut cands);

    // Whatever was masked once is masked everywhere it recurs.
    let first = resolve(cands.clone(), doc.text());
    cands.extend(spread::occurrences(doc, &first));
    // A value restores to what was found first, even where a later occurrence of it stands
    // first in the text.
    let mut found: HashMap<(Category, String), String> = HashMap::new();
    for c in &first {
        let text = &orig[doc.view.orig(c.s)..doc.view.orig(c.e)];
        found.entry((c.cat, c.ident.clone())).or_insert_with(|| text.to_string());
    }
    let clusters = resolve(cands, doc.text());

    let out = assign(doc, orig, &clusters, &names, &found)?;
    Ok((Redacted { kept, ..out }, names))
}

/// A placeholder already in the input ("[KISI_1]" typed into the minutes) is masked like a value,
/// so a restore gives back that literal text and never someone's name.
fn literal_placeholders(doc: &Doc, out: &mut Vec<Cand>) {
    for (r, p) in placeholders_in(doc.text()) {
        out.push(Cand::new(r.start, r.end, p.category, format!("lit:{p}")));
    }
}

fn assign(
    doc: &Doc,
    orig: &str,
    clusters: &[Cluster],
    names: &Names,
    found: &HashMap<(Category, String), String>,
) -> Result<Redacted, RedactError> {
    let mut ids: HashMap<(Category, &str), Placeholder> = HashMap::new();
    let mut next = [0u16; 18];
    let mut vault = Vault::default();
    let mut counts = Counts::default();
    let mut masked = String::with_capacity(orig.len());
    let mut spans = Vec::with_capacity(clusters.len());
    let mut prev = 0;
    for c in clusters {
        let (os, oe) = (doc.view.orig(c.s), doc.view.orig(c.e));
        if os < prev || oe <= os {
            continue;
        }
        masked.push_str(&orig[prev..os]);
        let p = match ids.get(&(c.cat, c.ident.as_str())) {
            Some(p) => *p,
            None => {
                let p = if c.cat.is_numbered() {
                    let n = &mut next[c.cat.index()];
                    if *n >= MAX_PLACEHOLDER_N {
                        return Err(RedactError::TooManyValues(c.cat));
                    }
                    *n += 1;
                    Placeholder::new(c.cat, *n)
                } else {
                    Placeholder::new(c.cat, 0)
                };
                ids.insert((c.cat, c.ident.as_str()), p);
                if !vault.contains(&p) {
                    counts.add_distinct(c.cat);
                    let value = display(c, names)
                        .or_else(|| found.get(&(c.cat, c.ident.clone())).cloned())
                        .unwrap_or_else(|| orig[os..oe].to_string());
                    vault.insert(p, value);
                }
                p
            }
        };
        counts.add_occurrence(c.cat);
        let ms = masked.len();
        masked.push_str(&p.to_string());
        spans.push(MaskedSpan { original: os..oe, masked: ms..masked.len(), placeholder: p });
        prev = oe;
    }
    masked.push_str(&orig[prev..]);
    Ok(Redacted { masked, vault, kept: Kept::default(), counts, spans })
}

/// A propagated name restores to the harvested original even where only its surname stood.
fn display(c: &Cluster, names: &Names) -> Option<String> {
    let id: usize = c.ident.strip_prefix("n#")?.parse().ok()?;
    names.recs.get(id).map(|r| r.display.clone())
}

impl Counts {
    fn add_distinct(&mut self, c: Category) {
        self.distinct[c.index()] += 1;
    }

    fn add_occurrence(&mut self, c: Category) {
        self.occurrences[c.index()] += 1;
    }
}
