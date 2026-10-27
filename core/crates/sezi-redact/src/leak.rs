//! The leak check (§4.5): run last, over the MASKED text, with placeholders made opaque. A tier
//! 1–2 hit, a vault value that still occurs, or a surviving token of a harvested name is a leak.
//!
//! Masking can change a value's context — a placeholder that swallowed a line break puts a
//! clerk's number back on the clerk's line — so inside [`crate::redact`] a finding is first
//! masked too and the text checked again (a few rounds); only what still survives refuses the
//! request. The model call is then not made and nothing leaves.

use std::collections::HashSet;

use crate::address;
use crate::category::{placeholders_in, Category};
use crate::digits;
use crate::patterns;
use crate::span::Cand;
use crate::spread;
use crate::token::{Doc, Kind};
use crate::vault::Vault;
use crate::RedactError;

/// Checks any text for a tier-1/2 hit outside its placeholders. `Err` names the category only,
/// never the value.
pub fn leak_check(text: &str) -> Result<(), RedactError> {
    let doc = opaque(text);
    match tier12(&doc).first() {
        Some(c) => Err(RedactError::Leak(c.cat)),
        None => Ok(()),
    }
}

/// [`leak_check`], and also: no value the vault maps occurs in `text`. This is the check for a
/// model's answer (H4, §5.4): the model saw no names, so a vault value in its output means the
/// masking failed or the model guessed — either way it is not shown.
pub fn leak_check_with(text: &str, vault: &Vault) -> Result<(), RedactError> {
    match findings(text, vault, &HashSet::new()).first() {
        Some(f) => Err(RedactError::Leak(f.2)),
        None => Ok(()),
    }
}

/// Everything the masked record still leaks, as byte ranges of `masked` (never inside a
/// placeholder): tier 1–2 hits, vault values, and keys that name propagation masks alone.
pub(crate) fn findings(masked: &str, vault: &Vault, name_keys: &HashSet<&str>) -> Vec<(usize, usize, Category)> {
    let doc = opaque(masked);
    let mut out: Vec<(usize, usize, Category)> = tier12(&doc).into_iter().map(|c| (c.s, c.e, c.cat)).collect();
    let (seqs, cats) = vault_seqs(vault);
    for (a, b, n) in spread::find_all(&doc, &seqs) {
        out.push((doc.toks[a].s, doc.toks[b].e, cats[n]));
    }
    for t in &doc.toks {
        if t.kind == Kind::Word && !t.suffix && name_keys.contains(t.key.as_str()) {
            out.push((t.s, t.e, Category::Kisi));
        }
    }
    // View offsets → bytes of `masked`.
    out.into_iter().map(|(s, e, c)| (doc.view.orig(s), doc.view.orig(e), c)).filter(|(s, e, _)| e > s).collect()
}

fn vault_seqs(vault: &Vault) -> (Vec<Vec<String>>, Vec<Category>) {
    let mut seqs = Vec::new();
    let mut cats = Vec::new();
    for (p, value) in vault.iter() {
        let d = Doc::new(value);
        let keys: Vec<String> = d.toks.iter().map(|t| t.key.clone()).collect();
        for seq in spread::seqs_for(p.category, &keys) {
            seqs.push(seq);
            cats.push(p.category);
        }
    }
    (seqs, cats)
}

/// The text with every placeholder replaced by as many `#` (no letter, digit or separator a
/// recognizer reads), so "[TCKN_1]" cannot look like the digit 1.
fn opaque(text: &str) -> Doc {
    let mut bytes = text.as_bytes().to_vec();
    for (r, _) in placeholders_in(text) {
        for b in &mut bytes[r] {
            *b = b'#';
        }
    }
    // Placeholders are ASCII, so replacing their bytes keeps the text valid UTF-8.
    let s = String::from_utf8(bytes).unwrap_or_default();
    Doc::new(&s)
}

fn tier12(doc: &Doc) -> Vec<Cand> {
    let mut v = Vec::new();
    digits::scan(doc, &mut v);
    patterns::scan(doc, None, &mut v);
    address::scan(doc, &mut v);
    v
}
