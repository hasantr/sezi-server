//! The vault (§4.6): placeholder → original, in memory for one request. The crate never writes it
//! anywhere; its `Debug` shows only how many entries it holds, so a stray `{:?}` in a log line
//! cannot leak what it maps.

use std::collections::BTreeMap;
use std::fmt;

use crate::category::{placeholders_in, Category, Placeholder};

#[derive(Default, Clone, PartialEq, Eq)]
pub struct Vault {
    entries: BTreeMap<Placeholder, String>,
}

impl Vault {
    pub(crate) fn insert(&mut self, p: Placeholder, original: String) {
        self.entries.entry(p).or_insert(original);
    }

    /// The original a placeholder stands for.
    pub fn get(&self, p: &Placeholder) -> Option<&str> {
        self.entries.get(p).map(String::as_str)
    }

    pub fn contains(&self, p: &Placeholder) -> bool {
        self.entries.contains_key(p)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in placeholder order.
    pub fn iter(&self) -> impl Iterator<Item = (&Placeholder, &str)> {
        self.entries.iter().map(|(p, s)| (p, s.as_str()))
    }

    /// The record's own esas no, as written ([`Category::Esas`]).
    pub fn esas(&self) -> Option<&str> {
        self.get(&Placeholder::new(Category::Esas, 0))
    }

    /// The record's court city and number, as written ([`Category::Mahkeme`]).
    pub fn court_place(&self) -> Option<&str> {
        self.get(&Placeholder::new(Category::Mahkeme, 0))
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Vault({} entries)", self.entries.len())
    }
}

/// Puts every placeholder the vault knows back to its original (the 1:1 answer). A placeholder
/// the vault does not know — one a model invented — is left as it is; the H4 validator rejects
/// such an answer before it gets here.
pub fn restore(text: &str, vault: &Vault) -> String {
    restore_where(text, vault, |_| true)
}

/// Restores only the given categories: a room answer and the sheet get `[ESAS]` and `[MAHKEME]`
/// back while persons stay as their roles (§4.6, decision 6).
pub fn restore_only(text: &str, vault: &Vault, categories: &[Category]) -> String {
    restore_where(text, vault, |c| categories.contains(&c))
}

fn restore_where(text: &str, vault: &Vault, keep: impl Fn(Category) -> bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev = 0;
    for (r, p) in placeholders_in(text) {
        if let Some(orig) = vault.get(&p).filter(|_| keep(p.category)) {
            out.push_str(&text[prev..r.start]);
            out.push_str(orig);
            prev = r.end;
        }
    }
    out.push_str(&text[prev..]);
    out
}
