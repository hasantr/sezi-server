//! Masking personal data in Turkish court hearing minutes before any text goes to an AI model
//! (docs/HEARINGS_BOT_PLAN.md §4, phase H1).
//!
//! Pure and synchronous: no I/O, no clock, no async, no dependencies. The relay's bot inbox runs it
//! (wasm32) and a device may later. It returns typed data and composes no sentence.
//!
//! ```text
//! normalize → recognize (tiers 1–4) → harvest + propagate names → resolve overlaps
//! → assign placeholders → residual nets → leak check → Redacted | RedactError
//! ```
//!
//! [`redact`] masks; [`restore`] puts the originals back for the 1:1 answer; [`restore_only`] for
//! a room or the sheet; [`leak_check`] lets the H4 validator run the same tier-1/2 net over a
//! model's answer; [`placeholders_in`] lists the placeholders an answer uses.
//!
//! | file | does |
//! |---|---|
//! | `norm.rs` · `token.rs` · `fold.rs` | the normalized view (offsets kept), words, Turkish case |
//! | `checksum.rs` · `digits.rs` | TCKN, VKN, IBAN, card, phone |
//! | `patterns.rs` | e-mail/KEP, plate, birth date, case numbers, UYAP codes, sicil |
//! | `address.rs` · `court.rs` | addresses; the record's esas no and court |
//! | `names/` | header role lines, body anchors, propagation |
//! | `nets.rs` · `given_names.rs` · `vocab.rs` | residual nets and their word lists |
//! | `span.rs` · `pipeline.rs` · `vault.rs` · `leak.rs` | overlaps, numbering, the vault, the leak check |

#![forbid(unsafe_code)]
// The scanners walk tokens by index because every rule looks at the neighbours (`i - 1`,
// `i + 2`, the gap between): an iterator would hide exactly what the rule reads.
#![allow(clippy::needless_range_loop)]

mod address;
mod category;
pub mod checksum;
mod court;
mod digits;
mod fold;
mod given_names;
mod leak;
mod names;
mod nets;
mod norm;
mod patterns;
mod pipeline;
mod span;
mod spread;
mod token;
mod vault;
mod vocab;

use core::fmt;
use core::ops::Range;

pub use category::{placeholders_in, Category, Placeholder, MAX_PLACEHOLDER_N};
pub use leak::{leak_check, leak_check_with};
pub use vault::{restore, restore_only, Vault};

/// What the caller knows beyond the text.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// The record's esas no from the H2 header parser ("2024/123"); found in the text when absent.
    pub esas_no: Option<String>,
    /// The record's court from the H2 parser ("Ankara 3. Asliye Hukuk Mahkemesi"); found in the
    /// text when absent.
    pub court: Option<String>,
    /// Names known to be in the record (a file name's words, the lawyer's own name…): harvested
    /// as if a role label had named them, and masked everywhere.
    pub known_names: Vec<String>,
}

/// What stays for the task, as typed data (§4.6). The rest of what is kept — dates, times,
/// deadlines, amounts, statutes, roles — stays in the masked text itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    /// The court's type, title-cased: "Asliye Hukuk", "Ağır Ceza". The model gets this, never
    /// the city or number.
    pub court_type: Option<String>,
    /// The court is a criminal one ("… Ceza …"): decision 3 sends such records rule-only.
    pub criminal: bool,
}

/// Per-category counts for the audit row (§8.2): numbers only, no content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    distinct: [u32; 18],
    occurrences: [u32; 18],
}

impl Counts {
    /// How many different values of this category were masked.
    pub fn distinct(&self, c: Category) -> u32 {
        self.distinct[c.index()]
    }

    /// How many places this category was masked at.
    pub fn occurrences(&self, c: Category) -> u32 {
        self.occurrences[c.index()]
    }

    /// (category, distinct, occurrences) for every category with at least one occurrence.
    pub fn iter(&self) -> impl Iterator<Item = (Category, u32, u32)> + '_ {
        Category::ALL.into_iter().filter(|c| self.occurrences(*c) > 0).map(|c| (c, self.distinct(c), self.occurrences(c)))
    }

    pub fn total(&self) -> u32 {
        self.occurrences.iter().sum()
    }
}

/// One masked span: where it was in the original, where its placeholder is in the masked text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskedSpan {
    pub original: Range<usize>,
    pub masked: Range<usize>,
    pub placeholder: Placeholder,
}

/// The result of [`redact`].
#[derive(Clone, Debug)]
pub struct Redacted {
    /// The text with every masked value replaced by its placeholder; everything else is the
    /// original, byte for byte.
    pub masked: String,
    /// Placeholder → original. Lives in memory for one request; never write it anywhere.
    pub vault: Vault,
    pub kept: Kept,
    pub counts: Counts,
    /// Offsets only, in order.
    pub spans: Vec<MaskedSpan>,
}

/// Why nothing may be sent. Carries a category, never a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedactError {
    /// The leak check found something it should have masked still in the masked text.
    Leak(Category),
    /// More than [`MAX_PLACEHOLDER_N`] different values of one category.
    TooManyValues(Category),
}

impl RedactError {
    /// The refusal code the bot answers with (§4.5); the category goes to the log, nothing else.
    pub fn code(&self) -> &'static str {
        match self {
            RedactError::Leak(_) => "hearings/mask-leak",
            RedactError::TooManyValues(_) => "hearings/mask-too-many",
        }
    }

    pub fn category(&self) -> Category {
        match self {
            RedactError::Leak(c) | RedactError::TooManyValues(c) => *c,
        }
    }
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code(), self.category().tag())
    }
}

impl std::error::Error for RedactError {}

/// Masks `text`. Fails closed: `Err` means the text must not be sent, and the caller falls back
/// to its rule-only answer (§4.2) — never to the unmasked text.
pub fn redact(text: &str, policy: &Policy) -> Result<Redacted, RedactError> {
    pipeline::run(text, policy)
}
