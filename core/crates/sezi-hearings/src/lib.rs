//! Reading a Turkish hearing record (duruşma zaptı / tutanağı) by rules, without a model
//! (docs/HEARINGS_BOT_PLAN.md §1.1 step 3, §3; phase H2).
//!
//! Pure and synchronous: bytes or text in, typed data out. The relay's bot inbox runs it inside
//! a Durable Object, so nothing here may grow an `async fn`, a clock or a file — the probe
//! (`examples/probe.rs`) is the only place that reads a file or times anything.
//!
//! ```text
//! read_file(bytes) ── PDF? ── pdf::extract (lopdf, capped) ─┐
//!                  └─ text? ─ usable::decode_text ──────────┤
//! read_text(str) ───────────────────────────────────────────┤
//!                                     usable::normalize ────┤
//!                                     usable::assess ───────┤ (refuse: no text layer / not a record)
//!                                     parse ────────────────┴→ Hearing { text, record, … }
//! ```
//!
//! **Typed, never sentences.** Fields, roles and court kinds are codes; refusals are
//! `hearings/…` codes ([`Refusal::code`]). The only strings that come out are the record's own
//! words: the court's name (the sheet's key), each decision's text, each deadline's phrase.
//!
//! **Names stay in.** This crate does not mask. Party names are [`Span`]s into
//! [`Hearing::text`] for the redactor (`sezi-redact`, H1); the runner (H4) joins the two.
//!
//! **The parser wins** (§5.4): the esas no and the court come only from here; the next hearing
//! from here when it was found.
//!
//! **What it costs** (native, release, 2026-10-27, LibreOffice PDFs of the fixtures): 0.46 ms for
//! one page, 2.3 ms for 5, 10.3 ms for 20; pasted text of one page 0.08 ms. The wasm build is
//! 2.09 MB raw / 0.83 MB gzipped (opt-z, LTO, no wasm-opt). The figure that decides the Workers
//! plan — CPU per invocation on workerd, 10 ms on Free — is H0's and needs the lab: run this
//! crate inside a worker on the lab's workerd (or a deployed test worker) over
//! `fixtures/civil_asliye_hukuk.pdf`, `long_5p.pdf` and `long_20p.pdf`, and read the CPU time
//! from the invocation's trace (`wrangler tail` / Workers Logs), not from `Date.now()`, which
//! does not advance while a Worker computes.
//!
//! Where things are: `refusal.rs` (codes, [`Limits`]), `pdf.rs` (lopdf under caps), `usable.rs`
//! (decoding, normalising, the usability check), `fold.rs` (Turkish case folding with a byte map
//! back), `date.rs`, `header.rs` (esas/karar/celse no, the hearing's date), `court.rs`,
//! `parties.rs` (roles, attendance), `decisions.rs` (numbered decisions, deadlines, the next
//! hearing), `summary.rs` (the rule-only summary), `probe.rs` (the structure-only report).

mod court;
mod date;
mod decisions;
mod fold;
mod header;
mod parties;
mod pdf;
pub mod probe;
mod refusal;
mod summary;
mod usable;

use serde::Serialize;

pub use court::{Court, CourtKind};
pub use date::{Date, DateStyle, Time};
pub use decisions::{Deadline, DeadlineUnit, Decision, MAX_DECISIONS, MAX_DECISION_CHARS};
pub use header::{CaseNo, CaseNoForm, Numbered, When};
pub use parties::{Attendance, Party, Role};
pub use pdf::{is_pdf, PdfFacts};
pub use refusal::{Limits, Refusal};
pub use summary::{AttendanceLine, DecisionLine, Field, NextHearing, RoleCount, RuleSummary};
pub use usable::{Anchors, Usability, Verdict};

/// A byte range into [`Hearing::text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Where the text came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Source {
    Pdf(PdfFacts),
    Text,
}

/// What the rules read from a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    pub case_no: Option<Numbered>,
    pub decision_no: Option<Numbered>,
    pub session_no: Option<u32>,
    pub court: Option<Court>,
    pub hearing: Option<When>,
    pub next_hearing: Option<When>,
    pub decisions: Vec<Decision>,
    pub parties: Vec<Party>,
    pub attendance: Vec<Attendance>,
}

/// A record read: the text every span points into, how usable it was, and what was parsed.
///
/// It holds the unmasked minutes (the text, decision texts, names by span). Nothing of it may be
/// logged or stored (docs/HEARINGS_BOT_PLAN.md §8): log [`Refusal::code`]s and counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hearing {
    /// The normalised text (line endings, composed letters, a Latin-1 misreading repaired). This
    /// is the text to hand the redactor: every [`Span`] indexes it.
    pub text: String,
    pub source: Source,
    pub usability: Usability,
    /// The Latin-1 reading of Turkish (`ÞÝÐ`) was found and repaired.
    pub repaired_latin1: bool,
    pub record: Record,
}

impl Hearing {
    /// The rule-only summary (§1.1 step 3): what the bot can answer with no model at all.
    pub fn summary(&self) -> RuleSummary {
        RuleSummary::of(&self.record)
    }

    /// The original words of a span.
    pub fn at(&self, span: Span) -> &str {
        &self.text[span.start..span.end]
    }
}

/// Read a file the member sent: a PDF by its magic bytes (whatever its declared type), else
/// text (UTF-8, UTF-16 with a BOM, or Windows-1254).
pub fn read_file(bytes: &[u8], limits: &Limits) -> Result<Hearing, Refusal> {
    if bytes.len() > limits.max_input_bytes {
        return Err(Refusal::TooLarge);
    }
    if is_pdf(bytes) {
        return read_pdf(bytes, limits);
    }
    let text = usable::decode_text(bytes).ok_or(Refusal::UnsupportedType)?;
    read_text(&text, limits)
}

/// Read a PDF's text layer (v1 has no OCR: a scan is [`Refusal::NoTextLayer`]).
pub fn read_pdf(bytes: &[u8], limits: &Limits) -> Result<Hearing, Refusal> {
    let (raw, facts) = pdf::extract(bytes, limits)?;
    finish(&raw, Source::Pdf(facts))
}

/// Read pasted text.
pub fn read_text(text: &str, limits: &Limits) -> Result<Hearing, Refusal> {
    if text.len() > limits.max_input_bytes {
        return Err(Refusal::TooLarge);
    }
    if text.chars().count() > limits.max_chars {
        return Err(Refusal::TooMuchText);
    }
    finish(text, Source::Text)
}

fn finish(raw: &str, source: Source) -> Result<Hearing, Refusal> {
    let (text, repaired_latin1) = usable::normalize(raw);
    let unmappable = matches!(&source, Source::Pdf(f) if f.fonts_unmappable > 0);
    let usability = usable::assess(&text, unmappable);
    if let Some(r) = refusal_of(usability.verdict, matches!(source, Source::Pdf(_))) {
        return Err(r);
    }
    let record = parse(&text);
    Ok(Hearing { text, source, usability, repaired_latin1, record })
}

/// The refusal a verdict means, if any. "Send the UYAP PDF" (no text layer) is only an answer to
/// a PDF; pasted text that is empty or garbled is simply not a record.
pub(crate) fn refusal_of(v: Verdict, pdf: bool) -> Option<Refusal> {
    match v {
        Verdict::Usable => None,
        Verdict::NoTextLayer | Verdict::Garbled if pdf => Some(Refusal::NoTextLayer),
        Verdict::NoTextLayer | Verdict::Garbled | Verdict::NotARecord => Some(Refusal::NotARecord),
    }
}

/// Parse normalised text (no usability check). Spans index `text`.
pub fn parse(text: &str) -> Record {
    let f = fold::Folded::new(text);
    let header_end = header::header_end(&f);
    let decisions_from = header::decisions_start(&f);
    // A label-less header can run into the body; the court and the case number are looked for
    // in the header first and, failing that, before the decisions.
    let search_end = decisions_from.unwrap_or(header_end).max(header_end);
    let decisions = decisions::decisions(text, &f, decisions_from.unwrap_or(header_end));
    // Attendance is read in the body, up to the decisions' heading (a record without one: to the
    // end — a decision's `yüzüne karşı` carries no attendance verb).
    let body_end = decisions_from.unwrap_or(f.s.len());
    Record {
        case_no: header::case_no(&f, header_end).or_else(|| header::case_no(&f, search_end)),
        decision_no: header::decision_no(&f, header_end),
        session_no: header::session_no(&f, header_end),
        court: court::find(text, &f, header_end).or_else(|| court::find(text, &f, search_end)),
        hearing: header::hearing(&f, header_end),
        next_hearing: decisions::next_hearing(&f, &decisions, decisions_from.unwrap_or(header_end)),
        attendance: parties::attendance(&f, header_end, body_end.max(header_end)),
        parties: parties::parties(&f, header_end),
        decisions,
    }
}
