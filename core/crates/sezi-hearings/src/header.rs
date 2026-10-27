//! The header fields: esas no, karar no, celse no, the hearing's date and time, and where the
//! header ends and the decisions begin.
//!
//! A label and its value may sit on the same line (`ESAS NO : 2024/123 Esas`) or on adjacent ones
//! (`ESAS NO` / `: 2024/123 Esas`, which is what `pdftotext` without `-layout` gives), and a
//! two-word label may itself be broken (`DURUŞMA` / `TARİHİ`). Every label pattern therefore
//! allows any whitespace between its words and before its colon.

use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::date::{self, Date, DateStyle, Time};
use crate::fold::{label, Folded};
use crate::Span;

/// A file number, `2024/123`. Serialises as that string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaseNo {
    pub year: u16,
    pub seq: u32,
}

impl std::fmt::Display for CaseNo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.year, self.seq)
    }
}

impl Serialize for CaseNo {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// How the esas no was labelled, for the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseNoForm {
    /// `ESAS NO : 2024/123`, `DOSYA NO : …`, `Esas: …`
    Label,
    /// `2024/123 Esas`, `2024/123 E.` in the header with no label before it
    Suffix,
    /// `E. 2024/123`
    Prefix,
}

/// A file number and where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Numbered {
    pub value: CaseNo,
    pub form: CaseNoForm,
    pub span: Span,
}

/// A date with an optional time, and where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct When {
    pub date: Date,
    pub time: Option<Time>,
    pub style: DateStyle,
    pub span: Span,
}

fn re(cell: &'static OnceLock<Regex>, build: impl FnOnce() -> String) -> &'static Regex {
    cell.get_or_init(|| Regex::new(&build()).expect("header regex"))
}

fn case_label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, || {
        format!(
            r"(?m)^[ \t]*(?:{}|{}|{}|{}|{})[ \t]*(?:\([^)\n]*\))?\s*:?\s*(\d{{4}})\s*/\s*(\d{{1,7}})",
            label("esas no"),
            label("esas numarası"),
            label("dosya no"),
            label("dosya numarası"),
            label("esas"),
        )
    })
}

fn case_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, || r"(?:^|[^\d/])(\d{4})\s*/\s*(\d{1,7})\s*(?:esas\b|e\.)".to_string())
}

fn case_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, || r"(?:^|[^\p{L}])e\.\s*(?:no\s*:?\s*)?(\d{4})\s*/\s*(\d{1,7})".to_string())
}

fn decision_no_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, || {
        format!(
            r"(?m)^[ \t]*(?:{}|{})\s*:?\s*(\d{{4}})\s*/\s*(\d{{1,7}})",
            label("karar no"),
            label("karar numarası"),
        )
    })
}

fn session_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // The colon is required: `celse arası` in the body is not a label.
    re(&RE, || {
        format!(
            r"(?m)^[ \t]*(?:{}|{}|{}|{})[ \t]*\s*:\s*(\d{{1,3}})(?:[^\d/]|$)",
            label("celse no"),
            label("celse"),
            label("oturum no"),
            label("oturum"),
        )
    })
}

fn hearing_date_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, || {
        format!(
            r"(?m)^[ \t]*(?:{}|{}|{})\s*:?",
            label("duruşma tarihi"),
            label("celse tarihi"),
            label("oturum tarihi"),
        )
    })
}

fn body_start_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // The first sentence of the minutes proper; the header's party lines come before it.
    re(&RE, || {
        [
            "belirli gün ve saatte",
            "açık yargılamaya",
            "açık duruşmaya",
            "celse açıldı",
            "duruşmaya başlandı",
            "celseye başlandı",
            "gereği düşünüldü",
        ]
        .iter()
        .map(|p| label(p))
        .collect::<Vec<_>>()
        .join("|")
    })
}

fn decisions_heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, || {
        // `ara karar` only as a heading: `bir önceki celse ara kararının …` is body text.
        format!(
            r"(?m){}\s*:?|^[ \t]*{}(?:[ıi])?\s*:",
            label("gereği düşünüldü"),
            label("ara karar"),
        )
    })
}

fn caseno(y: &str, s: &str) -> Option<CaseNo> {
    let year: u16 = y.parse().ok()?;
    let seq: u32 = s.parse().ok()?;
    ((1950..=2100).contains(&year) && seq > 0).then_some(CaseNo { year, seq })
}

/// Where the header ends: the first body sentence, or the whole text when there is none.
pub(crate) fn header_end(f: &Folded) -> usize {
    body_start_re().find(&f.s).map_or(f.s.len(), |m| m.start())
}

/// Where the decisions begin: after `GEREĞİ DÜŞÜNÜLDÜ:` (or `ARA KARAR:`), else `None`.
pub(crate) fn decisions_start(f: &Folded) -> Option<usize> {
    decisions_heading_re().find(&f.s).map(|m| m.end())
}

/// The esas no: a labelled one anywhere in the header, else `2024/123 Esas` / `E. 2024/123` in
/// the header. A file number in the body is some other file (a letter rogatory, an icra file).
pub(crate) fn case_no(f: &Folded, header_end: usize) -> Option<Numbered> {
    let hay = &f.s[..header_end];
    let tries: [(&Regex, CaseNoForm); 3] = [
        (case_label_re(), CaseNoForm::Label),
        (case_suffix_re(), CaseNoForm::Suffix),
        (case_prefix_re(), CaseNoForm::Prefix),
    ];
    for (re, form) in tries {
        if let Some(c) = re.captures(hay) {
            let (y, s) = (c.get(1).expect("year"), c.get(2).expect("seq"));
            if let Some(value) = caseno(y.as_str(), s.as_str()) {
                return Some(Numbered { value, form, span: f.span(y.start(), s.end()) });
            }
        }
    }
    None
}

/// The karar no, only when labelled (an interim record usually has none).
pub(crate) fn decision_no(f: &Folded, header_end: usize) -> Option<Numbered> {
    let c = decision_no_re().captures(&f.s[..header_end])?;
    let (y, s) = (c.get(1)?, c.get(2)?);
    let value = caseno(y.as_str(), s.as_str())?;
    Some(Numbered { value, form: CaseNoForm::Label, span: f.span(y.start(), s.end()) })
}

/// The celse (session) number.
pub(crate) fn session_no(f: &Folded, header_end: usize) -> Option<u32> {
    let c = session_re().captures(&f.s[..header_end])?;
    c[1].parse().ok().filter(|n| *n > 0)
}

/// The hearing's date (labelled `DURUŞMA TARİHİ`), and its time: right after the date, or a
/// `SAAT` / `DURUŞMA SAATİ` within the next line.
pub(crate) fn hearing(f: &Folded, header_end: usize) -> Option<When> {
    let m = hearing_date_re().find(&f.s[..header_end])?;
    // The date must follow the label closely: within the label's line or the next.
    let window_end = next_line_end(&f.s, m.end(), 2).min(f.s.len());
    let d = date::find_dates(&f.s[..window_end])
        .into_iter()
        .find(|d| d.start >= m.end())?;
    let after_date = next_line_end(&f.s, d.end, 2);
    // `… 10:30` on the date's line, else `saat 10:30` there or `DURUŞMA SAATİ : 10:30` below.
    let time = date::bare_time_at(&f.s, d.end).or_else(|| date::find_saat(&f.s, d.end, after_date));
    Some(When { date: d.date, time, style: d.style, span: f.span(d.start, d.end) })
}

/// The byte offset at the end of the `n`-th line from `from` (1 = the current line).
pub(crate) fn next_line_end(s: &str, from: usize, n: usize) -> usize {
    let mut at = from;
    for _ in 0..n {
        match s[at..].find('\n') {
            Some(i) => at += i + 1,
            None => return s.len(),
        }
    }
    at.saturating_sub(1).max(from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folded(s: &str) -> Folded {
        Folded::new(s)
    }

    #[test]
    fn case_no_forms() {
        for (text, want, form) in [
            ("ESAS NO : 2024/123 Esas", "2024/123", CaseNoForm::Label),
            ("ESAS NO\n: 2024/123 Esas", "2024/123", CaseNoForm::Label),
            ("Esas No: 2026/77", "2026/77", CaseNoForm::Label),
            ("DOSYA NO : 2025/771 E.", "2025/771", CaseNoForm::Label),
            ("ESAS : 2025/9", "2025/9", CaseNoForm::Label),
            ("T.C.\nANKARA\n2024/123 Esas\n", "2024/123", CaseNoForm::Suffix),
            ("Dosya 2024/55 E. sayılı", "2024/55", CaseNoForm::Suffix),
            ("E. 2023/4", "2023/4", CaseNoForm::Prefix),
            ("ESAS NO (İLK) : 2024/1", "2024/1", CaseNoForm::Label),
        ] {
            let f = folded(text);
            let n = case_no(&f, f.s.len()).unwrap_or_else(|| panic!("{text:?}"));
            assert_eq!(n.value.to_string(), want, "{text:?}");
            assert_eq!(n.form, form, "{text:?}");
            assert_eq!(&text[n.span.start..n.span.end].replace(' ', ""), want);
        }
    }

    #[test]
    fn no_case_no() {
        let f = folded("Toplam 18.500,00 TL ödenecektir. 1999/0 hatalı");
        assert!(case_no(&f, f.s.len()).is_none());
    }

    #[test]
    fn session_and_decision_numbers() {
        let f = folded("ESAS NO : 2026/915\nKARAR NO\n: 2026/1402\nCELSE NO\n: 2\n");
        assert_eq!(decision_no(&f, f.s.len()).unwrap().value.to_string(), "2026/1402");
        assert_eq!(session_no(&f, f.s.len()), Some(2));
        let f = folded("CELSE    : 3\n");
        assert_eq!(session_no(&f, f.s.len()), Some(3));
        let f = folded("celse arası 4 hafta");
        assert_eq!(session_no(&f, f.s.len()), None);
    }

    #[test]
    fn hearing_date_and_time() {
        let cases = [
            ("DURUŞMA TARİHİ : 14/10/2026\nDURUŞMA SAATİ : 10:30\n", "2026-10-14", Some("10:30")),
            ("DURUŞMA TARİHİ : 27.10.2026 saat 09.40\n", "2026-10-27", Some("09:40")),
            ("DURUŞMA TARİHİ: 27 Ekim 2026 Salı, saat 14:00\n", "2026-10-27", Some("14:00")),
            ("DURUŞMA\nTARİHİ\n: 21/10/2026\nHAKİM\n: X\n", "2026-10-21", None),
            ("Duruşma Tarihi: 9.11.2026\n\nHakim: X", "2026-11-09", None),
            ("DURUŞMA TARİHİ : 05-11-2026 10:00\n", "2026-11-05", Some("10:00")),
        ];
        for (text, d, t) in cases {
            let f = folded(text);
            let w = hearing(&f, f.s.len()).unwrap_or_else(|| panic!("{text:?}"));
            assert_eq!(w.date.iso(), d, "{text:?}");
            assert_eq!(w.time.map(|t| t.hhmm()).as_deref(), t, "{text:?}");
        }
    }

    #[test]
    fn the_header_ends_at_the_first_body_sentence() {
        let text = "DAVACI : A\nBelirli gün ve saatte celse açıldı.\nDavacı vekili: x";
        let f = folded(text);
        assert_eq!(&text[f.orig(header_end(&f))..][..7], "Belirli");
    }
}
