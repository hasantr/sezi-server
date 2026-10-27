//! The court: place (the courthouse's name, usually a city: `ANKARA`, `İSTANBUL ANADOLU`),
//! number (`3.`, absent for a single court) and type (`ASLİYE HUKUK`), found as
//! `<place> <n>. <type> MAHKEMESİ` on one line or with the place on the line above (UYAP prints
//! `T.C.` / `ANKARA` / `3. ASLİYE HUKUK MAHKEMESİ` on three lines).

use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::fold::{label, title_case, Folded};
use crate::Span;

/// The court's type. A code, never shown as is: the UI or the runner names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CourtKind {
    /// Asliye Hukuk
    CivilGeneral,
    /// Sulh Hukuk
    CivilPeace,
    /// İş
    Labour,
    /// Aile
    Family,
    /// Tüketici
    Consumer,
    /// Asliye Ticaret
    Commercial,
    /// Kadastro
    Cadastre,
    /// Fikri ve Sınai Haklar Hukuk
    IpCivil,
    /// İcra Hukuk
    EnforcementCivil,
    /// İcra Ceza
    EnforcementCriminal,
    /// Asliye Ceza
    CriminalGeneral,
    /// Ağır Ceza
    CriminalHeavy,
    /// Sulh Ceza (Hâkimliği)
    CriminalPeace,
    /// Çocuk
    Juvenile,
    /// Çocuk Ağır Ceza
    JuvenileHeavy,
    /// Fikri ve Sınai Haklar Ceza
    IpCriminal,
    /// İdare
    Administrative,
    /// Vergi
    Tax,
}

impl CourtKind {
    /// A criminal court: the plan's decision 3 sends these down the rule-only path.
    pub fn is_criminal(self) -> bool {
        matches!(
            self,
            Self::EnforcementCriminal
                | Self::CriminalGeneral
                | Self::CriminalHeavy
                | Self::CriminalPeace
                | Self::Juvenile
                | Self::JuvenileHeavy
                | Self::IpCriminal
        )
    }
}

/// Longest phrases first, so `çocuk ağır ceza` wins over `ağır ceza`.
const KINDS: [(&str, CourtKind); 18] = [
    ("fikri ve sınai haklar hukuk", CourtKind::IpCivil),
    ("fikri ve sınai haklar ceza", CourtKind::IpCriminal),
    ("çocuk ağır ceza", CourtKind::JuvenileHeavy),
    ("asliye ticaret", CourtKind::Commercial),
    ("asliye hukuk", CourtKind::CivilGeneral),
    ("asliye ceza", CourtKind::CriminalGeneral),
    ("sulh hukuk", CourtKind::CivilPeace),
    ("sulh ceza", CourtKind::CriminalPeace),
    ("icra hukuk", CourtKind::EnforcementCivil),
    ("icra ceza", CourtKind::EnforcementCriminal),
    ("ağır ceza", CourtKind::CriminalHeavy),
    ("tüketici", CourtKind::Consumer),
    ("kadastro", CourtKind::Cadastre),
    ("çocuk", CourtKind::Juvenile),
    ("aile", CourtKind::Family),
    ("idare", CourtKind::Administrative),
    ("vergi", CourtKind::Tax),
    ("iş", CourtKind::Labour),
];

/// The court as the record names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Court {
    pub kind: CourtKind,
    /// Title-cased place, `Ankara`, `İstanbul Anadolu`, `Iğdır`. `None` when the record does not
    /// name it next to the court.
    pub place: Option<String>,
    /// `3` for `3. Asliye Hukuk`; `None` for a court that has no number.
    pub number: Option<u16>,
    /// The court's name, title-cased: `Ankara 3. Asliye Hukuk Mahkemesi`. This is the sheet's key
    /// (docs/HEARINGS_BOT_PLAN.md §6.3), a datum taken from the record, not a sentence.
    pub name: String,
    /// Where the place starts and the court phrase ends, in the text (for the redactor, which
    /// masks the place and the number).
    pub span: Span,
}

fn court_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let kinds: Vec<String> = KINDS.iter().map(|(k, _)| label(k)).collect();
        // `mahkemesi` must end the word: `mahkemesine` (a letter rogatory to another court in the
        // body) is not this court. `hakimliği` covers `Sulh Ceza Hâkimliği`.
        let re = format!(
            r"(?:(\d{{1,3}})[ \t]*\.[ \t]*)?\b({})[ \t]+(?:{}|{})(?:[^\p{{L}}]|$)",
            kinds.join("|"),
            label("mahkemesi"),
            label("hakimliği"),
        );
        Regex::new(&re).expect("court regex")
    })
}

/// Words that sit on the lines around the court but are never its place.
const NOT_PLACE: [&str; 6] = ["t.c.", "t.c", "tc", "duruşma tutanağı", "duruşma", "tutanağı"];

/// The first court named before `until` (a FOLDED offset: the header's end).
pub(crate) fn find(text: &str, f: &Folded, until: usize) -> Option<Court> {
    let hay = &f.s[..until.min(f.s.len())];
    let c = court_re().captures(hay)?;
    let phrase = c.get(2).expect("kind");
    let kind_folded = normalize_kind(phrase.as_str());
    let kind = KINDS
        .iter()
        .find(|(k, _)| *k == kind_folded)
        .map(|(_, k)| *k)?;
    let number = c.get(1).and_then(|n| n.as_str().parse().ok());
    let whole = c.get(0).expect("match");
    let phrase_end = whole.as_str().trim_end_matches(|ch: char| !ch.is_alphabetic()).len() + whole.start();
    let head = c.get(1).map_or(phrase.start(), |n| n.start());

    // The place: the words before the number on the same line, else the line above.
    let line_start = hay[..head].rfind('\n').map_or(0, |i| i + 1);
    let mut place_range = place_words(hay, line_start, head);
    if place_range.is_none() && line_start > 0 {
        let prev_end = line_start - 1;
        let prev_start = hay[..prev_end].rfind('\n').map_or(0, |i| i + 1);
        place_range = place_words(hay, prev_start, prev_end);
    }

    let place = place_range.map(|(s, e)| title_case(&text[f.orig(s)..f.orig(e)]));
    let kind_text = title_case(&text[f.orig(phrase.start())..f.orig(phrase_end)]);
    let mut name = String::new();
    if let Some(p) = &place {
        name.push_str(p);
        name.push(' ');
    }
    if let Some(n) = number {
        name.push_str(&format!("{n}. "));
    }
    name.push_str(&kind_text);
    let start = place_range.map_or(head, |(s, _)| s);
    Some(Court { kind, place, number, name, span: f.span(start, phrase_end) })
}

/// Collapse the whitespace a label regex allowed, so `asliye\nhukuk` finds its kind.
fn normalize_kind(s: &str) -> String {
    let mut out = String::new();
    for w in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
    }
    // ASCII-fied spellings back to the table's.
    KINDS
        .iter()
        .map(|(k, _)| *k)
        .find(|k| ascii(k) == ascii(&out))
        .map_or(out, str::to_string)
}

fn ascii(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ı' => 'i',
            'ş' => 's',
            'ğ' => 'g',
            'ü' => 'u',
            'ö' => 'o',
            'ç' => 'c',
            c => c,
        })
        .collect()
}

/// `folded[start..end]` as a place: one to four words of letters (an apostrophe allowed), not
/// `T.C.` and not the record's title. Returns the trimmed folded range.
fn place_words(folded: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let seg = &folded[start..end];
    let mut seg_trimmed = seg.trim();
    // `T.C. ANKARA 3. ...` on one line: drop the leading T.C.
    for prefix in ["t.c.", "t.c"] {
        if let Some(rest) = seg_trimmed.strip_prefix(prefix) {
            seg_trimmed = rest.trim_start();
        }
    }
    if seg_trimmed.is_empty() || NOT_PLACE.contains(&seg_trimmed) {
        return None;
    }
    let words: Vec<&str> = seg_trimmed.split_whitespace().collect();
    if words.len() > 4 || !words.iter().all(|w| w.chars().all(|c| c.is_alphabetic() || c == '\'')) {
        return None;
    }
    let s = start + (seg_trimmed.as_ptr() as usize - seg.as_ptr() as usize);
    Some((s, s + seg_trimmed.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn court(text: &str) -> Option<Court> {
        let f = Folded::new(text);
        // `until` is a FOLDED offset: `I` → `ı` grows by a byte.
        find(text, &f, f.s.len())
    }

    #[test]
    fn uyap_three_line_header() {
        let c = court("T.C.\nANKARA\n3. ASLİYE HUKUK MAHKEMESİ\nDURUŞMA TUTANAĞI").unwrap();
        assert_eq!(c.name, "Ankara 3. Asliye Hukuk Mahkemesi");
        assert_eq!(c.kind, CourtKind::CivilGeneral);
        assert_eq!(c.number, Some(3));
    }

    #[test]
    fn one_line_with_a_two_word_place() {
        let c = court("T.C.\nİSTANBUL ANADOLU 12. İŞ MAHKEMESİ\n").unwrap();
        assert_eq!(c.name, "İstanbul Anadolu 12. İş Mahkemesi");
        assert_eq!(c.place.as_deref(), Some("İstanbul Anadolu"));
        assert_eq!(c.kind, CourtKind::Labour);
    }

    #[test]
    fn dotless_capital_i_in_the_place() {
        let text = "T.C.\nIĞDIR\n1. AİLE MAHKEMESİ";
        let c = court(text).unwrap();
        assert_eq!(c.name, "Iğdır 1. Aile Mahkemesi");
        assert_eq!(&text[c.span.start..c.span.end], "IĞDIR\n1. AİLE MAHKEMESİ");
    }

    #[test]
    fn no_number_and_criminal() {
        let c = court("KAĞITHANE ASLİYE CEZA MAHKEMESİ").unwrap();
        assert_eq!(c.name, "Kağıthane Asliye Ceza Mahkemesi");
        assert_eq!(c.number, None);
        assert!(c.kind.is_criminal());
        assert!(court("İZMİR\n7. AĞIR CEZA MAHKEMESİ").unwrap().kind.is_criminal());
        assert_eq!(court("ANKARA 2. ÇOCUK AĞIR CEZA MAHKEMESİ").unwrap().kind, CourtKind::JuvenileHeavy);
    }

    #[test]
    fn a_court_written_to_is_not_this_court() {
        assert!(court("İstanbul 2. Asliye Ticaret Mahkemesine talimat yazılmasına").is_none());
    }

    #[test]
    fn mixed_case_and_ascii() {
        let c = court("Antalya 4. Tüketici Mahkemesi").unwrap();
        assert_eq!(c.name, "Antalya 4. Tüketici Mahkemesi");
        let c = court("ANKARA 5. ASLIYE HUKUK MAHKEMESI").unwrap();
        assert_eq!(c.kind, CourtKind::CivilGeneral);
    }
}
