//! The numbered interim decisions (`1- …`, `2) …`, `3. …`), each with the deadlines it words and
//! the first role it names, and the next hearing (`Duruşmanın 09/12/2026 günü saat 10:30'a
//! bırakılmasına`).
//!
//! A deadline is quoted as worded and read as a number and a unit. It is never turned into a
//! date: when it starts running depends on notification (tebliğ), which the minutes do not settle.

use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::date::{self};
use crate::fold::{label, Folded};
use crate::header::{next_line_end, When};
use crate::parties::{mentions, Role};
use crate::Span;

/// The most decisions read from one record, and the most characters kept of each.
pub const MAX_DECISIONS: usize = 60;
pub const MAX_DECISION_CHARS: usize = 4_000;

/// One numbered interim decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub n: u32,
    /// The decision's words with line breaks joined (a hyphenated break re-joined), whitespace
    /// collapsed, the trailing comma dropped. Names are still in it.
    pub text: String,
    /// Where it is in the text (number to last word).
    pub span: Span,
    /// The first role it names (`Davacı vekiline …` → counsel of the plaintiff). Not "whose task
    /// it is" — that judgement is the model's — just the first role word.
    pub first_role: Option<Role>,
    pub first_role_of: Option<Role>,
    pub deadlines: Vec<Deadline>,
    /// This decision sets the next hearing.
    pub sets_next_hearing: bool,
}

/// A deadline as the decision words it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Deadline {
    /// Exactly as written in [`Decision::text`]: `2 hafta kesin süre`, `iki haftalık kesin süre`.
    pub phrase: String,
    pub amount: u32,
    pub unit: DeadlineUnit,
    /// `kesin süre` — a peremptory period.
    pub peremptory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineUnit {
    Day,
    Week,
    Month,
}

const NUMBER_WORDS: [(&str, u32); 17] = [
    ("bir", 1),
    ("iki", 2),
    ("üç", 3),
    ("dört", 4),
    ("beş", 5),
    ("altı", 6),
    ("yedi", 7),
    ("sekiz", 8),
    ("dokuz", 9),
    ("on", 10),
    ("yirmi", 20),
    ("otuz", 30),
    ("kırk", 40),
    ("elli", 50),
    ("altmış", 60),
    ("yetmiş", 70),
    ("doksan", 90),
];

fn item_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // A number at a line's start, a `-`, `)` or `.`, then something that is not a digit
    // (`3.000,00 TL` wrapped to a line's start is an amount, not item 3).
    RE.get_or_init(|| Regex::new(r"(?m)^[ \t]*(\d{1,2})[ \t]*[-.)][ \t]*([^\d\s.])").expect("item regex"))
}

fn end_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // What closes the decisions: the `Dair, …` line, the reading-out formula, a signature line.
    RE.get_or_init(|| {
        let formulas = [
            "okunup anlatıldı",
            "okunup usulen anlatıldı",
            "açıkça okundu",
            "tefhim olundu",
            "okunarak anlatıldı",
        ]
        .map(label)
        .join("|");
        Regex::new(&format!(
            r"(?m)^[ \t]*dair\b|\bdair[ \t,]|{formulas}|^[ \t]*(?:katip|kâtip|hakim|başkan|zabıt katibi)\b[^\n]*\d{{4,}}"
        ))
        .expect("decisions end regex")
    })
}

fn deadline_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let word = NUMBER_WORDS.map(|(w, _)| w).join("|");
        let num = format!(r"(?:\d{{1,3}}|(?:{word})(?:\s+(?:{word}))?)");
        Regex::new(&format!(
            r"(?:^|[^\p{{L}}\d])({num})(?:\s*\(\s*{num}\s*\))?\s*(gün|hafta|ay)(?:lük|lık|luk|lik)?\s+(?:(kesin)\s+)?(?:süre|mehil|içinde|içerisinde|zarfında)\p{{L}}*"
        ))
        .expect("deadline regex")
    })
}

fn next_hearing_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?s){}\p{{L}}*.{{0,160}}?(?:bırakılmas|ertelenmes|talik)",
            label("duruşma")
        ))
        .expect("next hearing regex")
    })
}

/// Decisions read from `text`, starting at `from` (after `GEREĞİ DÜŞÜNÜLDÜ:` when there is one).
pub(crate) fn decisions(text: &str, f: &Folded, from: usize) -> Vec<Decision> {
    let hay = &f.s[from..];
    // Item starts, numbered 1, 2, 3 … in order; a number out of sequence is part of the text.
    let mut starts: Vec<(u32, usize, usize)> = Vec::new(); // (n, line start, text start)
    let mut expect = 1u32;
    for c in item_re().captures_iter(hay) {
        if starts.len() == MAX_DECISIONS {
            break;
        }
        let n: u32 = c[1].parse().unwrap_or(0);
        if n == expect {
            starts.push((n, from + c.get(0).expect("item").start(), from + c.get(2).expect("text").start()));
            expect += 1;
        }
    }
    let Some(&(_, _, last_text)) = starts.last() else { return Vec::new() };
    let end = end_re().find(&f.s[last_text..]).map_or(f.s.len(), |m| last_text + m.start());

    let mut out = Vec::with_capacity(starts.len());
    for (i, &(n, line, at)) in starts.iter().enumerate() {
        let stop = starts.get(i + 1).map_or(end, |next| next.1);
        let raw = &text[f.orig(at)..f.orig(stop)];
        let text_clean = clean(raw);
        let folded = Folded::new(&text_clean);
        let first = mentions(&folded.s).into_iter().next();
        out.push(Decision {
            n,
            span: f.span(line, trim_end(&f.s, line, stop)),
            first_role: first.map(|m| m.2),
            first_role_of: first.and_then(|m| m.3),
            deadlines: deadlines(&text_clean, &folded),
            sets_next_hearing: next_hearing_re().is_match(&folded.s),
            text: text_clean,
        });
    }
    out
}

/// `stop` pulled back over trailing whitespace.
fn trim_end(s: &str, start: usize, stop: usize) -> usize {
    start + s[start..stop].trim_end().len()
}

/// Join a decision's lines: `hafta-\nlık` → `haftalık`, other breaks → a space; whitespace
/// collapsed; a trailing `,` / `;` dropped; capped at [`MAX_DECISION_CHARS`].
fn clean(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut pending_space = false;
    while let Some(c) = chars.next() {
        if c == '-' && out.chars().last().is_some_and(char::is_alphabetic) {
            // A hyphen at a line's end, a lower-case letter on the next line: a broken word.
            let mut look = chars.clone();
            let mut saw_newline = false;
            while let Some(&w) = look.peek() {
                if w == '\n' {
                    saw_newline = true;
                } else if !w.is_whitespace() {
                    break;
                }
                look.next();
            }
            if saw_newline && look.peek().is_some_and(|w| w.is_lowercase()) {
                chars = look;
                continue;
            }
        }
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    let trimmed = out.trim_end_matches([',', ';', ' ']);
    trimmed.chars().take(MAX_DECISION_CHARS).collect()
}

fn deadlines(text: &str, f: &Folded) -> Vec<Deadline> {
    deadline_re()
        .captures_iter(&f.s)
        .filter_map(|c| {
            let num = c.get(1).expect("number");
            let whole_end = c.get(0).expect("deadline").end();
            let amount = number(num.as_str())?;
            let unit = match &c[2] {
                "gün" => DeadlineUnit::Day,
                "hafta" => DeadlineUnit::Week,
                _ => DeadlineUnit::Month,
            };
            let span = f.span(num.start(), whole_end);
            Some(Deadline {
                phrase: text[span.start..span.end].to_string(),
                amount,
                unit,
                peremptory: c.get(3).is_some(),
            })
        })
        .collect()
}

/// `2` → 2, `iki` → 2, `on beş` → 15.
fn number(s: &str) -> Option<u32> {
    if let Ok(n) = s.parse() {
        return Some(n);
    }
    let mut total = 0;
    for w in s.split_whitespace() {
        total += NUMBER_WORDS.iter().find(|(k, _)| *k == w)?.1;
    }
    (total > 0).then_some(total)
}

/// The next hearing: from the decision that sets it, else from a `duruşmanın … bırakılmasına`
/// anywhere after `from`. Its date and time are read from the original text (a date may break
/// across lines there).
pub(crate) fn next_hearing(f: &Folded, decisions: &[Decision], from: usize) -> Option<When> {
    let (start, end) = decisions
        .iter()
        .find(|d| d.sets_next_hearing)
        .and_then(|d| folded_range(f, d.span))
        .or_else(|| next_hearing_re().find(&f.s[from..]).map(|m| (from + m.start(), from + m.end())))?;
    let d = date::find_dates(&f.s[..end]).into_iter().find(|d| d.start >= start)?;
    let time = date::find_saat(&f.s, d.end, next_line_end(&f.s, d.end, 2).min(end.max(d.end)))
        .or_else(|| date::bare_time_at(&f.s, d.end));
    Some(When { date: d.date, time, style: d.style, span: f.span(d.start, d.end) })
}

/// The folded range of an original span (the decision's).
fn folded_range(f: &Folded, span: Span) -> Option<(usize, usize)> {
    let start = (0..=f.s.len()).find(|&b| f.s.is_char_boundary(b) && f.orig(b) >= span.start)?;
    let end = (start..=f.s.len()).find(|&b| f.s.is_char_boundary(b) && f.orig(b) >= span.end)?;
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Vec<Decision> {
        let f = Folded::new(text);
        decisions(text, &f, 0)
    }

    #[test]
    fn numbering_styles() {
        for text in [
            "1-Bir,\n2-İki,\n3-Üç,\nDair, okunup anlatıldı.",
            "1- Bir,\n2- İki,\n3- Üç,\ndair açıkça okundu.",
            "1) Bir,\n2) İki,\n3) Üç,\n",
            "1. Bir,\n2. İki,\n3. Üç,\n",
        ] {
            let d = read(text);
            let got: Vec<_> = d.iter().map(|d| (d.n, d.text.as_str())).collect();
            assert_eq!(got, [(1, "Bir"), (2, "İki"), (3, "Üç")], "{text:?}");
        }
    }

    #[test]
    fn an_amount_wrapped_to_a_line_start_is_not_an_item() {
        let d = read("1-Ücret olan\n3.000,00 TL'nin yatırılmasına,\n2-Duruşmanın ertelenmesine,\n");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].text, "Ücret olan 3.000,00 TL'nin yatırılmasına");
    }

    #[test]
    fn a_hyphenated_line_break_is_rejoined() {
        let d = read("1-Davacı tarafa iki hafta-\nlık kesin süre verilmesine,\n");
        assert_eq!(d[0].text, "Davacı tarafa iki haftalık kesin süre verilmesine");
        assert_eq!(d[0].deadlines[0].phrase, "iki haftalık kesin süre");
        assert_eq!(d[0].deadlines[0].unit, DeadlineUnit::Week);
        assert!(d[0].deadlines[0].peremptory);
    }

    #[test]
    fn deadline_wordings() {
        for (text, phrase, amount, unit, kesin) in [
            ("2 hafta kesin süre verilmesine", "2 hafta kesin süre", 2, DeadlineUnit::Week, true),
            ("1 haftalık süre verilmesine", "1 haftalık süre", 1, DeadlineUnit::Week, false),
            ("7 günlük kesin süre verilmesine", "7 günlük kesin süre", 7, DeadlineUnit::Day, true),
            ("on beş gün içinde bildirmesine", "on beş gün içinde", 15, DeadlineUnit::Day, false),
            ("iki (2) haftalık kesin süre", "iki (2) haftalık kesin süre", 2, DeadlineUnit::Week, true),
            ("raporu için 1 ay süre verilmesine", "1 ay süre", 1, DeadlineUnit::Month, false),
            ("10 GÜN SÜRE VERİLMESİNE", "10 GÜN SÜRE", 10, DeadlineUnit::Day, false),
        ] {
            let f = Folded::new(text);
            let got = deadlines(text, &f);
            assert_eq!(got.len(), 1, "{text:?}");
            assert_eq!(
                (got[0].phrase.as_str(), got[0].amount, got[0].unit, got[0].peremptory),
                (phrase, amount, unit, kesin),
                "{text:?}"
            );
        }
        let f = Folded::new("09/12/2026 günü saat 10:30'a");
        assert!(deadlines("09/12/2026 günü saat 10:30'a", &f).is_empty());
    }

    #[test]
    fn the_next_hearing_and_its_time() {
        for (text, date, time) in [
            ("1-Duruşmanın 09/12/2026 günü saat 10:30'a bırakılmasına,\n", "2026-12-09", Some("10:30")),
            ("1-Duruşmanın 18.01.2027 günü saat 11.15'e bırakılmasına,\n", "2027-01-18", Some("11:15")),
            ("1-Duruşmanın 3 Aralık 2026 Perşembe günü saat 10:00'a bırakılmasına,\n", "2026-12-03", Some("10:00")),
            ("1-Duruşmanın 02/12/2026\ngünü saat 14:15'e bırakılmasına,\n", "2026-12-02", Some("14:15")),
            ("1-Keşfin 11/11/2026 günü yapılmasına,\n2-Duruşmanın 15 OCAK 2027 günü saat 09:45'e ertelenmesine,\n", "2027-01-15", Some("09:45")),
            ("1-Duruşmanın 17/12/2026 tarihine ertelenmesine,\n", "2026-12-17", None),
        ] {
            let f = Folded::new(text);
            let d = decisions(text, &f, 0);
            let w = next_hearing(&f, &d, 0).unwrap_or_else(|| panic!("{text:?}"));
            assert_eq!(w.date.iso(), date, "{text:?}");
            assert_eq!(w.time.map(|t| t.hhmm()).as_deref(), time, "{text:?}");
        }
    }

    #[test]
    fn first_role() {
        let d = read("1-Davacı vekiline süre verilmesine,\n2-Davalı tarafa tebliğine,\n3-Tanık Ali'nin celbine,\n");
        let got: Vec<_> = d.iter().map(|d| (d.first_role, d.first_role_of)).collect();
        assert_eq!(
            got,
            [
                (Some(Role::Counsel), Some(Role::Plaintiff)),
                (Some(Role::Defendant), None),
                (Some(Role::Witness), None)
            ]
        );
    }
}
