//! Dates and times as the minutes write them: `27/10/2026`, `27.10.2026`, `27-10-2026`,
//! `27 Ekim 2026` (any case, with or without a weekday after it), and `saat 10:30` / `10.30`.
//! Only real calendar dates are accepted; nothing here computes a date from another.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Serialize, Serializer};

/// A calendar date. Serialises as ISO `YYYY-MM-DD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

/// A wall-clock time. Serialises as `HH:MM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time {
    pub hour: u8,
    pub minute: u8,
}

/// How a date was written — for the probe, which reports shapes and never values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DateStyle {
    /// `27/10/2026`
    Slash,
    /// `27.10.2026`
    Dot,
    /// `27-10-2026`
    Dash,
    /// `27 Ekim 2026`
    MonthName,
}

impl Date {
    pub fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        if !(1950..=2100).contains(&year) || !(1..=12).contains(&month) || day == 0 {
            return None;
        }
        let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let days = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        (day <= days).then_some(Self { year, month, day })
    }

    /// `YYYY-MM-DD`.
    pub fn iso(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl Time {
    pub fn new(hour: u8, minute: u8) -> Option<Self> {
        (hour < 24 && minute < 60).then_some(Self { hour, minute })
    }

    /// `HH:MM`.
    pub fn hhmm(&self) -> String {
        format!("{:02}:{:02}", self.hour, self.minute)
    }
}

impl Serialize for Date {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.iso())
    }
}

impl Serialize for Time {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hhmm())
    }
}

/// A date found in folded text: its folded byte range, value and style.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FoundDate {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) date: Date,
    pub(crate) style: DateStyle,
}

const MONTHS: [(&str, u8); 18] = [
    ("ocak", 1),
    ("şubat", 2),
    ("subat", 2),
    ("mart", 3),
    ("nisan", 4),
    ("mayıs", 5),
    ("mayis", 5),
    ("haziran", 6),
    ("temmuz", 7),
    ("ağustos", 8),
    ("agustos", 8),
    ("eylül", 9),
    ("eylul", 9),
    ("ekim", 10),
    ("kasım", 11),
    ("kasim", 11),
    ("aralık", 12),
    ("aralik", 12),
];

fn numeric_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // The separators are captured so a mixed `27/10.2026` is not taken for a date.
    RE.get_or_init(|| {
        Regex::new(r"(?:^|[^\d])(\d{1,2})[ \t]*([./-])[ \t]*(\d{1,2})[ \t]*([./-])[ \t]*(\d{4})(?:[^\d]|$)")
            .expect("date regex")
    })
}

fn month_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let names: Vec<&str> = MONTHS.iter().map(|(n, _)| *n).collect();
        let re = format!(r"(?:^|[^\d])(\d{{1,2}})\s+({})\s+(\d{{4}})(?:[^\d]|$)", names.join("|"));
        Regex::new(&re).expect("month regex")
    })
}

fn time_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `saat 10:30`, `saat: 10.30`, `saat 9:45'e`, `saat 10'da` (minute 0).
    RE.get_or_init(|| {
        Regex::new(r"saat[iı]?\s*:?\s*(\d{1,2})(?:\s*[:.]\s*(\d{2})|\s*')").expect("time regex")
    })
}

fn bare_time_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[ \t,]*(\d{1,2})[:.](\d{2})(?:[^\d]|$)").expect("bare time regex"))
}

/// Every valid date in `folded`, in order of appearance.
pub(crate) fn find_dates(folded: &str) -> Vec<FoundDate> {
    let mut out = Vec::new();
    // `captures_iter` does not find overlapping matches, and the leading/trailing guards eat a
    // char each — so walk with an explicit cursor that restarts one char past each match start.
    let mut at = 0;
    while let Some(c) = numeric_re().captures_at(folded, at) {
        let d = c.get(1).expect("day");
        let y = c.get(5).expect("year");
        at = d.end();
        if c[2] != c[4] {
            continue;
        }
        let style = match &c[2] {
            "/" => DateStyle::Slash,
            "." => DateStyle::Dot,
            _ => DateStyle::Dash,
        };
        if let Some(date) = parse_ymd(&c[5], &c[3], &c[1]) {
            out.push(FoundDate { start: d.start(), end: y.end(), date, style });
        }
    }
    let mut at = 0;
    while let Some(c) = month_re().captures_at(folded, at) {
        let d = c.get(1).expect("day");
        let y = c.get(3).expect("year");
        at = d.end();
        let month = MONTHS.iter().find(|(n, _)| *n == &c[2]).map(|(_, m)| *m).expect("month name");
        let date = c[3]
            .parse()
            .ok()
            .zip(c[1].parse().ok())
            .and_then(|(year, day)| Date::new(year, month, day));
        if let Some(date) = date {
            out.push(FoundDate { start: d.start(), end: y.end(), date, style: DateStyle::MonthName });
        }
    }
    out.sort_by_key(|d| d.start);
    out
}

fn parse_ymd(y: &str, m: &str, d: &str) -> Option<Date> {
    Date::new(y.parse().ok()?, m.parse().ok()?, d.parse().ok()?)
}

/// The first `saat HH:MM` in `folded[from..until]`.
pub(crate) fn find_saat(folded: &str, from: usize, until: usize) -> Option<Time> {
    let hay = &folded[from..until.min(folded.len())];
    let c = time_re().captures(hay)?;
    let hour = c[1].parse().ok()?;
    let minute = c.get(2).map_or(Some(0), |m| m.as_str().parse().ok())?;
    Time::new(hour, minute)
}

/// A time written right after a date, with no `saat` (`14/10/2026 10:30`).
pub(crate) fn bare_time_at(folded: &str, at: usize) -> Option<Time> {
    let c = bare_time_re().captures(&folded[at..])?;
    Time::new(c[1].parse().ok()?, c[2].parse().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold::fold;

    fn dates(s: &str) -> Vec<(String, DateStyle)> {
        find_dates(&fold(s)).into_iter().map(|d| (d.date.iso(), d.style)).collect()
    }

    #[test]
    fn every_written_form() {
        assert_eq!(dates("27/10/2026"), [("2026-10-27".into(), DateStyle::Slash)]);
        assert_eq!(dates("tarih: 27.10.2026,"), [("2026-10-27".into(), DateStyle::Dot)]);
        assert_eq!(dates("5-11-2026"), [("2026-11-05".into(), DateStyle::Dash)]);
        assert_eq!(dates("27 Ekim 2026 Salı"), [("2026-10-27".into(), DateStyle::MonthName)]);
        assert_eq!(dates("15 OCAK 2027"), [("2027-01-15".into(), DateStyle::MonthName)]);
        assert_eq!(dates("3 ŞUBAT 2027"), [("2027-02-03".into(), DateStyle::MonthName)]);
        assert_eq!(dates("1 AĞUSTOS 2027"), [("2027-08-01".into(), DateStyle::MonthName)]);
    }

    #[test]
    fn not_dates() {
        assert!(dates("31/02/2026").is_empty(), "no 31 February");
        assert!(dates("29/02/2026").is_empty(), "2026 is not a leap year");
        assert_eq!(dates("29/02/2028").len(), 1);
        assert!(dates("27/10.2026").is_empty(), "mixed separators");
        assert!(dates("3.000,00 TL").is_empty());
        assert!(dates("2024/123").is_empty());
        assert!(dates("127/10/2026").is_empty(), "three-digit day");
    }

    #[test]
    fn adjacent_dates_are_both_found() {
        assert_eq!(dates("01/03/2024-02/03/2024").len(), 2);
    }

    #[test]
    fn times() {
        let f = fold("günü saat 10:30'a");
        assert_eq!(find_saat(&f, 0, f.len()).unwrap().hhmm(), "10:30");
        let f = fold("SAAT: 9.45");
        assert_eq!(find_saat(&f, 0, f.len()).unwrap().hhmm(), "09:45");
        let f = fold("saat 10'da");
        assert_eq!(find_saat(&f, 0, f.len()).unwrap().hhmm(), "10:00");
        let f = fold("saat 25:00");
        assert!(find_saat(&f, 0, f.len()).is_none());
        assert_eq!(bare_time_at(" 10:30\n", 0).unwrap().hhmm(), "10:30");
    }
}
