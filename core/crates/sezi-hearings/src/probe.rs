//! The H0 probe's report (docs/HEARINGS_BOT_PLAN.md §3.2): what a real record looks like to the
//! parser, as STRUCTURE ONLY — counts, yes/no, value shapes (`NNNN/NNN`), codes. It never holds
//! a word of the record, so it can be printed on the office's machine and pasted anywhere.
//!
//! The rule that keeps it so: everything rendered here is a number, a boolean, a [`shape`], or a
//! Rust identifier of this crate (`CivilGeneral`, `Counsel`). `tests/probe.rs` runs it over every
//! fixture and checks that none of the fixture's words appear in the output.

use std::collections::BTreeMap;
use std::fmt::{self, Write};

use crate::{is_pdf, Limits, PdfFacts, Record, Refusal, RuleSummary, Usability};

/// A value's shape: a letter → `A`/`a`, a digit → `N`, whitespace → ` `, ASCII punctuation kept,
/// anything else → `?`. `2024/123` → `NNNN/NNN`.
pub fn shape(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphabetic() {
                if c.is_uppercase() {
                    'A'
                } else {
                    'a'
                }
            } else if c.is_ascii_digit() {
                'N'
            } else if c.is_whitespace() {
                ' '
            } else if c.is_ascii_punctuation() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// The structure of one input. Build with [`report`], print with `Display`.
///
/// Unlike [`crate::read_file`] it goes on past a usability refusal — a refused real PDF is exactly
/// the one whose fonts and character counts we need to see — but it ends with the same verdict
/// (`tests/probe.rs` holds the two to that).
pub struct ProbeReport {
    bytes: usize,
    pdf: Option<PdfFacts>,
    usability: Option<Usability>,
    repaired_latin1: bool,
    record: Option<Record>,
    refusal: Option<Refusal>,
}

/// Read `bytes` as the bot would and keep only what the report prints.
pub fn report(bytes: &[u8], limits: &Limits) -> ProbeReport {
    let mut r = ProbeReport {
        bytes: bytes.len(),
        pdf: None,
        usability: None,
        repaired_latin1: false,
        record: None,
        refusal: None,
    };
    let raw = if bytes.len() > limits.max_input_bytes {
        Err(Refusal::TooLarge)
    } else if is_pdf(bytes) {
        crate::pdf::extract(bytes, limits).map(|(text, facts)| {
            r.pdf = Some(facts);
            text
        })
    } else {
        crate::usable::decode_text(bytes)
            .ok_or(Refusal::UnsupportedType)
            .and_then(|t| if t.chars().count() > limits.max_chars { Err(Refusal::TooMuchText) } else { Ok(t) })
    };
    let raw = match raw {
        Ok(raw) => raw,
        Err(refusal) => {
            r.refusal = Some(refusal);
            return r;
        }
    };
    let (text, repaired) = crate::usable::normalize(&raw);
    let usability = crate::usable::assess(&text, r.pdf.as_ref().is_some_and(|p| p.fonts_unmappable > 0));
    r.refusal = crate::refusal_of(usability.verdict, r.pdf.is_some());
    r.usability = Some(usability);
    r.repaired_latin1 = repaired;
    r.record = Some(crate::parse(&text));
    r
}

impl ProbeReport {
    /// The refusal the bot would answer with, if any.
    pub fn refusal(&self) -> Option<Refusal> {
        self.refusal
    }
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn role_key(role: crate::Role, of: Option<crate::Role>) -> String {
    match of {
        Some(of) => format!("{role:?}({of:?})"),
        None => format!("{role:?}"),
    }
}

impl fmt::Display for ProbeReport {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        writeln!(s, "bytes: {}", self.bytes)?;
        match self.refusal {
            Some(r) => writeln!(s, "verdict: refused {}", r.code())?,
            None => writeln!(s, "verdict: usable")?,
        }
        match &self.pdf {
            None => writeln!(s, "input: {}", if self.usability.is_some() { "text" } else { "-" })?,
            Some(p) => {
                writeln!(s, "input: pdf")?;
                writeln!(s, "pages: {}", p.pages)?;
                writeln!(s, "chars_per_page: {:?}", p.chars_per_page)?;
                writeln!(
                    s,
                    "fonts: {} (to_unicode {}, unmappable {})",
                    p.fonts, p.fonts_with_to_unicode, p.fonts_unmappable
                )?;
                writeln!(s, "image_pages: {}", p.image_pages)?;
                writeln!(s, "page_errors: {}", p.page_errors)?;
                writeln!(s, "encrypted_open: {}", yn(p.encrypted_open))?;
            }
        }
        let (Some(u), Some(r)) = (&self.usability, &self.record) else {
            return out.write_str(&s);
        };
        writeln!(
            s,
            "text: chars {} · bad {}‰ · letters {}‰ · latin1_repaired {}",
            u.chars,
            u.bad_permille,
            u.letter_permille,
            yn(self.repaired_latin1)
        )?;
        writeln!(
            s,
            "anchors: case {} · court {} · hearing {} · record {}",
            yn(u.anchors.case),
            yn(u.anchors.court),
            yn(u.anchors.hearing),
            yn(u.anchors.record)
        )?;

        match &r.case_no {
            Some(n) => writeln!(s, "case_no: yes · {:?} · {}", n.form, shape(&n.value.to_string()))?,
            None => writeln!(s, "case_no: no")?,
        }
        match &r.decision_no {
            Some(n) => writeln!(s, "decision_no: yes · {}", shape(&n.value.to_string()))?,
            None => writeln!(s, "decision_no: no")?,
        }
        match r.session_no {
            Some(n) => writeln!(s, "session_no: yes · {}", shape(&n.to_string()))?,
            None => writeln!(s, "session_no: no")?,
        }
        match &r.court {
            Some(c) => writeln!(
                s,
                "court: yes · {:?} · place {} · number {}",
                c.kind,
                yn(c.place.is_some()),
                yn(c.number.is_some())
            )?,
            None => writeln!(s, "court: no")?,
        }
        for (name, when) in [("hearing", &r.hearing), ("next_hearing", &r.next_hearing)] {
            match when {
                Some(w) => writeln!(s, "{name}: yes · {:?} · time {}", w.style, yn(w.time.is_some()))?,
                None => writeln!(s, "{name}: no")?,
            }
        }

        let d = &r.decisions;
        let lens: Vec<usize> = d.iter().map(|d| d.text.chars().count()).collect();
        writeln!(s, "decisions: {} · chars {:?}", d.len(), lens)?;
        let with_deadline = d.iter().filter(|d| !d.deadlines.is_empty()).count();
        let peremptory = d.iter().flat_map(|d| &d.deadlines).filter(|x| x.peremptory).count();
        let mut units: BTreeMap<String, u32> = BTreeMap::new();
        for x in d.iter().flat_map(|d| &d.deadlines) {
            *units.entry(format!("{:?}", x.unit)).or_default() += 1;
        }
        writeln!(s, "deadlines: in {with_deadline} decisions · peremptory {peremptory} · units {units:?}")?;
        writeln!(s, "sets_next_hearing: {}", d.iter().filter(|d| d.sets_next_hearing).count())?;
        let mut first: BTreeMap<String, u32> = BTreeMap::new();
        for x in d {
            let key = x.first_role.map_or("none".to_string(), |r| role_key(r, x.first_role_of));
            *first.entry(key).or_default() += 1;
        }
        writeln!(s, "first_roles: {first:?}")?;

        let mut roles: BTreeMap<String, u32> = BTreeMap::new();
        for p in &r.parties {
            *roles.entry(role_key(p.role, p.of)).or_default() += 1;
        }
        writeln!(s, "parties: {roles:?}")?;
        let mut att: BTreeMap<String, &str> = BTreeMap::new();
        for a in &r.attendance {
            att.insert(role_key(a.role, a.of), if a.present { "present" } else { "absent" });
        }
        writeln!(s, "attendance: {att:?}")?;
        let missing: Vec<String> = RuleSummary::of(r).missing.iter().map(|m| format!("{m:?}")).collect();
        writeln!(s, "missing: {missing:?}")?;
        out.write_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        assert_eq!(shape("2024/123"), "NNNN/NNN");
        assert_eq!(shape("İğdır 1."), "Aaaaa N.");
        assert_eq!(shape("10:30'a"), "NN:NN'a");
        assert_eq!(shape("—"), "?");
    }
}
