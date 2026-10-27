//! Parties by ROLE: the header's role lines (`DAVACI : …`, `VEKİLİ : …`), witnesses and experts
//! labelled in the body, and who attended (`Davacı vekili geldi, davalı vekili gelmedi`).
//!
//! Names are not interpreted here. A party carries the span of its value and a best-effort span
//! of the name inside it; masking them is `sezi-redact`'s job, joining the two is the runner's.

use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::fold::{label, Folded};
use crate::Span;

/// A role in the record. A code; the UI or the runner names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// davacı
    Plaintiff,
    /// davalı
    Defendant,
    /// vekil (of whom: [`Party::of`])
    Counsel,
    /// sanık
    Accused,
    /// müdafi
    DefenceCounsel,
    /// katılan
    JoinedParty,
    /// müşteki, şikayetçi
    Complainant,
    /// mağdur
    Victim,
    /// tanık
    Witness,
    /// bilirkişi
    Expert,
    /// tercüman
    Interpreter,
    /// ihbar olunan
    NotifiedParty,
    /// fer'i müdahil
    Intervener,
    /// alacaklı
    Creditor,
    /// borçlu
    Debtor,
    /// velisi, vasisi
    Guardian,
    /// taraflar — both sides at once
    BothParties,
    /// hâkim
    Judge,
    /// başkan
    PresidingJudge,
    /// üye hâkim
    MemberJudge,
    /// kâtip, zabıt kâtibi
    Clerk,
    /// C. savcısı
    Prosecutor,
}

/// A role line of the header (or a witness/expert labelled in the body).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Party {
    pub role: Role,
    /// For [`Role::Counsel`] / [`Role::DefenceCounsel`]: whose.
    pub of: Option<Role>,
    /// The whole value after the colon, to the end of its line.
    pub value: Span,
    /// The name inside it: up to the first ` - `, comma, address word, long number or `(`, with
    /// a leading `Av.` dropped. Best effort; the redactor does not rely on it alone.
    pub name: Span,
}

/// One "who came" statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Attendance {
    pub role: Role,
    pub of: Option<Role>,
    pub present: bool,
    pub span: Span,
}

/// Header labels, longest first. `None` for `of` means "the label's own role"; `VEKİLİ` alone is
/// resolved against the principal above it.
const LABELS: [(&str, Role, Option<Role>); 41] = [
    ("davacı vekilleri", Role::Counsel, Some(Role::Plaintiff)),
    ("davacı vekili", Role::Counsel, Some(Role::Plaintiff)),
    ("davalı vekilleri", Role::Counsel, Some(Role::Defendant)),
    ("davalı vekili", Role::Counsel, Some(Role::Defendant)),
    ("katılan vekili", Role::Counsel, Some(Role::JoinedParty)),
    ("müşteki vekili", Role::Counsel, Some(Role::Complainant)),
    ("sanık müdafileri", Role::DefenceCounsel, Some(Role::Accused)),
    ("sanık müdafii", Role::DefenceCounsel, Some(Role::Accused)),
    ("cumhuriyet savcısı", Role::Prosecutor, None),
    ("c. savcısı", Role::Prosecutor, None),
    ("c.savcısı", Role::Prosecutor, None),
    ("zabıt katibi", Role::Clerk, None),
    ("zabıt katibesi", Role::Clerk, None),
    ("üye hakim", Role::MemberJudge, None),
    ("ihbar olunan", Role::NotifiedParty, None),
    ("fer'i müdahil", Role::Intervener, None),
    ("feri müdahil", Role::Intervener, None),
    ("karşı davacı", Role::Plaintiff, None),
    ("karşı davalı", Role::Defendant, None),
    ("vekilleri", Role::Counsel, None),
    ("vekili", Role::Counsel, None),
    ("müdafileri", Role::DefenceCounsel, Some(Role::Accused)),
    ("müdafii", Role::DefenceCounsel, Some(Role::Accused)),
    ("müdafi", Role::DefenceCounsel, Some(Role::Accused)),
    ("davacılar", Role::Plaintiff, None),
    ("davacı", Role::Plaintiff, None),
    ("davalılar", Role::Defendant, None),
    ("davalı", Role::Defendant, None),
    ("sanıklar", Role::Accused, None),
    ("sanık", Role::Accused, None),
    ("katılanlar", Role::JoinedParty, None),
    ("katılan", Role::JoinedParty, None),
    ("müşteki", Role::Complainant, None),
    ("şikayetçi", Role::Complainant, None),
    ("mağdur", Role::Victim, None),
    ("alacaklı", Role::Creditor, None),
    ("borçlu", Role::Debtor, None),
    ("velisi", Role::Guardian, None),
    ("vasisi", Role::Guardian, None),
    ("tercüman", Role::Interpreter, None),
    ("başkan", Role::PresidingJudge, None),
];

/// Labels that read the same in the header and the body (a witness heard in the body is written
/// `TANIK : …` there too).
const BODY_LABELS: [(&str, Role); 4] = [
    ("tanık", Role::Witness),
    ("bilirkişi", Role::Expert),
    ("hakim", Role::Judge),
    ("katip", Role::Clerk),
];

fn header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let mut alts: Vec<String> = LABELS.iter().map(|(l, _, _)| label(l)).collect();
        alts.extend(BODY_LABELS.iter().map(|(l, _)| label(l)));
        // `DAVACI (BORÇLU) : …` — a parenthesis after the label is allowed and kept out of the
        // role. The value starts after the colon, possibly on the next line.
        let re = format!(
            r"(?m)^[ \t]*({})[ \t]*(\([^)\n]*\))?\s*:[ \t]*([^\n]*)",
            alts.join("|")
        );
        Regex::new(&re).expect("party label regex")
    })
}

fn body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alts: Vec<String> = BODY_LABELS[..2].iter().map(|(l, _)| label(l)).collect();
        // Upper-case only in the body would be too strict for pasted text, so the colon has to
        // follow the label directly: `Tanık beyanında; …` is no label.
        let re = format!(r"(?m)^[ \t]*({})[ \t]*:[ \t]*([^\n]*)", alts.join("|"));
        Regex::new(&re).expect("body label regex")
    })
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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

fn lookup(folded_label: &str) -> Option<(Role, Option<Role>)> {
    let l = ascii(&squash(folded_label));
    LABELS
        .iter()
        .find(|(k, _, _)| ascii(k) == l)
        .map(|(_, r, of)| (*r, *of))
        .or_else(|| BODY_LABELS.iter().find(|(k, _)| ascii(k) == l).map(|(_, r)| (*r, None)))
}

/// `(DAVACI (BORÇLU))` — the parenthesis names the side in an enforcement case; the label wins.
fn principal(role: Role) -> bool {
    matches!(
        role,
        Role::Plaintiff
            | Role::Defendant
            | Role::Accused
            | Role::JoinedParty
            | Role::Complainant
            | Role::Victim
            | Role::Creditor
            | Role::Debtor
            | Role::NotifiedParty
            | Role::Intervener
    )
}

/// The role lines of the header (`text[..header_end]`) and the witness/expert lines after it.
pub(crate) fn parties(f: &Folded, header_end: usize) -> Vec<Party> {
    let mut out = Vec::new();
    let mut last_principal: Option<Role> = None;
    for c in header_re().captures_iter(&f.s[..header_end]) {
        let Some((role, of)) = lookup(&c[1]) else { continue };
        let of = match (role, of) {
            (Role::Counsel, None) => last_principal,
            (_, of) => of,
        };
        if principal(role) {
            last_principal = Some(role);
        }
        let v = c.get(3).expect("value");
        let value = f.span(v.start(), v.end());
        for name in names_in(f, v.start(), v.end(), matches!(role, Role::Counsel | Role::DefenceCounsel)) {
            out.push(Party { role, of, value, name });
        }
        // `DAVALILAR : 1- A` / `2- B` / …: the numbered lines under a plural label are more of it.
        if enum_re().is_match(&f.s[v.start()..v.end()]) {
            let mut expect = 2;
            let mut at = (v.end() + 1).min(header_end);
            while at < header_end {
                let line_end = f.s[at..header_end].find('\n').map_or(header_end, |i| at + i);
                let line = &f.s[at..line_end];
                match enum_re().captures(line) {
                    Some(n) if n[1].parse::<u32>().ok() == Some(expect) && header_re().find(line).is_none() => {
                        out.push(Party { role, of, value: f.span(at, line_end), name: name_span(f, at, line_end) });
                        expect += 1;
                        at = line_end + 1;
                    }
                    _ => break,
                }
            }
        }
    }
    for c in body_re().captures_iter(&f.s[header_end..]) {
        let Some((role, _)) = lookup(&c[1]) else { continue };
        let v = c.get(2).expect("value");
        let (s, e) = (header_end + v.start(), header_end + v.end());
        out.push(Party { role, of: None, value: f.span(s, e), name: name_span(f, s, e) });
    }
    out
}

fn name_stop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\s[-–]\s|,|\(|\s{2,}|\t|\d{5,}|\b(?:mah\.|mahallesi|cad\.|caddesi|sok\.|sokak|bulvarı|no:|t\.c\.|tc:)",
        )
        .expect("name stop regex")
    })
}

fn enum_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[ \t]*(\d{1,2})[ \t]*[-.)][ \t]*\S").expect("enumeration regex"))
}

fn counsel_split_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+ve\s+av\.|\s*,\s*av\.").expect("counsel split regex"))
}

/// The names in a value: one, or for counsel `Av. A ve Av. B` / `Av. A, Av. B` several.
fn names_in(f: &Folded, start: usize, end: usize, counsel: bool) -> Vec<Span> {
    if !counsel {
        return vec![name_span(f, start, end)];
    }
    let seg = &f.s[start..end];
    let mut out = Vec::new();
    let mut at = 0;
    for m in counsel_split_re().find_iter(seg) {
        out.push(name_span(f, start + at, start + m.start()));
        // Keep the `av.` with the next name so the prefix rule drops it.
        at = m.end() - 3;
    }
    out.push(name_span(f, start + at, end));
    out
}

fn name_span(f: &Folded, start: usize, end: usize) -> Span {
    let mut start = start;
    if enum_re().is_match(&f.s[start..end]) {
        // `1- Nermin …`: the number is not part of the name.
        let skip = f.s[start..end].find(['-', '.', ')']).map_or(0, |i| i + 1);
        start += skip;
    }
    let seg = &f.s[start..end];
    let stop = name_stop_re().find(seg).map_or(seg.len(), |m| m.start());
    let mut s = start;
    let head = &seg[..stop];
    let lead = head.len() - head.trim_start().len();
    s += lead;
    let mut body = head.trim();
    for prefix in ["av.", "av "] {
        if let Some(rest) = body.strip_prefix(prefix) {
            s += body.len() - rest.trim_start().len();
            body = rest.trim_start();
        }
    }
    f.span(s, s + body.len())
}

/// Role words in running text, for the decisions' first role and for attendance.
fn mention_res() -> &'static [(Regex, Role, Option<Role>)] {
    static RES: OnceLock<Vec<(Regex, Role, Option<Role>)>> = OnceLock::new();
    RES.get_or_init(|| {
        let side = r"(?:\s+(?:borçlu|alacaklı|asil|taraf)\p{L}*)?";
        let table: Vec<(String, Role, Option<Role>)> = vec![
            (format!(r"\bdavac[ıi]\p{{L}}*{side}\s+vekil\p{{L}}*"), Role::Counsel, Some(Role::Plaintiff)),
            (format!(r"\bdaval[ıi]\p{{L}}*{side}\s+vekil\p{{L}}*"), Role::Counsel, Some(Role::Defendant)),
            (r"\bkatılan\p{L}*\s+vekil\p{L}*".into(), Role::Counsel, Some(Role::JoinedParty)),
            (r"\bmüşteki\p{L}*\s+vekil\p{L}*".into(), Role::Counsel, Some(Role::Complainant)),
            (r"\btaraf\s+vekil\p{L}*".into(), Role::Counsel, Some(Role::BothParties)),
            (r"\b(?:sanı[kğ]\p{L}*\s+)?müdafi\p{L}*".into(), Role::DefenceCounsel, Some(Role::Accused)),
            (r"\bvekil\p{L}*".into(), Role::Counsel, None),
            (r"\b(?:c\.\s*|cumhuriyet\s+)savcı\p{L}*".into(), Role::Prosecutor, None),
            (format!(r"\bdavac[ıi]\p{{L}}*{side}"), Role::Plaintiff, None),
            (format!(r"\bdaval[ıi]\p{{L}}*{side}"), Role::Defendant, None),
            (r"\btaraflar\p{L}*|\btarafların\b".into(), Role::BothParties, None),
            (r"\bsanı[kğ]\p{L}*".into(), Role::Accused, None),
            (r"\bkatılan\p{L}*".into(), Role::JoinedParty, None),
            (r"\bmüşteki\p{L}*".into(), Role::Complainant, None),
            (r"\bmağdur\p{L}*".into(), Role::Victim, None),
            (r"\btanı[kğ]\p{L}*".into(), Role::Witness, None),
            (r"\bbilirkişi\p{L}*".into(), Role::Expert, None),
            (r"\btercüman\p{L}*".into(), Role::Interpreter, None),
            (r"\balacaklı\p{L}*".into(), Role::Creditor, None),
            (r"\bborçlu\p{L}*".into(), Role::Debtor, None),
        ];
        table
            .into_iter()
            .map(|(re, r, of)| (Regex::new(&re).expect("mention regex"), r, of))
            .collect()
    })
}

/// A role mentioned in folded text: `(start, end, role, of)`, earliest first, overlaps resolved
/// to the longer match. A bare `vekili` takes the principal mentioned just before it.
pub(crate) fn mentions(folded: &str) -> Vec<(usize, usize, Role, Option<Role>)> {
    let mut all: Vec<(usize, usize, Role, Option<Role>)> = Vec::new();
    for (re, role, of) in mention_res() {
        for m in re.find_iter(folded) {
            all.push((m.start(), m.end(), *role, *of));
        }
    }
    all.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut out: Vec<(usize, usize, Role, Option<Role>)> = Vec::new();
    for m in all {
        if out.last().is_some_and(|l| m.0 < l.1) {
            continue;
        }
        let m = match m {
            (s, e, Role::Counsel, None) => {
                let of = out.iter().rev().find(|l| principal(l.2)).map(|l| l.2);
                (s, e, Role::Counsel, of)
            }
            m => m,
        };
        out.push(m);
    }
    out
}

fn verb_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Negatives are listed before their positives so `gelmedi` never reads as `geldi`.
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(gelmedi\p{L}*|gelmemiş\p{L}*|katılmadı\p{L}*|hazır\s+değil\p{L}*|hazır\s+olmadı\p{L}*|iştirak\s+etmedi\p{L}*|bağlanamadı\p{L}*)|(geldi\p{L}*|hazır(?:dır|dı|lar|lardır)?\b|katıldı\p{L}*|iştirak\s+etti\p{L}*|bağlandı\p{L}*))",
        )
        .expect("attendance verb regex")
    })
}

/// Who came, read from `text[from..until]` (the body before the decisions). Each verb settles
/// every role mentioned since the previous clause boundary; the first statement about a role wins.
pub(crate) fn attendance(f: &Folded, from: usize, until: usize) -> Vec<Attendance> {
    let hay = &f.s[from..until];
    let mut out: Vec<Attendance> = Vec::new();
    let mut clause_start = 0;
    for v in verb_re().captures_iter(hay) {
        let whole = v.get(0).expect("verb");
        let present = v.get(2).is_some();
        let start = boundary_before(hay, clause_start, whole.start());
        for (s, _, role, of) in mentions(&hay[start..whole.start()]) {
            if matches!(role, Role::Judge | Role::Clerk) {
                continue;
            }
            if out.iter().any(|a| a.role == role && a.of == of) {
                continue;
            }
            let span = f.span(from + start + s, from + whole.end());
            out.push(Attendance { role, of, present, span });
        }
        clause_start = whole.end();
    }
    out
}

/// The last clause boundary in `hay[floor..at]`: a comma, semicolon, colon, or a full stop that
/// ends a sentence (not `Av.` or `C.`). Not a blank line: lopdf turns a wrapped line of a PDF
/// into one (`… ARIKANLI ile` / `` / `davalı vekili …`), so it says nothing about clauses.
fn boundary_before(hay: &str, floor: usize, at: usize) -> usize {
    let seg = &hay[floor..at];
    let bytes = seg.as_bytes();
    let mut i = seg.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b',' | b';' | b':' => return floor + i + 1,
            b'.' => {
                let word_start = seg[..i].rfind(|c: char| !c.is_alphabetic()).map_or(0, |p| p + 1);
                let word = &seg[word_start..i];
                let abbrev = word.chars().count() <= 2;
                if !abbrev {
                    return floor + i + 1;
                }
            }
            _ => {}
        }
    }
    floor
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(text: &str) -> Vec<(Role, Option<Role>, bool)> {
        let f = Folded::new(text);
        attendance(&f, 0, f.s.len()).into_iter().map(|a| (a.role, a.of, a.present)).collect()
    }

    #[test]
    fn who_came() {
        assert_eq!(
            att("Davacı vekili Av. Selin DEMİRKOL geldi, davalı vekili\ngelmedi."),
            [(Role::Counsel, Some(Role::Plaintiff), true), (Role::Counsel, Some(Role::Defendant), false)]
        );
        assert_eq!(
            att("Davacı vekili Av. A ile davalı vekili Av. B hazır."),
            [(Role::Counsel, Some(Role::Plaintiff), true), (Role::Counsel, Some(Role::Defendant), true)]
        );
        assert_eq!(
            att("Davacı asil ve vekili ile davalı asil geldi."),
            [
                (Role::Plaintiff, None, true),
                (Role::Counsel, Some(Role::Plaintiff), true),
                (Role::Defendant, None, true)
            ]
        );
        assert_eq!(
            att("Tutuklu sanık SEGBİS ile bağlandı. Katılan gelmedi. C. Savcısı hazır."),
            [(Role::Accused, None, true), (Role::JoinedParty, None, false), (Role::Prosecutor, None, true)]
        );
        assert_eq!(att("Taraf vekilleri geldi."), [(Role::Counsel, Some(Role::BothParties), true)]);
        assert_eq!(
            att("C. Savcısı hazır. Açık duruşmaya devam olundu.\n\nTanık Gül ESEN'in celp edilmesine rağmen gelmediği görüldü."),
            [(Role::Prosecutor, None, true), (Role::Witness, None, false)]
        );
    }

    #[test]
    fn header_lines() {
        let text = "DAVACI : Ali VELİ - Kızılay Mah. No:1\nVEKİLİ : Av. Ece SU\nDAVALI (ALACAKLI) : X A.Ş.\nVEKİLİ : Av. Can\n";
        let f = Folded::new(text);
        let p = parties(&f, f.s.len());
        let got: Vec<_> = p.iter().map(|p| (p.role, p.of, &text[p.name.start..p.name.end])).collect();
        assert_eq!(
            got,
            [
                (Role::Plaintiff, None, "Ali VELİ"),
                (Role::Counsel, Some(Role::Plaintiff), "Ece SU"),
                (Role::Defendant, None, "X A.Ş."),
                (Role::Counsel, Some(Role::Defendant), "Can"),
            ]
        );
    }

    #[test]
    fn a_value_on_the_next_line() {
        let text = "DAVACI\n: Kadir ÜZÜMCÜLER - Tepebaşı\nHAKİM\n: Volkan E 130044\n";
        let f = Folded::new(text);
        let p = parties(&f, f.s.len());
        assert_eq!(&text[p[0].name.start..p[0].name.end], "Kadir ÜZÜMCÜLER");
        assert_eq!(p[1].role, Role::Judge);
        assert_eq!(&text[p[1].name.start..p[1].name.end], "Volkan E");
    }
}
