//! The model's answer, checked before anything of it is shown or written
//! (docs/HEARINGS_BOT_PLAN.md §5.4). Pure. The answer is treated as hostile: a provider's schema
//! guarantee is not relied on, and nothing the model says acts by itself.
//!
//! In order:
//! 1. **The shape.** One JSON object with exactly the schema's seven fields, each of its type;
//!    an unknown field anywhere, a missing one, or a wrong type is `hearings/model-invalid`.
//!    `is_hearing_record: false` is `hearings/not-a-record`.
//! 2. **Placeholders.** Every placeholder an answer uses must be one the vault holds, and nothing
//!    may LOOK like one without being one (`[KİŞİ_1]`, `[KISI_0]`): an invented or mangled
//!    placeholder is `hearings/model-invalid` — restoring would leave it, or worse, guess.
//! 3. **No name-like text.** The model saw no names, so a name in its answer is fabricated or a
//!    masking miss. Each string is run through `sezi_redact::leak_check_with` (tier 1–2 hits —
//!    identity numbers, phones, e-mail, plates, case numbers, addresses — and every vault value,
//!    case-folded): any hit is `hearings/model-leak`, with no exception. Then through the whole
//!    redactor once more with the placeholders blanked, for what the model wrote itself: a person
//!    (a given name and surname, a name after a role word or an honorific), a company, an all-caps
//!    run — also `hearings/model-leak`, UNLESS the hit names an institution, a law or a day rather
//!    than a person: its last word, or one of the two words after it, is the head of such a name
//!    ("Zafer Bayramı", "Deniz Ticaret Hukuku", "Deniz Kuvvetleri Komutanlığı", "TÜRK MEDENİ
//!    KANUNU"; [`INSTITUTION_HEADS`]). A company form is never excused, and the residual net for
//!    long digit runs is not asked at all: a number the record had is a vault value (caught
//!    above), and one the model made up is nobody's data. Until 2026-10-27 every category of the
//!    second run rejected the answer, so ordinary legal prose fell to rule-only.
//!
//!    **The whole answer, not the string** (§5.4 says "stripped and flagged"): what is left to
//!    catch is real data or a name the model put in a decision, and a summary with that decision
//!    cut out of it is worse than the rule-only answer, which at least has every decision.
//!
//!    A **link** is a leak too: the 1:1 answer restores the placeholders inside it, and a tap would
//!    send the names to whatever address an injected record chose ([`has_link`]: a scheme, `www.`,
//!    a host of a common top-level domain before `/`, `?` or `#`, or ANY dotted host in one word
//!    with a placeholder). A citation's slash ("Yargıtay 2.HD/2023-1234", "4721 s.TMK/m.166") is
//!    not a link.
//! 4. **Dates.** Real calendar dates, 2000 to (hearing date + 3 years); a next hearing after the
//!    hearing. A bad one is `hearings/model-invalid`.
//! 5. **The rules win.** Court and esas no never come from the model at all. The next hearing is
//!    the parser's whenever it found one; a model that disagrees is noted ("kontrol edin").
//! 6. **Deadlines are quoted, never computed.** A deadline phrase must occur in the masked
//!    record as written (case and spacing aside); otherwise the parser's phrase for that decision
//!    is used, or none.
//! 7. **Caps.** ≤ 30 decisions, each ≤ 500 characters, notes ≤ 1,000, ≤ 30 attendance lines:
//!    longer is cut with "…".

use sezi_hearings::{Date, RuleSummary, Time};
use sezi_redact::{leak_check_with, placeholders_in, redact, Category, Policy, Vault};

pub(super) const MAX_DECISIONS: usize = 30;
pub(super) const MAX_TEXT_CHARS: usize = 500;
pub(super) const MAX_NOTES_CHARS: usize = 1000;
const MAX_ATTENDANCE: usize = 30;
const MAX_ROLE_CHARS: usize = 60;
const MAX_COURT_TYPE_CHARS: usize = 80;

pub(super) const INVALID: &str = "hearings/model-invalid";
pub(super) const LEAK: &str = "hearings/model-leak";
pub(super) const NOT_A_RECORD: &str = "hearings/not-a-record";

/// Whose task a decision is, as the schema's enum names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Party {
    Plaintiff,
    Defendant,
    Court,
    Expert,
    Witness,
    Other,
}

impl Party {
    /// The schema's enum, read whatever its casing: structured outputs constrain the answer to
    /// the schema, but do not promise an enum value's case, so "DAVACI" is "davacı". Folded the
    /// Turkish way (`I` → `ı`, `İ` → `i`, then lower case) — `str::to_lowercase` alone would make
    /// "DAVACI" "davaci" and "BİLİRKİŞİ" an `i` with a combining dot.
    fn parse(s: &str) -> Option<Self> {
        Some(match fold_tr(s.trim()).as_str() {
            "davacı" => Party::Plaintiff,
            "davalı" => Party::Defendant,
            "mahkeme" => Party::Court,
            "bilirkişi" => Party::Expert,
            "tanık" => Party::Witness,
            "diğer" => Party::Other,
            _ => return None,
        })
    }
}

/// One checked decision. `text` is still MASKED: placeholders are restored only for the 1:1
/// answer, and replaced by roles for the sheet.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct ModelDecision {
    pub(super) n: u32,
    pub(super) text: String,
    pub(super) party: Option<Party>,
    pub(super) deadline: Option<String>,
}

/// The model's answer, as far as it survived the checks.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct ModelSummary {
    pub(super) hearing_date: Option<Date>,
    /// The parser's when it found one, else the model's.
    pub(super) next_hearing: Option<(Date, Option<Time>)>,
    /// The parser found a next hearing and the model said another.
    pub(super) next_disagrees: bool,
    pub(super) attendance: Vec<(String, bool)>,
    pub(super) decisions: Vec<ModelDecision>,
    pub(super) notes: Option<String>,
}

/// Check the model's JSON text against the vault, the masked record and the rules' reading.
pub(super) fn validate(json: &str, vault: &Vault, masked: &str, rules: &RuleSummary) -> Result<ModelSummary, &'static str> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).map_err(|_| INVALID)?;
    let o = exact(&v, &["is_hearing_record", "court_type", "hearing_date", "next_hearing", "attendance", "decisions", "notes"])?;
    if !o["is_hearing_record"].as_bool().ok_or(INVALID)? {
        return Err(NOT_A_RECORD);
    }
    // Every string the answer holds, checked once for placeholders and names.
    if let Some(ct) = opt_str(&o["court_type"])? {
        if ct.chars().count() > MAX_COURT_TYPE_CHARS {
            return Err(INVALID);
        }
        clean(ct, vault)?;
    }
    let hearing_date = opt_str(&o["hearing_date"])?.map(iso_date).transpose()?;
    let anchor = rules.hearing_date.or(hearing_date);
    if let Some(d) = hearing_date {
        in_range(d, anchor)?;
    }
    let model_next = match &o["next_hearing"] {
        serde_json::Value::Null => None,
        n => {
            let n = exact(n, &["date", "time"])?;
            let date = iso_date(n["date"].as_str().ok_or(INVALID)?)?;
            in_range(date, anchor)?;
            if anchor.is_some_and(|h| date <= h) {
                return Err(INVALID);
            }
            let time = opt_str(&n["time"])?.map(hhmm).transpose()?;
            Some((date, time))
        }
    };
    let parser_next = rules.next_hearing.map(|n| (n.date, n.time));
    let next_disagrees = matches!((parser_next, model_next), (Some(p), Some(m)) if p.0 != m.0 || (p.1.is_some() && m.1.is_some() && p.1 != m.1));
    let mut attendance = Vec::new();
    for a in o["attendance"].as_array().ok_or(INVALID)?.iter().take(MAX_ATTENDANCE) {
        let a = exact(a, &["role", "present"])?;
        let role = a["role"].as_str().ok_or(INVALID)?.trim();
        let present = a["present"].as_bool().ok_or(INVALID)?;
        if role.is_empty() {
            continue;
        }
        clean(role, vault)?;
        attendance.push((cut(role, MAX_ROLE_CHARS), present));
    }
    let mut decisions = Vec::new();
    for d in o["decisions"].as_array().ok_or(INVALID)?.iter().take(MAX_DECISIONS) {
        let d = exact(d, &["n", "text", "party", "deadline_phrase"])?;
        let n = d["n"].as_u64().filter(|n| (1..=99).contains(n)).ok_or(INVALID)? as u32;
        let text = d["text"].as_str().ok_or(INVALID)?.trim();
        if text.is_empty() {
            continue;
        }
        clean(text, vault)?;
        let party = match opt_str(&d["party"])? {
            None => None,
            Some(p) => Some(Party::parse(p).ok_or(INVALID)?),
        };
        let deadline = match opt_str(&d["deadline_phrase"])? {
            Some(p) if quoted(p, masked) => {
                clean(p, vault)?;
                Some(p.trim().to_string())
            }
            // Not the record's own words: the rules' phrase for that decision, or none.
            _ => rules.decisions.iter().find(|r| r.n == n).and_then(|r| r.deadlines.first().cloned()),
        };
        decisions.push(ModelDecision { n, text: cut(text, MAX_TEXT_CHARS), party, deadline });
    }
    let notes = match opt_str(&o["notes"])?.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            clean(s, vault)?;
            Some(cut(s, MAX_NOTES_CHARS))
        }
        None => None,
    };
    Ok(ModelSummary {
        hearing_date,
        next_hearing: parser_next.or(model_next),
        next_disagrees,
        attendance,
        decisions,
        notes,
    })
}

/// `v` as an object with exactly these keys.
fn exact<'a>(v: &'a serde_json::Value, keys: &[&str]) -> Result<&'a serde_json::Map<String, serde_json::Value>, &'static str> {
    let o = v.as_object().ok_or(INVALID)?;
    let ok = o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k));
    ok.then_some(o).ok_or(INVALID)
}

fn opt_str(v: &serde_json::Value) -> Result<Option<&str>, &'static str> {
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s)),
        _ => Err(INVALID),
    }
}

fn iso_date(s: &str) -> Result<Date, &'static str> {
    let p: Vec<&str> = s.trim().split('-').collect();
    let num = |x: &str, len: usize| (x.len() == len && x.bytes().all(|b| b.is_ascii_digit())).then(|| x.parse::<u16>().ok()).flatten();
    match p.as_slice() {
        [y, m, d] => {
            let (y, m, d) = (num(y, 4).ok_or(INVALID)?, num(m, 2).ok_or(INVALID)?, num(d, 2).ok_or(INVALID)?);
            Date::new(y, m as u8, d as u8).ok_or(INVALID)
        }
        _ => Err(INVALID),
    }
}

fn hhmm(s: &str) -> Result<Time, &'static str> {
    let (h, m) = s.trim().split_once(':').ok_or(INVALID)?;
    let two = |x: &str| (x.len() == 2 && x.bytes().all(|b| b.is_ascii_digit())).then(|| x.parse::<u8>().ok()).flatten();
    Time::new(two(h).ok_or(INVALID)?, two(m).ok_or(INVALID)?).ok_or(INVALID)
}

/// 2000 to (the hearing + 3 years); with no hearing date known, 2000 to 2100.
fn in_range(d: Date, hearing: Option<Date>) -> Result<(), &'static str> {
    let lo = Date { year: 2000, month: 1, day: 1 };
    let hi = hearing.map_or(Date { year: 2100, month: 12, day: 31 }, |h| Date { year: h.year + 3, ..h });
    (d >= lo && d <= hi).then_some(()).ok_or(INVALID)
}

/// Does the phrase occur in the masked record, as worded (case and spacing aside)?
fn quoted(phrase: &str, masked: &str) -> bool {
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let p = norm(phrase);
    !p.is_empty() && norm(masked).contains(&p)
}

/// A string of the answer passes 2. and 3. of the module doc.
fn clean(s: &str, vault: &Vault) -> Result<(), &'static str> {
    let found = placeholders_in(s);
    if found.iter().any(|(_, p)| !vault.contains(p)) {
        return Err(INVALID);
    }
    if lookalike(s, &found) {
        return Err(INVALID);
    }
    // A link: restoring its placeholders for the 1:1 answer would put the names into an address
    // a tap sends them to. A summary of interim decisions never needs one.
    if has_link(s) {
        return Err(LEAK);
    }
    leak_check_with(s, vault).map_err(|_| LEAK)?;
    // The redactor once more, over the text with every placeholder blanked to a neutral word:
    // whatever it would still mask (a name, an all-caps run, a number) the model wrote itself.
    let mut blank = String::with_capacity(s.len());
    let mut prev = 0;
    for (r, _) in &found {
        blank.push_str(&s[prev..r.start]);
        blank.push_str("kişi");
        prev = r.end;
    }
    blank.push_str(&s[prev..]);
    let again = redact(&blank, &Policy::default()).map_err(|_| LEAK)?;
    let leaks = again.spans.iter().any(|sp| match sp.placeholder.category {
        // The record's own esas no and court are what the rules restore; a long digit run the
        // model made up is nobody's (module doc, 3.).
        Category::Esas | Category::Mahkeme | Category::Numara => false,
        Category::Kisi | Category::Ad => !names_an_institution(&blank, sp.original.clone()),
        _ => true,
    });
    if leaks {
        return Err(LEAK);
    }
    Ok(())
}

/// The head word of a name that is an institution, a law, a field of law or a day — never a
/// person's surname — as the start of its folded form ("bakanlığ" is "Bakanlığı",
/// "Bakanlığı'na", "Bakanlığından").
const INSTITUTION_HEADS: [&str; 44] = [
    "bakanlığ", "müdürlüğ", "başkanlığ", "komutanlığ", "kaymakamlığ", "valiliğ", "başsavcılığ",
    "savcılığ", "hakimliğ", "mahkemes", "daires", "kurum", "kurul", "hastanes", "üniversites",
    "fakültes", "enstitüs", "belediyes", "odas", "baros", "noterliğ", "kanun", "yasas", "hukuk",
    "tüzüğ", "yönetmeliğ", "bayram", "savaş", "köprüs", "meydan", "park", "müzes", "merkez",
    "kuvvetler", "holding", "ofis", "okul", "lises", "camii", "havaliman", "limanı", "istasyon",
    "terminal", "gazetes",
];

/// The redactor's hit at `range` of `s` is the start of an institution's name rather than a
/// person: its last word, or one of the next two words (joined to it by spaces), is a head in
/// [`INSTITUTION_HEADS`].
fn names_an_institution(s: &str, range: std::ops::Range<usize>) -> bool {
    let word_key = |w: &str| {
        // A suffix after an apostrophe is the case ending: "Komutanlığı'na" is "komutanlığı".
        let w = w.split(['\'', '’']).next().unwrap_or("");
        fold_tr(w.trim_matches(|c: char| !c.is_alphanumeric()))
    };
    let is_head = |w: &str| {
        let k = word_key(w);
        !k.is_empty() && INSTITUTION_HEADS.iter().any(|h| k.starts_with(h))
    };
    let hit = s.get(range.clone()).unwrap_or("");
    if hit.split_whitespace().last().is_some_and(is_head) {
        return true;
    }
    s.get(range.end..).unwrap_or("").split_whitespace().take(2).any(is_head)
}

/// Lower case, the Turkish way: `I` → `ı`, `İ` → `i` (`str::to_lowercase` alone makes "DAVACI"
/// "davaci" and "İ" an `i` with a combining dot).
fn fold_tr(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            'I' => vec!['ı'],
            'İ' => vec!['i'],
            c => c.to_lowercase().collect(),
        })
        .collect()
}

/// Top-level domains a link is recognised by when nothing else marks it as one: the common
/// generic and country ones, and the reserved names examples use. A legal abbreviation before a
/// slash ("2.HD/", "s.TMK/", "m.119/") is none of these.
const LINK_TLDS: [&str; 40] = [
    "com", "net", "org", "info", "biz", "io", "co", "me", "app", "dev", "xyz", "site", "online", "link",
    "top", "shop", "club", "page", "pw", "ws", "tr", "gov", "edu", "ai", "ly", "to", "cc", "tv", "us", "uk",
    "eu", "de", "ru", "nl", "fr", "cn", "example", "test", "invalid", "localhost",
];

/// A web address in `s`: a scheme (`://`, `mailto:`), `www.`, a dotted host whose last label is
/// one of [`LINK_TLDS`] followed by `/`, `?` or `#` ("x.example/r?a=…", "x.co?ad=…"), or — in a
/// word that also holds a placeholder — ANY dotted host before `/`, `?` or `#`: restoring would
/// put a name into it, so no top-level domain is given the benefit of the doubt there. Citations
/// ("Yargıtay 2.HD/2023-1234", "4721 s.TMK/m.166", "HMK m.119/1"), amounts and dates are not.
fn has_link(s: &str) -> bool {
    let low = s.to_lowercase();
    if low.contains("://") || low.contains("www.") || low.contains("mailto:") {
        return true;
    }
    let host_char = |c: char| c.is_alphanumeric() || c == '-' || c == '.';
    // Start of the whitespace-delimited word around byte `i`, and its end.
    let word_of = |i: usize| {
        let start = low[..i].rfind(char::is_whitespace).map_or(0, |k| k + low[k..].chars().next().map_or(1, char::len_utf8));
        let end = low[i..].find(char::is_whitespace).map_or(low.len(), |k| i + k);
        &low[start..end]
    };
    low.match_indices(['/', '?', '#']).any(|(i, _)| {
        let start = low[..i].char_indices().rev().take_while(|&(_, c)| host_char(c)).last().map_or(i, |(k, _)| k);
        let labels: Vec<&str> = low[start..i].split('.').collect();
        if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
            return false;
        }
        let tld = labels[labels.len() - 1];
        if LINK_TLDS.contains(&tld) {
            return true;
        }
        let word = word_of(i);
        let dotted_word = tld.chars().any(char::is_alphabetic) || labels.iter().any(|l| l.chars().any(char::is_alphabetic));
        dotted_word && !placeholders_in(&word.to_uppercase()).is_empty()
    })
}

/// A `[` that opens something shaped like a placeholder (upper-case letters, an optional `_n`,
/// `]`) which is not one of `found`.
fn lookalike(s: &str, found: &[(std::ops::Range<usize>, sezi_redact::Placeholder)]) -> bool {
    let starts: Vec<usize> = found.iter().map(|(r, _)| r.start).collect();
    for (i, _) in s.match_indices('[') {
        if starts.contains(&i) {
            continue;
        }
        let rest = &s[i + 1..];
        let Some(end) = rest.find(']') else { continue };
        let inner = &rest[..end];
        let (tag, num) = inner.split_once('_').unwrap_or((inner, ""));
        let tag_like = !tag.is_empty() && tag.chars().all(|c| c.is_uppercase());
        let num_like = num.is_empty() || num.chars().all(|c| c.is_ascii_digit());
        if tag_like && num_like && inner.chars().count() <= 12 {
            return true;
        }
    }
    false
}

/// `s` cut to `n` characters, with "…" when it was longer.
pub(super) fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
    out = out.trim_end().to_string();
    out.push('…');
    out
}

#[cfg(test)]
#[path = "hearings_validate_tests.rs"]
mod tests;
