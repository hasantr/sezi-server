//! What the hearings bot says and writes (docs/HEARINGS_BOT_PLAN.md §1.1 step 6, §4.6, §6.3),
//! built from the rules' reading and, when there is one, the model's checked answer. Pure.
//!
//! - **The 1:1 answer** to the lawyer carries the real names: every placeholder the vault holds
//!   is restored (`sezi_redact::restore`). It goes nowhere else.
//! - **The sheet row** carries roles: only `[ESAS]` and `[MAHKEME]` come back; every other
//!   placeholder becomes a neutral word ("(kişi)"), and the cell is leak-checked once more. The
//!   key — court and esas no — comes from the rules alone, and goes only to the office's own
//!   sheet, which needs it to find the row.
//! - **Deadlines** are the record's words, never a computed end date (tebliğ decides when one
//!   starts, and the minutes do not settle it).
//!
//! Labels (roles, "Sonraki duruşma") are here, in Turkish and English, because the relay is the
//! speaker and no app translates a built-in bot's message; whole sentences are `builtin_copy.rs`.

use super::builtin_copy::{line, Line};
use super::builtin_sheet::{Row, Upsert};
use super::hearings_validate::{cut, ModelSummary, Party};
use crate::bots::builtin_hearings_rules::Columns;
use crate::bots::builtin_rules::Lang;
use sezi_hearings::{Date, Role, RuleSummary, Time};
use sezi_redact::{leak_check_with, placeholders_in, restore, restore_only, Category, Vault};

/// A decisions cell, at most (characters). Google allows 50,000; a row should stay readable.
pub(super) const MAX_DECISIONS_CELL: usize = 2000;

fn tr(lang: Lang) -> bool {
    lang == Lang::Tr
}

/// `dd.mm.yyyy`, as Turkish offices write a date.
pub(super) fn day(d: Date) -> String {
    format!("{:02}.{:02}.{:04}", d.day, d.month, d.year)
}

fn when(d: Date, t: Option<Time>) -> String {
    match t {
        Some(t) => format!("{} {}", day(d), t.hhmm()),
        None => day(d),
    }
}

/// The UTC day of `ms` (the relay does not know the member's zone).
pub(super) fn today(ms: i64) -> Date {
    let days = ms.div_euclid(86_400_000);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm, as `builtin_ai`).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    Date { year: y as u16, month: m as u8, day: d as u8 }
}

/// A role as a lawyer says it ("davacı vekili", "plaintiff's counsel").
pub(super) fn role_label(lang: Lang, role: Role, of: Option<Role>) -> String {
    let base = |r: Role| -> &'static str {
        let (t, e) = match r {
            Role::Plaintiff => ("davacı", "plaintiff"),
            Role::Defendant => ("davalı", "defendant"),
            Role::Counsel => ("vekil", "counsel"),
            Role::Accused => ("sanık", "accused"),
            Role::DefenceCounsel => ("müdafi", "defence counsel"),
            Role::JoinedParty => ("katılan", "joined party"),
            Role::Complainant => ("müşteki", "complainant"),
            Role::Victim => ("mağdur", "victim"),
            Role::Witness => ("tanık", "witness"),
            Role::Expert => ("bilirkişi", "expert"),
            Role::Interpreter => ("tercüman", "interpreter"),
            Role::NotifiedParty => ("ihbar olunan", "notified party"),
            Role::Intervener => ("fer'i müdahil", "intervener"),
            Role::Creditor => ("alacaklı", "creditor"),
            Role::Debtor => ("borçlu", "debtor"),
            Role::Guardian => ("veli/vasi", "guardian"),
            Role::BothParties => ("taraflar", "the parties"),
            Role::Judge => ("hâkim", "judge"),
            Role::PresidingJudge => ("başkan", "presiding judge"),
            Role::MemberJudge => ("üye hâkim", "member judge"),
            Role::Clerk => ("kâtip", "clerk"),
            Role::Prosecutor => ("savcı", "prosecutor"),
        };
        if tr(lang) {
            t
        } else {
            e
        }
    };
    match (role, of) {
        (Role::Counsel, Some(p)) if tr(lang) => format!("{} vekili", base(p)),
        (Role::DefenceCounsel, Some(p)) if tr(lang) => format!("{} müdafii", base(p)),
        (Role::Counsel | Role::DefenceCounsel, Some(p)) => format!("{}'s {}", base(p), base(role)),
        _ => base(role).to_string(),
    }
}

fn party_label(lang: Lang, p: Party) -> &'static str {
    match (tr(lang), p) {
        (true, Party::Plaintiff) => "Davacı",
        (true, Party::Defendant) => "Davalı",
        (true, Party::Court) => "Mahkeme",
        (true, Party::Expert) => "Bilirkişi",
        (true, Party::Witness) => "Tanık",
        (true, Party::Other) => "Diğer",
        (false, Party::Plaintiff) => "Plaintiff",
        (false, Party::Defendant) => "Defendant",
        (false, Party::Court) => "Court",
        (false, Party::Expert) => "Expert",
        (false, Party::Witness) => "Witness",
        (false, Party::Other) => "Other",
    }
}

/// One decision line from parts: "1. Davacı: … — iki haftalık kesin süre".
fn decision_line(n: u32, party: Option<&str>, text: &str, deadline: Option<&str>) -> String {
    let mut s = format!("{n}. ");
    if let Some(p) = party {
        s.push_str(p);
        s.push_str(": ");
    }
    s.push_str(text);
    if let Some(d) = deadline.filter(|d| !d.is_empty() && !text.contains(*d)) {
        s.push_str(" — ");
        s.push_str(d);
    }
    s
}

/// What the answer is made from.
pub(super) struct View<'a> {
    pub(super) rules: &'a RuleSummary,
    /// The model's checked answer (masked), when the model path ran and passed.
    pub(super) model: Option<&'a ModelSummary>,
    /// The record's vault, when masking succeeded.
    pub(super) vault: Option<&'a Vault>,
}

impl View<'_> {
    fn next(&self) -> Option<(Date, Option<Time>)> {
        self.model.and_then(|m| m.next_hearing).or(self.rules.next_hearing.map(|n| (n.date, n.time)))
    }

    fn hearing(&self) -> Option<Date> {
        self.rules.hearing_date.or(self.model.and_then(|m| m.hearing_date))
    }
}

/// The 1:1 answer to the lawyer, names restored. `note` heads it (why the model did not run);
/// `ask` ends it with the sheet question for that esas no.
pub(super) fn one_to_one(lang: Lang, v: &View<'_>, note: Option<Line>, ask: Option<&str>) -> String {
    let mut out: Vec<String> = Vec::new();
    if let Some(n) = note {
        out.push(line(lang, n).to_string());
    }
    let mut head: Vec<String> = Vec::new();
    if let Some(c) = &v.rules.court {
        head.push(c.clone());
    }
    if let Some(e) = &v.rules.case_no {
        head.push(if tr(lang) { format!("{e} E.") } else { format!("case {e}") });
    }
    if let Some(d) = v.hearing() {
        head.push(format!("{} {}", if tr(lang) { "duruşma" } else { "hearing" }, day(d)));
    }
    if !head.is_empty() {
        out.push(head.join(" · "));
    }
    if let Some((d, t)) = v.next() {
        let check = v.model.is_some_and(|m| m.next_disagrees);
        let label = if tr(lang) { "Sonraki duruşma" } else { "Next hearing" };
        let mut s = format!("{label}: {}", when(d, t));
        if check {
            s.push_str(if tr(lang) { " (kontrol edin)" } else { " (please check)" });
        }
        out.push(s);
    }
    let restored = |s: &str| v.vault.map_or_else(|| s.to_string(), |vault| restore(s, vault));
    let decisions: Vec<String> = match v.model {
        Some(m) => m
            .decisions
            .iter()
            .map(|d| {
                let text = restored(&d.text);
                let deadline = d.deadline.as_deref().map(restored);
                decision_line(d.n, d.party.map(|p| party_label(lang, p)), &text, deadline.as_deref())
            })
            .collect(),
        None => v
            .rules
            .decisions
            .iter()
            .filter(|d| !d.sets_next_hearing)
            .take(super::hearings_validate::MAX_DECISIONS)
            .map(|d| decision_line(d.n, None, &cut(&d.text, 500), d.deadlines.first().map(String::as_str)))
            .collect(),
    };
    if !decisions.is_empty() {
        out.push(format!("{}:", if tr(lang) { "Ara karar" } else { "Interim decisions" }));
        out.extend(decisions);
    }
    let (came, absent) = if tr(lang) { ("geldi", "gelmedi") } else { ("present", "absent") };
    let attendance: Vec<String> = match v.model.filter(|m| !m.attendance.is_empty()) {
        Some(m) => m.attendance.iter().map(|(r, p)| format!("{} {}", restored(r), if *p { came } else { absent })).collect(),
        None => v
            .rules
            .attendance
            .iter()
            .map(|a| format!("{} {}", role_label(lang, a.role, a.of), if a.present { came } else { absent }))
            .collect(),
    };
    if !attendance.is_empty() {
        out.push(format!("{}: {}", if tr(lang) { "Katılım" } else { "Attendance" }, attendance.join(" · ")));
    }
    if let Some(n) = v.model.and_then(|m| m.notes.as_deref()) {
        out.push(format!("{}: {}", if tr(lang) { "Not" } else { "Note" }, restored(n)));
    }
    if let Some(esas) = ask {
        out.push(String::new());
        out.push(line(lang, Line::HearingsAskSheet).replace("{esas}", esas));
    }
    out.join("\n")
}

/// An answer as the messages it is sent in: whole lines, each message at most `max` characters,
/// so the closing question is never the part cut off (a line longer than `max` alone is cut).
pub(super) fn messages(text: &str, max: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for l in text.lines() {
        let l = cut(l, max);
        let need = cur.chars().count() + l.chars().count() + usize::from(!cur.is_empty());
        if need > max && !cur.is_empty() {
            out.push(std::mem::take(&mut cur).trim_end().to_string());
        }
        if !cur.is_empty() {
            cur.push('\n');
        }
        cur.push_str(&l);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim_end().to_string());
    }
    out
}

/// A masked text with roles where persons were: every placeholder but `[ESAS]` / `[MAHKEME]`
/// becomes a neutral word (those two are restored by [`sheet_row`], after its leak check).
pub(super) fn roles_only(lang: Lang, s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev = 0;
    for (r, p) in placeholders_in(s) {
        if matches!(p.category, Category::Esas | Category::Mahkeme) {
            continue;
        }
        out.push_str(&s[prev..r.start]);
        out.push_str(match (tr(lang), p.category) {
            (true, Category::Kisi) => "(kişi)",
            (true, Category::Sirket) => "(şirket)",
            (true, Category::Adres) => "(adres)",
            (true, _) => "(gizli)",
            (false, Category::Kisi) => "(person)",
            (false, Category::Sirket) => "(company)",
            (false, Category::Adres) => "(address)",
            (false, _) => "(redacted)",
        });
        prev = r.end;
    }
    out.push_str(&s[prev..]);
    out
}

/// The row the office's sheet gets (§6.3): the key, and role-only fields. `masked_rule_decisions`
/// are the rules' decisions, each masked on its own, for when the model did not run (`None` for
/// one that would not mask: it is left out). `None` when the rules found no court or no esas no:
/// there is no row to find or make.
pub(super) fn sheet_row(
    lang: Lang,
    cols: &Columns,
    v: &View<'_>,
    masked_rule_decisions: &[Option<String>],
    lawyer: &str,
    now_ms: i64,
) -> Option<Upsert> {
    let (court, esas) = (v.rules.court.as_ref()?, v.rules.case_no.as_ref()?);
    let vault = v.vault?;
    let key = Row(vec![(cols.court.clone(), court.clone()), (cols.esas.clone(), esas.clone())]);
    let lines: Vec<String> = match v.model {
        Some(m) => m
            .decisions
            .iter()
            .map(|d| {
                let deadline = d.deadline.as_deref().map(|x| roles_only(lang, x));
                decision_line(d.n, d.party.map(|p| party_label(lang, p)), &roles_only(lang, &d.text), deadline.as_deref())
            })
            .collect(),
        None => v
            .rules
            .decisions
            .iter()
            .zip(masked_rule_decisions)
            .filter(|(d, _)| !d.sets_next_hearing)
            .filter_map(|(d, m)| Some(decision_line(d.n, None, &roles_only(lang, &cut(m.as_ref()?, 500)), None)))
            .collect(),
    };
    let decisions = cut(&lines.join("\n"), MAX_DECISIONS_CELL);
    // The last net, before the esas no and the court come back: a cell that still carries a
    // vault value (or any tier 1–2 hit) is not written at all.
    let decisions = match leak_check_with(&decisions, vault) {
        Ok(()) => restore_only(&decisions, vault, &[Category::Esas, Category::Mahkeme]),
        Err(_) => String::new(),
    };
    let row = Row(vec![
        (cols.hearing.clone(), v.hearing().map(day).unwrap_or_default()),
        (cols.next.clone(), v.next().map(|(d, t)| when(d, t)).unwrap_or_default()),
        (cols.decisions.clone(), decisions),
        (cols.lawyer.clone(), lawyer.trim().to_string()),
        (cols.updated.clone(), day(today(now_ms))),
    ]);
    Some(Upsert { key, row })
}

#[cfg(test)]
#[path = "hearings_answer_tests.rs"]
mod tests;
