//! The rule-only summary (docs/HEARINGS_BOT_PLAN.md §1.1 step 3): the header, the next hearing,
//! the numbered decisions and who came, as typed data with no spans. It is what the bot answers
//! with when no model is configured (`ai: false`), when the case is criminal (decision 3), and
//! when the model call fails; and what the model's answer is checked against (§5.4).
//!
//! Decision texts still carry names. Where they may go (only to the lawyer, 1:1) is the runner's
//! rule, not this crate's.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{CourtKind, Date, Record, Role, Time};

/// A field the rules looked for. [`RuleSummary::missing`] lists those not found, so the runner can
/// say "esas no bulunamadı" without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    CaseNo,
    Court,
    HearingDate,
    NextHearing,
    Decisions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NextHearing {
    pub date: Date,
    pub time: Option<Time>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionLine {
    pub n: u32,
    pub text: String,
    pub first_role: Option<Role>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_role_of: Option<Role>,
    /// Each deadline's phrase as worded. Never a computed date.
    pub deadlines: Vec<String>,
    pub sets_next_hearing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AttendanceLine {
    pub role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub of: Option<Role>,
    pub present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RoleCount {
    pub role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub of: Option<Role>,
    pub count: u32,
}

/// What the rules alone say about a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleSummary {
    /// `Ankara 3. Asliye Hukuk Mahkemesi` — with the esas no, the sheet's key.
    pub court: Option<String>,
    pub court_kind: Option<CourtKind>,
    /// A criminal court (decision 3: the rule-only path).
    pub criminal: bool,
    /// `2024/123`
    pub case_no: Option<String>,
    pub decision_no: Option<String>,
    pub session_no: Option<u32>,
    pub hearing_date: Option<Date>,
    pub hearing_time: Option<Time>,
    pub next_hearing: Option<NextHearing>,
    pub decisions: Vec<DecisionLine>,
    pub attendance: Vec<AttendanceLine>,
    /// How many parties of each role the header (and the body's witness/expert lines) name.
    pub roles: Vec<RoleCount>,
    pub missing: Vec<Field>,
}

impl RuleSummary {
    pub fn of(r: &Record) -> Self {
        let mut counts: BTreeMap<(Role, Option<Role>), u32> = BTreeMap::new();
        for p in &r.parties {
            *counts.entry((p.role, p.of)).or_default() += 1;
        }
        let mut missing = Vec::new();
        if r.case_no.is_none() {
            missing.push(Field::CaseNo);
        }
        if r.court.is_none() {
            missing.push(Field::Court);
        }
        if r.hearing.is_none() {
            missing.push(Field::HearingDate);
        }
        if r.next_hearing.is_none() {
            missing.push(Field::NextHearing);
        }
        if r.decisions.is_empty() {
            missing.push(Field::Decisions);
        }
        Self {
            court: r.court.as_ref().map(|c| c.name.clone()),
            court_kind: r.court.as_ref().map(|c| c.kind),
            criminal: r.court.as_ref().is_some_and(|c| c.kind.is_criminal()),
            case_no: r.case_no.map(|n| n.value.to_string()),
            decision_no: r.decision_no.map(|n| n.value.to_string()),
            session_no: r.session_no,
            hearing_date: r.hearing.map(|w| w.date),
            hearing_time: r.hearing.and_then(|w| w.time),
            next_hearing: r.next_hearing.map(|w| NextHearing { date: w.date, time: w.time }),
            decisions: r
                .decisions
                .iter()
                .map(|d| DecisionLine {
                    n: d.n,
                    text: d.text.clone(),
                    first_role: d.first_role,
                    first_role_of: d.first_role_of,
                    deadlines: d.deadlines.iter().map(|x| x.phrase.clone()).collect(),
                    sets_next_hearing: d.sets_next_hearing,
                })
                .collect(),
            attendance: r
                .attendance
                .iter()
                .map(|a| AttendanceLine { role: a.role, of: a.of, present: a.present })
                .collect(),
            roles: counts.into_iter().map(|((role, of), count)| RoleCount { role, of, count }).collect(),
            missing,
        }
    }
}
