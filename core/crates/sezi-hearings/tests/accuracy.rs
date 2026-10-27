//! The truth of each fake record, written by hand from the fixture (not from the parser's output,
//! which `parse.json` snapshots): the fields the bot answers with and the sheet keys on. A miss
//! here is a parser bug, whatever `parse.json` says.

use std::path::Path;

use sezi_hearings::{read_text, Limits, RuleSummary};

struct Truth {
    name: &'static str,
    court: &'static str,
    criminal: bool,
    case_no: &'static str,
    hearing: &'static str,
    hearing_time: Option<&'static str>,
    next: &'static str,
    next_time: Option<&'static str>,
    decisions: usize,
    deadlines: &'static [&'static str],
    /// (present, absent) attendance statements
    attendance: (usize, usize),
}

const TRUTH: [Truth; 7] = [
    Truth {
        name: "civil_asliye_hukuk",
        court: "Ankara 3. Asliye Hukuk Mahkemesi",
        criminal: false,
        case_no: "2024/123",
        hearing: "2026-10-14",
        hearing_time: Some("10:30"),
        next: "2026-12-09",
        next_time: Some("10:30"),
        decisions: 4,
        deadlines: &["2 hafta kesin süre", "1 haftalık süre"],
        attendance: (1, 1),
    },
    Truth {
        name: "labour_is",
        court: "İstanbul Anadolu 12. İş Mahkemesi",
        criminal: false,
        case_no: "2025/4471",
        hearing: "2026-10-27",
        hearing_time: Some("09:40"),
        next: "2027-01-18",
        next_time: Some("11:15"),
        decisions: 4,
        deadlines: &["iki haftalık kesin süre", "1 ay süre"],
        attendance: (2, 0),
    },
    Truth {
        name: "family_aile",
        court: "Iğdır 1. Aile Mahkemesi",
        criminal: false,
        case_no: "2026/58",
        hearing: "2026-10-27",
        hearing_time: Some("14:00"),
        next: "2026-12-03",
        next_time: Some("10:00"),
        decisions: 3,
        deadlines: &["on gün süre"],
        attendance: (3, 0),
    },
    Truth {
        name: "enforcement_icra_hukuk",
        court: "Bursa 2. İcra Hukuk Mahkemesi",
        criminal: false,
        case_no: "2025/771",
        hearing: "2026-11-05",
        hearing_time: None,
        next: "2026-12-17",
        next_time: Some("09:30"),
        decisions: 4,
        deadlines: &["7 günlük kesin süre"],
        attendance: (1, 1),
    },
    Truth {
        name: "criminal_agir_ceza",
        court: "İzmir 7. Ağır Ceza Mahkemesi",
        criminal: true,
        case_no: "2025/309",
        hearing: "2026-10-22",
        hearing_time: None,
        next: "2027-01-15",
        next_time: Some("09:45"),
        decisions: 4,
        deadlines: &["10 gün süre"],
        // sanık (SEGBİS), müdafi, katılan vekili, C. savcısı present; katılan, tanık absent
        attendance: (4, 2),
    },
    Truth {
        name: "civil_split_labels",
        court: "Eskişehir 2. Sulh Hukuk Mahkemesi",
        criminal: false,
        case_no: "2026/915",
        hearing: "2026-10-21",
        hearing_time: None,
        next: "2026-12-02",
        next_time: Some("14:15"),
        decisions: 3,
        deadlines: &["iki haftalık kesin süre"],
        attendance: (1, 1),
    },
    Truth {
        name: "consumer_mixed_case",
        court: "Antalya 4. Tüketici Mahkemesi",
        criminal: false,
        case_no: "2026/77",
        hearing: "2026-11-09",
        hearing_time: None,
        next: "2027-01-20",
        next_time: Some("10:00"),
        decisions: 3,
        deadlines: &["2 haftalık kesin süre"],
        attendance: (1, 0),
    },
];

/// Written AFTER the parser, in other wordings, and run once before any fix: the first run's
/// score is the honest one (reported in the H2 hand-over), the fixes that followed are below.
const HELDOUT: [Truth; 3] = [
    Truth {
        name: "heldout_commercial",
        court: "İstanbul 9. Asliye Ticaret Mahkemesi",
        criminal: false,
        case_no: "2023/612",
        hearing: "2026-10-16",
        hearing_time: None,
        next: "2026-11-26",
        next_time: Some("11:00"),
        decisions: 3,
        deadlines: &["15 günlük süre", "bir haftalık kesin mehil"],
        attendance: (2, 0),
    },
    Truth {
        name: "heldout_criminal_asliye",
        court: "Ankara Batı 4. Asliye Ceza Mahkemesi",
        criminal: true,
        case_no: "2026/1188",
        hearing: "2026-10-08",
        hearing_time: None,
        next: "2027-02-12",
        next_time: Some("09:00"),
        decisions: 3,
        deadlines: &["30 gün içinde"],
        attendance: (3, 1),
    },
    Truth {
        name: "heldout_pasted",
        court: "Kocaeli 1. Kadastro Mahkemesi",
        criminal: false,
        case_no: "2026/33",
        hearing: "2026-11-03",
        hearing_time: Some("10:20"),
        next: "2027-01-21",
        next_time: Some("13:30"),
        decisions: 2,
        deadlines: &["2 hafta içinde"],
        attendance: (1, 1),
    },
];

fn summary(name: &str) -> RuleSummary {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(format!("{name}.txt"));
    let text = std::fs::read_to_string(path).unwrap();
    read_text(&text, &Limits::default()).unwrap().summary()
}

#[test]
fn every_field_of_every_record() {
    check(&TRUTH);
}

#[test]
fn every_field_of_the_held_out_records() {
    check(&HELDOUT);
}

fn check(truth: &[Truth]) {
    let mut fields = 0;
    let mut wrong = Vec::new();
    for t in truth {
        let s = summary(t.name);
        let next = s.next_hearing.map(|n| (n.date.iso(), n.time.map(|x| x.hhmm())));
        let deadlines: Vec<String> = s.decisions.iter().flat_map(|d| d.deadlines.clone()).collect();
        let present = s.attendance.iter().filter(|a| a.present).count();
        let absent = s.attendance.len() - present;
        let checks: [(&str, bool); 10] = [
            ("court", s.court.as_deref() == Some(t.court)),
            ("criminal", s.criminal == t.criminal),
            ("case_no", s.case_no.as_deref() == Some(t.case_no)),
            ("hearing", s.hearing_date.map(|d| d.iso()).as_deref() == Some(t.hearing)),
            ("hearing_time", s.hearing_time.map(|x| x.hhmm()).as_deref() == t.hearing_time),
            ("next", next.as_ref().map(|n| n.0.as_str()) == Some(t.next)),
            ("next_time", next.as_ref().and_then(|n| n.1.as_deref()) == t.next_time),
            ("decisions", s.decisions.len() == t.decisions),
            ("deadlines", deadlines == t.deadlines),
            ("attendance", (present, absent) == t.attendance),
        ];
        for (field, ok) in checks {
            fields += 1;
            if !ok {
                wrong.push(format!("{}: {field}", t.name));
            }
        }
        // Every decision is numbered 1..n, and exactly one sets the next hearing.
        assert!(s.decisions.iter().enumerate().all(|(i, d)| d.n as usize == i + 1), "{}", t.name);
        assert_eq!(s.decisions.iter().filter(|d| d.sets_next_hearing).count(), 1, "{}", t.name);
        assert!(s.missing.is_empty(), "{}: {:?}", t.name, s.missing);
    }
    eprintln!("{} of {fields} fields right", fields - wrong.len());
    assert!(wrong.is_empty(), "{wrong:#?}");
}
