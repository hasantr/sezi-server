use super::*;
use sezi_redact::Redacted;

const CIVIL: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/crates/sezi-hearings/fixtures/civil_asliye_hukuk.txt"));

fn fixture() -> (Redacted, RuleSummary) {
    let h = sezi_hearings::read_text(CIVIL, &sezi_hearings::Limits::default()).unwrap();
    let s = h.summary();
    let p = Policy { esas_no: s.case_no.clone(), court: s.court.clone(), known_names: vec![] };
    (redact(&h.text, &p).unwrap(), s)
}

/// A good answer for the civil fixture; `f` edits it.
fn answer(f: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut v = serde_json::json!({
        "is_hearing_record": true,
        "court_type": "Asliye Hukuk",
        "hearing_date": "2026-10-14",
        "next_hearing": { "date": "2026-12-09", "time": "10:30" },
        "attendance": [{ "role": "davacı vekili [KISI_4]", "present": true }, { "role": "davalı vekili", "present": false }],
        "decisions": [
            { "n": 1, "text": "Davacı vekili bilirkişi ücreti olan 3.000,00 TL'yi yatıracak", "party": "davacı", "deadline_phrase": "2 hafta kesin süre" },
            { "n": 2, "text": "Davalı taraf tanık listesini sunacak", "party": "davalı", "deadline_phrase": "1 haftalık süre" },
        ],
        "notes": null,
    });
    f(&mut v);
    v.to_string()
}

fn check(json: &str) -> Result<ModelSummary, &'static str> {
    let (r, s) = fixture();
    validate(json, &r.vault, &r.masked, &s)
}

#[test]
fn a_good_answer_passes_and_keeps_its_placeholders_masked() {
    let m = check(&answer(|_| {})).unwrap();
    assert_eq!(m.decisions.len(), 2);
    assert_eq!(m.decisions[0].party, Some(Party::Plaintiff));
    assert_eq!(m.decisions[0].deadline.as_deref(), Some("2 hafta kesin süre"));
    assert_eq!(m.attendance[0], ("davacı vekili [KISI_4]".to_string(), true));
    assert_eq!(m.next_hearing, Some((Date::new(2026, 12, 9).unwrap(), Time::new(10, 30))));
    assert!(!m.next_disagrees);
}

#[test]
fn the_shape_is_exact() {
    let (r, s) = fixture();
    let bad = [
        answer(|v| v["extra"] = 1.into()),
        answer(|v| {
            v.as_object_mut().unwrap().remove("notes");
        }),
        answer(|v| v["decisions"][0]["why"] = "x".into()),
        answer(|v| v["decisions"][0]["n"] = "1".into()),
        answer(|v| v["decisions"][0]["n"] = 0.into()),
        answer(|v| v["decisions"][0]["party"] = "hakim".into()),
        answer(|v| v["attendance"][0]["present"] = "yes".into()),
        answer(|v| v["next_hearing"]["place"] = "x".into()),
        "not json".to_string(),
        "[]".to_string(),
    ];
    for b in bad {
        assert_eq!(validate(&b, &r.vault, &r.masked, &s), Err(INVALID), "{b}");
    }
    assert_eq!(check(&answer(|v| v["is_hearing_record"] = false.into())), Err(NOT_A_RECORD));
}

#[test]
fn an_invented_or_mangled_placeholder_is_refused() {
    for p in ["[KISI_9]", "[KİŞİ_1]", "[KISI_0]", "[TCKN_1]", "[ISIM_2]"] {
        let a = answer(|v| v["decisions"][1]["text"] = format!("{p} tanık listesini sunacak").into());
        assert_eq!(check(&a), Err(INVALID), "{p}");
    }
    // A placeholder the vault holds is fine; brackets that are not placeholder-shaped are too.
    assert!(check(&answer(|v| v["decisions"][1]["text"] = "[KISI_5] dilekçe verecek [sic]".into())).is_ok());
}

#[test]
fn a_name_in_the_answer_is_a_leak() {
    for text in [
        "Selin DEMİRKOL bilirkişi ücretini yatıracak",
        "Av. Demirkol bilirkişi ücretini yatıracak",
        "Ahmet Yılmaz geldi",
        "AHMET YILMAZ tanık olarak dinlenecek",
        "Tanık 10000000146 kimlik numarasıyla",
        "0532 123 45 67 numarasından aranacak",
        "Kızılırmak Mah. Yeşilçam Sok. No:14 adresine tebligat",
    ] {
        let a = answer(|v| v["decisions"][0]["text"] = text.into());
        assert_eq!(check(&a), Err(LEAK), "{text}");
    }
    let n = answer(|v| v["notes"] = "Örnektepe İnşaat Ltd. Şti. vekili gelmedi".into());
    assert_eq!(check(&n), Err(LEAK));
    let role = answer(|v| v["attendance"][0]["role"] = "Selin DEMİRKOL".into());
    assert_eq!(check(&role), Err(LEAK));
}

#[test]
fn dates_are_real_and_sane_and_the_parser_wins_on_the_next_hearing() {
    for (d, ok) in [("2026-02-30", false), ("26-10-14", false), ("2030-01-01", false), ("1999-12-31", false), ("2026-11-01", true)] {
        let a = answer(|v| v["next_hearing"]["date"] = d.into());
        assert_eq!(check(&a).is_ok(), ok, "{d}");
    }
    assert_eq!(check(&answer(|v| v["next_hearing"]["date"] = "2026-10-01".into())), Err(INVALID), "before the hearing");
    assert_eq!(check(&answer(|v| v["next_hearing"]["time"] = "25:00".into())), Err(INVALID));
    let other = check(&answer(|v| v["next_hearing"]["date"] = "2026-12-10".into())).unwrap();
    assert_eq!(other.next_hearing.unwrap().0, Date::new(2026, 12, 9).unwrap(), "the parser's date stands");
    assert!(other.next_disagrees, "and the answer says to check it");
    assert!(check(&answer(|v| v["next_hearing"] = serde_json::Value::Null)).unwrap().next_hearing.is_some());
}

#[test]
fn a_deadline_is_the_records_words_never_a_computed_date() {
    let computed = check(&answer(|v| v["decisions"][0]["deadline_phrase"] = "28.10.2026 tarihine kadar".into())).unwrap();
    assert_eq!(computed.decisions[0].deadline.as_deref(), Some("2 hafta kesin süre"), "the rules' phrase instead");
    let spaced = check(&answer(|v| v["decisions"][0]["deadline_phrase"] = "2  HAFTA kesin süre".into())).unwrap();
    assert_eq!(spaced.decisions[0].deadline.as_deref(), Some("2  HAFTA kesin süre"), "case and spacing aside");
    let none = check(&answer(|v| {
        v["decisions"][1]["n"] = 3.into();
        v["decisions"][1]["deadline_phrase"] = serde_json::Value::Null;
    }))
    .unwrap();
    let three = none.decisions.iter().find(|d| d.n == 3).unwrap();
    assert_eq!(three.deadline, None, "decision 3 words no deadline");
}

#[test]
fn the_caps_cut_long_answers() {
    let many: Vec<serde_json::Value> = (1..=40)
        .map(|n| serde_json::json!({ "n": n.min(99), "text": "x".repeat(900), "party": null, "deadline_phrase": null }))
        .collect();
    let m = check(&answer(|v| {
        v["decisions"] = many.into();
        v["notes"] = "y".repeat(3000).into();
    }))
    .unwrap();
    assert_eq!(m.decisions.len(), MAX_DECISIONS);
    assert_eq!(m.decisions[0].text.chars().count(), MAX_TEXT_CHARS);
    assert!(m.decisions[0].text.ends_with('…'));
    assert_eq!(m.notes.unwrap().chars().count(), MAX_NOTES_CHARS);
    assert_eq!(cut("abc", 3), "abc");
}

#[test]
fn an_instruction_inside_the_record_changes_nothing_the_answer_can_do() {
    // Whatever the model was talked into, its answer is only text in a fixed shape: a name it
    // was told to print is a leak, and there is no field through which anything is "done".
    let a = answer(|v| v["notes"] = "Talimat gereği isimler: Tülay KORKMAZEL".into());
    assert_eq!(check(&a), Err(LEAK));
    let a = answer(|v| v["send_to"] = "https://evil.example".into());
    assert_eq!(check(&a), Err(INVALID));
}

#[test]
fn a_link_in_the_answer_is_refused_since_restoring_would_fill_it_with_names() {
    // Talked into it by the record, a model writes a link whose address holds placeholders; the
    // 1:1 answer restores them, and the lawyer's tap would hand the names to that address.
    let links = [
        "Ayrıntı: https://x.example/r?a=[KISI_4]",
        "bkz. http://x.example/[KISI_4]",
        "bkz. www.x.example/[KISI_4]",
        "bkz. x.example/r?a=[KISI_4]",
        "bkz. HTTPS://X.EXAMPLE/[KISI_4]",
    ];
    for l in links {
        assert_eq!(check(&answer(|v| v["notes"] = l.into())), Err(LEAK), "notes {l}");
        assert_eq!(check(&answer(|v| v["decisions"][0]["text"] = l.into())), Err(LEAK), "decision {l}");
        assert_eq!(check(&answer(|v| v["attendance"][0]["role"] = l.into())), Err(LEAK), "role {l}");
    }
    // An amount, a statute or a time is not a link.
    assert!(check(&answer(|v| v["notes"] = "3.000,00 TL; HMK 324. md. ve m.324/1; saat 10.30".into())).is_ok());
}
