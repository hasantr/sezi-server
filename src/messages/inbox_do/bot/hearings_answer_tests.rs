use super::super::hearings_validate::ModelDecision;
use super::*;
use sezi_redact::{redact, Policy, Redacted};

const CIVIL: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/crates/sezi-hearings/fixtures/civil_asliye_hukuk.txt"));

fn fixture() -> (Redacted, RuleSummary) {
    let h = sezi_hearings::read_text(CIVIL, &sezi_hearings::Limits::default()).unwrap();
    let s = h.summary();
    let p = Policy { esas_no: s.case_no.clone(), court: s.court.clone(), known_names: vec![] };
    (redact(&h.text, &p).unwrap(), s)
}

fn model() -> ModelSummary {
    ModelSummary {
        hearing_date: None,
        next_hearing: Some((Date::new(2026, 12, 9).unwrap(), Time::new(10, 30))),
        next_disagrees: true,
        attendance: vec![("davacı vekili [KISI_4]".into(), true), ("davalı vekili".into(), false)],
        decisions: vec![
            ModelDecision {
                n: 1,
                text: "[KISI_4] bilirkişi ücreti 3.000 TL'yi yatıracak, [ESAS] dosyasında".into(),
                party: Some(Party::Plaintiff),
                deadline: Some("2 hafta kesin süre".into()),
            },
            ModelDecision { n: 2, text: "[SIRKET_1] tanık listesi sunacak".into(), party: Some(Party::Defendant), deadline: None },
        ],
        notes: Some("[KISI_5] gelmedi".into()),
    }
}

#[test]
fn the_lawyer_gets_the_names_back_and_the_plans_layout() {
    let (r, s) = fixture();
    let m = model();
    let v = View { rules: &s, model: Some(&m), vault: Some(&r.vault) };
    let text = one_to_one(Lang::Tr, &v, None, Some("2024/123"));
    let want = [
        "Ankara 3. Asliye Hukuk Mahkemesi · 2024/123 E. · duruşma 14.10.2026",
        "Sonraki duruşma: 09.12.2026 10:30 (kontrol edin)",
        "Ara karar:",
        "1. Davacı: Selin DEMİRKOL bilirkişi ücreti 3.000 TL'yi yatıracak, 2024/123 dosyasında — 2 hafta kesin süre",
        "2. Davalı: Örnektepe İnşaat Ltd. Şti tanık listesi sunacak",
        "Katılım: davacı vekili Selin DEMİRKOL geldi · davalı vekili gelmedi",
        "Not: Kemalettin ARSLANCI gelmedi",
        "",
        "Tabloya yazayım mı? (2024/123 satırı varsa güncellenir, yoksa eklenir) evet / hayır",
    ]
    .join("\n");
    assert_eq!(text, want);
    let en = one_to_one(Lang::En, &v, Some(Line::HearingsSummaryFailed), None);
    assert!(en.starts_with("The summary couldn't be made right now"));
    assert!(en.contains("Next hearing: 09.12.2026 10:30 (please check)") && en.contains("Attendance: "));
}

#[test]
fn the_rules_alone_answer_with_the_records_own_words() {
    let (r, s) = fixture();
    let v = View { rules: &s, model: None, vault: Some(&r.vault) };
    let text = one_to_one(Lang::Tr, &v, Some(Line::HearingsCriminal), None);
    assert!(text.starts_with("Ceza dosyası: yapay zekâya gönderilmedi"));
    assert!(text.contains("1. Davacı vekiline bilirkişi ücreti olan 3.000,00 TL'yi yatırması için 2 hafta kesin süre"));
    assert!(text.contains("2. Davalı tarafa tanık listesini sunması için 1 haftalık süre verilmesine"));
    assert!(!text.contains("4. Duruşmanın"), "the next hearing is its own line");
    assert!(text.contains("Katılım: davacı vekili geldi · davalı vekili gelmedi"));
    assert_eq!(role_label(Lang::En, Role::Counsel, Some(Role::Plaintiff)), "plaintiff's counsel");
    assert_eq!(role_label(Lang::Tr, Role::DefenceCounsel, Some(Role::Accused)), "sanık müdafii");
}

#[test]
fn the_sheet_row_carries_roles_not_people() {
    let (r, s) = fixture();
    let m = model();
    let cols = Columns::defaults(Lang::Tr);
    let v = View { rules: &s, model: Some(&m), vault: Some(&r.vault) };
    let u = sheet_row(Lang::Tr, &cols, &v, &[], "Deneme Üye", 1_761_523_200_000).unwrap();
    assert_eq!(u.key.0, vec![("Mahkeme".into(), "Ankara 3. Asliye Hukuk Mahkemesi".into()), ("Esas No".into(), "2024/123".into())]);
    let cells: std::collections::HashMap<_, _> = u.row.0.iter().cloned().collect();
    assert_eq!(cells["Duruşma Tarihi"], "14.10.2026");
    assert_eq!(cells["Sonraki Duruşma"], "09.12.2026 10:30");
    assert_eq!(cells["Avukat"], "Deneme Üye");
    assert_eq!(cells["Güncelleme"], "27.10.2025");
    assert_eq!(
        cells["Ara Karar"],
        "1. Davacı: (kişi) bilirkişi ücreti 3.000 TL'yi yatıracak, 2024/123 dosyasında — 2 hafta kesin süre\n2. Davalı: (şirket) tanık listesi sunacak"
    );
    for (_, value) in r.vault.iter().filter(|(p, _)| !matches!(p.category, Category::Esas | Category::Mahkeme)) {
        assert!(!serde_json::to_string(&u.row).unwrap().contains(value), "{value}");
    }
    // No court or no esas no: no row to find or add.
    let mut no_court = s.clone();
    no_court.court = None;
    assert!(sheet_row(Lang::Tr, &cols, &View { rules: &no_court, model: Some(&m), vault: Some(&r.vault) }, &[], "x", 0).is_none());
    // No vault (masking refused): no row.
    assert!(sheet_row(Lang::Tr, &cols, &View { rules: &s, model: None, vault: None }, &[], "x", 0).is_none());
}

#[test]
fn a_cell_that_still_carries_a_vault_value_is_not_written() {
    let (r, s) = fixture();
    let mut m = model();
    m.decisions[1].text = "Selin DEMİRKOL tanık listesi sunacak".into(); // as if a check had missed it
    let v = View { rules: &s, model: Some(&m), vault: Some(&r.vault) };
    let u = sheet_row(Lang::Tr, &Columns::defaults(Lang::Tr), &v, &[], "x", 0).unwrap();
    assert_eq!(u.row.0.iter().find(|(k, _)| k == "Ara Karar").unwrap().1, "");
}

#[test]
fn a_long_answer_goes_in_whole_lines_and_keeps_its_question() {
    let body: Vec<String> = (0..300).map(|i| format!("{i}. {}", "söz ".repeat(10))).collect();
    let text = format!("{}\n\nTabloya yazayım mı? evet / hayır", body.join("\n"));
    let parts = messages(&text, 4000);
    assert!(parts.len() >= 4);
    assert!(parts.iter().all(|p| p.chars().count() <= 4000));
    assert!(parts.last().unwrap().ends_with("Tabloya yazayım mı? evet / hayır"));
    let lines = |s: &str| s.lines().map(str::trim_end).filter(|l| !l.is_empty()).map(str::to_string).collect::<Vec<_>>();
    assert_eq!(lines(&parts.join("\n")), lines(&text), "every line, once, in order");
    assert_eq!(messages("kısa", 4000), vec!["kısa".to_string()]);
}

#[test]
fn days_are_utc_civil_dates() {
    assert_eq!(day(today(0)), "01.01.1970");
    assert_eq!(day(today(1_761_523_200_000)), "27.10.2025");
    assert_eq!(day(today(951_782_400_000)), "29.02.2000");
}
