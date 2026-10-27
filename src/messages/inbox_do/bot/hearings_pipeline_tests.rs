//! The hearings bot's whole round against a stub model and a stub sheet (docs/HEARINGS_BOT_PLAN.md
//! §9 "Worker tests"): the same `read` → model → `finish` → upsert body the inbox runs, with the
//! two network calls answered here. What the round does in the Durable Object around these
//! steps (D1, the store, sending) cannot run on the host; everything that decides what LEAVES
//! the relay is here.
//!
//! Inputs are fake: `sezi-hearings`' fixtures and `sezi-redact`'s golden set (invented names,
//! made-up numbers). The golden marks (`{{KISI:…}}`) name what must never reach the model.

use super::super::builtin_sheet::{body_v2_json, judge_upsert, Landed};
use super::*;
use crate::bots::builtin_hearings_rules::validate as validate_rules;
use std::cell::RefCell;

const CORE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../core/crates");

fn file(rel: &str) -> Vec<u8> {
    std::fs::read(format!("{CORE}/{rel}")).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn cfg(extra: serde_json::Value) -> HearingsConfig {
    let mut h = serde_json::json!({ "allowed_room": "r1" });
    for (k, v) in extra.as_object().unwrap() {
        h[k] = v.clone();
    }
    validate_rules(Some(serde_json::from_value(h).unwrap()), None, Lang::Tr, false).unwrap().config
}

/// A golden minute's text, what its marks say must never reach the model (whole values, and each
/// word of a person's or company's name of four letters or more: surnames recur alone), and the
/// part of that the sheet row may not carry either (all but the esas no and the court's place,
/// which the office's own sheet gets back, §4.6).
fn golden(name: &str) -> (String, Vec<String>, Vec<String>) {
    let raw = String::from_utf8(file(&format!("sezi-redact/tests/golden/{name}.zabit"))).unwrap();
    let raw: String = raw.lines().filter(|l| !l.starts_with("#!")).collect::<Vec<_>>().join("\n");
    let (mut text, mut forbidden, mut row) = (String::new(), Vec::new(), Vec::new());
    let mut rest = raw.as_str();
    while let Some(i) = rest.find("{{") {
        text.push_str(&rest[..i]);
        let j = rest[i..].find("}}").unwrap() + i;
        let (tag, value) = rest[i + 2..j].split_once(':').unwrap();
        assert!(!value.starts_with('@'), "a generated mark: pick a golden file without one");
        text.push_str(value);
        let mut add = |v: &str| {
            forbidden.push(v.to_string());
            if !matches!(tag, "ESAS" | "MAHKEME") {
                row.push(v.to_string());
            }
        };
        if value.chars().count() >= 3 {
            add(value);
        }
        if matches!(tag, "KISI" | "SIRKET") {
            for w in value.split(|c: char| !c.is_alphabetic()).filter(|w| w.chars().count() >= 4) {
                add(w);
            }
        }
        rest = &rest[j + 2..];
    }
    text.push_str(rest);
    // Words that are also procedural vocabulary are not names to look for.
    let vocabulary = |w: &String| !["İNŞAAT", "TİCARET", "Şirketi", "LTD.", "ŞTİ."].contains(&w.as_str());
    forbidden.retain(vocabulary);
    row.retain(vocabulary);
    (text, forbidden, row)
}

/// The stub model: records what it was sent, answers a valid summary that uses the first person
/// placeholder of the record it got.
/// What the stub model answers a request with: (status, body).
type Reply = Box<dyn Fn(&serde_json::Value) -> (u16, String)>;

struct StubModel {
    seen: RefCell<Vec<String>>,
    reply: Reply,
}

impl StubModel {
    fn good() -> Self {
        StubModel { seen: RefCell::new(Vec::new()), reply: Box::new(good_reply) }
    }

    fn with(reply: impl Fn(&serde_json::Value) -> (u16, String) + 'static) -> Self {
        StubModel { seen: RefCell::new(Vec::new()), reply: Box::new(reply) }
    }

    fn call(&self, body: &serde_json::Value) -> (u16, String) {
        self.seen.borrow_mut().push(body.to_string());
        (self.reply)(body)
    }
}

fn anthropic(json: &serde_json::Value) -> String {
    serde_json::json!({
        "content": [{ "type": "text", "text": json.to_string() }],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 1500, "output_tokens": 420 },
    })
    .to_string()
}

fn good_reply(body: &serde_json::Value) -> (u16, String) {
    let user = body["messages"][0]["content"].as_str().unwrap();
    let person = sezi_redact::placeholders_in(user)
        .into_iter()
        .find(|(_, p)| p.category == Category::Kisi)
        .map(|(_, p)| p.to_string())
        .unwrap_or_default();
    let answer = serde_json::json!({
        "is_hearing_record": true,
        "court_type": null,
        "hearing_date": null,
        "next_hearing": null,
        "attendance": [{ "role": "davacı vekili", "present": true }],
        "decisions": [
            { "n": 1, "text": format!("Davacı vekili bilirkişi ücretini yatıracak ({person} adına)"), "party": "davacı", "deadline_phrase": null },
        ],
        "notes": null,
    });
    (200, anthropic(&answer))
}

struct Round {
    answer: Answer,
    /// Every request body the stub model was sent.
    sent: Vec<String>,
}

fn context<'a>(h: &'a HearingsConfig, writes_sheet: bool) -> Context<'a> {
    Context {
        lang: Lang::Tr,
        columns: &h.columns,
        model: &h.model,
        provider: h.provider,
        // Not a name any fixture uses: the lawyer's own cell is the one name the row carries.
        lawyer: "Deneme Üye",
        now_ms: 1_761_523_200_000, // 2025-10-27
        writes_sheet,
    }
}

fn round(h: &HearingsConfig, input: Input<'_>, gates: Gates, model: &StubModel) -> Round {
    let (reading, step) = match read(input, h, gates) {
        Step::Refused { line: _, audit } => panic!("refused: {}", audit.outcome),
        Step::RuleOnly { reading, why } => (reading, ModelStep::Skipped(why)),
        Step::Model { reading, body } => {
            let answered = model.call(&body);
            (reading, ModelStep::Answered(Ok(answered)))
        }
    };
    let answer = finish(&reading, step, &context(h, true));
    Round { answer, sent: model.seen.borrow().clone() }
}

const ON: Gates = Gates { has_key: true, under_cap: true, bot_under_cap: true };

fn assert_none_of(haystack: &str, forbidden: &[String], what: &str) {
    for f in forbidden {
        assert!(!haystack.contains(f.as_str()), "{what} carries {f:?}");
    }
}

#[test]
fn golden_minutes_reach_the_model_masked_and_come_back_with_names_for_the_lawyer_only() {
    for name in [
        "01_civil_alacak",
        "03_family_bosanma",
        "07_labour_kidem_ihbar",
        "09_enforcement_istihkak",
        "25_civil_manevi_tazminat_uyap",
        "28_family_split_lines",
        "32_civil_court_words_and_apostrophes",
    ] {
        let (text, forbidden, row_forbidden) = golden(name);
        let h = cfg(serde_json::json!({}));
        let model = StubModel::good();
        let r = round(&h, Input::Text(&text), ON, &model);
        assert_eq!(r.sent.len(), 1, "{name}: one model call");
        assert_eq!(r.answer.audit.outcome, "ok", "{name}");
        // Not one golden mark in what the model got: names, ids, addresses, the esas no, the
        // court's place.
        assert_none_of(&r.sent[0], &forbidden, &format!("{name}: the model request"));
        // The lawyer's answer has the names back (the placeholder the stub used is restored).
        assert!(!r.answer.text.contains("[KISI_"), "{name}: restored for the lawyer");
        // The sheet row: the key (court, esas no) and roles — never a person.
        let u = r.answer.upsert.as_ref().unwrap_or_else(|| panic!("{name}: a row to propose"));
        let body = body_v2_json("s3cr3t-sheet", false, Some("b-1"), 1, "u", "Ayşe", None, u);
        let row_only = serde_json::to_string(&u.row).unwrap();
        assert_none_of(&row_only, &row_forbidden, &format!("{name}: the sheet row"));
        assert!(!body.contains("\"text\""), "{name}: v2 carries no text");
        assert_eq!(r.answer.audit.tokens_in, Some(1500));
        assert!(r.answer.audit.masked.iter().any(|(t, n)| *t == "KISI" && *n > 0), "{name}");
    }
}

#[test]
fn a_criminal_case_never_reaches_the_model_unless_the_owner_says_so() {
    let (text, forbidden, row_forbidden) = golden("20_criminal_karsiliksiz_cek");
    let h = cfg(serde_json::json!({}));
    let never = StubModel::with(|_| panic!("decision 3: no model call for a criminal case"));
    let r = round(&h, Input::Text(&text), ON, &never);
    assert!(r.sent.is_empty());
    assert_eq!(r.answer.audit.outcome, "hearings/criminal");
    assert_eq!(r.answer.audit.model, None);
    assert!(r.answer.text.starts_with(super::super::builtin_copy::line(Lang::Tr, Line::HearingsCriminal)));
    // Still read by the rules, and its row is still roles only.
    if let Some(u) = &r.answer.upsert {
        assert_none_of(&serde_json::to_string(&u.row).unwrap(), &row_forbidden, "the criminal row");
    }
    let opted_in = cfg(serde_json::json!({ "criminal_ai": true }));
    let model = StubModel::good();
    let r = round(&opted_in, Input::Text(&text), ON, &model);
    assert_eq!(r.sent.len(), 1, "criminal_ai: the owner's choice");
    assert_none_of(&r.sent[0], &forbidden, "the criminal request");
}

#[test]
fn a_masking_refusal_falls_back_to_the_rules_and_sends_nothing() {
    // More than 999 different e-mail addresses: `sezi-redact` refuses (`mask-too-many`).
    let mut text = String::from(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/crates/sezi-hearings/fixtures/civil_asliye_hukuk.txt")));
    for i in 0..1001 {
        text.push_str(&format!("Bildirim adresi olarak kisi{i}@ornekalanadi.com.tr kaydedildi.\n"));
    }
    let h = cfg(serde_json::json!({}));
    let never = StubModel::with(|_| panic!("a refused masking sends nothing"));
    let r = round(&h, Input::Text(&text), ON, &never);
    assert!(r.sent.is_empty());
    assert!(r.answer.audit.outcome.starts_with("hearings/mask-"), "{}", r.answer.audit.outcome);
    assert!(r.answer.text.starts_with(super::super::builtin_copy::line(Lang::Tr, Line::HearingsSummaryFailed)));
    assert!(r.answer.text.contains("Sonraki duruşma: 09.12.2026 10:30"), "the rules' answer still comes");
    assert!(r.answer.upsert.is_none(), "no vault, no masked row: nothing goes to the sheet");
}

#[test]
fn an_answer_that_fails_the_checks_falls_back_to_the_rules() {
    let civil = String::from_utf8(file("sezi-hearings/fixtures/civil_asliye_hukuk.txt")).unwrap();
    let h = cfg(serde_json::json!({}));
    let replies: Vec<(&str, Reply)> = vec![
        ("hearings/model-invalid", Box::new(|_| (200, anthropic(&serde_json::json!({ "is_hearing_record": true }))))),
        ("hearings/model-leak", Box::new(|b| {
            let (s, body) = good_reply(b);
            (s, body.replace("Davacı vekili bilirkişi", "Selin DEMİRKOL bilirkişi"))
        })),
        ("hearings/model-invalid", Box::new(|b| {
            let (s, body) = good_reply(b);
            (s, body.replace("[KISI_", "[KISI_9"))
        })),
        ("hearings/not-a-record", Box::new(|_| {
            let a = serde_json::json!({ "is_hearing_record": false, "court_type": null, "hearing_date": null,
                "next_hearing": null, "attendance": [], "decisions": [], "notes": null });
            (200, anthropic(&a))
        })),
        ("ai/bad-key", Box::new(|_| (401, String::new()))),
        ("ai/overloaded", Box::new(|_| (529, String::new()))),
        ("ai/refused", Box::new(|_| (200, serde_json::json!({ "content": [], "stop_reason": "refusal" }).to_string()))),
        ("hearings/model-invalid", Box::new(|_| (200, serde_json::json!({ "content": [{ "type": "text", "text": "{\"is_" }], "stop_reason": "max_tokens" }).to_string()))),
    ];
    for (code, reply) in replies {
        let model = StubModel::with(reply);
        let r = round(&h, Input::Text(&civil), ON, &model);
        assert_eq!(r.answer.audit.outcome, code);
        assert!(r.answer.text.starts_with(super::super::builtin_copy::line(Lang::Tr, Line::HearingsSummaryFailed)), "{code}");
        // The rules' answer: header, next hearing, decisions as the record words them.
        assert!(r.answer.text.contains("Ankara 3. Asliye Hukuk Mahkemesi · 2024/123 E. · duruşma 14.10.2026"), "{code}");
        assert!(r.answer.text.contains("2 hafta kesin süre"), "{code}: the deadline as worded");
        assert!(!r.answer.text.contains("DEMİRKOL bilirkişi"), "{code}: nothing of a refused answer is shown");
        // The row still goes, from the rules' decisions, masked one by one.
        let u = r.answer.upsert.as_ref().unwrap();
        let cell = &u.row.0.iter().find(|(k, _)| k == "Ara Karar").unwrap().1;
        assert!(cell.contains("1. Davacı vekiline bilirkişi ücreti"), "{code}: {cell}");
        assert!(!cell.contains("Duruşmanın"), "the next-hearing decision is its own column");
    }
}

#[test]
fn ai_off_no_key_and_the_daily_cap_answer_by_the_rules() {
    let civil = String::from_utf8(file("sezi-hearings/fixtures/civil_asliye_hukuk.txt")).unwrap();
    let never = || StubModel::with(|_| panic!("no model call"));
    let off = round(&cfg(serde_json::json!({ "ai": false })), Input::Text(&civil), ON, &never());
    assert_eq!(off.answer.audit.outcome, "hearings/ai-off");
    assert!(off.answer.text.starts_with("Ankara 3. Asliye"), "a rule-only bot says no apology");
    let h = cfg(serde_json::json!({}));
    let nokey = round(&h, Input::Text(&civil), Gates { has_key: false, under_cap: true, bot_under_cap: true }, &never());
    assert_eq!(nokey.answer.audit.outcome, "ai/no-key");
    let cap = round(&h, Input::Text(&civil), Gates { has_key: true, under_cap: false, bot_under_cap: true }, &never());
    assert_eq!(cap.answer.audit.outcome, "hearings/daily-limit");
    assert!(cap.answer.text.starts_with(super::super::builtin_copy::line(Lang::Tr, Line::HearingsDailyLimit)));
}

#[test]
fn past_the_bots_own_daily_calls_every_member_is_answered_by_the_rules() {
    // Adversarial review 2026-10-27: 50 calls a member a day, no bound per bot, so the owner's
    // spend grew with the office.
    let civil = String::from_utf8(file("sezi-hearings/fixtures/civil_asliye_hukuk.txt")).unwrap();
    let h = cfg(serde_json::json!({ "daily_calls": 120 }));
    let cap = |member: i64, bot: i64| gates_of(true, member, bot, &h);
    assert!(cap(0, 119).bot_under_cap && !cap(0, 120).bot_under_cap, "the owner's number, exactly");
    assert!(cap(49, 0).under_cap && !cap(50, 0).under_cap, "a member's own 50 still holds");
    let never = StubModel::with(|_| panic!("no model call past the bot's day"));
    let r = round(&h, Input::Text(&civil), cap(3, 120), &never);
    assert_eq!(r.answer.audit.outcome, "hearings/bot-daily-limit");
    let said = super::super::builtin_copy::line(Lang::Tr, Line::HearingsBotDailyLimit);
    assert!(r.answer.text.starts_with(said), "{}", r.answer.text);
    assert!(r.answer.text.contains("Ankara 3. Asliye"), "the rules' answer follows the line");
    assert!(r.answer.upsert.is_some(), "the row is still proposed from the rules");
    // The member's own cap, when both are spent, is the one they hear: it is theirs to wait out.
    assert_eq!(round(&h, Input::Text(&civil), cap(50, 120), &never).answer.audit.outcome, "hearings/daily-limit");
}

#[test]
fn what_the_rules_will_not_read_is_refused_with_its_line() {
    let h = cfg(serde_json::json!({}));
    let cases: [(Vec<u8>, &str, Line); 5] = [
        (file("sezi-hearings/fixtures/scan.pdf"), "hearings/no-text-layer", Line::HearingsNoTextLayer),
        (file("sezi-hearings/fixtures/no_tounicode.pdf"), "hearings/no-text-layer", Line::HearingsNoTextLayer),
        (file("sezi-hearings/fixtures/encrypted_user.pdf"), "hearings/pdf-encrypted", Line::HearingsPdfEncrypted),
        (file("sezi-hearings/fixtures/not_a_record.txt"), "hearings/not-a-record", Line::HearingsNotARecord),
        (vec![0x89, b'P', b'N', b'G', 0, 1, 2, 0xff, 0xfe, 0], "hearings/unsupported-type", Line::HearingsUnsupportedType),
    ];
    for (bytes, code, want) in cases {
        match read(Input::File { bytes: &bytes, name: "x.pdf" }, &h, ON) {
            Step::Refused { line, audit } => {
                assert_eq!((audit.outcome, line), (code, want));
                assert_eq!(audit.masked_json(), "{}");
            }
            _ => panic!("{code}: not refused"),
        }
    }
    match read(Input::Text("merhaba, nasılsın?"), &h, ON) {
        Step::Refused { line, .. } => assert_eq!(line, Line::HearingsNotARecord),
        _ => panic!("a chat line is not a record"),
    }
}

#[test]
fn a_pdf_is_read_by_its_text_layer_and_its_name_is_only_a_hint() {
    let pdf = file("sezi-hearings/fixtures/civil_asliye_hukuk.pdf");
    let h = cfg(serde_json::json!({}));
    let model = StubModel::good();
    let r = round(&h, Input::File { bytes: &pdf, name: "Tülay Korkmazel zabıt.pdf" }, ON, &model);
    assert_eq!((r.answer.audit.input, r.answer.audit.pages), ("pdf", 1));
    assert!(r.answer.audit.chars > 500);
    assert!(!r.sent[0].contains("Korkmazel") && !r.sent[0].contains("KORKMAZEL") && !r.sent[0].contains("zabıt.pdf"));
    assert_eq!(name_words("Tülay Korkmazel zabıt 2024-123.pdf"), vec!["Tülay", "Korkmazel"]);
    assert_eq!(name_words("Duruşma Tutanağı.pdf"), Vec::<String>::new());
}

#[test]
fn the_stub_sheet_gets_the_upsert_and_its_answer_names_the_row() {
    let civil = String::from_utf8(file("sezi-hearings/fixtures/civil_asliye_hukuk.txt")).unwrap();
    let h = cfg(serde_json::json!({}));
    let r = round(&h, Input::Text(&civil), ON, &StubModel::good());
    let u = r.answer.upsert.as_ref().unwrap();
    assert!(r.answer.text.ends_with("Tabloya yazayım mı? (2024/123 satırı varsa güncellenir, yoksa eklenir) evet / hayır"));
    // What a proposal and a job keep, and what goes to the stub sheet.
    let stored = u.to_json(Some(7));
    let (back, audit) = super::super::builtin_sheet::Upsert::parse(&stored).unwrap();
    assert_eq!((&back, audit), (u, Some(7)));
    let body = body_v2_json("s3cr3t-sheet", false, Some("b-17"), 1_761_200_000_000, "u", "Ayşe", None, &back);
    let stub_sheet = |b: &str| -> (u16, String) {
        let v: serde_json::Value = serde_json::from_str(b).unwrap();
        assert_eq!((v["v"].as_i64(), v["op"].as_str(), v["secret"].as_str()), (Some(2), Some("upsert"), Some("s3cr3t-sheet")));
        assert_eq!(v["key"]["Mahkeme"], "Ankara 3. Asliye Hukuk Mahkemesi");
        assert_eq!(v["key"]["Esas No"], "2024/123");
        assert_eq!(v["row"]["Sonraki Duruşma"], "09.12.2026 10:30");
        assert_eq!(v["row"]["Duruşma Tarihi"], "14.10.2026");
        assert_eq!(v["row"]["Avukat"], "Deneme Üye");
        assert!(v.get("text").is_none());
        (200, r#"{"ok":true,"matched":true,"row":17}"#.to_string())
    };
    let (status, answer) = stub_sheet(&body);
    assert_eq!(judge_upsert(status, &answer), Ok(Landed::Updated(17)));
    let ankara: Vec<String> = ["Selin", "DEMİRKOL", "KORKMAZEL", "ARSLANCI", "Örnektepe", "104477", "Kızılırmak"].map(String::from).to_vec();
    assert_none_of(&body, &ankara, "the sheet POST");
}

#[test]
fn a_passing_model_failure_is_tried_again_and_only_an_outcome_is_counted() {
    let status = |s: u16| -> Result<(u16, String), &'static str> { Ok((s, String::new())) };
    // A rate limit, an overload, a gateway error or no answer at all (status 0, the timeout):
    // tried again, and the member's daily count is not spent on it.
    for s in [0u16, 429, 502, 503, 529] {
        for attempts in 0..MODEL_ATTEMPTS - 1 {
            assert_eq!(after_call(&status(s), attempts), AfterCall::Retry, "{s} after {attempts}");
        }
        // The last try answers rule-only — still not counted: no model answer came of it.
        assert_eq!(after_call(&status(s), MODEL_ATTEMPTS - 1), AfterCall::Keep { counted: false }, "{s}");
    }
    // An answer, or a failure no retry mends (a bad key, a bad request, an unknown model): kept
    // at once, and counted.
    for s in [200u16, 400, 401, 404] {
        assert_eq!(after_call(&status(s), 0), AfterCall::Keep { counted: true }, "{s}");
    }
    // An address refused before any call: nothing was asked, nothing is counted or retried.
    assert_eq!(after_call(&Err("ai/unreachable"), 0), AfterCall::Keep { counted: false });
}
