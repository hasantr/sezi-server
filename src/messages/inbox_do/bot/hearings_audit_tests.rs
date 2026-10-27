//! The hearings kind's tables and retention on rusqlite (the `builtin_store_tests` style): the
//! audit row holds no content, the bot's sent answers are blanked and expired, a proposal keeps
//! no minutes, and the `allowed_room` gate is the active-membership statement.

use super::super::builtin_hearings::{SENT_BLANK, SENT_EXPIRE};
use super::super::builtin_sheet::Upsert;
use super::super::builtin_store as bs;
use super::super::hearings_pipeline::{finish, read, Context, Gates, Input, ModelStep, Step};
use super::*;
use crate::bots::builtin_hearings_rules::validate;
use crate::bots::builtin_rules::Lang;
use rusqlite::{params, Connection};

const CIVIL: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/crates/sezi-hearings/fixtures/civil_asliye_hukuk.txt"));
/// What the civil fixture names; none of it may be in a stored row.
const NAMES: [&str; 12] = [
    "Nazlı", "ÇEVİKTAŞ", "Oğuzhan", "BALKAYA", "Tülay", "KORKMAZEL", "Selin", "DEMİRKOL", "Kemalettin", "ARSLANCI",
    "Örnektepe", "Kızılırmak",
];

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    for t in super::super::store::TABLES.iter().chain(bs::TABLES.iter()).chain(TABLES.iter()) {
        c.execute_batch(t).unwrap();
    }
    c
}

/// A round of the civil fixture, rule-only (no model needed to fill the audit).
fn round() -> (AuditRecord, Upsert) {
    let h = validate(Some(serde_json::from_value(serde_json::json!({ "allowed_room": "r1", "ai": false })).unwrap()), None, Lang::Tr, false)
        .unwrap()
        .config;
    let Step::RuleOnly { reading, why } = read(Input::Text(CIVIL), &h, Gates { has_key: false, under_cap: true, bot_under_cap: true }) else {
        panic!("rule-only")
    };
    let cx = Context {
        lang: Lang::Tr,
        columns: &h.columns,
        model: &h.model,
        provider: h.provider,
        lawyer: "Deneme Üye",
        now_ms: 1_761_523_200_000,
        writes_sheet: true,
    };
    let a = finish(&reading, ModelStep::Skipped(why), &cx);
    (a.audit, a.upsert.unwrap())
}

#[test]
fn the_audit_row_is_numbers_and_codes() {
    let (a, _) = round();
    let c = db();
    let id: i64 = c
        .query_row(
            AUDIT_PUT,
            params!["u1", 1_000i64, a.input, a.pages, a.chars, a.masked_json(), a.model, a.tokens_in, a.tokens_out, a.outcome],
            |r| r.get(0),
        )
        .unwrap();
    c.execute(AUDIT_SHEET, params![SheetOutcome::Updated.as_str(), id]).unwrap();
    let row: Vec<String> = c
        .query_row("SELECT * FROM bot_hearings_audit WHERE id = ?", [id], |r| {
            Ok((0..12).map(|i| r.get::<_, rusqlite::types::Value>(i).map(|v| format!("{v:?}")).unwrap()).collect())
        })
        .unwrap();
    let all = row.join("|");
    for n in NAMES.iter().chain(["2024/123", "Ankara", "ANKARA", "Asliye", "bilirkişi"].iter()) {
        assert!(!all.contains(n), "the audit row carries {n:?}: {all}");
    }
    let masked: serde_json::Value = serde_json::from_str(&a.masked_json()).unwrap();
    assert!(masked.as_object().unwrap().keys().all(|k| k.chars().all(|c| c.is_ascii_uppercase())), "tags only: {masked}");
    assert!(masked["KISI"].as_u64().unwrap() >= 5);
    assert_eq!((a.input, a.outcome), ("text", "hearings/ai-off"));
    // The owner's view: counts.
    let by: Vec<(String, i64)> = c
        .prepare(AUDIT_BY_OUTCOME)
        .unwrap()
        .query_map([0i64], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(by, vec![("hearings/ai-off".to_string(), 1)]);
    let sheet: i64 = c.query_row(AUDIT_BY_SHEET, [0i64], |r| r.get(1)).unwrap();
    assert_eq!(sheet, 1);
    c.execute(AUDIT_EXPIRE, [1_001i64]).unwrap();
    assert_eq!(c.query_row("SELECT COUNT(*) FROM bot_hearings_audit", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
}

#[test]
fn a_proposal_and_a_job_keep_the_role_only_row_and_no_minutes() {
    let (_, u) = round();
    let c = db();
    let json = u.to_json(Some(3));
    c.execute(bs::PROPOSAL_PUT, params!["u1", json, "", 1i64, rusqlite::types::Null]).unwrap();
    c.execute(bs::JOB_PUSH, params!["u1", "Deneme Üye", "", json, 1i64, 1i64, 1i64, 1i64, rusqlite::types::Null]).unwrap();
    let stored: String = c
        .query_row("SELECT p.row_json || p.text || j.text || j.row_json FROM bot_ai_proposals p, bot_sheet_jobs j", [], |r| r.get(0))
        .unwrap();
    for n in NAMES {
        assert!(!stored.contains(n), "{n}");
    }
    assert!(!stored.contains("GEREĞİ DÜŞÜNÜLDÜ") && !stored.contains("celseye başlandı"), "no minutes");
    assert!(stored.contains("Ankara 3. Asliye Hukuk Mahkemesi") && stored.contains("2024/123"), "the key, for the office's sheet");
}

#[test]
fn the_bots_sent_answers_are_blanked_when_delivered_and_gone_after_a_day() {
    let c = db();
    let put = "INSERT INTO bot_sent (msg_uid, user_id, device_id, pending_id, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)";
    c.execute(put, params!["b-1", "u1", "d1", 5i64, "{\"names\":\"x\"}", 100i64]).unwrap();
    c.execute(put, params!["b-1", "u1", "d2", 6i64, "{\"names\":\"x\"}", 100i64]).unwrap();
    c.execute(put, params!["b-2", "u2", "d9", 5i64, "{\"other\":1}", 100i64]).unwrap();
    c.execute(SENT_BLANK, params!["u1", 5i64]).unwrap();
    let payloads: Vec<(String, String)> = c
        .prepare("SELECT device_id, payload_json FROM bot_sent ORDER BY device_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(payloads[0], ("d1".into(), String::new()), "the device that has it");
    assert_eq!(payloads[1].1, "{\"names\":\"x\"}", "a device still owed it keeps it for a resend");
    assert_eq!(payloads[2].1, "{\"other\":1}", "another member's id space");
    c.execute(SENT_EXPIRE, [101i64]).unwrap();
    assert_eq!(c.query_row("SELECT COUNT(*) FROM bot_sent", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
}

#[test]
fn only_an_active_member_of_the_room_is_let_in() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
        "CREATE TABLE group_members (group_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
           joined_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active', added_by TEXT, PRIMARY KEY (group_id, user_id));
         INSERT INTO group_members VALUES ('avukatlar', 'ayse', 'member', 1, 'active', NULL);
         INSERT INTO group_members VALUES ('avukatlar', 'davetli', 'member', 1, 'pending', NULL);
         INSERT INTO group_members VALUES ('muvekkiller', 'musteri', 'member', 1, 'active', NULL);",
    )
    .unwrap();
    let allowed = |u: &str| c.query_row(crate::groups::GROUP_ROLE_SQL, params!["avukatlar", u], |r| r.get::<_, String>(0)).is_ok();
    assert!(allowed("ayse"));
    assert!(!allowed("davetli"), "an invitation not accepted is not membership");
    assert!(!allowed("musteri"), "a member of another room");
    assert!(!allowed("yabanci"));
}
