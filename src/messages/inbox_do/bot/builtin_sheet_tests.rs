use super::*;

/// THE shared vector (docs/BOTS_HELPER_PLAN.md, "the sheet POST"): the core's Apps Script is
/// tested against these exact bytes. Change them in both places or neither.
pub(super) const VECTOR_ROW: &str = concat!(
    r#"{"v":1,"secret":"s3cr3t-sheet","test":false,"row_id":"b0000000-0000-4000-8000-000000000002-17","at":1761200000000,"#,
    r#""who":{"user_id":"a0000000-0000-4000-8000-000000000001","name":"Ayşe"},"room":null,"#,
    r#""text":"Yarın 10:00 duruşma, Ankara 3. Asliye","#,
    r#""row":{"Tarih":"2026-10-27","Saat":"10:00","Mahkeme":"Ankara 3. Asliye"}}"#,
);
pub(super) const VECTOR_TEST: &str = concat!(
    r#"{"v":1,"secret":"s3cr3t-sheet","test":true,"row_id":null,"at":1761200000000,"#,
    r#""who":{"user_id":"a0000000-0000-4000-8000-000000000001","name":"Ayşe"},"room":null,"#,
    r#""text":"Merhaba! Bu, bot sahibinin bir denemesi.","row":null}"#,
);
/// A sheet bot's row from a call in a group (Phase 3): `room` after `who`, no `row` (a plain
/// sheet bot writes the words; an AI bot's confirmed room row carries both).
pub(super) const VECTOR_ROOM: &str = concat!(
    r#"{"v":1,"secret":"s3cr3t-sheet","test":false,"row_id":"b0000000-0000-4000-8000-000000000002-18","at":1761200000000,"#,
    r#""who":{"user_id":"a0000000-0000-4000-8000-000000000001","name":"Ayşe"},"#,
    r#""room":{"id":"c0000000-0000-4000-8000-000000000003","name":"Hukuk Bürosu"},"#,
    r#""text":"Yarın 10:00 duruşma, Ankara 3. Asliye","row":null}"#,
);

const WHO: &str = "a0000000-0000-4000-8000-000000000001";

#[test]
fn a_call_from_a_room_names_the_room_after_who() {
    let room = SheetRoom { id: "c0000000-0000-4000-8000-000000000003", name: "Hukuk Bürosu" };
    let text = "Yarın 10:00 duruşma, Ankara 3. Asliye";
    let row_id = "b0000000-0000-4000-8000-000000000002-18";
    let body = body_json("s3cr3t-sheet", false, Some(row_id), 1_761_200_000_000, WHO, "Ayşe", Some(room), text, None);
    assert_eq!(body, VECTOR_ROOM);
}

#[test]
fn the_body_is_the_shared_vector_byte_for_byte() {
    let row = Row(vec![
        ("Tarih".into(), "2026-10-27".into()),
        ("Saat".into(), "10:00".into()),
        ("Mahkeme".into(), "Ankara 3. Asliye".into()),
    ]);
    let text = "Yarın 10:00 duruşma, Ankara 3. Asliye";
    let row_id = "b0000000-0000-4000-8000-000000000002-17";
    assert_eq!(
        body_json("s3cr3t-sheet", false, Some(row_id), 1_761_200_000_000, WHO, "Ayşe", None, text, Some(&row)),
        VECTOR_ROW
    );
    let test_text = "Merhaba! Bu, bot sahibinin bir denemesi.";
    let test = body_json("s3cr3t-sheet", true, None, 1_761_200_000_000, WHO, "Ayşe", None, test_text, None);
    assert_eq!(test, VECTOR_TEST);
}

#[test]
fn a_row_keeps_the_order_it_was_written_in_and_its_caps() {
    let r = Row::parse(r#"{"Zeta": "1", "Alfa": 2, "Mid": true, "Obj": {"x": 1}, "Arr": [1], "Nul": null}"#).unwrap();
    assert_eq!(
        r.0,
        vec![("Zeta".into(), "1".into()), ("Alfa".into(), "2".into()), ("Mid".into(), "true".into())]
    );
    assert_eq!(r.to_json(), r#"{"Zeta":"1","Alfa":"2","Mid":"true"}"#);
    let wide: String = format!(
        "{{{}}}",
        (0..30).map(|i| format!("\"c{i}\":\"v\"")).collect::<Vec<_>>().join(",")
    );
    assert_eq!(Row::parse(&wide).unwrap().0.len(), MAX_COLUMNS);
    let long = format!(r#"{{"{}": "{}"}}"#, "k".repeat(100), "ü".repeat(900));
    let r = Row::parse(&long).unwrap();
    assert_eq!(r.0[0].0.chars().count(), MAX_COLUMN_CHARS);
    assert_eq!(r.0[0].1.chars().count(), MAX_CELL_CHARS);
    assert_eq!(Row::parse(r#"{"a":"1","a":"2"}"#).unwrap().0, vec![("a".into(), "1".into())], "first wins");
    for bad in ["[1,2]", "\"x\"", "{}", r#"{"": "x"}"#, r#"{"a": {}}"#, "{", r#"{"a":"1"} trailing"#] {
        assert_eq!(Row::parse(bad), None, "{bad}");
    }
}

#[test]
fn only_a_2xx_saying_ok_true_is_a_write() {
    assert_eq!(judge(200, r#"{"ok":true}"#), Ok(()));
    assert_eq!(judge(200, " {\"ok\": true, \"row\": 5}\n"), Ok(()));
    assert_eq!(judge(200, r#"{"ok":false,"error":"secret"}"#), Err("bot/sheet-secret"));
    assert_eq!(judge(200, r#"{"ok":false,"error":"sheet"}"#), Err("bot/sheet-refused"));
    assert_eq!(judge(200, r#"{"ok":false,"error":"no-sheet"}"#), Err("bot/sheet-no-sheet"));
    assert_eq!(judge(200, "<html>Sign in</html>"), Err("bot/sheet-bad-response"));
    assert_eq!(judge(200, r#"{"ok":"yes"}"#), Err("bot/sheet-bad-response"));
    assert_eq!(judge(500, r#"{"ok":true}"#), Err("bot/sheet-bad-response"));
    assert_eq!(judge(404, "Not Found"), Err("bot/sheet-not-found"));
}

#[test]
fn apps_scripts_302_is_followed_as_a_get_under_the_url_rule() {
    let exec = "https://script.google.com/macros/s/AKfy/exec";
    let echo = "https://script.googleusercontent.com/macros/echo?user_content_key=abc&lib=x";
    assert_eq!(next_hop(302, Some(echo), exec, true, false), Hop::Next(echo.into(), false));
    assert_eq!(next_hop(303, Some(echo), exec, true, false), Hop::Next(echo.into(), false));
    assert_eq!(next_hop(307, Some(echo), exec, true, false), Hop::Next(echo.into(), true), "307 repeats the POST");
    assert_eq!(next_hop(308, Some(echo), exec, false, false), Hop::Next(echo.into(), false), "a GET stays a GET");
    assert_eq!(
        next_hop(302, Some("/macros/s/AKfy/dev"), exec, true, false),
        Hop::Next("https://script.google.com/macros/s/AKfy/dev".into(), false),
        "a relative Location resolves against the hop"
    );
    assert_eq!(
        next_hop(302, Some("https://accounts.google.com/ServiceLogin?x"), exec, true, false),
        Hop::Fail("bot/sheet-access"),
        "not deployed for Anyone"
    );
    for lan in ["http://192.168.1.32/x", "https://10.1.1.1/x", "https://router.lan/x", "http://example.com/x"] {
        assert_eq!(next_hop(302, Some(lan), exec, true, false), Hop::Fail("bot/sheet-url-refused"), "{lan}");
    }
    assert_eq!(next_hop(302, None, exec, true, false), Hop::Fail("bot/sheet-bad-response"));
    assert_eq!(
        next_hop(302, Some("http://sezilab-server:18999/echo"), "http://sezilab-server:18999/exec", true, true),
        Hop::Next("http://sezilab-server:18999/echo".into(), false),
        "the lab escape reaches the stand-in"
    );
}

/// A sheet address stored while the lab's LAN escape was on is judged again at every write:
/// with the escape off it is not fetched, and a public one passes as written.
#[test]
fn a_stored_sheet_address_is_judged_again_before_its_first_fetch() {
    assert_eq!(first_hop("http://192.168.1.10/exec", true).as_deref(), Ok("http://192.168.1.10/exec"));
    assert_eq!(first_hop("http://192.168.1.10/exec", false), Err("bot/sheet-unreachable"));
    assert_eq!(first_hop("https://localhost/exec", false), Err("bot/sheet-unreachable"));
    let public = "https://script.google.com/macros/s/AKfy/exec";
    assert_eq!(first_hop(public, false).as_deref(), Ok(public));
}
