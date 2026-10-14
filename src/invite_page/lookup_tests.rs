//! The invite page's one statement against the real schema, and what [`describe`] makes of its
//! row: a usable invite says what it is, every unusable one says the same nothing, and the answer
//! never carries the token, the code or an account id.

use super::lookup::{
    describe, DescribeRow, InviteKind, InviteView, DESCRIBE_BY_CODE_SQL, DESCRIBE_BY_TOKEN_SQL,
};
use crate::auth::hashing::sha256_hex;
use crate::auth::invite_code::code_hash;
use rusqlite::{params, Connection};

const NOW: i64 = 1_780_000_000;
const PERSONAL_TOKEN: &str = "PersonalToken_24chars_xx";
const PERSONAL_CODE: &str = "K7QM4827";
const CLASS_TOKEN: &str = "ClassToken_24characters_";
const CLASS_CODE: &str = "B2CD3FGH";

fn db() -> Connection {
    let db = crate::test_schema::full_schema();
    db.execute_batch(
        "UPDATE server_settings SET name = 'Kampüs Sezi' WHERE id = 1;
         INSERT INTO users (id, email, identity_pubkey, identity_ed_pub, display_name, role, created_at)
         VALUES ('u-ayse-0001', 'ayse@sezgi.local', x'00', x'AA', 'Ayşe Demir', 'admin', 1),
                ('u-boss-0002', 'boss@sezgi.local', x'00', x'BB', NULL, 'owner', 1);
         INSERT INTO groups (id, name, created_by, created_at, updated_at)
         VALUES ('g-course-1', 'BİL203 Ders', 'u-ayse-0001', 1, 1);",
    )
    .unwrap();
    db
}

#[allow(clippy::too_many_arguments)]
fn mint(
    db: &Connection,
    token: &str,
    code: &str,
    owner: Option<&str>,
    kind: &str,
    seats: i64,
    label: Option<&str>,
    landing: Option<&str>,
) {
    db.execute(
        "INSERT INTO invite_tokens
           (token, token_hash, email_hint, used, owner_user_id, expires_at, created_at,
            kind, max_uses, uses, introduce, landing_room_id, landing_needs_approval,
            code, code_hash)
         VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8, 0, 1, ?9, 1, ?10, ?11)",
        params![
            token,
            sha256_hex(token),
            label,
            owner,
            NOW + 3 * 86_400,
            NOW - 60,
            kind,
            seats,
            landing,
            code,
            code_hash(code)
        ],
    )
    .unwrap();
}

fn mint_personal(db: &Connection) {
    mint(
        db,
        PERSONAL_TOKEN,
        PERSONAL_CODE,
        Some("u-ayse-0001"),
        "personal",
        1,
        Some("for Mehmet, his private number"),
        None,
    );
}

fn mint_class(db: &Connection, seats: i64) {
    mint(
        db,
        CLASS_TOKEN,
        CLASS_CODE,
        Some("u-ayse-0001"),
        "class",
        seats,
        Some("BIL203 · 2026 fall"),
        Some("g-course-1"),
    );
}

fn row_by(db: &Connection, sql: &str, key: &str, now: i64) -> DescribeRow {
    db.query_row(sql, params![key, now], |r| {
        Ok(DescribeRow {
            server_name: r.get("server_name")?,
            kind: r.get("kind")?,
            label: r.get("label")?,
            used: r.get("used")?,
            expires_at: r.get("expires_at")?,
            revoked_at: r.get("revoked_at")?,
            max_uses: r.get("max_uses")?,
            taken: r.get("taken")?,
            has_minter: r.get("has_minter")?,
            inviter_name: r.get("inviter_name")?,
            landing_group: r.get("landing_group")?,
            needs_approval: r.get("needs_approval")?,
        })
    })
    .unwrap()
}

fn by_code(db: &Connection, code: &str) -> Option<InviteView> {
    describe(
        &row_by(db, DESCRIBE_BY_CODE_SQL, &code_hash(code), NOW),
        NOW,
    )
}

#[test]
fn a_live_personal_invite_names_the_server_and_the_inviter_and_nothing_private() {
    let db = db();
    mint_personal(&db);
    let view = by_code(&db, PERSONAL_CODE).expect("a live invite is described");
    assert_eq!(
        view,
        InviteView {
            kind: InviteKind::Personal,
            server_name: "Kampüs Sezi".into(),
            inviter_name: Some("Ayşe Demir".into()),
            label: None,
            landing_group: None,
            landing_needs_approval: false,
            seats_left: None,
            expires_at: NOW + 3 * 86_400,
        }
    );
}

#[test]
fn a_live_class_invite_names_itself_its_group_and_its_seats() {
    let db = db();
    mint_class(&db, 120);
    let view = by_code(&db, CLASS_CODE).unwrap();
    assert_eq!(view.kind, InviteKind::Class);
    assert_eq!(view.label.as_deref(), Some("BIL203 · 2026 fall"));
    assert_eq!(view.landing_group.as_deref(), Some("BİL203 Ders"));
    assert!(view.landing_needs_approval);
    assert_eq!(view.seats_left, Some(120));
}

/// The no-token guarantee, on the wire: the JSON's keys are exactly the allow-list, and nothing
/// that redeems, nor any account id, appears anywhere in it.
#[test]
fn the_answer_carries_no_token_no_code_and_no_account_id() {
    let db = db();
    mint_personal(&db);
    mint_class(&db, 30);
    for (code, token) in [(PERSONAL_CODE, PERSONAL_TOKEN), (CLASS_CODE, CLASS_TOKEN)] {
        let view = by_code(&db, code).unwrap();
        let json = serde_json::to_value(&view).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "expires_at",
                "inviter_name",
                "kind",
                "label",
                "landing_group",
                "landing_needs_approval",
                "seats_left",
                "server_name"
            ],
            "a new field in the answer is a decision, not a side effect"
        );
        let text = json.to_string();
        for secret in [
            token.to_string(),
            sha256_hex(token),
            code.to_string(),
            crate::auth::invite_code::display(code),
            code_hash(code),
            "u-ayse-0001".to_string(),
            "g-course-1".to_string(),
            "ayse@sezgi.local".to_string(),
        ] {
            assert!(!text.contains(&secret), "{secret} leaked into {text}");
        }
    }
}

/// Not only which keys, but what each kind fills them with: a personal invite names its inviter and
/// nothing else of the admin's; a class invite names itself and its group and never its minter.
#[test]
fn each_kind_fills_exactly_its_own_values() {
    let db = db();
    mint_personal(&db);
    mint_class(&db, 30);
    let personal = serde_json::to_value(by_code(&db, PERSONAL_CODE).unwrap()).unwrap();
    assert_eq!(
        personal,
        serde_json::json!({
            "kind": "personal",
            "server_name": "Kampüs Sezi",
            "inviter_name": "Ayşe Demir",
            "label": null,
            "landing_group": null,
            "landing_needs_approval": false,
            "seats_left": null,
            "expires_at": NOW + 3 * 86_400,
        })
    );
    let class = serde_json::to_value(by_code(&db, CLASS_CODE).unwrap()).unwrap();
    assert_eq!(
        class,
        serde_json::json!({
            "kind": "class",
            "server_name": "Kampüs Sezi",
            "inviter_name": null,
            "label": "BIL203 · 2026 fall",
            "landing_group": "BİL203 Ders",
            "landing_needs_approval": true,
            "seats_left": 30,
            "expires_at": NOW + 3 * 86_400,
        })
    );
}

/// A personal invite's label is the admin's own note about whom it is for.
#[test]
fn a_personal_invites_admin_note_is_never_shown() {
    let db = db();
    mint_personal(&db);
    let text = serde_json::to_string(&by_code(&db, PERSONAL_CODE).unwrap()).unwrap();
    assert!(!text.contains("Mehmet"));
}

#[test]
fn an_unknown_code_is_one_row_with_nothing_in_it() {
    let db = db();
    mint_personal(&db);
    let row = row_by(&db, DESCRIBE_BY_CODE_SQL, &code_hash("ZZZZ9999"), NOW);
    assert_eq!(row.server_name.as_deref(), Some("Kampüs Sezi"));
    assert!(row.kind.is_none() && row.expires_at.is_none() && row.inviter_name.is_none());
    assert_eq!(describe(&row, NOW), None);
}

/// Every way of being unusable is the same `None` — the answer cannot tell a guesser whether the
/// code never existed, was used, expired, was withdrawn or is full.
#[test]
fn spent_expired_withdrawn_full_and_unknown_all_answer_alike() {
    let unusable = |setup: &dyn Fn(&Connection), code: &str| {
        let db = db();
        mint_personal(&db);
        mint_class(&db, 2);
        setup(&db);
        by_code(&db, code)
    };
    let used = |db: &Connection| {
        db.execute(
            "UPDATE invite_tokens SET used = 1, uses = 1 WHERE token = ?1",
            [PERSONAL_TOKEN],
        )
        .unwrap();
    };
    let expired = |db: &Connection| {
        db.execute("UPDATE invite_tokens SET expires_at = ?1", [NOW])
            .unwrap();
    };
    let revoked = |db: &Connection| {
        db.execute("UPDATE invite_tokens SET revoked_at = ?1", [NOW - 1])
            .unwrap();
    };
    let full = |db: &Connection| {
        // Two verified redemptions on a two-seat class invite.
        for (i, user) in ["u-ayse-0001", "u-boss-0002"].iter().enumerate() {
            db.execute(
                "INSERT INTO invite_attributions
                   (invite_token_hash, inviter_user_id, used_by, created_at, expires_at,
                    redeemed_at, verified_at, genesis, kind, source_hash, introduce)
                 VALUES (?1, 'u-ayse-0001', ?2, 1, ?3, ?4, ?4, 0, 'class', ?5, 0)",
                params![
                    sha256_hex(&format!("redemption-{i}")),
                    user,
                    NOW + 86_400,
                    NOW - 10,
                    sha256_hex(CLASS_TOKEN)
                ],
            )
            .unwrap();
        }
        db.execute(
            "UPDATE invite_tokens SET uses = 2 WHERE token = ?1",
            [CLASS_TOKEN],
        )
        .unwrap();
    };
    assert_eq!(unusable(&used, PERSONAL_CODE), None, "used");
    assert_eq!(unusable(&expired, PERSONAL_CODE), None, "expired personal");
    assert_eq!(unusable(&expired, CLASS_CODE), None, "expired class");
    assert_eq!(unusable(&revoked, CLASS_CODE), None, "withdrawn class");
    assert_eq!(unusable(&full, CLASS_CODE), None, "full class");
    assert_eq!(unusable(&|_| {}, "ZZZZ9999"), None, "unknown");
}

/// A class invite that LOOKS full because a student scanned and walked away is counted as redeem
/// would count it: the abandoned seat is free, so the page does not turn the next student away.
#[test]
fn an_abandoned_seat_is_counted_free_as_redeem_would() {
    let db = db();
    mint_class(&db, 1);
    db.execute(
        "INSERT INTO invite_attributions
           (invite_token_hash, inviter_user_id, created_at, expires_at, redeemed_at, genesis,
            kind, source_hash, introduce)
         VALUES (?1, 'u-ayse-0001', 1, ?2, ?3, 0, 'class', ?4, 0)",
        params![
            sha256_hex("abandoned"),
            NOW + 86_400,
            NOW - 3_600,
            sha256_hex(CLASS_TOKEN)
        ],
    )
    .unwrap();
    // Its verification code ran out an hour ago.
    db.execute(
        "INSERT INTO verification_codes
           (email, code_hash, attempts, invite_token, invite_token_hash, expires_at, created_at)
         VALUES ('gone@sezgi.local', 'h', 0, NULL, ?1, ?2, ?3)",
        params![sha256_hex("abandoned"), NOW - 3_000, NOW - 3_600],
    )
    .unwrap();
    db.execute(
        "UPDATE invite_tokens SET uses = 1 WHERE token = ?1",
        [CLASS_TOKEN],
    )
    .unwrap();
    assert_eq!(by_code(&db, CLASS_CODE).unwrap().seats_left, Some(1));
}

/// The founding invite has no minter. It is public while the server is unowned and spent after,
/// so it is never described — even if it somehow carried a code.
#[test]
fn the_founding_invite_is_never_described() {
    let db = db();
    mint(
        &db,
        "GenesisToken_24_chars_xx",
        "C3DF4GHJ",
        None,
        "personal",
        1,
        None,
        None,
    );
    assert_eq!(by_code(&db, "C3DF4GHJ"), None);
    let row = row_by(&db, DESCRIBE_BY_TOKEN_SQL, "GenesisToken_24_chars_xx", NOW);
    assert_eq!(describe(&row, NOW), None);
}

/// The app's personal envelope carries the token, not the code; both find the same invite.
#[test]
fn a_token_finds_the_same_invite_as_its_code() {
    let db = db();
    mint_personal(&db);
    let by_token = describe(
        &row_by(&db, DESCRIBE_BY_TOKEN_SQL, PERSONAL_TOKEN, NOW),
        NOW,
    );
    assert_eq!(by_token, by_code(&db, PERSONAL_CODE));
    assert!(by_token.is_some());
}

/// A server that never set a name, an inviter with only whitespace for a name, a landing group
/// that was deleted: the answer degrades to what is known, never to an empty string.
#[test]
fn missing_names_degrade_to_absent_not_empty() {
    let db = db();
    db.execute_batch(
        "UPDATE server_settings SET name = '   ' WHERE id = 1;
         UPDATE users SET display_name = '  ' WHERE id = 'u-ayse-0001';",
    )
    .unwrap();
    mint(
        &db,
        CLASS_TOKEN,
        CLASS_CODE,
        Some("u-ayse-0001"),
        "class",
        5,
        Some(" "),
        Some("g-deleted"),
    );
    let view = by_code(&db, CLASS_CODE).unwrap();
    assert_eq!(view.server_name, "Sezi");
    assert_eq!(view.inviter_name, None);
    assert_eq!(view.label, None);
    assert_eq!(view.landing_group, None);
    assert!(!view.landing_needs_approval, "no group, nothing to approve");
}

/// Critic (review/k6-critic): a class invite introduces nobody, and neither its page nor the
/// app's card names the minter — yet the JSON answer carries the minting admin's display name to
/// anyone holding a code read off a projector. Redeeming the code would never tell them that.
#[test]
fn a_class_invite_does_not_name_its_minter() {
    let db = db();
    mint_class(&db, 120);
    let view = by_code(&db, CLASS_CODE).unwrap();
    assert_eq!(
        view.inviter_name, None,
        "the minter's name reaches every code holder through the JSON"
    );
}
