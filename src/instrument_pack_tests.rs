//! Tests for the operator-hosted instrument pack.
//!
//! Two kinds, because a worker handler cannot be called without workerd: the PURE helpers
//! (sniffing, range parsing, conditional GET, name cleaning) are exercised directly, and the
//! parts that only exist as a choice inside a handler — which auth gate each route reaches for,
//! whether the migration is wired up — are asserted at SOURCE level, the shape `admin/mod.rs`
//! and `groups_tests.rs` already use. The D1 half is pinned with rusqlite against the real
//! migration file, as `media/avatar.rs` does.

use super::*;
use rusqlite::{params, Connection, OptionalExtension};

const MIGRATION: &str = include_str!("../migrations/0038_instrument_pack.sql");
const SOURCE: &str = include_str!("instrument_pack.rs");

// ── Who may call what (source-level; see the module header) ─────────────────────

/// The first 40 lines of a handler decide its gate, so the assertions are scoped to the function
/// body rather than the file — `handlers.rs` in admin/ shows why: a module legitimately mixes
/// gates, and a file-wide check would be satisfied by the wrong function.
fn head_of(func: &str) -> String {
    let at = SOURCE
        .find(func)
        .unwrap_or_else(|| panic!("{func} must exist — if it was renamed, re-point this guard"));
    SOURCE[at..].lines().take(40).collect::<Vec<_>>().join("\n")
}

/// Uploading and deleting the pack are OWNER-only. `require_admin` would hand every admin the
/// power to replace a file that every member on the server then downloads and feeds to a synth.
#[test]
fn writing_the_pack_is_owner_only() {
    for func in ["pub async fn put_pack", "pub async fn delete_pack"] {
        let head = head_of(func);
        assert!(
            head.contains("require_owner("),
            "{func} must gate on require_owner"
        );
        assert!(
            !head.contains("require_admin("),
            "{func} must NOT accept a plain admin: hosting a pack is server configuration"
        );
    }
}

/// Reading is member-level and reading ONLY: neither GET may reach for the owner gate (that
/// would make the pack unusable by the people it is for), and both must still prove the calling
/// device is live.
#[test]
fn reading_the_pack_is_member_level() {
    for func in ["pub async fn meta", "pub async fn download"] {
        let head = head_of(func);
        assert!(
            head.contains("require_active_auth("),
            "{func} must gate on require_active_auth"
        );
        assert!(
            !head.contains("require_owner("),
            "{func} must NOT be owner-only — members are who the pack is for"
        );
    }
}

/// `require_auth` verifies a stateless JWT and nothing else, so a revoked device keeps ~15
/// minutes of access. This module sits OUTSIDE `admin/`, so the guard in `admin/mod.rs` does not
/// see it — that is why the same assertion is repeated here.
#[test]
fn no_route_gates_on_the_stateless_jwt_alone() {
    assert!(
        !SOURCE.contains("require_auth("),
        "use require_active_auth: a revoked device's access token stays valid for ~15 minutes"
    );
}

/// A migration missing from `self_provision.rs`'s hand-maintained list is one a SELF-HOSTED relay
/// never runs — the table simply never exists there, and every pack route fails on it. That
/// exact omission shipped once before (2026-08-25, `self_provision.rs`'s own history).
#[test]
fn the_migration_is_wired_into_self_provision() {
    let src = include_str!("self_provision.rs");
    assert!(
        src.contains("0038_instrument_pack.sql"),
        "migrations/0038_instrument_pack.sql must be include_str!'d by self_provision.rs"
    );
    assert!(
        src.contains("(\n        \"0038_instrument_pack\","),
        "the MIGRATIONS list must carry the 0038_instrument_pack key"
    );
}

// ── The SoundFont sniff ─────────────────────────────────────────────────────────

#[test]
fn only_a_riff_sfbk_header_is_accepted() {
    let mut sf2 = b"RIFF".to_vec();
    sf2.extend_from_slice(&[0x40, 0, 0, 0]); // the RIFF length, whatever it says
    sf2.extend_from_slice(b"sfbk");
    sf2.extend_from_slice(b"LISTINFO...");
    assert!(is_sf2(&sf2));

    // A RIFF container that is not a SoundFont — a .wav is the near miss that matters, since it
    // has the same first four bytes.
    let mut wav = b"RIFF".to_vec();
    wav.extend_from_slice(&[0x40, 0, 0, 0]);
    wav.extend_from_slice(b"WAVEfmt ");
    assert!(!is_sf2(&wav), "a WAV shares the RIFF magic and must still be refused");

    assert!(!is_sf2(b"PK\x03\x04 a zip file"), "a zip is not a SoundFont");
    assert!(!is_sf2(b""), "an empty body is not a SoundFont");
    assert!(!is_sf2(b"RIFF\0\0\0\0sfb"), "11 bytes cannot carry the header");
}

// ── Range: bytes=N- ─────────────────────────────────────────────────────────────

#[test]
fn an_open_ended_range_resumes_from_the_offset() {
    assert_eq!(parse_range(Some("bytes=1000-"), 4096), RangeAsk::From(1000));
    assert_eq!(parse_range(Some("bytes=0-"), 4096), RangeAsk::From(0));
    // Whitespace and casing are the client's business, not ours.
    assert_eq!(parse_range(Some("  BYTES=12- "), 4096), RangeAsk::From(12));
    // The last byte is still inside the object.
    assert_eq!(parse_range(Some("bytes=4095-"), 4096), RangeAsk::From(4095));
}

#[test]
fn a_range_at_or_past_the_end_is_unsatisfiable() {
    assert_eq!(parse_range(Some("bytes=4096-"), 4096), RangeAsk::Unsatisfiable);
    assert_eq!(parse_range(Some("bytes=9999-"), 4096), RangeAsk::Unsatisfiable);
    // An empty object cannot satisfy any offset, including zero.
    assert_eq!(parse_range(Some("bytes=0-"), 0), RangeAsk::Unsatisfiable);
}

#[test]
fn every_form_we_do_not_implement_is_answered_whole() {
    // No header at all.
    assert_eq!(parse_range(None, 4096), RangeAsk::Whole);
    // A closed range, a suffix range and a multi-range: legal to ignore, and answering them with
    // a 206 whose content-range says something else would be the actual bug.
    assert_eq!(parse_range(Some("bytes=0-1023"), 4096), RangeAsk::Whole);
    assert_eq!(parse_range(Some("bytes=-500"), 4096), RangeAsk::Whole);
    assert_eq!(parse_range(Some("bytes=0-99,200-299"), 4096), RangeAsk::Whole);
    // An unknown unit, and plain rubbish.
    assert_eq!(parse_range(Some("items=0-"), 4096), RangeAsk::Whole);
    assert_eq!(parse_range(Some("bytes=abc-"), 4096), RangeAsk::Whole);
    assert_eq!(parse_range(Some(""), 4096), RangeAsk::Whole);
}

// ── ETag / If-None-Match ────────────────────────────────────────────────────────

#[test]
fn the_etag_is_the_hash_in_quotes() {
    assert_eq!(etag_of("deadbeef"), "\"deadbeef\"");
}

#[test]
fn if_none_match_recognises_the_hash_it_is_sent() {
    let hash = "9f86d081884c7d65";
    assert!(if_none_match_hits("\"9f86d081884c7d65\"", hash));
    assert!(if_none_match_hits("W/\"9f86d081884c7d65\"", hash), "a weak validator counts");
    assert!(if_none_match_hits("9f86d081884c7d65", hash), "an unquoted hash counts");
    assert!(if_none_match_hits("*", hash), "* matches whatever we hold");
    assert!(
        if_none_match_hits("\"old\", \"9f86d081884c7d65\"", hash),
        "a list is compared entry by entry"
    );
    // A different pack must NOT produce a 304 — that is the bug where a member is stuck on the
    // old SoundFont for ever.
    assert!(!if_none_match_hits("\"someotherhash\"", hash));
    assert!(!if_none_match_hits("", hash));
}

// ── X-Pack-Name ─────────────────────────────────────────────────────────────────

#[test]
fn the_display_name_is_cleaned_and_capped() {
    assert_eq!(sanitize_name(Some("  GeneralUser GS v2.0.3 ".into())), "GeneralUser GS v2.0.3");
    assert_eq!(sanitize_name(None), "");
    assert_eq!(sanitize_name(Some("   ".into())), "");
    // Control characters (a CR/LF header-injection attempt among them) are dropped, not escaped.
    assert_eq!(sanitize_name(Some("Piano\r\nX-Evil: 1".into())), "PianoX-Evil: 1");
    // Over the cap → truncated, with no trailing whitespace left behind.
    let long = "a".repeat(200);
    assert_eq!(sanitize_name(Some(long)).chars().count(), 120);
}

// ── The D1 slot (rusqlite twin of the real migration) ───────────────────────────

fn db_with_schema() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(MIGRATION).unwrap();
    db
}

fn upsert(db: &Connection, hash: &str, name: &str, size: i64, store: &str, at_ms: i64) {
    db.execute(UPSERT_PACK_SQL, params![hash, name, size, store, at_ms])
        .unwrap();
}

fn select(db: &Connection) -> Option<(String, String, i64, String)> {
    db.query_row(SELECT_PACK_SQL, [], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })
    .optional()
    .unwrap()
}

/// Meta before and after: nothing hosted → no row (the 404 `no_pack` class), and after a PUT the
/// row carries exactly what the response promised.
#[test]
fn meta_is_empty_until_a_pack_is_uploaded() {
    let db = db_with_schema();
    assert_eq!(select(&db), None, "a fresh server hosts no pack");

    upsert(&db, "hash-a", "GeneralUser GS", 31_000_000, "r2-primary", 1_700_000_000_000);
    assert_eq!(
        select(&db),
        Some((
            "hash-a".into(),
            "GeneralUser GS".into(),
            31_000_000,
            "r2-primary".into()
        ))
    );
}

/// One server, one pack: a second upload REPLACES the row rather than adding one, and every
/// column moves — including the store_id, so a pack that landed on a different backend is still
/// read from the right one.
#[test]
fn a_second_upload_replaces_the_single_slot() {
    let db = db_with_schema();
    upsert(&db, "hash-a", "Old pack", 100, "r2-primary", 10);
    upsert(&db, "hash-b", "New pack", 200, "s3-abcd1234", 20);

    let n: i64 = db
        .query_row("SELECT COUNT(*) FROM instrument_pack", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "id = 1 is the primary key → exactly one pack");
    assert_eq!(
        select(&db),
        Some(("hash-b".into(), "New pack".into(), 200, "s3-abcd1234".into()))
    );
}

/// The schema's CHECK is what makes "one pack" a fact rather than a convention: no second row
/// can be written even by a hand-typed INSERT.
#[test]
fn a_second_row_cannot_be_inserted() {
    let db = db_with_schema();
    upsert(&db, "hash-a", "", 100, "r2-primary", 10);
    let err = db.execute(
        "INSERT INTO instrument_pack (id, hash, name, size_bytes, store_id, uploaded_at_ms)
         VALUES (2, 'hash-b', '', 200, 'r2-primary', 20)",
        [],
    );
    assert!(err.is_err(), "CHECK (id = 1) must reject a second pack row");
}

/// DELETE empties the slot, and the next meta read finds nothing — the 404 the client needs in
/// order to fall back to the procedural synth.
#[test]
fn delete_empties_the_slot() {
    let db = db_with_schema();
    upsert(&db, "hash-a", "GeneralUser GS", 100, "r2-primary", 10);
    db.execute(DELETE_PACK_SQL, []).unwrap();
    assert_eq!(select(&db), None);
    // Idempotent: deleting again is a no-op, not an error.
    assert_eq!(db.execute(DELETE_PACK_SQL, []).unwrap(), 0);
}

/// The hash IS the object key, which is what makes a stale hash harmless: the old and the new
/// pack never share a key, so replacing one cannot overwrite the bytes the other named.
#[test]
fn the_stored_hash_addresses_the_object() {
    let db = db_with_schema();
    upsert(&db, "abc123", "", 100, "r2-primary", 10);
    let (hash, _, _, _) = select(&db).unwrap();
    assert_eq!(
        crate::storage::instrument_pack_key(&hash),
        "packs/abc123.sf2"
    );
}
