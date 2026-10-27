//! The bot's blob check, case by case, and the record it reads — on the REAL migration chain, so
//! the columns the check trusts are the ones `/media/upload` writes.

use super::*;
use rusqlite::params;

const MEMBER: &str = "member-0000-0000-0000-000000000001";
const BOT: &str = "bot-00000-0000-0000-0000-000000000002";
const OTHER: &str = "other-000-0000-0000-0000-000000000003";
const NOW_S: i64 = 1_761_200_000;

/// The record of a file MEMBER uploaded for their 1:1 with BOT, as the kernel declares it.
fn good() -> BlobRecord {
    BlobRecord {
        uploader_id: MEMBER.into(),
        scope_kind: Some("peer".into()),
        scope_id: Some(BOT.into()),
        size_bytes: 120_000,
        expires_at: NOW_S + 30 * 86_400,
        store_id: "r2-primary".into(),
    }
}

#[test]
fn the_senders_own_file_for_this_bot_opens() {
    let rec = good();
    assert_eq!(check(Some(&rec), MEMBER, BOT, NOW_S), Ok(&rec));
    // At the cap exactly, and at its last second, still.
    let edge = BlobRecord { size_bytes: MAX_BOT_FILE_CIPHERTEXT as i64, expires_at: NOW_S, ..good() };
    assert!(check(Some(&edge), MEMBER, BOT, NOW_S).is_ok());
}

/// (a) The attack of plan §8.1: a member quotes the `media_id` of a file someone else uploaded —
/// to them, or to the bot — in a manifest of their own.
#[test]
fn a_blob_someone_else_uploaded_is_refused_even_for_this_bot() {
    let theirs = BlobRecord { uploader_id: OTHER.into(), ..good() };
    assert_eq!(check(Some(&theirs), MEMBER, BOT, NOW_S), Err(Refusal::NotTheSenders));
    // A frame with no sender the relay knows opens nothing.
    assert_eq!(check(Some(&good()), "", BOT, NOW_S), Err(Refusal::NotTheSenders));
}

/// (b) The sender's own blob, but meant for another chat: a person, a room, another bot, or one
/// uploaded with no scope (only its uploader may download that one).
#[test]
fn the_senders_blob_for_any_other_chat_is_refused() {
    let cases = [
        (Some("peer"), Some(OTHER)),
        (Some("peer"), Some("bot-another")),
        (Some("room"), Some(BOT)),
        (Some("room"), Some("room-1")),
        (None, None),
        (Some("peer"), None),
        (None, Some(BOT)),
    ];
    for (kind, id) in cases {
        let rec = BlobRecord {
            scope_kind: kind.map(str::to_string),
            scope_id: id.map(str::to_string),
            ..good()
        };
        assert_eq!(check(Some(&rec), MEMBER, BOT, NOW_S), Err(Refusal::NotForThisBot), "{kind:?} {id:?}");
    }
    assert_eq!(check(Some(&good()), MEMBER, "", NOW_S), Err(Refusal::NotForThisBot));
}

/// (c) Past retention: gone, even before the daily sweep deletes it.
#[test]
fn an_expired_blob_is_refused() {
    let old = BlobRecord { expires_at: NOW_S - 1, ..good() };
    assert_eq!(check(Some(&old), MEMBER, BOT, NOW_S), Err(Refusal::Expired));
}

/// (d) Bigger than a bot reads: refused before a byte is fetched.
#[test]
fn a_blob_over_the_bots_cap_is_refused() {
    let big = BlobRecord { size_bytes: MAX_BOT_FILE_CIPHERTEXT as i64 + 1, ..good() };
    assert_eq!(check(Some(&big), MEMBER, BOT, NOW_S), Err(Refusal::TooLarge));
    let nonsense = BlobRecord { size_bytes: -1, ..good() };
    assert_eq!(check(Some(&nonsense), MEMBER, BOT, NOW_S), Err(Refusal::TooLarge));
    // The relay's own 50 MiB upload ceiling is far above it.
    const { assert!(MAX_BOT_FILE_CIPHERTEXT < 50 * 1024 * 1024) };
    assert_eq!(MAX_BOT_FILE_BYTES, 10 * 1024 * 1024, "the hearings parser's limit (plan §3.1)");
}

#[test]
fn no_record_is_refused_and_every_refusal_has_a_code() {
    assert_eq!(check(None, MEMBER, BOT, NOW_S), Err(Refusal::Missing));
    let all = [Refusal::Missing, Refusal::NotTheSenders, Refusal::NotForThisBot, Refusal::Expired, Refusal::TooLarge];
    let codes: std::collections::BTreeSet<_> = all.iter().map(|r| r.code()).collect();
    assert_eq!(codes.len(), all.len());
    assert!(codes.iter().all(|c| c.starts_with("bot-file/")));
}

/// The record the check is handed is what `/media/upload`'s INSERT wrote: its uploader and its
/// declared scope, read back by [`BLOB_RECORD_SQL`] on the real schema.
#[test]
fn the_record_is_read_from_what_the_upload_wrote() {
    let db = crate::test_schema::full_schema();
    for u in [MEMBER, OTHER] {
        db.execute(
            "INSERT INTO users (id, email, identity_pubkey, created_at) VALUES (?1, ?1 || '@x.test', x'00', 1)",
            params![u],
        )
        .unwrap();
    }
    // The handler's INSERT, column for column (`media/handlers.rs::upload`).
    let insert = "INSERT INTO media_objects (blob_id, uploader_id, size_bytes, created_at, expires_at, content_type, scope_kind, scope_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    let exp = NOW_S + 86_400;
    db.execute(insert, params!["m-mine", MEMBER, 500, NOW_S, exp, "application/pdf", "peer", BOT]).unwrap();
    db.execute(insert, params!["m-theirs", OTHER, 500, NOW_S, exp, "application/pdf", "peer", MEMBER]).unwrap();
    db.execute(insert, params!["m-legacy", MEMBER, 500, NOW_S, exp, "application/pdf", None::<String>, None::<String>])
        .unwrap();
    let read = |id: &str| -> Option<BlobRecord> {
        db.query_row(BLOB_RECORD_SQL, params![id], |r| {
            Ok(BlobRecord {
                uploader_id: r.get(0)?,
                scope_kind: r.get(1)?,
                scope_id: r.get(2)?,
                size_bytes: r.get(3)?,
                expires_at: r.get(4)?,
                store_id: r.get(5)?,
            })
        })
        .ok()
    };
    let mine = read("m-mine");
    assert_eq!(mine.as_ref().map(|r| r.store_id.as_str()), Some("r2-primary"), "the column DEFAULT");
    assert!(check(mine.as_ref(), MEMBER, BOT, NOW_S).is_ok());
    assert_eq!(check(read("m-theirs").as_ref(), MEMBER, BOT, NOW_S), Err(Refusal::NotTheSenders));
    assert_eq!(check(read("m-legacy").as_ref(), MEMBER, BOT, NOW_S), Err(Refusal::NotForThisBot));
    assert_eq!(check(read("m-none").as_ref(), MEMBER, BOT, NOW_S), Err(Refusal::Missing));
}
