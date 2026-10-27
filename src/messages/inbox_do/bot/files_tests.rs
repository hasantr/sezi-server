//! A member's file in the bot inbox: its rows, `getFile`'s rate, and the decryption the inbox
//! runs — on rusqlite through the DO's own `Exec`, and on the real `sezi_file`.

use super::super::store::tests::Lite;
use super::super::store::TABLES as BOT_TABLES;
use super::super::updates::UPDATE_TTL_MS;
use super::*;
use rusqlite::Connection;

const T0: i64 = 1_761_200_000_000;

fn db() -> Lite {
    let c = Connection::open_in_memory().unwrap();
    for t in BOT_TABLES.iter().chain(TABLES.iter()) {
        c.execute_batch(t).unwrap();
    }
    Lite(c)
}

fn put(db: &Lite, file_id: &str, update_id: i64, at: i64) {
    db.run(FILE_PUT, &[Arg::T(file_id), Arg::I(update_id), Arg::T("alice"), Arg::T("{}"), Arg::I(at)]);
}

fn found(db: &Lite, file_id: &str, now: i64) -> bool {
    !db.texts(FILE_GET, &[Arg::T(file_id), Arg::I(now - UPDATE_TTL_MS)]).is_empty()
}

/// A program bot's file lives its update's 24 h — and only that, whether or not a webhook took
/// the update long before — and reads nothing past it even before the sweep runs.
#[test]
fn a_file_is_readable_for_its_updates_day_and_then_gone() {
    let db = db();
    put(&db, "f-1", 7, T0);
    assert!(found(&db, "f-1", T0 + UPDATE_TTL_MS), "at the end of its day");
    assert!(!found(&db, "f-1", T0 + UPDATE_TTL_MS + 1), "past it, before any sweep");
    assert!(!found(&db, "f-other", T0), "an id this inbox never minted");
    db.run(FILE_EXPIRE, &[Arg::I(T0 + 1)]);
    assert_eq!(db.int("SELECT COUNT(*) FROM bot_files", &[]), Some(0));
}

/// A built-in bot's file goes the moment its update is handled (plan §8.2), its neighbours' stay.
#[test]
fn a_handled_updates_files_are_deleted_with_it() {
    let db = db();
    put(&db, "f-a1", 1, T0);
    put(&db, "f-a2", 1, T0);
    put(&db, "f-b", 2, T0);
    db.run(FILES_OF_UPDATE_DROP, &[Arg::I(1)]);
    assert!(!found(&db, "f-a1", T0) && !found(&db, "f-a2", T0));
    assert!(found(&db, "f-b", T0));
}

/// `MediaReceived` goes to the member once per file, at its first successful open.
#[test]
fn the_member_hears_received_once() {
    let db = db();
    put(&db, "f-1", 1, T0);
    assert_eq!(db.texts(FILE_RECEIVED, &[Arg::T("f-1")]), vec!["f-1".to_string()]);
    assert!(db.texts(FILE_RECEIVED, &[Arg::T("f-1")]).is_empty(), "a second open says nothing");
    assert!(db.texts(FILE_RECEIVED, &[Arg::T("f-none")]).is_empty());
}

#[test]
fn get_file_is_held_to_twenty_a_minute() {
    let db = db();
    for i in 0..READS_PER_MINUTE {
        assert_eq!(take_read(&db, T0 + i * 100), Ok(()), "read {i}");
    }
    // The 21st waits until the first leaves the window: 60 s after it, less the 2.1 s gone.
    assert_eq!(take_read(&db, T0 + 2_100), Err(58));
    assert_eq!(take_read(&db, T0 + READ_WINDOW_MS - 1), Err(1), "never a zero wait");
    assert_eq!(take_read(&db, T0 + READ_WINDOW_MS), Ok(()), "the first read has left the window");
    assert_eq!(admit_read(0, 0, T0), Ok(()));
}

#[test]
fn a_file_id_is_opaque_and_never_the_media_id() {
    let (a, b) = (new_file_id(), new_file_id());
    assert_ne!(a, b);
    assert!(a.starts_with("f-") && a.len() == 38, "{a}");
    assert!(crate::bots::api_input::parse_get_file(&serde_json::json!({ "file_id": a })).is_ok());
}

/// The decryptor the inbox calls is the kernel's own, and it opens what the kernel's encryptor
/// sealed: the bytes back exactly, a wrong key refused, and a manifest that lies about the size
/// refused before it can size an allocation.
#[test]
fn the_inbox_opens_a_kernel_sealed_file_and_nothing_else() {
    let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (mut manifest, ciphertext) = sezi_file::encrypt_in_memory(&plain, "zabit.pdf", "application/pdf").unwrap();
    manifest.media_id = "media-1".into();
    assert_eq!(sezi_file::decrypt_in_memory(&manifest, &ciphertext).unwrap(), plain);
    assert!(ciphertext.len() as u64 <= MAX_BOT_FILE_CIPHERTEXT);

    let (other, _) = sezi_file::encrypt_in_memory(b"x", "y", "text/plain").unwrap();
    let wrong_key = FileManifest { key_b64: other.key_b64, ..manifest.clone() };
    assert!(sezi_file::decrypt_in_memory(&wrong_key, &ciphertext).is_err());
    let lying = FileManifest { size: u64::MAX, ..manifest };
    assert!(sezi_file::decrypt_in_memory(&lying, &ciphertext).is_err());
}

#[test]
fn every_refusal_is_answered_with_a_documented_code() {
    // The statuses are §2.5's error table's (`conformance_tests.rs` holds the table to the code).
    let src = include_str!("files.rs");
    for pair in [
        "(404, \"file-unavailable\")",
        "(413, \"file-too-large\")",
        "(422, \"file-unreadable\")",
        "(409, \"builtin-active\")",
    ] {
        assert!(src.contains(pair), "{pair}");
    }
}
