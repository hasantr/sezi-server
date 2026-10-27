//! A file a member sent the bot 1:1 (H3, docs/HEARINGS_BOT_PLAN.md §1.2, §8.1, §8.2).
//!
//! The engine hands the tick an `Inbound::File`: the manifests, keys included. What a program
//! reads must never carry a key, so the tick splits it in its synchronous block: the update
//! (`kind: "file"`, `updates::file_update`) names each file by an opaque `file_id` this inbox
//! mints, and the manifest waits in `bot_files` under that id, readable only here. A `file_id`
//! means nothing to any other bot: it is looked up in this inbox's own SQLite.
//!
//! **Opening one** ([`UserInbox::bot_file_bytes`], the one door): the row; then the relay's record
//! of the blob, judged by `media::bot_access::check` — uploaded by the member who sent the frame,
//! declared for a 1:1 with this bot, not expired, at most 10 MiB — BEFORE the store is read; then
//! the store; then `sezi_file::decrypt_in_memory`. The plaintext lives in the caller's memory and
//! nowhere else: no row, no log, no cache. The first open that succeeds tells the member's devices
//! `MediaReceived`, so their file shows as received, as a person's device makes it show.
//!
//! **Who opens.** A program, through `getFile {file_id}`: the DECRYPTED bytes over its own
//! authenticated API ([`UserInbox::bot_get_file`]), [`READS_PER_MINUTE`] a minute per bot — the
//! program never sees a key or a `media_id`. A built-in kind, in-process: the hearing-minutes
//! runner (H4) calls `bot_file_bytes` itself; the sheet and AI kinds read text only and answer a
//! file with one line (`builtin_run.rs`, `Line::TextOnly`).
//!
//! **How long.** A program bot's `bot_files` row lives as its updates do, 24 h from arrival, so a
//! program that was down an hour still gets the bytes; a webhook that took the update has deleted
//! it by then, which is why the row is not tied to the update. A built-in bot's row goes the
//! moment its round handles the update (§8.2). The blob itself follows the media store's
//! retention: only its uploader may delete it.

use super::store::{Arg, Exec};
use super::updates::{file_update, Who, UPDATE_TTL_MS};
use super::*;
use crate::media::bot_access::{self, BlobRecord, Refusal, MAX_BOT_FILE_BYTES, MAX_BOT_FILE_CIPHERTEXT};
use sezi_protocol::inner::{ChatPayload, FileManifest, InnerMessage};

/// `getFile`s one bot may make in a minute: each reads up to 10 MiB from the store and decrypts it
/// in this object, so this bounds what a program can make the relay hold, not only how often.
pub(super) const READS_PER_MINUTE: i64 = 20;
/// The sliding window of [`READS_PER_MINUTE`].
pub(super) const READ_WINDOW_MS: i64 = 60_000;

pub(super) const TABLES: [&str; 3] = [
    // One row per file of a `kind: "file"` update; `manifest_json` holds the key. `received`: the
    // member has been told `MediaReceived` (the first open that succeeded).
    "CREATE TABLE IF NOT EXISTS bot_files (
        file_id TEXT PRIMARY KEY, update_id INTEGER, from_user TEXT NOT NULL,
        manifest_json TEXT NOT NULL, created_at INTEGER NOT NULL,
        received INTEGER NOT NULL DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS idx_bot_files_update ON bot_files(update_id)",
    // One row per `getFile` admitted, for a minute.
    "CREATE TABLE IF NOT EXISTS bot_file_reads (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL)",
];

/// Bind: file_id, update_id, from, manifest_json, now.
pub(super) const FILE_PUT: &str = "INSERT INTO bot_files (file_id, update_id, from_user, manifest_json, created_at)
      VALUES (?, ?, ?, ?, ?)";
/// A file still within its 24 h. Bind: file_id, cutoff.
pub(super) const FILE_GET: &str =
    "SELECT from_user, manifest_json FROM bot_files WHERE file_id = ? AND created_at >= ?";
/// The first successful open, once: answers the id only when it was not yet marked. Bind: file_id.
pub(super) const FILE_RECEIVED: &str =
    "UPDATE bot_files SET received = 1 WHERE file_id = ? AND received = 0 RETURNING file_id";
/// A handled update's files (a built-in bot's, §8.2). Bind: update_id.
pub(super) const FILES_OF_UPDATE_DROP: &str = "DELETE FROM bot_files WHERE update_id = ?";
/// Bind: cutoff.
pub(super) const FILE_EXPIRE: &str = "DELETE FROM bot_files WHERE created_at < ?";
/// Bind: cutoff (now − window). A read at the cutoff has left the window.
pub(super) const READS_PRUNE: &str = "DELETE FROM bot_file_reads WHERE at <= ?";
pub(super) const READS_COUNT: &str = "SELECT COUNT(*) FROM bot_file_reads";
pub(super) const READS_OLDEST: &str = "SELECT COALESCE(MIN(at), 0) FROM bot_file_reads";
/// Bind: at.
pub(super) const READS_PUT: &str = "INSERT INTO bot_file_reads (at) VALUES (?)";

/// A file id of this inbox's: `f-<uuid>`. Opaque — it is neither the `media_id` nor derived from it.
pub(super) fn new_file_id() -> String {
    format!("f-{}", uuid::Uuid::new_v4())
}

/// One more `getFile` in the window, or the seconds until one fits (at least one).
pub(super) fn admit_read(count: i64, oldest_ms: i64, now_ms: i64) -> std::result::Result<(), u64> {
    if count < READS_PER_MINUTE {
        return Ok(());
    }
    Err(((oldest_ms + READ_WINDOW_MS - now_ms).max(0) as u64).div_ceil(1000).max(1))
}

/// Count and take a read slot, synchronously, or `Err(retry_after_s)`.
pub(super) fn take_read<E: Exec>(db: &E, now_ms: i64) -> std::result::Result<(), u64> {
    db.run(READS_PRUNE, &[Arg::I(now_ms - READ_WINDOW_MS)]);
    let count = db.int(READS_COUNT, &[]).unwrap_or(0);
    admit_read(count, db.int(READS_OLDEST, &[]).unwrap_or(0), now_ms)?;
    db.run(READS_PUT, &[Arg::I(now_ms)]);
    Ok(())
}

/// Why a file did not open. The program hears it as a code; the log names the relay's reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileError {
    /// No such file here, past its 24 h, or the relay's record refused it (`bot_access`): not the
    /// sender's upload, not for this bot, expired, gone. One answer for all, so a program cannot
    /// learn whether a blob it was pointed at exists.
    Unavailable,
    /// Over the 10 MiB a bot reads.
    TooLarge,
    /// The bytes did not open with the member's manifest (a broken or forged one).
    Unreadable,
    /// D1 or the store did not answer: try again later.
    StoreDown,
}

impl FileError {
    /// What a program is answered.
    pub(super) fn answer(self) -> Result<Response> {
        match self {
            FileError::Unavailable => crate::bots::api::bot_err(404, "file-unavailable"),
            FileError::TooLarge => crate::bots::api::bot_err(413, "file-too-large"),
            FileError::Unreadable => crate::bots::api::bot_err(422, "file-unreadable"),
            // ≥ 500: the Worker hands the program `bot/inbox-unavailable`, "retry later".
            FileError::StoreDown => crate::bots::api::bot_err(502, "inbox-unavailable"),
        }
    }
}

#[derive(Deserialize)]
struct FileRow {
    from_user: String,
    manifest_json: String,
}

impl UserInbox {
    /// A member's file, queued for the program (or the built-in round) as one `kind: "file"`
    /// update, its manifests in `bot_files`. Synchronous — called inside the tick's block.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn bot_queue_file(
        &self,
        from: &str,
        who: Option<&Who>,
        msg_uid: Option<&str>,
        manifests: &[FileManifest],
        caption: Option<&str>,
        ext: &serde_json::Value,
        remote_id: i64,
        now: i64,
    ) {
        let files: Vec<(String, &FileManifest)> = manifests.iter().map(|m| (new_file_id(), m)).collect();
        let update = file_update(now, from, who, msg_uid, caption, ext, &files);
        let Some(update_id) = self.bot_push_update(&update, now) else {
            return;
        };
        let db = self.bot_store().db;
        for (file_id, m) in &files {
            let Ok(manifest_json) = serde_json::to_string(m) else {
                continue;
            };
            db.run(FILE_PUT, &[Arg::T(file_id), Arg::I(update_id), Arg::T(from), Arg::T(&manifest_json), Arg::I(now)]);
        }
        self.bot_note_update_src(update_id, from, remote_id, msg_uid);
    }

    /// THE way into a member's file: verified against the relay's own record of the blob before a
    /// byte is read, then fetched and decrypted in memory. The bytes are the caller's to drop —
    /// nothing here keeps them. The hearing-minutes runner (H4) calls this in-process; `getFile`
    /// is the program's door to it.
    pub(super) async fn bot_file_bytes(&self, ctx: &BotCtx, file_id: &str) -> std::result::Result<Vec<u8>, FileError> {
        let now = crate::utils::now_ms() as i64;
        let row: Option<FileRow> = self
            .state
            .storage()
            .sql()
            .exec_raw(
                FILE_GET,
                Some(vec![JsValue::from_str(file_id), JsValue::from_f64((now - UPDATE_TTL_MS) as f64)]),
            )
            .and_then(|c| c.to_array())
            .ok()
            .and_then(|v: Vec<FileRow>| v.into_iter().next());
        let row = row.ok_or(FileError::Unavailable)?;
        let manifest: FileManifest = serde_json::from_str(&row.manifest_json).map_err(|_| FileError::Unreadable)?;
        // The member's word, checked first because it is free; the record below is the one trusted.
        if manifest.size > MAX_BOT_FILE_BYTES {
            return Err(FileError::TooLarge);
        }
        let record = self.bot_blob_record(&manifest.media_id).await?;
        let record = bot_access::check(record.as_ref(), &row.from_user, &ctx.bot_id, now / 1000).map_err(|r| {
            console_log!("[bot] file refused: {}", r.code());
            if r == Refusal::TooLarge {
                FileError::TooLarge
            } else {
                FileError::Unavailable
            }
        })?;
        let router = crate::storage::StorageRouter::from_env(&self.env).await.map_err(|_| FileError::StoreDown)?;
        if !router.any_available() {
            return Err(FileError::Unavailable);
        }
        let blob = match router.get(&record.store_id, &crate::storage::media_key(&manifest.media_id)).await {
            Ok(Some(b)) => b,
            Ok(None) => return Err(FileError::Unavailable),
            Err(_) => return Err(FileError::StoreDown),
        };
        if blob.bytes.len() as u64 > MAX_BOT_FILE_CIPHERTEXT {
            return Err(FileError::TooLarge);
        }
        let plain = sezi_file::decrypt_in_memory(&manifest, &blob.bytes).map_err(|_| {
            console_log!("[bot] file refused: bot-file/unreadable");
            FileError::Unreadable
        })?;
        if plain.len() as u64 > MAX_BOT_FILE_BYTES {
            return Err(FileError::TooLarge);
        }
        self.bot_note_received(ctx, file_id, &row.from_user, &manifest.media_id).await;
        Ok(plain)
    }

    /// The `media_objects` row of a blob, from D1.
    async fn bot_blob_record(&self, media_id: &str) -> std::result::Result<Option<BlobRecord>, FileError> {
        let db = self.env.d1("DB").map_err(|_| FileError::StoreDown)?;
        db.prepare(bot_access::BLOB_RECORD_SQL)
            .bind(&[crate::d1util::d1_text(media_id)])
            .map_err(|_| FileError::StoreDown)?
            .first(None)
            .await
            .map_err(|_| FileError::StoreDown)
    }

    /// The first open of a file tells the member's devices it was received (their attachment's
    /// third tick), as a person's device does after its download. Once per file; best effort.
    async fn bot_note_received(&self, ctx: &BotCtx, file_id: &str, member: &str, media_id: &str) {
        let first = self.bot_store().db.texts(FILE_RECEIVED, &[Arg::T(file_id)]);
        if first.is_empty() {
            return;
        }
        let payload = ChatPayload::new(None, None, InnerMessage::MediaReceived { media_id: media_id.to_string() });
        match self.bot_encrypt_payload(ctx, member, &payload).await {
            Ok(_) => self.arm_alarm_within(0).await,
            Err(e) => console_log!("[bot] MediaReceived not queued: {e:?}"),
        }
    }

    /// `/bot/file`: a program's `getFile`, after the Worker's checks — the bytes, or a code.
    pub(super) async fn bot_get_file(&self, body: &serde_json::Value) -> Result<Response> {
        // A built-in bot is the reader of its own files (`builtin_run.rs`), as of its updates.
        if self.builtin_config().is_some() {
            return crate::bots::api::bot_err(409, "builtin-active");
        }
        let ctx = self.bot_ctx()?;
        let file_id = body.get("file_id").and_then(|v| v.as_str()).unwrap_or("");
        if let Err(retry_after_s) = take_read(&self.bot_store().db, crate::utils::now_ms() as i64) {
            return super::send_guard::rate_limited(retry_after_s);
        }
        match self.bot_file_bytes(&ctx, file_id).await {
            Ok(bytes) => {
                let mut resp = Response::from_bytes(bytes)?;
                resp.headers_mut().set("content-type", "application/octet-stream")?;
                Ok(resp)
            }
            Err(e) => e.answer(),
        }
    }
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
