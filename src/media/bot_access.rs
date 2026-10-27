//! May a bot's inbox open this blob? (H3, docs/HEARINGS_BOT_PLAN.md §1.2, §8.1)
//!
//! A member's 1:1 file reaches a bot as an Olm-sealed manifest: a `media_id` and the key that
//! opens it. The manifest is the SENDER's word. The bot's inbox reads the store in-process, with
//! no `/media/:id` download gate in the way, so without this check a member could quote a
//! `media_id` from another chat — one they were sent, or saw in a log — and have the bot open a
//! blob the member could not download themselves, with its plaintext then in a program's hands.
//!
//! So before ANY read of the blob, the inbox asks the relay's own record of it: the
//! `media_objects` row `/media/upload` wrote from the uploader's token and declared scope
//! (`media/handlers.rs`), never the manifest. The blob must be
//! - (a) uploaded by the account that sent this frame (`uploader_id`, from the access token);
//! - (b) declared for a 1:1 with THIS bot (`scope_kind = 'peer'`, `scope_id = bot`) — the scope
//!   the kernel declares for any 1:1 file, so a blob meant for a person or a room is not one;
//! - (c) not past its `expires_at` (the retention the download path enforces too);
//! - (d) at most [`MAX_BOT_FILE_CIPHERTEXT`] as stored: a bot reads a file whole, in memory.
//!
//! Pure: the record comes in, a verdict goes out, and `bot_access_tests.rs` holds each refusal.
//! A room-scoped variant (a file a member's room call hands the bot, H7) will need its own rule —
//! `scope_kind = 'room'` and the caller's membership — and must not loosen this one.

use serde::Deserialize;

/// The largest file a bot reads: the hearing-minutes parser's own limit (plan §3.1), and what one
/// Durable Object should hold in memory twice (ciphertext and plaintext) for one round. The app
/// refuses a bigger file to a bot before uploading it (`core/src/kernel/bots.rs`
/// `BOT_MAX_FILE_BYTES`) — keep the two equal.
pub(crate) const MAX_BOT_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// The largest blob that can hold such a file: STREAM adds a 16-byte tag per chunk, which for the
/// kernel's 64 KiB chunks is 2.5 KiB over 10 MiB; the slack is a chunk, so no sender's chunking
/// within reason is refused for its tags. What decrypts is held to [`MAX_BOT_FILE_BYTES`] again.
pub(crate) const MAX_BOT_FILE_CIPHERTEXT: u64 = MAX_BOT_FILE_BYTES + 64 * 1024;

/// The relay's record of a blob. Bind: blob_id (the manifest's `media_id`).
pub(crate) const BLOB_RECORD_SQL: &str = "SELECT uploader_id, scope_kind, scope_id, size_bytes, expires_at, store_id
       FROM media_objects WHERE blob_id = ?1 LIMIT 1";

/// One `media_objects` row, as [`BLOB_RECORD_SQL`] reads it.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlobRecord {
    pub(crate) uploader_id: String,
    #[serde(default)]
    pub(crate) scope_kind: Option<String>,
    #[serde(default)]
    pub(crate) scope_id: Option<String>,
    pub(crate) size_bytes: i64,
    /// Seconds.
    pub(crate) expires_at: i64,
    /// Which store holds it (`StorageRouter::get` routes there).
    pub(crate) store_id: String,
}

/// Why a bot may not open a blob. The program is told less than this (`bot/file-unavailable` for
/// all but [`Refusal::TooLarge`]: whether someone else's blob EXISTS is not its business); the
/// relay's log names which (`code`), never the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No record: never uploaded, acked away, or swept by retention.
    Missing,
    /// (a) Someone other than this frame's sender uploaded it.
    NotTheSenders,
    /// (b) Declared for another chat, a room, or nobody.
    NotForThisBot,
    /// (c) Past its retention.
    Expired,
    /// (d) Bigger than a bot reads.
    TooLarge,
}

impl Refusal {
    /// The log code.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Refusal::Missing => "bot-file/missing",
            Refusal::NotTheSenders => "bot-file/not-the-senders",
            Refusal::NotForThisBot => "bot-file/not-for-this-bot",
            Refusal::Expired => "bot-file/expired",
            Refusal::TooLarge => "bot-file/too-large",
        }
    }
}

/// May the bot `bot_id` open the blob `record` describes, sent to it by `sender` (the relay's
/// sender of the frame that carried the manifest), at `now_s`? The record back when it may.
pub(crate) fn check<'a>(
    record: Option<&'a BlobRecord>,
    sender: &str,
    bot_id: &str,
    now_s: i64,
) -> Result<&'a BlobRecord, Refusal> {
    let rec = record.ok_or(Refusal::Missing)?;
    if sender.is_empty() || rec.uploader_id != sender {
        return Err(Refusal::NotTheSenders);
    }
    let for_this_bot = rec.scope_kind.as_deref() == Some("peer") && rec.scope_id.as_deref() == Some(bot_id);
    if bot_id.is_empty() || !for_this_bot {
        return Err(Refusal::NotForThisBot);
    }
    // The download path's own rule: past `expires_at` is gone, whatever the sweep has done.
    if rec.expires_at < now_s {
        return Err(Refusal::Expired);
    }
    if rec.size_bytes < 0 || rec.size_bytes as u64 > MAX_BOT_FILE_CIPHERTEXT {
        return Err(Refusal::TooLarge);
    }
    Ok(rec)
}

#[cfg(test)]
#[path = "bot_access_tests.rs"]
mod tests;
