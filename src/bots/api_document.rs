//! `sendDocument` (bot API 1.4): a program sends a FILE into a 1:1 chat — a book, a document.
//!
//! The one method whose body is not JSON: the bytes are the body (`application/octet-stream`),
//! what they are is in the query (`user_id`, `name`, `mime`), so a file is not held to the JSON
//! methods' 64 KiB. Up to [`MAX_DOCUMENT_BYTES`]. The Worker checks the target as `sendMessage`
//! does, encrypts the file as a member's app does (`sezi_file::encrypt_in_memory`: a fresh key,
//! XChaCha20-Poly1305 STREAM), stores the ciphertext as a media blob only that member may fetch
//! (scope `peer`), and hands the manifest to the bot's inbox, which seals it to every device of the
//! member (`inbox_do/bot/send_file.rs`). Their app downloads and opens it like any file.
//!
//! `sendAppFile` (bot API 1.5) is the same file for the bot's INTERFACE: stored the same way, held
//! to the same reply-only rule by the inbox, but sent as no message — its manifest (where the blob
//! is and its key) comes back to the program, which hands it to its interface in an `answerApp`,
//! and the member's app opens it there (a book straight into the reader), nothing in the chat.
//!
//! The plaintext passes through this Worker in memory, as it does through `getFile`; the store
//! keeps only ciphertext. A send the inbox refuses (reply-only, a send limit, no device) takes
//! the blob back out.

use worker::*;

use super::api::{bot_err, inbox_answer, send_target, Target, SEND_TARGET_SQL};
use super::api_input::{parse_document, DocumentReq};
use super::token::BotAuth;
use crate::d1util::d1_text;

/// The largest document: the same 10 MiB a bot may read from a member (`getFile`).
pub(crate) const MAX_DOCUMENT_BYTES: u64 = crate::media::bot_access::MAX_BOT_FILE_BYTES;

/// `for_app`: `sendAppFile` — no message, the manifest back to the program.
pub(crate) async fn send_document(
    mut req: Request,
    env: &Env,
    db: &D1Database,
    bot: &BotAuth,
    for_app: bool,
) -> Result<Response> {
    let url = req.url()?;
    let query: serde_json::Map<String, serde_json::Value> =
        url.query_pairs().map(|(k, v)| (k.into_owned(), serde_json::Value::String(v.into_owned()))).collect();
    let DocumentReq { user_id: to, name, mime } = match parse_document(&serde_json::Value::Object(query)) {
        Ok(d) => d,
        Err((status, code)) => return bot_err(status, code),
    };
    let declared = req.headers().get("content-length")?.and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_DOCUMENT_BYTES) {
        return bot_err(413, "file-too-large");
    }
    let target: Option<Target> = db
        .prepare(SEND_TARGET_SQL)
        .bind(&[d1_text(&to), d1_text(&bot.bot_id)])?
        .first(None)
        .await?;
    if let Err((status, code)) = send_target(target.as_ref()) {
        return bot_err(status, code);
    }
    let router = crate::storage::StorageRouter::from_env(env).await?;
    if !router.any_available() {
        return bot_err(503, "no-file-store");
    }
    let bytes = req.bytes().await.unwrap_or_default();
    if bytes.is_empty() {
        return bot_err(400, "bad-request");
    }
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return bot_err(413, "file-too-large");
    }
    let (mut manifest, ciphertext) = sezi_file::encrypt_in_memory(&bytes, &name, &mime)
        .map_err(|e| Error::RustError(format!("encrypt: {e}")))?;
    drop(bytes);
    let media_id = match crate::media::store_blob::store_media_blob(
        env,
        db,
        &router,
        &bot.bot_id,
        Some(("peer", &to)),
        ciphertext,
        "application/octet-stream",
    )
    .await?
    {
        Ok(id) => id,
        Err(refused) => return Ok(refused),
    };
    manifest.media_id = media_id.clone();
    let method = if for_app { "sendAppFile" } else { "sendDocument" };
    let call = serde_json::json!({ "method": method, "to": to, "manifest": manifest });
    let resp = super::bot_inbox(env, &bot.bot_id, Method::Post, "/bot/api", Some(call.to_string())).await;
    let sent = matches!(&resp, Ok(r) if r.status_code() == 200);
    if !sent {
        // Nothing was sent: the blob goes again. Best effort; expiry sweeps what this misses.
        if let Ok(stmt) = db
            .prepare("DELETE FROM media_objects WHERE blob_id = ? RETURNING size_bytes, store_id")
            .bind(&[d1_text(&media_id)])
        {
            #[derive(serde::Deserialize)]
            struct Gone {
                size_bytes: i64,
                store_id: String,
            }
            if let Ok(Some(g)) = stmt.first::<Gone>(None).await {
                crate::usage::media_removed(db, &[(bot.bot_id.clone(), g.size_bytes)]).await;
                let _ = router.delete(&g.store_id, &crate::storage::media_key(&media_id)).await;
            }
        }
    }
    inbox_answer(resp).await
}

#[cfg(test)]
mod tests {
    use crate::bots::api_input::{document_mime_ok, document_name_ok};

    #[test]
    fn names_and_types_are_held_to_their_shape() {
        assert!(document_name_ok("Yaşar Kemal - İnce Memed.epub"));
        assert!(!document_name_ok(""));
        assert!(!document_name_ok("../etc/passwd"));
        assert!(!document_name_ok("a\nb.pdf"));
        assert!(!document_name_ok(&"a".repeat(201)));
        assert!(document_mime_ok("application/epub+zip"));
        assert!(document_mime_ok("application/vnd.openxmlformats-officedocument.wordprocessingml.document"));
        assert!(!document_mime_ok("text"));
        assert!(!document_mime_ok("text/html; charset=utf-8"));
        assert!(!document_mime_ok("/x"));
    }
}
