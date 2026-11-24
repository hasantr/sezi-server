//! A program's `sendDocument` (bot API 1.4), the inbox's half: the Worker has encrypted the file
//! and stored its blob (`bots/api_document.rs`, scope `peer` = the member), and hands over its
//! manifest. Here it is held to what a 1:1 text is held to — the reply-only rule and the send
//! limits — and sealed to every device of the member as an ordinary `InnerMessage::File`: their
//! app downloads and opens it as any file a person sent.

use super::*;
use sezi_protocol::inner::{ChatPayload, FileManifest, InnerMessage};

impl UserInbox {
    pub(super) async fn bot_send_document(&self, ctx: &BotCtx, body: &serde_json::Value) -> Result<Response> {
        let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
        let Some(manifest) = body
            .get("manifest")
            .and_then(|m| serde_json::from_value::<FileManifest>(m.clone()).ok())
        else {
            return crate::bots::api::bot_err(400, "bad-request");
        };
        let store = self.bot_store();
        let now = crate::utils::now_ms() as i64;
        let scope = dm_scope::Scope::stored(store.kv_get(dm_scope::KV_SCOPE).as_deref());
        if !dm_scope::may_write(&store.db, scope, to, now) {
            return crate::bots::api::bot_err(403, "reply-only");
        }
        let db = store.db;
        let chat = send_guard::chat_key(Some(to), None);
        let slot = match send_guard::take_slot(&db, &chat, now) {
            Ok(slot) => slot,
            Err(retry_after_s) => return send_guard::rate_limited(retry_after_s),
        };
        let msg_uid = send::new_msg_uid();
        let mut payload = ChatPayload::new(None, None, InnerMessage::File(manifest));
        payload.msg_uid = Some(msg_uid.clone());
        match self.bot_encrypt_payload(ctx, to, &payload).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                send_guard::refund(&db, slot);
                return crate::bots::api::bot_err(409, "no-devices");
            }
            Err(e) => {
                send_guard::refund(&db, slot);
                return Err(e);
            }
        }
        self.bot_drain_outbox(ctx).await;
        self.bot_rearm().await;
        Response::from_json(&crate::bots::api_answer::sent(&msg_uid))
    }

    /// `sendAppFile` (API 1.5): the same reply-only rule, then nothing is sent — the manifest goes
    /// back to the program for its interface (`answerApp`). No send slot: it is no message, and an
    /// interface opening books one after another would otherwise trip the chat's send limit; the
    /// call budget and the member's storage still bound it.
    pub(super) async fn bot_app_file(&self, body: &serde_json::Value) -> Result<Response> {
        let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
        let Some(manifest) = body
            .get("manifest")
            .and_then(|m| serde_json::from_value::<FileManifest>(m.clone()).ok())
        else {
            return crate::bots::api::bot_err(400, "bad-request");
        };
        let store = self.bot_store();
        let now = crate::utils::now_ms() as i64;
        let scope = dm_scope::Scope::stored(store.kv_get(dm_scope::KV_SCOPE).as_deref());
        if !dm_scope::may_write(&store.db, scope, to, now) {
            return crate::bots::api::bot_err(403, "reply-only");
        }
        Response::from_json(&crate::bots::api_answer::app_file(&manifest))
    }
}
