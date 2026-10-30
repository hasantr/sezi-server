//! Messaging — the Olm 1:1 encrypt/decrypt surface.
//!
//! Hybrid flow:
//!   - Encrypt: Dart → Rust (produces the envelope, advances the session ratchet)
//!             → Dart posts it to the server via `/messages/send`.
//!   - Decrypt: Dart receives the envelope from the server over WS → hands it to Rust
//!             (plaintext + an up-to-date session blob come back).
//!
//! Session blob: one vodozemac::olm::Session pickle per (server, user, DEVICE) — every device
//! of a peer runs its own Olm account, which is what the archive/promotion logic further down
//! depends on. Rust owns the storage (`sezi_store::peer_store`'s olm_blobs plus
//! olm_session_archive).
//!
//! On the first message (no session yet):
//!   encrypt_to_peer  → otk_pub_b64 is supplied, an outbound session is built, a PreKey msg
//!                      is produced.
//!   decrypt_from_peer → a PreKey msg arrived, an inbound session is built, the identity's
//!                      OTK is consumed.
//!
//! Later messages: session_blob is supplied and the ratchet advances.
//!
//! ## Why the encrypt/decrypt surface is `pub`
//!
//! It IS the crypto layer's API, and unlike `Identity::account` none of it hands out a secret:
//! every one of these takes the key as a parameter and returns ciphertext or plaintext, so the
//! visibility exposes an operation, not a credential.

use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::Curve25519PublicKey;

use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::FileManifest;
use sezi_protocol::inner::{ActivityEvent, ActivityWireScope, ChatPayload, InnerMessage};

use crate::identity::to_key32;

#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// The envelope to put in the `/messages/send` body (base64 of JSON of WireEnvelope).
    pub envelope_b64: String,
    /// The updated session pickle (must be persisted).
    pub new_session_blob: String,
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    /// InnerMessage::Text body.
    ///
    /// For a file message this is NOT a placeholder — it is the `FileManifest` serialised to
    /// JSON, and that manifest carries `key_b64` and `nonce_b64`, i.e. the attachment's
    /// XChaCha20 STREAM key. Treat this field as key-bearing on the file path; the string
    /// `"[file]"` appears nowhere in the code.
    pub plaintext: String,
    /// "text" or "file" — so the UI can tell which kind it is.
    pub kind: String,
    /// The updated session pickle (must be persisted).
    pub new_session_blob: String,
    /// For a PreKey msg an OTK was consumed → the identity blob must be updated.
    /// None for a normal msg.
    pub new_identity_blob: Option<String>,
    /// Thread identifier. `None` → the general ("general") thread. Otherwise a UUID.
    pub thread_id: Option<String>,
    /// Proposed thread title (set at creation or rename time).
    /// When the other side sees it, it records it in its local thread store.
    pub thread_title: Option<String>,
}

/// Sends plaintext to a peer; returns envelope_b64 + the up-to-date session blob.
///
/// On the first message `session_blob = None`, `peer_otk_pub_b64 = Some`. On later
/// messages `session_blob = Some`, `peer_otk_pub_b64 = None`.
///
/// `thread_id = None` → the general thread. `thread_title` is set only when a thread is
/// created or renamed.
pub fn encrypt_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    plaintext: String,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    encrypt_inner_to_peer(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        InnerMessage::Text { body: plaintext },
        thread_id,
        thread_title,
    )
}

/// K5c re-login proof: opens the Account from `identity_blob` and produces its Ed25519
/// signing key plus a fresh challenge signature. At `/auth/relogin` the server binds this
/// pubkey to the user's registered SPK signature (identity) and verifies the challenge
/// (liveness). When the `refresh_token` dies (rotate/expire) this recovers the session
/// WITHOUT a NEW IDENTITY → pairing survives. Returns `(ed25519_pub_b64, ts,
/// signature_b64)`. The challenge format matches the server exactly:
/// `sezgi-relogin:{uid}:{ts}`.
pub fn build_relogin_proof(
    identity_blob: &str,
    pickle_key: &[u8],
    user_id: &str,
) -> Result<(String, u64, String), String> {
    let key = to_key32(pickle_key)?;
    let pickle = AccountPickle::from_encrypted(identity_blob, &key)
        .map_err(|e| format!("crypto/identity-blob-unreadable: {e}"))?;
    let account = Account::from(pickle);
    let ed_pub_b64 = vodozemac::base64_encode(account.ed25519_key().as_bytes());
    let ts = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let challenge = format!("sezgi-relogin:{user_id}:{ts}");
    let sig = account.sign(challenge.as_bytes());
    let sig_b64 = vodozemac::base64_encode(sig.to_bytes());
    Ok((ed_pub_b64, ts, sig_b64))
}

/// The shared body of every encrypt path. Not exposed to the UI; `encrypt_to_peer` and
/// `encrypt_file_manifest_to_peer` both go through it. When a stable correlation id is needed,
/// use `encrypt_inner_to_peer_uid` instead.
pub fn encrypt_inner_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    inner: InnerMessage,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    encrypt_inner_to_peer_uid(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        inner,
        thread_id,
        thread_title,
        None,
        serde_json::Value::Null, // control paths carry no metadata
    )
}

/// `encrypt_inner_to_peer` + a stable `msg_uid` (= the sender's `local_id`), embedded in the E2E
/// payload so EVERY device of the peer stores the SAME id — the per-device `remote_id` differs
/// between siblings, so sibling read-sync cannot match on it. `Some(local_id)` for user-visible
/// 1:1 messages (text/media); `None` is not written to the wire at all (skip_if). The group path
/// carries it separately, in this crate's `megolm.rs`.
///
/// `ext` is the payload's metadata object exactly as the sender's own row holds it — a caption, an
/// album slot, a voice note's length and waveform, the forwarded flag — and it is carried WHOLE,
/// not picked apart: until 2026-10-06 this function took only the forwarded flag, and every
/// attachment's metadata stopped at the sender's row (B07). `Value::Null` for none, which leaves
/// the field off the wire.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_inner_to_peer_uid(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    inner: InnerMessage,
    thread_id: Option<String>,
    thread_title: Option<String>,
    msg_uid: Option<String>,
    ext: serde_json::Value,
) -> Result<EncryptedMessage, String> {
    let key = to_key32(&pickle_key)?;

    let pickle = AccountPickle::from_encrypted(&identity_blob, &key)
        .map_err(|e| format!("crypto/identity-blob-unreadable: {e}"))?;
    let account = Account::from(pickle);

    let mut session = match session_blob.as_deref() {
        Some(blob) => unpickle_session(blob, &key)?,
        None => {
            let otk = peer_otk_pub_b64.ok_or_else(|| "crypto/first-message-needs-otk".to_string())?;
            let peer_x = Curve25519PublicKey::from_base64(&peer_x_pub_b64)
                .map_err(|e| format!("peer x_pub: {e}"))?;
            let peer_otk =
                Curve25519PublicKey::from_base64(&otk).map_err(|e| format!("peer otk_pub: {e}"))?;
            account
                .create_outbound_session(SessionConfig::version_1(), peer_x, peer_otk)
                .map_err(|e| format!("outbound session: {e}"))?
        }
    };

    let mut payload = ChatPayload::new(thread_id, thread_title, inner);
    payload.msg_uid = msg_uid;
    payload.ext = ext;
    let payload_bytes = payload.encode();
    let cipher = session
        .encrypt(&payload_bytes)
        .map_err(|e| format!("encrypt: {e}"))?;

    let envelope = WireEnvelope::from_olm(&cipher);
    let envelope_json =
        serde_json::to_vec(&envelope).map_err(|e| format!("envelope serialize: {e}"))?;
    let envelope_b64 = vodozemac::base64_encode(envelope_json);

    let new_session_blob = pickle_session(&session, &key);

    Ok(EncryptedMessage {
        envelope_b64,
        new_session_blob,
    })
}

/// Kernel-internal decrypt: returns the raw `ChatPayload`, NOT the `(kind, body)` flattening the
/// FRB-exposed `DecryptedMessage` does. `handle_inbound` stores the canonical payload AS IS and
/// routes on the `InnerMessage` variant, so nothing has to re-derive an InnerMessage from a
/// `(kind, plaintext-json)` pair. `decrypt_from_peer` wraps this and flattens it for Dart.
///
/// A PreKey message consumes an OTK, so `new_identity_blob` comes back too and MUST be persisted
/// — otherwise the same OTK is consumed twice.
pub struct DecryptedPayload {
    pub payload: ChatPayload,
    pub new_session_blob: String,
    pub new_identity_blob: Option<String>,
    /// Which of the offered sessions actually decrypted this message, exactly as it was passed in,
    /// or `None` when none did and a fresh inbound session had to be built.
    ///
    /// The caller needs it to PROMOTE a session that was working all along. When two peers collide
    /// (both create an outbound session at once) each ends up storing the other's, and the only way
    /// back is for the side that can still read a displaced session to make it current again. Told
    /// which blob worked, the caller does that; left guessing, it keeps the wrong one and the pair
    /// never converges.
    pub used_session: Option<String>,
}

/// Inbound decrypt error type. It DISTINGUISHES an identity-X clash against the
/// pinned/verified device key (impersonation OR a legitimate key rotation) from a generic
/// decrypt failure (replay/gap/MAC/no-session/parse). The kernel reads this distinction to
/// choose between the KeyChanged sink and generic self-heal: on `IdentityMismatch`,
/// self-heal/re-pair is NOT triggered.
///
/// `Other` carries the string-based behavior; the caller preserves the "message index" /
/// "can't be created" distinctions inside it.
#[derive(Debug)]
pub enum InboundDecryptError {
    /// The PreKey identity-X does not match the pinned device key — a forged envelope OR a
    /// legitimate rotation. No handshake reply is sent (drop); trust converges to
    /// `key_changed`.
    IdentityMismatch,
    /// Every other kind of decrypt failure — the string message is preserved.
    Other(String),
}

impl std::fmt::Display for InboundDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityMismatch => {
                f.write_str("crypto/prekey-x-pub-mismatch")
            }
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

impl From<String> for InboundDecryptError {
    fn from(msg: String) -> Self {
        Self::Other(msg)
    }
}

impl From<InboundDecryptError> for String {
    fn from(err: InboundDecryptError) -> Self {
        err.to_string()
    }
}

pub fn decrypt_payload_from_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    session_blob: Option<String>,
    envelope_b64: String,
) -> Result<DecryptedPayload, InboundDecryptError> {
    // The FRB `decrypt_from_peer` path hands these in by value (its signature is FROZEN —
    // frb_generated depends on it); pass refs to the inner &str-signature fn (this wrapper
    // owns the only copy).
    decrypt_payload_from_peer_with_expected_identity(
        &identity_blob,
        &pickle_key,
        session_blob,
        envelope_b64,
        None,
    )
}

/// Kernel path: while building a new/recovery inbound session from a PreKey, this binds the
/// sender's on-wire identity-X key to the expected device key that came from the QR code or
/// the signed device list. `None` is the FRB/legacy first-contact behavior.
pub fn decrypt_payload_from_peer_with_expected_identity(
    identity_blob: &str,
    pickle_key: &[u8],
    session_blob: Option<String>,
    envelope_b64: String,
    expected_peer_x_pub_b64: Option<&str>,
) -> Result<DecryptedPayload, InboundDecryptError> {
    let candidates: Vec<String> = session_blob.into_iter().collect();
    decrypt_payload_from_peer_sessions(
        identity_blob,
        pickle_key,
        &candidates,
        envelope_b64,
        expected_peer_x_pub_b64,
    )
}

/// Decrypt against SEVERAL candidate sessions, current one first.
///
/// One session per device is the assumption that breaks a call. Two peers who both start a session
/// at the same moment — which a call guarantees, since each end must send its own ICE candidates —
/// each end up storing the other's session, and neither can read the other. Recovery cannot help:
/// it would have to claim the one-time key a second time, and one-time keys are consumed on first
/// use. Measured on two devices as `unknown one-time key`, on every attempt, in both directions.
///
/// Offering the displaced sessions as well makes the collision survivable: whichever session the
/// peer actually used decrypts, and `used_session` tells the caller which one to promote so the
/// pair converges instead of fighting over a single slot.
pub fn decrypt_payload_from_peer_sessions(
    identity_blob: &str,
    pickle_key: &[u8],
    session_blobs: &[String],
    envelope_b64: String,
    expected_peer_x_pub_b64: Option<&str>,
) -> Result<DecryptedPayload, InboundDecryptError> {
    // identity_blob/pickle_key are taken by REF so the inbound hot path does not clone three
    // fields off ServerCtx per message.
    let key = to_key32(pickle_key)?;

    let pickle = AccountPickle::from_encrypted(identity_blob, &key)
        .map_err(|e| format!("crypto/identity-blob-unreadable: {e}"))?;
    let mut account = Account::from(pickle);

    let envelope_bytes =
        vodozemac::base64_decode(&envelope_b64).map_err(|e| format!("envelope base64: {e}"))?;
    let envelope: WireEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(|e| format!("envelope json: {e}"))?;
    let olm = envelope.to_olm().map_err(|e| format!("olm parse: {e}"))?;

    let mut identity_changed = false;
    let mut used_session: Option<String> = None;
    // Try EVERY offered session before concluding there is none. The first entry is the current
    // one; the rest are sessions this device was displaced from (`olm_session_archive`), and
    // reading one of those here is what avoids the recovery attempt the function doc describes.
    //
    // The FIRST candidate's error is the one reported if everything fails, which is the most
    // informative one: it comes from the session most likely to have been the right one. The text
    // is for humans — `inbound.rs` discriminates on the `InboundDecryptError` variant, not on a
    // substring, so rewording these does not reroute the gap/self-heal decision.
    let mut first_err: Option<String> = None;
    let mut decrypted: Option<(Vec<u8>, vodozemac::olm::Session)> = None;
    for blob in session_blobs {
        let mut s = match unpickle_session(blob, &key) {
            Ok(s) => s,
            Err(e) => {
                // A corrupt archive entry must not sink the whole decrypt: skip it and keep going.
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
                continue;
            }
        };
        match s.decrypt(&olm) {
            Ok(p) => {
                used_session = Some(blob.clone());
                decrypted = Some((p, s));
                break;
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(format!("normal decrypt: {e}"));
                }
            }
        }
    }
    let (plain_bytes, session) = match (decrypted, &olm) {
        (Some(ok), _) => ok,
        (None, OlmMessage::PreKey(pre)) => {
            // An identity-X pin clash propagates TYPED via `?` — it must NOT be wrapped in
            // map_err(format!) (O-H3: if IdentityMismatch is swallowed into Other, the security
            // decision is lost).
            verify_prekey_identity(pre, expected_peer_x_pub_b64)?;
            // `inbound recovery:` when we HAD sessions and none matched, `inbound:` when we had
            // none at all — the two cases need different reading in the log and always have.
            let label = if session_blobs.is_empty() {
                "inbound"
            } else {
                "inbound recovery"
            };
            let r = account
                .create_inbound_session(SessionConfig::version_1(), pre.identity_key(), pre)
                .map_err(|e| format!("{label}: {e}"))?;
            identity_changed = true;
            (r.plaintext, r.session)
        }
        (None, OlmMessage::Normal(_)) => {
            return Err(InboundDecryptError::Other(first_err.unwrap_or_else(|| {
                "crypto/no-session-for-normal-message".into()
            })))
        }
    };

    let new_session_blob = pickle_session(&session, &key);
    let payload =
        ChatPayload::decode(&plain_bytes).map_err(|e| format!("chat payload parse: {e}"))?;
    let new_identity_blob = if identity_changed {
        Some(account.pickle().encrypt(&key))
    } else {
        None
    };

    Ok(DecryptedPayload {
        payload,
        new_session_blob,
        new_identity_blob,
        used_session,
    })
}

fn verify_prekey_identity(
    pre: &vodozemac::olm::PreKeyMessage,
    expected_peer_x_pub_b64: Option<&str>,
) -> Result<(), InboundDecryptError> {
    let Some(expected_b64) = expected_peer_x_pub_b64 else {
        return Ok(());
    };
    let expected = Curve25519PublicKey::from_base64(expected_b64).map_err(|e| {
        InboundDecryptError::Other(format!("crypto/expected-peer-x-pub-unreadable: {e}"))
    })?;
    if pre.identity_key() != expected {
        return Err(InboundDecryptError::IdentityMismatch);
    }
    Ok(())
}

/// FRB-exposed decrypt: flattens a `DecryptedPayload` into a `(kind, body)` pair for Dart.
/// **The contract is frozen** (frb_generated depends on it) — do not change fields or shape.
///
/// Every control variant below is really handled by the kernel's `handle_inbound`; the arms here
/// exist only so this legacy path maps them instead of failing to parse. Where an arm says more
/// than that, the extra sentence is the reason it is worth reading.
pub fn decrypt_from_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    session_blob: Option<String>,
    envelope_b64: String,
) -> Result<DecryptedMessage, String> {
    let DecryptedPayload {
        payload,
        new_session_blob,
        new_identity_blob,
        // The FRB surface hands Dart a single session; session promotion is a kernel concern.
        used_session: _,
    } = decrypt_payload_from_peer(identity_blob, pickle_key, session_blob, envelope_b64)?;
    let ChatPayload {
        inner,
        thread_id,
        thread_title,
        ..
    } = payload;
    let (kind, body) = match inner {
        InnerMessage::Text { body } => ("text".to_string(), body),
        InnerMessage::File(manifest) => {
            let body = serde_json::to_string(&manifest)
                .map_err(|e| format!("manifest serialize: {e}"))?;
            ("file".to_string(), body)
        }
        InnerMessage::FileGroup { manifests } => {
            let body = serde_json::to_string(&manifests)
                .map_err(|e| format!("crypto/manifest-group-serialize-failed: {e}"))?;
            ("file_group".to_string(), body)
        }
        InnerMessage::RichText { delta_json, plain_text } => {
            // Dart needs both fields, so we wrap them and embed them inside plaintext as
            // JSON. Dart parses it.
            let inner_json = serde_json::json!({
                "delta": delta_json,
                "plain": plain_text,
            });
            ("rich_text".to_string(), inner_json.to_string())
        }
        // User-HTML card — the K7 kernel projection renders it (html_message); this legacy
        // FRB path only maps it for forward compatibility (body = raw html).
        InnerMessage::HtmlMessage { html } => ("html_message".to_string(), html),
        InnerMessage::Location {
            latitude,
            longitude,
            label,
            accuracy,
        } => {
            let inner_json = serde_json::json!({
                "latitude": latitude,
                "longitude": longitude,
                "label": label,
                "accuracy": accuracy,
            });
            ("location".to_string(), inner_json.to_string())
        }
        InnerMessage::LinkPreview {
            url,
            title,
            description,
            image_url,
            body_text,
        } => {
            let inner_json = serde_json::json!({
                "url": url,
                "title": title,
                "description": description,
                "image_url": image_url,
                "body_text": body_text,
            });
            ("link_preview".to_string(), inner_json.to_string())
        }
        InnerMessage::Activity {
            plugin_id,
            activity_id,
            seq,
            event,
            payload,
            .. // scope: this is the legacy 1:1 path (groups go via kernel InnerMessage::encode)
        } => {
            // The plugin spine: every co-presence variant rides one wire type.
            // Dart's `_handleInbound` routes to the PluginRegistry by plugin_id.
            // The `event` enum comes out as serde-tagged JSON, i.e. {"type": "..."}.
            let inner_json = serde_json::json!({
                "plugin_id": plugin_id,
                "activity_id": activity_id,
                "seq": seq,
                "event": event,
                "payload": payload,
            });
            ("activity".to_string(), inner_json.to_string())
        }
        // CallLog is a local call-history record ONLY — never sent, never decrypted; it must
        // not appear on this legacy decrypt path (defensive: if it does, swallow as control).
        InnerMessage::CallLog { .. } => ("control".to_string(), String::new()),
        // An edit is invisible: the kernel rewrites its message's words; it is never a row.
        InnerMessage::MessageEdit { .. } => ("control".to_string(), String::new()),
        // A batch of co-presence events is sent only to a kernel that said it reads batches,
        // and this path never says so (its single events carry `reads_batch: false`).
        InnerMessage::ActivityBatch { .. } => ("control".to_string(), String::new()),
        // A reaction is invisible: the kernel applies it to its message; it is never a row.
        InnerMessage::Reaction { .. } => ("control".to_string(), String::new()),
        // A room delete is invisible: the kernel applies it to its message; it is never a row.
        InnerMessage::RoomDelete { .. } => ("control".to_string(), String::new()),
        // Same shape as CallLog, and here the swallow is a security property rather than
        // defensiveness. A room-access notice is written locally by each member's own device
        // from its own view of the membership; one that arrives over the wire is by definition
        // someone else's claim about who may read a room, which is exactly the assertion this
        // feature refuses to trust. It is dropped, not rendered.
        InnerMessage::RoomAccessNotice { .. } => ("control".to_string(), String::new()),
        // The recording notice is the same class: each device writes its own from the signal it
        // heard, so one from the wire is somebody's claim and is dropped.
        InnerMessage::CallRecordingNotice { .. } => ("control".to_string(), String::new()),
        // So is the app-added notice: each device writes its own from the install it applied.
        InnerMessage::PluginAddedNotice { .. } => ("control".to_string(), String::new()),
        // And the room-bot notice: each device writes its own from its own group refresh.
        InnerMessage::RoomBotNotice { .. } => ("control".to_string(), String::new()),
        InnerMessage::P2pBlobOffer { ticket, manifest } => {
            // Ticket + manifest travel together in the body as one JSON object.
            // Dart's `_handleInbound` sees `kind == "p2p_blob_offer"` → hands the ticket to
            // iroh.recv_blob and decrypts the returned bytes with the manifest key/nonce.
            let manifest_value = serde_json::to_value(&manifest)
                .map_err(|e| format!("manifest serialize: {e}"))?;
            let inner_json = serde_json::json!({
                "ticket": ticket,
                "manifest": manifest_value,
            });
            ("p2p_blob_offer".to_string(), inner_json.to_string())
        }
        InnerMessage::P2pBlobReceived { ticket_hash, .. } => {
            let inner_json = serde_json::json!({ "ticket_hash": ticket_hash });
            ("p2p_blob_received".to_string(), inner_json.to_string())
        }
        InnerMessage::MediaReceived { media_id } => {
            let inner_json = serde_json::json!({ "media_id": media_id });
            ("media_received".to_string(), inner_json.to_string())
        }
        InnerMessage::RoomKeyShare { room_id, session_id, session_key_b64 } => {
            let inner_json = serde_json::json!({
                "room_id": room_id,
                "session_id": session_id,
                "session_key_b64": session_key_b64,
            });
            ("room_key_share".to_string(), inner_json.to_string())
        }
        InnerMessage::GroupReceipt { room_id, msg_uids, read } => {
            let inner_json = serde_json::json!({
                "room_id": room_id,
                "msg_uids": msg_uids,
                "read": read,
            });
            ("group_receipt".to_string(), inner_json.to_string())
        }
        InnerMessage::GroupJoinAccepted { room_id } => {
            let inner_json = serde_json::json!({ "room_id": room_id });
            ("group_join_accepted".to_string(), inner_json.to_string())
        }
        InnerMessage::GroupMembershipChanged { room_id } => {
            let inner_json = serde_json::json!({ "room_id": room_id });
            ("group_membership_changed".to_string(), inner_json.to_string())
        }
        InnerMessage::StateDigest { delivered_upto, read_upto, reply } => {
            let inner_json = serde_json::json!({
                "delivered_upto": delivered_upto,
                "read_upto": read_upto,
                "reply": reply,
            });
            ("state_digest".to_string(), inner_json.to_string())
        }
        InnerMessage::CallSignal { call_id, signal_type, data } => {
            let inner_json = serde_json::json!({
                "call_id": call_id,
                "signal_type": signal_type,
                "data": data,
            });
            ("call_signal".to_string(), inner_json.to_string())
        }
        InnerMessage::PluginRecord {
            plugin_id,
            collection,
            record_id,
            parent_id,
            op,
            fields_json,
            lamport,
            room,
        } => {
            let inner_json = serde_json::json!({
                "plugin_id": plugin_id,
                "collection": collection,
                "record_id": record_id,
                "parent_id": parent_id,
                "op": op,
                "fields_json": fields_json,
                "lamport": lamport,
                "room": room,
            });
            ("plugin_record".to_string(), inner_json.to_string())
        }
        InnerMessage::PluginInstall {
            plugin_id,
            name,
            icon,
            html,
            version,
            mode,
            room,
            code_ref,
            web_enabled,
            policy_rev,
        } => {
            let inner_json = serde_json::json!({
                "plugin_id": plugin_id,
                "name": name,
                "icon": icon,
                "html": html,
                "version": version,
                "mode": mode,
                "room": room,
                "code_ref": code_ref,
                "web_enabled": web_enabled,
                "policy_rev": policy_rev,
            });
            ("plugin_install".to_string(), inner_json.to_string())
        }
        InnerMessage::PluginRecordSnapshot { room, records } => {
            let recs = serde_json::to_value(&records)
                .map_err(|e| format!("snapshot serialize: {e}"))?;
            let inner_json = serde_json::json!({ "room": room, "records": recs });
            ("plugin_record_snapshot".to_string(), inner_json.to_string())
        }
        InnerMessage::PluginSnapshotRequest { room } => {
            let inner_json = serde_json::json!({ "room": room });
            ("plugin_snapshot_request".to_string(), inner_json.to_string())
        }
        InnerMessage::PluginInstallRequest { room } => {
            let inner_json = serde_json::json!({ "room": room });
            ("plugin_install_request".to_string(), inner_json.to_string())
        }
        // Defensive: the kernel's `handle_inbound` early branch takes all of these, so this path
        // should never see one. Swallowed as an invisible control row if it does.
        InnerMessage::OutboundCopy { .. }
        | InnerMessage::DeviceStatePacket { .. }
        | InnerMessage::DeviceStateRequest { .. }
        | InnerMessage::ReadSelfSync { .. }
        | InnerMessage::DeleteSelfSync { .. }
        | InnerMessage::OwnFileRequest { .. }
        | InnerMessage::OwnFileOffer { .. }
        | InnerMessage::EscrowCopy { .. }
        | InnerMessage::TakeoverNotice { .. }
        | InnerMessage::RoomKeyGossip { .. }
        | InnerMessage::RoomKeyRequest { .. }
        | InnerMessage::GroupOutboundCopy { .. }
        | InnerMessage::PluginEpochKeyShare { .. }
        | InnerMessage::PluginRemoved { .. }
        | InnerMessage::Typing { .. }
        | InnerMessage::ProfileAvatar { .. }
        // Bot-bound: a human never shows one; the kernel drops it before this matters.
        | InnerMessage::BotCall { .. }
        | InnerMessage::BotTap { .. } => ("control".to_string(), String::new()),
        // A group-library card travels over Megolm only, and the kernel projection draws it; on
        // this legacy 1:1 path it is mapped for completeness, the card as its JSON.
        InnerMessage::LibraryCard(card) => {
            let body = serde_json::to_string(&card)
                .map_err(|e| format!("crypto/library-card-serialize-failed: {e}"))?;
            ("library_card".to_string(), body)
        }
        InnerMessage::Unknown => {
            // Forward compat: an unknown `kind` from a newer client. The payload is empty — an
            // old client could not interpret it anyway — and Dart acks it with a UI warning.
            ("unknown".to_string(), String::new())
        }
    };

    Ok(DecryptedMessage {
        plaintext: body,
        kind,
        new_session_blob,
        new_identity_blob,
        thread_id,
        thread_title,
    })
}

pub fn pickle_session(session: &Session, key: &[u8; 32]) -> String {
    session.pickle().encrypt(key)
}

pub fn unpickle_session(blob: &str, key: &[u8; 32]) -> Result<Session, String> {
    let pickle = SessionPickle::from_encrypted(blob, key)
        .map_err(|e| format!("crypto/session-pickle-unreadable: {e}"))?;
    Ok(Session::from_pickle(pickle))
}

/// Injects `media_id` into the manifest JSON and sends it to the peer over Olm.
/// Shares the same session management as `encrypt_to_peer`.
pub fn encrypt_file_manifest_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    manifest_json: String,
    media_id: String,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    let mut manifest: FileManifest =
        serde_json::from_str(&manifest_json).map_err(|e| format!("manifest parse: {e}"))?;
    manifest.media_id = media_id;
    encrypt_inner_to_peer(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        InnerMessage::File(manifest),
        thread_id,
        thread_title,
    )
}

/// Sends text formatted as Quill Delta JSON to the peer. `plain_text` is the flat version the
/// recipient falls back to (clients without a toolbar, or preview generation). Shares the
/// same session management as encrypt_to_peer.
pub fn encrypt_rich_text_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    delta_json: String,
    plain_text: String,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    encrypt_inner_to_peer(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        InnerMessage::RichText {
            delta_json,
            plain_text,
        },
        thread_id,
        thread_title,
    )
}

/// A web-page preview produced on the sender side. URL + OpenGraph metadata + optional user
/// text. The server only ever sees an opaque envelope.
///
/// (A doc block describing multi-manifest `FileGroup` sending used to sit here, above the
/// wrong function — it belongs to `encrypt_file_group_to_peer`, which had no doc at all. It
/// evidently drifted during an insertion. Moved to its real owner during the English sweep.)
pub fn encrypt_link_preview_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    url: String,
    title: Option<String>,
    description: Option<String>,
    image_url: Option<String>,
    body_text: Option<String>,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    encrypt_inner_to_peer(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        InnerMessage::LinkPreview {
            url,
            title,
            description,
            image_url,
            body_text,
        },
        thread_id,
        thread_title,
    )
}

/// One-shot location sharing (a snapshot, not live). Sent to the peer over Olm.
/// Plaintext JSON: `{latitude, longitude, label?, accuracy?}`.
/// The server only ever sees an opaque envelope; location is always E2E.
pub fn encrypt_location_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    latitude: f64,
    longitude: f64,
    label: Option<String>,
    accuracy: Option<f64>,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    encrypt_inner_to_peer(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        InnerMessage::Location {
            latitude,
            longitude,
            label,
            accuracy,
        },
        thread_id,
        thread_title,
    )
}

/// Send several file manifests to a peer inside ONE Olm message.
///
/// Each manifest's `media_id` is patched from `media_ids[i]` (the ids that come back after
/// the parallel uploads), so the two slices MUST have the same length — otherwise this
/// returns an error. The list may not be empty.
///
/// Even a single-element list technically produces an `InnerMessage::FileGroup`; for one
/// file the caller may prefer `encrypt_file_manifest_to_peer` (backward compatibility).
pub fn encrypt_file_group_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    manifest_jsons: Vec<String>,
    media_ids: Vec<String>,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    if manifest_jsons.is_empty() {
        return Err("crypto/manifest-jsons-empty".into());
    }
    if manifest_jsons.len() != media_ids.len() {
        return Err(format!(
            "crypto/manifest-media-length-mismatch: manifest_jsons {} vs media_ids {}",
            manifest_jsons.len(),
            media_ids.len()
        ));
    }
    let mut manifests = Vec::with_capacity(manifest_jsons.len());
    for (i, mj) in manifest_jsons.iter().enumerate() {
        let mut m: FileManifest =
            serde_json::from_str(mj).map_err(|e| format!("manifest[{i}] parse: {e}"))?;
        m.media_id = media_ids[i].clone();
        manifests.push(m);
    }
    encrypt_inner_to_peer(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        InnerMessage::FileGroup { manifests },
        thread_id,
        thread_title,
    )
}

/// Plugin / SharedActivity event envelope. Co-presence features (piano, drawing, chess,
/// watch/view/listen together) all ride a single wire variant.
///
/// `plugin_id`: an id from the compile-time-known Dart kSezgiPlugins list.
/// `activity_id`: ties together every event of the same activity (e.g. one chess game).
///   UUID v4 recommended.
/// `seq`: a monotonically increasing counter within the plugin, so late or out-of-order
///   events can be told apart.
/// `event_kind`: "invite" | "join" | "leave" | "domain". The first three are control events
///   for the ChatRuntime state machine; domain is a plugin-domain event (supplied together
///   with `event_domain_name`).
/// `event_domain_name`: required only for `event_kind="domain"`; a string the plugin
///   recognizes (such as "note", "doc", "list").
/// `payload`: the plugin's own schema (an opaque JSON string). The Sezgi protocol never
///   interprets the schema; it only carries it.
pub fn encrypt_activity_to_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    peer_x_pub_b64: String,
    peer_otk_pub_b64: Option<String>,
    session_blob: Option<String>,
    plugin_id: String,
    activity_id: String,
    seq: u64,
    event_kind: String,
    event_domain_name: Option<String>,
    payload: String,
    thread_id: Option<String>,
    thread_title: Option<String>,
) -> Result<EncryptedMessage, String> {
    if plugin_id.is_empty() {
        return Err("crypto/plugin-id-empty".into());
    }
    if activity_id.is_empty() {
        return Err("crypto/activity-id-empty".into());
    }
    let event = ActivityEvent::from_wire(&event_kind, event_domain_name.as_deref())?;
    encrypt_inner_to_peer(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        InnerMessage::Activity {
            plugin_id,
            activity_id,
            seq,
            event,
            payload,
            // 1:1 co-presence (the group path goes via the kernel's activity intents)
            scope: ActivityWireScope::Direct,
            // This path cannot read a batch (its decrypt above drops one).
            reads_batch: false,
        },
        thread_id,
        thread_title,
    )
}
