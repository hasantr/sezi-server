//! Messaging — the Olm 1:1 encrypt/decrypt surface.
//!
//! The kernel seals through `sezi-session` and the encrypt here (`encrypt_inner_to_peer_framed`),
//! and reads through `decrypt_payload_from_peer_sessions`; the rest of the encrypt/decrypt
//! wrappers (`encrypt_to_peer`, `encrypt_inner_to_peer(_uid)`,
//! `decrypt_payload_from_peer(_with_expected_identity)`) are thin shapes over those two that only
//! tests and the recorded corpora call. The legacy Dart bridge — `decrypt_from_peer` and its
//! `DecryptedMessage`, and one `encrypt_*_to_peer` per wire variant — had no caller and was
//! deleted on 2026-11-06 (CRY-2).
//!
//! Session blob: one vodozemac::olm::Session pickle per (server, user, DEVICE) — every device
//! of a peer runs its own Olm account, which is what the archive/promotion logic further down
//! depends on. Rust owns the storage (`sezi_store::peer_store`'s olm_blobs plus
//! olm_session_archive).
//!
//! On the first message (no session yet) the sender supplies the peer's one-time key, an
//! outbound session is built and a PreKey message produced; the receiver builds an inbound
//! session from it and its identity's one-time key is consumed. Later messages: session_blob is
//! supplied and the ratchet advances.
//!
//! ## Why the encrypt/decrypt surface is `pub`
//!
//! It IS the crypto layer's API, and unlike `Identity::account` none of it hands out a secret:
//! every one of these takes the key as a parameter and returns ciphertext or plaintext, so the
//! visibility exposes an operation, not a credential.

use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::Curve25519PublicKey;

use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::{ChatPayload, InnerMessage};

use crate::identity::to_key32;

#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// The envelope to put in the `/messages/send` body (base64 of JSON of WireEnvelope).
    pub envelope_b64: String,
    /// The updated session pickle (must be persisted).
    pub new_session_blob: String,
}

/// Sends plaintext to a peer; returns envelope_b64 + the up-to-date session blob. Tests and the
/// recorded corpora only.
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

/// `encrypt_inner_to_peer_uid` with no correlation id and no metadata. Tests and the recorded
/// corpora only; the kernel seals through `encrypt_inner_to_peer_framed`.
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
    encrypt_inner_to_peer_framed(
        identity_blob,
        pickle_key,
        peer_x_pub_b64,
        peer_otk_pub_b64,
        session_blob,
        inner,
        thread_id,
        thread_title,
        msg_uid,
        ext,
        false,
    )
}

/// `encrypt_inner_to_peer_uid`, and with `frame` the payload is framed first — padded to a bucket,
/// deflated when that pays (`sezi_protocol::payload_frame`). Only for a device that said it reads
/// framed payloads (`kernel/olm_frame.rs`); with `frame = false` the bytes are today's exactly.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_inner_to_peer_framed(
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
    frame: bool,
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
    let mut payload_bytes = payload.encode();
    if frame {
        payload_bytes = sezi_protocol::payload_frame::seal(&payload_bytes);
    }
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

/// A decrypted 1:1 payload: the raw `ChatPayload`. `handle_inbound` stores the canonical payload
/// AS IS and routes on the `InnerMessage` variant.
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

/// Decrypt with at most one candidate session and no pinned sender key. Tests and the recorded
/// corpora only; the kernel reads through `decrypt_payload_from_peer_sessions`.
pub fn decrypt_payload_from_peer(
    identity_blob: String,
    pickle_key: Vec<u8>,
    session_blob: Option<String>,
    envelope_b64: String,
) -> Result<DecryptedPayload, InboundDecryptError> {
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
/// the signed device list. `None` is the first-contact behavior. Tests only; the kernel passes its
/// candidates to `decrypt_payload_from_peer_sessions`.
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
    // A framed payload (padded, maybe deflated; `sezi_protocol::payload_frame`) is opened first;
    // a plain one — every older sender's — passes as it is.
    let plain_bytes = sezi_protocol::payload_frame::open(&plain_bytes)
        .map_err(|e| format!("chat payload frame: {e}"))?;
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

pub fn pickle_session(session: &Session, key: &[u8; 32]) -> String {
    session.pickle().encrypt(key)
}

pub fn unpickle_session(blob: &str, key: &[u8; 32]) -> Result<Session, String> {
    let pickle = SessionPickle::from_encrypted(blob, key)
        .map_err(|e| format!("crypto/session-pickle-unreadable: {e}"))?;
    Ok(Session::from_pickle(pickle))
}
