//! Megolm group crypto — group (room) E2E.
//!
//! Where Olm (messaging.rs) is pairwise 1:1, Megolm is for group messaging: the sender creates
//! a `GroupSession` and encrypts messages with it (a single ciphertext goes to all members),
//! then ships the `session_key` to each member separately over 1:1 Olm (`RoomKeyShare`) →
//! members build an `InboundGroupSession` and decrypt.
//!
//! Key storage: `sezi_store::group_store` (opaque pickle blob). This module is pure
//! crypto — it never touches the DB, it takes and returns blob strings (messaging.rs pattern).
//! It is not FFI; its only caller is the kernel's group send/receive paths.

use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle, MegolmMessage,
    SessionConfig, SessionKey,
};

use sezi_protocol::envelope::WireEnvelope;
use sezi_protocol::inner::{ChatPayload, InnerMessage};

use crate::identity::to_key32;

/// Result of creating a new outbound group session.
pub struct CreateGroupSessionResult {
    /// GroupSession pickle (written to group_store; opaque).
    pub session_pickle: String,
    /// Session id (for inbound matching and the wire).
    pub session_id: String,
    /// Initial key to distribute to members (base64). Travels over 1:1 Olm.
    pub session_key_b64: String,
}

/// Create a new outbound `GroupSession` for a room.
pub fn create_group_session(pickle_key: Vec<u8>) -> Result<CreateGroupSessionResult, String> {
    let key = to_key32(&pickle_key)?;
    let session = GroupSession::new(SessionConfig::version_1());
    let session_id = session.session_id();
    let session_key_b64 = session.session_key().to_base64();
    let session_pickle = session.pickle().encrypt(&key);
    Ok(CreateGroupSessionResult {
        session_pickle,
        session_id,
        session_key_b64,
    })
}

/// Read the current `session_key` (base64) out of an existing outbound `GroupSession` pickle.
/// This does not advance the ratchet (it is a key export, not an encrypt), so the pickle is
/// unchanged and needs no write-back. Used to hand the key to a member added later: once that
/// member feeds it to `import_inbound_group_session` they can decrypt from the session's
/// current index forward — not past messages (Megolm forward secrecy; older messages are a
/// separate "history package" feature).
pub fn group_session_key(
    session_pickle: String,
    pickle_key: Vec<u8>,
) -> Result<String, String> {
    let key = to_key32(&pickle_key)?;
    let pickle = GroupSessionPickle::from_encrypted(&session_pickle, &key)
        .map_err(|e| format!("crypto/group-session-pickle-unreadable: {e}"))?;
    let session = GroupSession::from_pickle(pickle);
    Ok(session.session_key().to_base64())
}

/// Result of encrypting a group message.
pub struct EncryptedRoomMessage {
    /// Wire envelope (base64 of JSON of WireEnvelope, kind=2). Identical for every member.
    pub envelope_b64: String,
    /// Session id (for the write-back to group_store; constant for the session's lifetime).
    pub session_id: String,
    /// The advanced GroupSession pickle (written back to group_store; the ratchet).
    pub new_session_pickle: String,
    /// This message's index within the session (the ratchet counter).
    pub message_index: u32,
}

/// Encrypt an `InnerMessage` for a group using the given outbound `GroupSession` pickle.
///
/// `ext` is the payload's whole metadata object, as on the 1:1 path
/// (`messaging::encrypt_inner_to_peer_uid`): a caption, an album slot, voice data, the forwarded
/// flag. Carried as given; `Value::Null` for none.
pub fn encrypt_to_room(
    session_pickle: String,
    pickle_key: Vec<u8>,
    inner: InnerMessage,
    thread_id: Option<String>,
    thread_title: Option<String>,
    msg_uid: Option<String>,
    ext: serde_json::Value,
) -> Result<EncryptedRoomMessage, String> {
    let key = to_key32(&pickle_key)?;
    let pickle = GroupSessionPickle::from_encrypted(&session_pickle, &key)
        .map_err(|e| format!("crypto/group-session-pickle-unreadable: {e}"))?;
    let mut session = GroupSession::from_pickle(pickle);
    let session_id = session.session_id();
    // msg_uid (= the sender's local_id) is embedded in the E2E payload so every member sees the
    // same id and echoes it back in the `GroupReceipt`.
    let mut payload = ChatPayload::new(thread_id, thread_title, inner);
    payload.msg_uid = msg_uid;
    payload.ext = ext;
    let message_index = session.message_index();
    let msg = session.encrypt(payload.encode());
    let envelope = WireEnvelope::from_megolm(&msg, &session_id);
    let envelope_json = serde_json::to_vec(&envelope).map_err(|e| format!("envelope json: {e}"))?;
    let envelope_b64 = vodozemac::base64_encode(envelope_json);
    let new_session_pickle = session.pickle().encrypt(&key);
    Ok(EncryptedRoomMessage {
        envelope_b64,
        session_id,
        new_session_pickle,
        message_index,
    })
}

/// Result of building an `InboundGroupSession` from a member's session_key.
pub struct ImportInboundResult {
    pub inbound_pickle: String,
    pub session_id: String,
}

/// Build an inbound group session from a `session_key` a member shared (it arrived over 1:1
/// Olm) → we can now decrypt that member's group messages.
pub fn import_inbound_group_session(
    session_key_b64: String,
    pickle_key: Vec<u8>,
) -> Result<ImportInboundResult, String> {
    let key = to_key32(&pickle_key)?;
    let session_key =
        SessionKey::from_base64(&session_key_b64).map_err(|e| format!("session key parse: {e}"))?;
    let session = InboundGroupSession::new(&session_key, SessionConfig::version_1());
    let session_id = session.session_id();
    let inbound_pickle = session.pickle().encrypt(&key);
    Ok(ImportInboundResult {
        inbound_pickle,
        session_id,
    })
}

/// Merge two inbound pickles for the same `session_id`, keeping the ratchet that knows the most
/// history (lowest `first_known_index`).
///
/// **Never blind-overwrite instead** (`ON CONFLICT DO UPDATE blob=excluded`): a gossip or share
/// re-import can carry a newer, further-advanced key, and clobbering the earlier-index session
/// with it makes old messages surface as `UnknownMessageIndex` / "signature invalid". `merge`
/// returns the best ratchet for Equal/Better/Worse; on the rare Unconnected (a genuinely
/// different session) take whichever knows more history. A corrupt `existing` loses to
/// `incoming`, which is freshly valid.
pub fn merge_inbound_pickles(
    existing_pickle: String,
    incoming_pickle: String,
    pickle_key: Vec<u8>,
) -> Result<String, String> {
    let key = to_key32(&pickle_key)?;
    let mut incoming = InboundGroupSession::from_pickle(
        InboundGroupSessionPickle::from_encrypted(&incoming_pickle, &key)
            .map_err(|e| format!("incoming inbound pickle: {e}"))?,
    );
    // existing unpickle failed → the stored row is corrupt → use the fresh (incoming) one.
    let mut existing = match InboundGroupSessionPickle::from_encrypted(&existing_pickle, &key) {
        Ok(p) => InboundGroupSession::from_pickle(p),
        Err(_) => return Ok(incoming_pickle),
    };
    match existing.merge(&mut incoming) {
        Some(merged) => Ok(merged.pickle().encrypt(&key)),
        // Unconnected (should not happen for the same session_id) → keep whichever knows more
        // history.
        None => {
            if existing.first_known_index() <= incoming.first_known_index() {
                Ok(existing_pickle)
            } else {
                Ok(incoming_pickle)
            }
        }
    }
}

/// Result of decrypting a group message.
pub struct DecryptedRoomMessage {
    /// The decrypted canonical payload (thread + inner).
    pub payload: ChatPayload,
    /// The advanced InboundGroupSession pickle (written back to group_store).
    pub new_inbound_pickle: String,
    /// The message's index within the session (replay/ordering detection).
    pub message_index: u32,
}

/// Decrypt a group envelope with the given `InboundGroupSession` pickle.
pub fn decrypt_from_room(
    inbound_pickle: String,
    pickle_key: Vec<u8>,
    envelope_b64: String,
) -> Result<DecryptedRoomMessage, String> {
    let key = to_key32(&pickle_key)?;
    let pickle = InboundGroupSessionPickle::from_encrypted(&inbound_pickle, &key)
        .map_err(|e| format!("crypto/inbound-session-pickle-unreadable: {e}"))?;
    let mut session = InboundGroupSession::from_pickle(pickle);
    let env_bytes =
        vodozemac::base64_decode(&envelope_b64).map_err(|_| "envelope base64".to_string())?;
    let envelope: WireEnvelope =
        serde_json::from_slice(&env_bytes).map_err(|e| format!("envelope json: {e}"))?;
    let msg: MegolmMessage = envelope.to_megolm().map_err(|e| format!("{e:?}"))?;
    let decrypted = session
        .decrypt(&msg)
        .map_err(|e| format!("megolm decrypt: {e}"))?;
    let payload =
        ChatPayload::decode(&decrypted.plaintext).map_err(|e| format!("payload decode: {e}"))?;
    let new_inbound_pickle = session.pickle().encrypt(&key);
    Ok(DecryptedRoomMessage {
        payload,
        new_inbound_pickle,
        message_index: decrypted.message_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkey() -> Vec<u8> {
        vec![7u8; 32]
    }

    /// The forwarded flag reaches every member of a room, not only a 1:1 peer.
    ///
    /// Written after the 1:1 lane shipped alone and the first forward Hasan tried went to a
    /// group, where it arrived looking like something he had typed. Megolm builds its own payload
    /// rather than sharing the Olm builder, so "the flag works" on one lane says nothing about
    /// the other — which is exactly why this is a separate test and not an assumption.
    #[test]
    fn forwarded_reaches_the_room() {
        let k = pkey();
        let created = create_group_session(k.clone()).unwrap();
        let enc = encrypt_to_room(
            created.session_pickle.clone(),
            k.clone(),
            InnerMessage::Text { body: "a forwarded word".into() },
            None,
            None,
            Some("out-fwd".into()),
            ChatPayload::forwarded_ext(true),
        )
        .unwrap();
        let imported =
            import_inbound_group_session(created.session_key_b64.clone(), k.clone()).unwrap();
        let got = decrypt_from_room(imported.inbound_pickle, k.clone(), enc.envelope_b64).unwrap();
        assert!(got.payload.is_forwarded(), "a member has to see that it was forwarded");
        assert_eq!(got.payload.msg_uid.as_deref(), Some("out-fwd"), "and the receipt id survives");

        // The other half: an ordinary group message is NOT marked. Absence has to read as
        // "written by the sender", or every message in every room starts claiming otherwise.
        let plain = encrypt_to_room(
            created.session_pickle,
            k.clone(),
            InnerMessage::Text { body: "my own words".into() },
            None,
            None,
            Some("out-plain".into()),
            serde_json::Value::Null,
        )
        .unwrap();
        let imported = import_inbound_group_session(created.session_key_b64, k.clone()).unwrap();
        let got = decrypt_from_room(imported.inbound_pickle, k, plain.envelope_b64).unwrap();
        assert!(!got.payload.is_forwarded());
    }

    /// A photo's caption, album slot and voice data, as the sender's row holds them.
    fn media_ext() -> serde_json::Value {
        ChatPayload::new(None, None, InnerMessage::Text { body: String::new() })
            .with_media_meta(Some("the class"), Some("album-1"), Some(0), Some(2))
            .with_voice(&sezi_protocol::inner::VoiceNoteMeta {
                duration_ms: 4_300,
                waveform: vec![0, 40, 255],
            })
            .ext
    }

    /// A message's `ext` reaches the room WHOLE, with and without the forwarded flag.
    ///
    /// B07: every attachment's caption, album and voice data stopped at the sender's own row,
    /// because this function built a fresh payload whose `ext` could only ever receive the
    /// forwarded flag. The second half is the merge rule: forwarding something that already has
    /// metadata must add the flag beside it, never replace it.
    #[test]
    fn ext_reaches_the_room_with_and_without_forwarded() {
        let k = pkey();
        let created = create_group_session(k.clone()).unwrap();
        let ext = media_ext();
        let photo = InnerMessage::Text { body: "a photo".into() };
        let enc = encrypt_to_room(
            created.session_pickle.clone(),
            k.clone(),
            photo.clone(),
            None,
            None,
            Some("out-ext".into()),
            ext.clone(),
        )
        .unwrap();
        let imported =
            import_inbound_group_session(created.session_key_b64.clone(), k.clone()).unwrap();
        let got = decrypt_from_room(imported.inbound_pickle, k.clone(), enc.envelope_b64).unwrap();
        assert_eq!(got.payload.ext, ext, "the whole `ext`, not a whitelist of it");
        assert_eq!(got.payload.caption().as_deref(), Some("the class"));
        assert_eq!(got.payload.album_count(), Some(2));
        assert_eq!(got.payload.voice().map(|v| v.duration_ms), Some(4_300));
        assert!(!got.payload.is_forwarded(), "metadata alone is not a forward");

        let forwarded = ChatPayload::new(None, None, photo.clone())
            .with_media_meta(Some("the class"), Some("album-1"), Some(0), Some(2))
            .with_forwarded()
            .ext;
        let enc = encrypt_to_room(
            created.session_pickle,
            k.clone(),
            photo,
            None,
            None,
            Some("out-ext-fwd".into()),
            forwarded,
        )
        .unwrap();
        let imported = import_inbound_group_session(created.session_key_b64, k.clone()).unwrap();
        let got = decrypt_from_room(imported.inbound_pickle, k, enc.envelope_b64).unwrap();
        assert!(got.payload.is_forwarded());
        assert_eq!(
            got.payload.caption().as_deref(),
            Some("the class"),
            "the flag sits beside the caption; it does not replace it"
        );
    }

    #[test]
    fn megolm_room_roundtrip() {
        let k = pkey();
        // Alice creates the group session.
        let created = create_group_session(k.clone()).unwrap();
        // She encrypts the message for the group.
        let enc = encrypt_to_room(
            created.session_pickle.clone(),
            k.clone(),
            InnerMessage::Text { body: "hello group".into() },
            None,
            None,
            Some("out-1".into()),
            serde_json::Value::Null,
        )
        .unwrap();
        // Bob builds an inbound session from Alice's session_key.
        let imported =
            import_inbound_group_session(created.session_key_b64.clone(), k.clone()).unwrap();
        assert_eq!(imported.session_id, created.session_id, "the session_id must match");
        // Bob decrypts the message.
        let dec = decrypt_from_room(imported.inbound_pickle, k.clone(), enc.envelope_b64).unwrap();
        match dec.payload.inner {
            InnerMessage::Text { body } => assert_eq!(body, "hello group"),
            other => panic!("unexpected inner: {other:?}"),
        }
        // msg_uid must travel inside the E2E payload (receipt correlation, Faz 6 #1).
        assert_eq!(dec.payload.msg_uid.as_deref(), Some("out-1"));
        assert_eq!(enc.message_index, 0, "the first message is index 0");
        assert_eq!(dec.message_index, 0);
    }

    /// G5 fix: the group wire envelope must carry `session_id` so the receiver picks the right
    /// inbound session deterministically (no brute force, no wrong-session "signature invalid").
    #[test]
    fn wire_envelope_carries_session_id() {
        let k = pkey();
        let created = create_group_session(k.clone()).unwrap();
        let enc = encrypt_to_room(
            created.session_pickle,
            k,
            InnerMessage::Text { body: "x".into() },
            None,
            None,
            None,
            serde_json::Value::Null,
        )
        .unwrap();
        let sid = sezi_protocol::envelope::WireEnvelope::megolm_session_id(&enc.envelope_b64);
        assert_eq!(
            sid.as_deref(),
            Some(enc.session_id.as_str()),
            "the envelope session_id equals the outbound session_id (so the choice is deterministic)"
        );
    }

    #[test]
    fn late_joiner_key_decrypts_forward_not_history() {
        let k = pkey();
        let created = create_group_session(k.clone()).unwrap();
        // Message 0 is sent (the member is not in the group yet).
        let enc0 = encrypt_to_room(
            created.session_pickle.clone(),
            k.clone(),
            InnerMessage::Text { body: "eski".into() },
            None,
            None,
            None,
            serde_json::Value::Null,
        )
        .unwrap();
        // The late-joining member receives the current key (index 1).
        let late_key = group_session_key(enc0.new_session_pickle.clone(), k.clone()).unwrap();
        let imported = import_inbound_group_session(late_key, k.clone()).unwrap();
        // History (index 0) cannot be decrypted (forward secrecy).
        assert!(
            decrypt_from_room(imported.inbound_pickle.clone(), k.clone(), enc0.envelope_b64).is_err(),
            "a member added later must not be able to decrypt an older message"
        );
        // The new message (index 1) does decrypt.
        let enc1 = encrypt_to_room(
            enc0.new_session_pickle,
            k.clone(),
            InnerMessage::Text { body: "yeni".into() },
            None,
            None,
            None,
            serde_json::Value::Null,
        )
        .unwrap();
        let dec = decrypt_from_room(imported.inbound_pickle, k.clone(), enc1.envelope_b64).unwrap();
        match dec.payload.inner {
            InnerMessage::Text { body } => assert_eq!(body, "yeni"),
            other => panic!("beklenmeyen inner: {other:?}"),
        }
    }

    /// A4 (atomic inbound) group-leg verification: after a Megolm inbound pickle has decrypted a
    /// message and advanced, can the same message (same index) be decrypted again from the
    /// advanced pickle? If yes, the group crash window (a crash between "pickle written"
    /// `groups.rs:587` and "row missing" `:432`) is recovered on redelivery via re-decrypt plus
    /// the deterministic local_id (`gin-{session}-{index}`) → group A4 is already safe. This
    /// differs from 1:1 Olm: Olm consumes the message key, so a re-decrypt fails with "message
    /// index can't be created", while Megolm decrypts repeatedly from first_known_index onward.
    /// This test pins that recovery invariant — evidence that no structural A4 change is needed
    /// for groups, since touching decrypt_room_envelope would risk a working path.
    #[test]
    fn megolm_redecrypt_same_index_after_pickle_advance() {
        let k = pkey();
        let created = create_group_session(k.clone()).unwrap();
        let enc = encrypt_to_room(
            created.session_pickle,
            k.clone(),
            InnerMessage::Text { body: "kurtarilabilir".into() },
            None,
            None,
            Some("uid-a4".into()),
            serde_json::Value::Null,
        )
        .unwrap();
        let imported = import_inbound_group_session(created.session_key_b64, k.clone()).unwrap();
        // First decrypt → the pickle advances (new_inbound_pickle).
        let dec1 =
            decrypt_from_room(imported.inbound_pickle, k.clone(), enc.envelope_b64.clone()).unwrap();
        assert_eq!(dec1.message_index, 0);
        // Re-decrypt the same message (index 0) from the advanced pickle → post-crash redelivery.
        let dec2 = decrypt_from_room(dec1.new_inbound_pickle, k, enc.envelope_b64).unwrap();
        assert_eq!(
            dec2.message_index, 0,
            "an advanced pickle must still decrypt the SAME index again (the group A4 recovery path)"
        );
        match dec2.payload.inner {
            InnerMessage::Text { body } => assert_eq!(body, "kurtarilabilir"),
            other => panic!("beklenmeyen inner: {other:?}"),
        }
    }

    #[test]
    fn olm_envelope_rejected_by_megolm() {
        // to_megolm must reject an envelope with kind != 2 (no protocol mixing).
        let env = WireEnvelope { kind: 1, ciphertext: "AAAA".into(), session_id: None };
        assert!(env.to_megolm().is_err());
    }

    /// P0 #3 (corruption source): for the same session_id, merge keeps the ratchet that knows
    /// more history — a blind overwrite with a further-advanced index loses old messages.
    #[test]
    fn merge_keeps_more_history_ratchet() {
        let k = pkey();
        let created = create_group_session(k.clone()).unwrap();
        // index-0 message.
        let enc0 = encrypt_to_room(
            created.session_pickle.clone(),
            k.clone(),
            InnerMessage::Text { body: "eski".into() },
            None,
            None,
            None,
            serde_json::Value::Null,
        )
        .unwrap();
        // Further-advanced (current) key — this is what late-joiner distribution carries.
        let late_key = group_session_key(enc0.new_session_pickle.clone(), k.clone()).unwrap();
        let full = import_inbound_group_session(created.session_key_b64.clone(), k.clone()).unwrap();
        let late = import_inbound_group_session(late_key, k.clone()).unwrap();
        assert_eq!(full.session_id, late.session_id, "the same session_id");
        // merge(late, full) must keep the full-history ratchet (index 0) → index-0 decrypts.
        let merged = merge_inbound_pickles(
            late.inbound_pickle.clone(),
            full.inbound_pickle.clone(),
            k.clone(),
        )
        .unwrap();
        assert!(
            decrypt_from_room(merged, k.clone(), enc0.envelope_b64.clone()).is_ok(),
            "the merge must keep the full-history ratchet (index 0 still decrypts)"
        );
        // Control: late alone cannot decrypt index 0 → a blind overwrite would create exactly
        // this corruption.
        assert!(
            decrypt_from_room(late.inbound_pickle, k.clone(), enc0.envelope_b64).is_err(),
            "a late key alone cannot decrypt index 0 — this is exactly what a blind overwrite would lose"
        );
    }
}
