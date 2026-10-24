//! Wire envelope: turns an Olm `OlmMessage` into a kind tag + base64 ciphertext for
//! the wire. The server sees only this struct; its contents are opaque to it.

use serde::{Deserialize, Serialize};
use vodozemac::megolm::MegolmMessage;
use vodozemac::olm::{Message, OlmMessage, PreKeyMessage};

use sezi_error::{Error, Result};

/// An encrypted message on the wire (Olm 1:1 or Megolm group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    /// 0 = Olm PreKey (the first 1:1 message), 1 = Olm Normal, 2 = Megolm (group).
    pub kind: u8,
    /// Ciphertext, base64.
    pub ciphertext: String,
    /// The sender's outbound `session_id` for Megolm (kind=2) — it lets the receiver pick
    /// the RIGHT inbound session DETERMINISTICALLY. Without it the receiver brute-forces
    /// every session under `(room,sender)`, and under multi-device/key churn the wrong
    /// session answers "signature invalid" — that was the G5 root cause. Absent (an old
    /// sender, or Olm) → `None` → brute-force fallback (forward-compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

const KIND_PREKEY: u8 = 0;
const KIND_NORMAL: u8 = 1;
const KIND_MEGOLM: u8 = 2;

impl WireEnvelope {
    pub fn from_olm(msg: &OlmMessage) -> Self {
        match msg {
            OlmMessage::PreKey(m) => Self {
                kind: KIND_PREKEY,
                ciphertext: vodozemac::base64_encode(m.to_bytes()),
                session_id: None,
            },
            OlmMessage::Normal(m) => Self {
                kind: KIND_NORMAL,
                ciphertext: vodozemac::base64_encode(m.to_bytes()),
                session_id: None,
            },
        }
    }

    pub fn to_olm(&self) -> Result<OlmMessage> {
        let bytes = vodozemac::base64_decode(&self.ciphertext)
            .map_err(|_| Error::Malformed("envelope base64"))?;
        match self.kind {
            KIND_PREKEY => Ok(OlmMessage::PreKey(
                PreKeyMessage::from_bytes(&bytes).map_err(|_| Error::Malformed("prekey bytes"))?,
            )),
            KIND_NORMAL => Ok(OlmMessage::Normal(
                Message::from_bytes(&bytes).map_err(|_| Error::Malformed("message bytes"))?,
            )),
            _ => Err(Error::Malformed("envelope kind")),
        }
    }

    /// Wrap a Megolm group message (kind=2). `session_id` is the outbound session id → the
    /// receiver picks the RIGHT inbound session deterministically (the G5 fix: no brute
    /// force, no wrong session).
    pub fn from_megolm(msg: &MegolmMessage, session_id: &str) -> Self {
        Self {
            kind: KIND_MEGOLM,
            ciphertext: vodozemac::base64_encode(msg.to_bytes()),
            session_id: Some(session_id.to_string()),
        }
    }

    /// Read the Megolm `session_id` out of a group `envelope_b64`, if it carries one — used
    /// at decrypt time to pick the RIGHT inbound session. Unparseable, or the field is
    /// missing (an old sender) → `None`, and the caller falls back to brute force. Pure
    /// helper.
    pub fn megolm_session_id(envelope_b64: &str) -> Option<String> {
        let bytes = vodozemac::base64_decode(envelope_b64).ok()?;
        let env: WireEnvelope = serde_json::from_slice(&bytes).ok()?;
        env.session_id
    }

    /// Unwrap a Megolm group message. `kind != 2` is an error (wrong protocol).
    pub fn to_megolm(&self) -> Result<MegolmMessage> {
        if self.kind != KIND_MEGOLM {
            return Err(Error::Malformed("envelope kind not megolm"));
        }
        let bytes = vodozemac::base64_decode(&self.ciphertext)
            .map_err(|_| Error::Malformed("envelope base64"))?;
        MegolmMessage::from_bytes(&bytes).map_err(|_| Error::Malformed("megolm bytes"))
    }
}
