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
    /// A scheduled message's id (kind=3, `crate::scheduled`): the receiver opens the ciphertext
    /// with the one-time key it got for this id from the sender over Olm. Absent on every other
    /// kind, so their bytes are what they always were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

const KIND_PREKEY: u8 = 0;
const KIND_NORMAL: u8 = 1;
const KIND_MEGOLM: u8 = 2;
/// A scheduled message the relay held and released (`crate::scheduled`). Sent only to devices that
/// said they read it: an older build would read it as a broken Olm frame.
pub const KIND_SCHEDULED: u8 = 3;
/// Base64 of `{"kind":3` — the start of every release this crate writes (its fields serialize in
/// declaration order, `kind` first).
const SCHEDULED_PREFIX_B64: &str = "eyJraW5kIjoz";

impl WireEnvelope {
    pub fn from_olm(msg: &OlmMessage) -> Self {
        match msg {
            OlmMessage::PreKey(m) => Self {
                kind: KIND_PREKEY,
                ciphertext: vodozemac::base64_encode(m.to_bytes()),
                session_id: None,
                schedule: None,
            },
            OlmMessage::Normal(m) => Self {
                kind: KIND_NORMAL,
                ciphertext: vodozemac::base64_encode(m.to_bytes()),
                session_id: None,
                schedule: None,
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
            schedule: None,
        }
    }

    /// Wrap a scheduled message's sealed payload (kind=3) as the `envelope_b64` the relay holds and
    /// releases: base64 of this struct's JSON, like every envelope.
    pub fn scheduled_b64(schedule_id: &str, sealed_b64: &str) -> String {
        let env = Self {
            kind: KIND_SCHEDULED,
            ciphertext: sealed_b64.to_string(),
            session_id: None,
            schedule: Some(schedule_id.to_string()),
        };
        vodozemac::base64_encode(serde_json::to_vec(&env).expect("envelope serialize"))
    }

    /// Does `envelope_b64` start the way [`WireEnvelope::scheduled_b64`] writes a release —
    /// base64 of `{"kind":3` (nine bytes, so twelve characters that do not depend on what follows)?
    /// The relay refuses such an envelope on its ordinary send path with this test alone (no
    /// decode), and a receiver reads nothing else as a release ([`WireEnvelope::scheduled_parts`]
    /// checks it first), so the two can never disagree.
    pub fn is_scheduled_b64(envelope_b64: &str) -> bool {
        envelope_b64.starts_with(SCHEDULED_PREFIX_B64)
    }

    /// The `(schedule id, sealed payload)` of a scheduled `envelope_b64`, or `None` for any other
    /// envelope — the one test the inbound path makes before it reads a frame as Olm.
    pub fn scheduled_parts(envelope_b64: &str) -> Option<(String, String)> {
        if !Self::is_scheduled_b64(envelope_b64) {
            return None;
        }
        let bytes = vodozemac::base64_decode(envelope_b64).ok()?;
        let env: WireEnvelope = serde_json::from_slice(&bytes).ok()?;
        if env.kind != KIND_SCHEDULED {
            return None;
        }
        Some((env.schedule?, env.ciphertext))
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
