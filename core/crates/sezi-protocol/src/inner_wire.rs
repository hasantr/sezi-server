//! Wire record/wrapper types — `ActivityEvent` (typed plugin event) and `ChatPayload` (the Olm
//! body: it flatten-wraps InnerMessage and carries thread/ext/msg_uid). The canonical paths stay
//! `crate::inner::{ActivityEvent, ChatPayload}` via the re-export there.

use serde::{Deserialize, Serialize};

use super::{default_schema_version, is_default_ext, InnerMessage, WIRE_SCHEMA_VERSION};
use sezi_error::Result;

/// A plugin Activity event — the typed wire split.
///
/// JSON wire:
/// ```text
/// {"type": "invite"}
/// {"type": "join"}
/// {"type": "leave"}
/// {"type": "domain", "name": "note"}
/// ```
///
/// The control events (Invite/Join/Leave) are reserved for ChatRuntime's state machine and need
/// not be forwarded to the plugin. Domain events carry the plugin author's own semantics; `name`
/// is a string the plugin recognizes (such as "note", "doc", "list"). The Sezgi protocol never
/// interprets `name`, it only transports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActivityEvent {
    Invite,
    Join,
    Leave,
    Domain { name: String },
}

impl ActivityEvent {
    /// The name the plugin sees — the variant name for control events, `name` for domain
    /// events. A single string-compare surface.
    pub fn wire_name(&self) -> &str {
        match self {
            ActivityEvent::Invite => "invite",
            ActivityEvent::Join => "join",
            ActivityEvent::Leave => "leave",
            ActivityEvent::Domain { name } => name.as_str(),
        }
    }

    pub fn is_control(&self) -> bool {
        !matches!(self, ActivityEvent::Domain { .. })
    }

    /// Build the enum from the `(kind, name)` pair coming over the Dart FFI bridge.
    /// An unknown kind or an empty domain name yields Err.
    ///
    /// The failures answer with a stable `activity/…` code rather than a sentence: this `Err`
    /// crosses the FRB waist (`kernel/ffi/plugin.rs`) and, with no mapping for it in Dart, is
    /// shown verbatim. They are plugin-author diagnostics — a plugin passed a kind the host does
    /// not know — so no user can act on them differently, but they must not be Turkish prose.
    /// The match arms below (`"invite"`, `"join"`, `"leave"`, `"domain"`) are WIRE values and are
    /// not touched.
    pub fn from_wire(
        kind: &str,
        domain_name: Option<&str>,
    ) -> std::result::Result<Self, String> {
        match kind {
            "invite" => Ok(ActivityEvent::Invite),
            "join" => Ok(ActivityEvent::Join),
            "leave" => Ok(ActivityEvent::Leave),
            "domain" => {
                let name = domain_name
                    .ok_or_else(|| "activity/domain-name-required".to_string())?;
                if name.is_empty() {
                    return Err("activity/domain-name-empty".to_string());
                }
                Ok(ActivityEvent::Domain {
                    name: name.to_string(),
                })
            }
            other => Err(format!("activity/unknown-kind: {other}")),
        }
    }
}

/// Where a co-presence activity lives, as its sender states it on the wire.
///
/// JSON wire:
/// ```text
/// {"type": "direct"}
/// {"type": "room", "room_id": "<group id>"}
/// ```
///
/// Required on every [`InnerMessage::Activity`]. It replaced an optional `room` whose absence
/// meant "1:1", which let a 1:1 event pass for one of a room's sessions (B01, 2026-10-06): a
/// member who joined a room's session as a 1:1 ended it for everyone with a room-less leave, and
/// anybody holding an Olm session with a member could reach that member's open room session by
/// leaving the room off. Now "no room" cannot be said at all — `Direct` is a statement, and the
/// receiver drops an event whose scope is not the one the session is bound to
/// (`kernel/activity_scope.rs`).
///
/// `Direct` names nobody: the other side of a 1:1 is the envelope's sender, which the receiver
/// already knows from the Olm session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActivityWireScope {
    /// A 1:1 session between the sender and the receiver.
    Direct,
    /// A group session in this room. The receiver checks the sender is an active member.
    Room { room_id: String },
}

impl ActivityWireScope {
    /// The room, for a group session.
    pub fn room_id(&self) -> Option<&str> {
        match self {
            ActivityWireScope::Direct => None,
            ActivityWireScope::Room { room_id } => Some(room_id),
        }
    }
}

/// A group-library item pointed at from the room's chat — the card "Sohbette paylaş" sends
/// ([`InnerMessage::LibraryCard`]). A POINTER, never the item: no key, no hash, no part list.
/// Opening it looks the item up in the room's own library, so it opens only for someone who can
/// already see the item there, and a card that outlives its item simply finds nothing.
///
/// Every field is the SENDER's word and untrusted: the reader's projection checks the ids and the
/// title against the library record's own rules and that `room_id` is the room the message
/// arrived in, and shows anything else as an unsupported message.
///
/// No server id rides along: a server id is each device's own name for the address it attached
/// (`registry::k7_server_id_for`), and the message arrived on the server it is about.
///
/// `item_kind` and `media` are strings on the wire, like `CallLog.status`, so a value a later
/// build adds reads as a material / a file here instead of failing the decode of the message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryCardRef {
    pub room_id: String,
    pub author_id: String,
    pub item_id: String,
    pub title: String,
    /// `"recording"` | `"material"` — the library record's `kind`. Not called `kind`: that name
    /// is the enum tag the whole message is internally tagged with.
    pub item_kind: String,
    /// `"audio"` | `"video"` | `"file"`.
    pub media: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
}

/// The decrypted body of an Olm envelope. It wraps InnerMessage and carries the thread
/// information. Flattened in JSON.
///
/// Versioning:
///   - `schema_version` rides at the payload root; v1 (the default) is the current format and the
///     ground for v2+ changes (group chat / Megolm, binary envelope, etc.). An old client parses
///     with default=1 and silently swallows new fields (ext, new InnerMessage variants) or
///     degrades them to `Unknown`.
///   - `ext` is the forward-compatible metadata slot — future extra fields (e.g. `reply_to`,
///     `react_to`, `expire_at`) can live there. When empty/`Null` it is omitted from the wire; an
///     old client silently skips a field it does not know.
/// A voice note's length and the shape of what was said, carried in a file message's `ext`
/// (see [`ChatPayload::with_voice`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceNoteMeta {
    pub duration_ms: u32,
    /// One level per bar, 0 (silence) to 255 (the loudest the recorder measured).
    pub waveform: Vec<u8>,
}

impl VoiceNoteMeta {
    /// More bars than any bubble draws; a longer list from a sender is not trusted.
    pub const MAX_BARS: usize = 128;
    /// A voice note longer than an hour is not a voice note.
    pub const MAX_MS: u32 = 3_600_000;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatPayload {
    /// Wire schema version. v1 = the current JSON + Olm envelope format.
    /// `WIRE_SCHEMA_VERSION` is always written when producing a message; thanks to
    /// `default = 1` a field-less payload from an old sender still parses.
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    /// `None` → the "general" thread. Otherwise a UUID v4 string.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub thread_id: Option<String>,
    /// Set when a thread is created or renamed. On seeing it, the other side stores or updates
    /// its local thread store.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub thread_title: Option<String>,
    /// Group message correlation id, for receipts. Set only on group messages, where it is
    /// the sender's `local_id`. It travels inside the E2E payload so every member sees the same
    /// id; when a member receives or reads the message they send those ids back to the sender in a
    /// `GroupReceipt`, and the sender matches its own message with `find_by_local_id`. `None` for
    /// 1:1 (1:1 receipts work off msg_id). Forward compatible: an old client never sees this field
    /// (skip_if None).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub msg_uid: Option<String>,
    /// Forward-compatible metadata. New fields are embedded here as a JSON object and old clients
    /// skip them tolerantly. `Null` (the default) is not written to the wire — it saves bandwidth
    /// and keeps the JSON output clean.
    #[serde(default, skip_serializing_if = "is_default_ext")]
    pub ext: serde_json::Value,
    /// The actual message. Flattened at the JSON root (kind + variant fields).
    #[serde(flatten)]
    pub inner: InnerMessage,
}

impl ChatPayload {
    pub fn new(
        thread_id: Option<String>,
        thread_title: Option<String>,
        inner: InnerMessage,
    ) -> Self {
        Self {
            schema_version: WIRE_SCHEMA_VERSION,
            thread_id,
            thread_title,
            msg_uid: None,
            ext: serde_json::Value::Null,
            inner,
        }
    }

    /// Attach the group message correlation id — the sender calls this with `local_id` in
    /// `handle_send_group`, and members echo that id back in their receipts.
    pub fn with_msg_uid(mut self, uid: impl Into<String>) -> Self {
        self.msg_uid = Some(uid.into());
        self
    }

    /// Media caption + album tag (written into `ext` forward-compatibly; old clients neither see
    /// nor break on it). `caption` = the text shown under the media bubble; `album_id` = a shared
    /// id that groups images sent from the same selection into one grid bubble in the
    /// conversation (`album_index`/`album_count` give the tile position and total). Empty/None
    /// fields are not written to `ext` (clean JSON).
    pub fn with_media_meta(
        mut self,
        caption: Option<&str>,
        album_id: Option<&str>,
        album_index: Option<u32>,
        album_count: Option<u32>,
    ) -> Self {
        let mut obj = serde_json::Map::new();
        if let Some(c) = caption.map(str::trim).filter(|c| !c.is_empty()) {
            obj.insert("caption".into(), serde_json::Value::String(c.to_string()));
        }
        if let Some(a) = album_id.filter(|a| !a.is_empty()) {
            obj.insert("album_id".into(), serde_json::Value::String(a.to_string()));
            if let Some(i) = album_index {
                obj.insert("album_index".into(), serde_json::Value::from(i));
            }
            if let Some(n) = album_count {
                obj.insert("album_count".into(), serde_json::Value::from(n));
            }
        }
        if !obj.is_empty() {
            self.ext = serde_json::Value::Object(obj);
        }
        self
    }

    /// Attach a voice note's length and waveform, merged into `ext` like the caption.
    ///
    /// The receiver used to know nothing about a voice message until it had downloaded and
    /// started playing it: the bubble said "0:00" and drew a flat line. The recorder already
    /// measures the level while you speak; this carries a few dozen of those samples and the
    /// duration with the message, so the bubble shows a real waveform and a real length at once.
    /// An old client ignores the key.
    pub fn with_voice(mut self, voice: &VoiceNoteMeta) -> Self {
        let mut obj = match self.ext {
            serde_json::Value::Object(o) => o,
            _ => serde_json::Map::new(),
        };
        let mut v = serde_json::Map::new();
        v.insert("ms".into(), serde_json::Value::from(voice.duration_ms));
        // A plain array of 0–255 levels: ~150 bytes for 48 bars, and readable in a debugger.
        let wave: Vec<serde_json::Value> = voice
            .waveform
            .iter()
            .take(VoiceNoteMeta::MAX_BARS)
            .map(|&b| serde_json::Value::from(b))
            .collect();
        v.insert("wave".into(), serde_json::Value::Array(wave));
        obj.insert("voice".into(), serde_json::Value::Object(v));
        self.ext = serde_json::Value::Object(obj);
        self
    }

    /// The voice note's length and waveform, if the sender attached them. Anything malformed —
    /// a length past an hour, a waveform longer than [`VoiceNoteMeta::MAX_BARS`], a level past 255 —
    /// reads as absent: the bubble falls back to what it showed before, never to an error.
    pub fn voice(&self) -> Option<VoiceNoteMeta> {
        let v = self.ext.get("voice")?;
        let duration_ms = u32::try_from(v.get("ms")?.as_u64()?).ok()?;
        if duration_ms > VoiceNoteMeta::MAX_MS {
            return None;
        }
        let arr = v.get("wave")?.as_array()?;
        if arr.len() > VoiceNoteMeta::MAX_BARS {
            return None;
        }
        let waveform = arr
            .iter()
            .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect::<Option<Vec<u8>>>()?;
        Some(VoiceNoteMeta { duration_ms, waveform })
    }

    /// Mark this message as one the sender FORWARDED rather than wrote.
    ///
    /// It rides in `ext` so an old client parses the message normally and simply does not know it
    /// was forwarded — the degradation is "shown as an ordinary message", never a parse failure.
    ///
    /// Deliberately a bare flag and NOT the original sender's name. Carrying that would tell the
    /// new recipient who first wrote the words, which is a disclosure the forwarder may not intend
    /// and is a product decision rather than a technical one. The field can be widened later
    /// without breaking anything; it cannot be un-sent.
    ///
    /// Merges into `ext` rather than replacing it, because `with_media_meta` also lives there and
    /// a forwarded message with a caption must keep both.
    pub fn with_forwarded(mut self) -> Self {
        self.ext = mark_forwarded(self.ext);
        self
    }

    /// The `ext` of a message whose only metadata is the forwarded flag — the text lanes, which
    /// carry `forwarded: bool` where an attachment carries its whole `ext`. `Null` when it was not
    /// forwarded, so an ordinary message's payload stays byte-for-byte what it was.
    pub fn forwarded_ext(forwarded: bool) -> serde_json::Value {
        if forwarded {
            mark_forwarded(serde_json::Value::Null)
        } else {
            serde_json::Value::Null
        }
    }

    /// The `ext` of a group TEXT: the forwarded flag and the mentions, each only when there is
    /// one (`crate::mentions`). `Null` for an ordinary text, so its payload stays byte for byte
    /// what it was before mentions existed. The text lanes carry these two where an attachment
    /// carries its whole `ext`.
    pub fn text_ext(forwarded: bool, mentions: &[crate::mentions::MentionSpan]) -> serde_json::Value {
        crate::mentions::write(Self::forwarded_ext(forwarded), mentions)
    }

    /// [`Self::text_ext`] for a text that answers an earlier message (`crate::reply`).
    pub fn reply_text_ext(
        forwarded: bool,
        mentions: &[crate::mentions::MentionSpan],
        reply: Option<&crate::reply::ReplyRef>,
    ) -> serde_json::Value {
        crate::reply::write(Self::text_ext(forwarded, mentions), reply)
    }

    /// The reply this payload's `ext` carries, its shape checked (`crate::reply::read`).
    pub fn reply(&self) -> Option<crate::reply::ReplyRef> {
        crate::reply::read(&self.ext)
    }

    /// The sticker this payload is, believed: a TEXT whose body is exactly the emoji its
    /// `ext.sticker` spells (`crate::sticker::believed`). Anything else is no sticker.
    pub fn sticker(&self) -> Option<crate::sticker::StickerRef> {
        match &self.inner {
            InnerMessage::Text { body } => crate::sticker::believed(body, &self.ext),
            _ => None,
        }
    }

    /// The mentions this payload's `ext` carries, NOT vetted against the body — the receiving
    /// kernel vets them ([`crate::mentions::vet`]) and decides who may say `@herkes`.
    pub fn mentions(&self) -> Vec<crate::mentions::MentionSpan> {
        crate::mentions::read(&self.ext)
    }

    /// Was this message forwarded? Absent or non-boolean → false, so a malformed `ext` from any
    /// sender degrades to "an ordinary message" rather than to an error.
    pub fn is_forwarded(&self) -> bool {
        self.ext
            .get("forwarded")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Read the media caption out of `ext` (None if absent). The projection carries it into
    /// MessageView.
    pub fn caption(&self) -> Option<String> {
        self.ext.get("caption").and_then(|v| v.as_str()).map(str::to_string)
    }

    /// The album id from `ext` (None if absent). Consecutive messages with the same album_id are
    /// grouped into a single grid bubble in the UI.
    pub fn album_id(&self) -> Option<String> {
        self.ext.get("album_id").and_then(|v| v.as_str()).map(str::to_string)
    }

    /// The tile position within the album (0-based) and the total tile count, from `ext`.
    pub fn album_index(&self) -> Option<u32> {
        self.ext.get("album_index").and_then(|v| v.as_u64()).map(|n| n as u32)
    }
    pub fn album_count(&self) -> Option<u32> {
        self.ext.get("album_count").and_then(|v| v.as_u64()).map(|n| n as u32)
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("chat payload serialize")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// Add the forwarded flag to an `ext`, keeping every key already there. The one definition of what
/// the flag looks like on the wire, for `with_forwarded` and `forwarded_ext` both.
fn mark_forwarded(ext: serde_json::Value) -> serde_json::Value {
    let mut obj = match ext {
        serde_json::Value::Object(o) => o,
        _ => serde_json::Map::new(),
    };
    obj.insert("forwarded".into(), serde_json::Value::Bool(true));
    serde_json::Value::Object(obj)
}
