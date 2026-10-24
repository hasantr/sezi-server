//! A reply: which earlier message of the same conversation a text answers (board R5-Reply,
//! decision F1b of `docs/FIELD_READINESS_PLAN.md`).
//!
//! It travels in the payload's `ext` as `"reply": {"uid": …, "by": …, "kind": "text", "text": …}`
//! beside an ordinary text body; an old client ignores `ext` and shows the answer alone.
//!
//! - `uid` is the original's `msg_uid` — its sender's `local_id`, the one id every device of
//!   every member holds for it — so each device finds its OWN copy of the original.
//! - `by` is the original's author (a user id), and `kind` what it was (a text, a photo …).
//! - `text` is a SNAPSHOT of its first [`SNAPSHOT_CHARS`] characters, carried so that a device
//!   without the original (linked later, joined later, history cut) still reads what was answered.
//!   Hasan accepted on 2026-10-16 that a member who joined after the original sees that much of it:
//!   the one replying chose to quote it.
//!
//! Pure shape checks only; resolving `uid` against the local store and deciding "a reply to me"
//! is the kernel's (`kernel/reply.rs`).

use serde::{Deserialize, Serialize};

/// The key under `ext`.
pub const EXT_KEY: &str = "reply";

/// How much of the original a reply carries, in characters (not bytes, not UTF-16 units).
pub const SNAPSHOT_CHARS: usize = 100;

/// An id longer than this is not one.
const MAX_ID_LEN: usize = 160;

/// What the original was, as far as a quote needs to say.
pub const KINDS: [&str; 6] = ["text", "photo", "video", "file", "voice", "other"];

/// A reply's reference to the message it answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRef {
    /// The original's `msg_uid`.
    pub uid: String,
    /// The original's author.
    pub by: String,
    /// One of [`KINDS`].
    pub kind: String,
    /// The first [`SNAPSHOT_CHARS`] characters of its text — a caption or a file name for media;
    /// absent for a voice note or anything without words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl ReplyRef {
    /// A reference as it should be sent: the snapshot cut to [`SNAPSHOT_CHARS`], an unknown kind
    /// called `other`, empty text dropped.
    pub fn new(uid: impl Into<String>, by: impl Into<String>, kind: &str, text: Option<&str>) -> Self {
        Self {
            uid: uid.into(),
            by: by.into(),
            kind: if KINDS.contains(&kind) { kind } else { "other" }.to_string(),
            text: text.map(snapshot).filter(|t| !t.is_empty()),
        }
    }
}

/// The first [`SNAPSHOT_CHARS`] characters of `text`, on one line.
pub fn snapshot(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(SNAPSHOT_CHARS)
        .collect()
}

/// The reply an `ext` carries, as a receiver may believe its SHAPE: ids present and plausible,
/// a known kind, the snapshot cut to size and to one line. Anything else reads as no reply — the
/// words still arrive, as an ordinary message.
pub fn read(ext: &serde_json::Value) -> Option<ReplyRef> {
    let r: ReplyRef = serde_json::from_value(ext.get(EXT_KEY)?.clone()).ok()?;
    let id_ok = |s: &str| !s.is_empty() && s.len() <= MAX_ID_LEN;
    if !id_ok(&r.uid) || !id_ok(&r.by) || !KINDS.contains(&r.kind.as_str()) {
        return None;
    }
    Some(ReplyRef::new(r.uid, r.by, &r.kind, r.text.as_deref()))
}

/// `ext` with this reply under [`EXT_KEY`] (or without it), every other key kept; an `ext` left
/// empty is `Null`.
pub fn write(ext: serde_json::Value, reply: Option<&ReplyRef>) -> serde_json::Value {
    let mut obj = match ext {
        serde_json::Value::Object(o) => o,
        _ => serde_json::Map::new(),
    };
    match reply {
        Some(r) => {
            obj.insert(EXT_KEY.into(), serde_json::to_value(r).expect("reply serializes"));
        }
        None => {
            obj.remove(EXT_KEY);
        }
    }
    if obj.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_round_trips_beside_other_keys() {
        let r = ReplyRef::new("uid-1", "u-mert", "text", Some("Sınav 3. bölümden mi olacak?"));
        let ext = write(serde_json::json!({"forwarded": true}), Some(&r));
        assert_eq!(ext["forwarded"], true);
        assert_eq!(read(&ext), Some(r));
        assert_eq!(write(ext, None), serde_json::json!({"forwarded": true}));
        assert_eq!(write(serde_json::Value::Null, None), serde_json::Value::Null);
    }

    #[test]
    fn the_snapshot_is_a_hundred_characters_on_one_line() {
        let long = "çok uzun bir cümle\n\n".repeat(20);
        let s = snapshot(&long);
        assert_eq!(s.chars().count(), SNAPSHOT_CHARS, "characters, not bytes: ç is two bytes");
        assert!(!s.contains('\n'));
        // A sender who sends more is cut on arrival.
        let ext = serde_json::json!({"reply": {"uid": "u", "by": "b", "kind": "text", "text": long}});
        assert_eq!(read(&ext).unwrap().text.unwrap().chars().count(), SNAPSHOT_CHARS);
    }

    #[test]
    fn a_malformed_reply_is_no_reply() {
        for bad in [
            serde_json::json!({"reply": "x"}),
            serde_json::json!({"reply": {"uid": "", "by": "b", "kind": "text"}}),
            serde_json::json!({"reply": {"uid": "u", "by": "b", "kind": "script"}}),
            serde_json::json!({"reply": {"uid": "u", "kind": "text"}}),
            serde_json::json!({"reply": {"uid": "u".repeat(200), "by": "b", "kind": "text"}}),
        ] {
            assert_eq!(read(&bad), None, "{bad}");
        }
        assert_eq!(read(&serde_json::Value::Null), None);
    }

    #[test]
    fn an_unknown_kind_is_sent_as_other_and_empty_text_as_none() {
        let r = ReplyRef::new("u", "b", "sticker", Some("   "));
        assert_eq!((r.kind.as_str(), r.text), ("other", None));
    }
}
