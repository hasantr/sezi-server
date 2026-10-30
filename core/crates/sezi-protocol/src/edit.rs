//! Editing a message: the author's new words for a text they sent (Hasan, 2026-10-29: within the
//! "delete for everyone" window, and nobody sees the earlier versions).
//!
//! On the wire an edit is its own invisible message, [`crate::inner::InnerMessage::MessageEdit`],
//! that names its target the way a reaction does (`crate::reaction`): the target's `msg_uid` and
//! its author, so every device finds its OWN copy. It carries the whole new content — a `Text` or
//! a `RichText` — never a diff, so a device that missed an earlier edit still ends on the latest.
//!
//! Each device keeps only the latest words, written over the message's stored payload, and the
//! editor's time in its `ext` (`edited_at`): that is what the "edited" mark reads, and what the
//! last-writer-wins order compares against. Equal times break by [`newer`], so every device
//! settles on the same words whatever order the copies arrive in, and a redelivery changes
//! nothing.
//!
//! Pure shape checks only; finding the target and deciding who may edit is the kernel's
//! (`kernel/message_edit.rs`).

use crate::inner::InnerMessage;

/// The `ext` key holding when a message was last edited (the editor's clock, epoch ms).
pub const EDITED_AT_KEY: &str = "edited_at";

/// The most an edit's new content may weigh, serialised. The relay refuses an envelope over
/// 64 KiB, and the content is base64-encoded TWICE on the way: the ciphertext inside the
/// `WireEnvelope` JSON, then that JSON for the wire (`megolm.rs`, the Olm path alike) — so at
/// most 64 × ¾ × ¾ ≈ 36 KiB of payload fits, minus the edit's own fields and the framing.
/// 40 KiB, the first value, assumed one layer: an edit between ~36 and 40 KiB was stored here
/// and refused by the relay on every retry (review 2026-10-29).
pub const MAX_EDIT_CONTENT_BYTES: usize = 32 * 1024;

/// Can `content` be the new words of a message: a `Text` or a `RichText` with something in it,
/// and not over [`MAX_EDIT_CONTENT_BYTES`]. A file, a card or anything else never replaces a
/// message's words.
pub fn valid_content(content: &InnerMessage) -> bool {
    let words = match content {
        InnerMessage::Text { body } => body,
        InnerMessage::RichText { plain_text, .. } => plain_text,
        _ => return false,
    };
    !words.trim().is_empty() && content.encode().len() <= MAX_EDIT_CONTENT_BYTES
}

/// When the message this `ext` belongs to was last edited, if it was.
pub fn edited_at(ext: &serde_json::Value) -> Option<i64> {
    ext.get(EDITED_AT_KEY)?.as_i64()
}

/// `ext` with `edited_at` set to `at_ms`, every other key kept.
pub fn write_edited_at(ext: serde_json::Value, at_ms: i64) -> serde_json::Value {
    let mut obj = match ext {
        serde_json::Value::Object(o) => o,
        _ => serde_json::Map::new(),
    };
    obj.insert(EDITED_AT_KEY.into(), serde_json::Value::from(at_ms));
    serde_json::Value::Object(obj)
}

/// Does an edit at `at_ms` with `content` win over the message's current state — last edited at
/// `old_at_ms` (`None`: never edited, which any edit wins over) with `old_content`? A later time
/// wins; at the same time the larger serialised content wins, so two devices that disagree at one
/// millisecond still agree on the words. An equal pair is not newer.
pub fn newer(
    at_ms: i64,
    content: &InnerMessage,
    old_at_ms: Option<i64>,
    old_content: &InnerMessage,
) -> bool {
    match old_at_ms {
        None => true,
        Some(old) => (at_ms, content.encode()) > (old, old_content.encode()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(body: &str) -> InnerMessage {
        InnerMessage::Text { body: body.into() }
    }

    #[test]
    fn only_words_can_be_the_new_content() {
        assert!(valid_content(&text("fixed")));
        assert!(valid_content(&InnerMessage::RichText {
            delta_json: r#"[{"insert":"bold\n"}]"#.into(),
            plain_text: "bold".into(),
        }));
        assert!(!valid_content(&text("  ")), "nothing to say is not an edit");
        assert!(!valid_content(&InnerMessage::HtmlMessage { html: "<b>x</b>".into() }));
        assert!(!valid_content(&InnerMessage::Unknown));
        assert!(!valid_content(&text(&"a".repeat(MAX_EDIT_CONTENT_BYTES))), "over the limit");
    }

    #[test]
    fn edited_at_is_written_beside_every_other_key() {
        let ext = serde_json::json!({"forwarded": true});
        let ext = write_edited_at(ext, 42);
        assert_eq!(edited_at(&ext), Some(42));
        assert_eq!(ext["forwarded"], true);
        assert_eq!(edited_at(&serde_json::Value::Null), None);
        assert_eq!(edited_at(&write_edited_at(serde_json::Value::Null, 7)), Some(7));
    }

    #[test]
    fn the_later_edit_wins_and_a_tie_breaks_the_same_way_everywhere() {
        let (a, b) = (text("a"), text("b"));
        assert!(newer(1, &a, None, &b), "any edit wins over the words as sent");
        assert!(newer(2, &a, Some(1), &b));
        assert!(!newer(1, &a, Some(2), &b), "an older edit does not undo a later one");
        let one = newer(5, &a, Some(5), &b);
        let other = newer(5, &b, Some(5), &a);
        assert_ne!(one, other, "exactly one of the two wins");
        assert!(!newer(5, &a, Some(5), &a), "the same edit twice is no change");
    }
}
