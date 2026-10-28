//! Reactions: one emoji a person puts on a message (the WhatsApp model — one per person per
//! message; choosing another replaces it, choosing the same one again takes it back).
//!
//! On the wire a reaction is its own invisible message, [`crate::inner::InnerMessage::Reaction`],
//! that names its target the way a reply does (`crate::reply`): the target's `msg_uid` and its
//! author, so every device finds its OWN copy of the message. `emoji: None` is the removal.
//!
//! Ordering is last-writer-wins per (message, reactor) by the reactor's own clock (`at_ms`);
//! equal times break by [`newer`], so every device settles on the same answer whatever order the
//! copies arrive in, and a redelivery changes nothing.
//!
//! Pure shape checks only; finding the target and deciding who may react is the kernel's
//! (`kernel/reactions.rs`).

/// The longest emoji accepted, in UTF-8 bytes: room for a family or a flag sequence with skin
/// tones and joiners, not for a sentence.
pub const MAX_EMOJI_BYTES: usize = 32;

/// An id longer than this is not one (the same bound `crate::reply` keeps).
const MAX_ID_LEN: usize = 160;

/// Is `emoji` something a reaction may carry: non-empty, at most [`MAX_EMOJI_BYTES`], no
/// whitespace and no control characters, and no ASCII letter or digit — an emoji sequence, not
/// words. A keycap digit (`1️⃣`) is refused with the words; it is the one emoji this costs.
pub fn valid_emoji(emoji: &str) -> bool {
    !emoji.is_empty()
        && emoji.len() <= MAX_EMOJI_BYTES
        && !emoji
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c.is_ascii_alphanumeric())
}

/// Are these plausible ids for a reaction's target: present, and short enough to be ids.
pub fn valid_target(uid: &str, by: &str) -> bool {
    let ok = |s: &str| !s.is_empty() && s.len() <= MAX_ID_LEN;
    ok(uid) && ok(by)
}

/// Does `(at_ms, emoji)` win over `(old_at_ms, old_emoji)` — the last-writer-wins rule. A later
/// time wins; at the same time the larger emoji (a removal counts as the empty string) wins, so
/// two devices that disagree at one millisecond still agree on the outcome. An equal pair is not
/// newer: the second copy of a reaction changes nothing.
pub fn newer(at_ms: i64, emoji: Option<&str>, old_at_ms: i64, old_emoji: Option<&str>) -> bool {
    (at_ms, emoji.unwrap_or("")) > (old_at_ms, old_emoji.unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_are_accepted_and_words_are_not() {
        for ok in ["👍", "❤️", "😂", "😮", "😢", "🙏", "👨‍💻", "🇹🇷", "👍🏽", "#️⃣"] {
            assert!(valid_emoji(ok), "{ok}");
        }
        for bad in ["", "ok", "a👍", "👍 ", " ", "1", "1️⃣", "\u{7}", "👍\n", "\u{a0}"] {
            assert!(!valid_emoji(bad), "{bad:?}");
        }
        assert!(!valid_emoji(&"😀".repeat(9)), "36 bytes is over the limit");
        assert!(valid_emoji(&"😀".repeat(8)), "32 bytes is the limit");
    }

    #[test]
    fn the_later_reaction_wins_and_a_tie_breaks_the_same_way_everywhere() {
        assert!(newer(2, Some("👍"), 1, Some("❤️")));
        assert!(!newer(1, Some("❤️"), 2, Some("👍")));
        assert!(newer(2, None, 1, Some("👍")), "a later removal wins");
        assert!(!newer(1, Some("👍"), 2, None), "an older reaction does not undo a removal");
        // A tie: both orders of arrival agree.
        let a = newer(5, Some("👍"), 5, Some("❤️"));
        let b = newer(5, Some("❤️"), 5, Some("👍"));
        assert_ne!(a, b, "exactly one of the two wins");
        assert!(newer(5, Some("👍"), 5, None), "at one time a reaction wins over its removal");
        assert!(!newer(5, Some("👍"), 5, Some("👍")), "the same reaction twice is no change");
    }

    #[test]
    fn a_target_needs_both_ids() {
        assert!(valid_target("uid", "u-1"));
        assert!(!valid_target("", "u-1"));
        assert!(!valid_target("uid", ""));
        assert!(!valid_target(&"u".repeat(200), "u-1"));
    }
}
