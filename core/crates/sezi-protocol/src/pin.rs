//! Pinned messages (Hasan, 2026-11-06): anyone in a conversation may pin a message to the top of
//! it, or take a pin off, in a 1:1 and in a group alike — Sezi gives nobody moderation powers, so
//! there is no admin rule here. A conversation shows at most [`MAX_PINS_PER_CONVERSATION`] live
//! pins.
//!
//! On the wire a pin is its own invisible message, [`crate::inner::InnerMessage::Pin`], that names
//! its target the way a reaction does (`crate::reaction`): the target's `msg_uid` and its author,
//! so every device finds its OWN copy of the message. `pinned: false` is the unpin.
//!
//! A pin carries its own end, `until_ms` (epoch ms, the pinner's clock), chosen when pinning:
//! [`PinDuration`]. It expires on every device by itself — nothing is sent when it ends; each
//! device reads it as gone once its clock passes `until_ms` ([`is_live`]).
//!
//! Ordering is last-writer-wins per (conversation, message) by the pinner's clock (`at_ms`); equal
//! times break by [`newer`], so every device settles on the same answer whatever order the copies
//! arrive in, and a redelivery changes nothing.
//!
//! Pure rules only; finding the target and deciding who may pin is the kernel's
//! (`kernel/message_pins.rs`).

/// The most pins a conversation shows at once. Pinning past it is refused on the pinner's device
/// (`pin/limit-reached`): the person takes one off first. Two people pinning at the same moment
/// can still make it eleven; every device then shows the newest ten.
pub const MAX_PINS_PER_CONVERSATION: usize = 10;

/// One day in milliseconds.
pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// How long a pin stays, chosen when pinning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinDuration {
    Day,
    Week,
    Month,
    /// No end: it stays until someone takes it off.
    Forever,
}

impl PinDuration {
    /// The pin's end for a pin made at `at_ms`; `None` for [`PinDuration::Forever`].
    pub fn until(self, at_ms: i64) -> Option<i64> {
        let days = match self {
            PinDuration::Day => 1,
            PinDuration::Week => 7,
            PinDuration::Month => 30,
            PinDuration::Forever => return None,
        };
        Some(at_ms.saturating_add(days * DAY_MS))
    }
}

/// Are these plausible ids for a pin's target (the same bounds a reaction keeps).
pub fn valid_target(uid: &str, by: &str) -> bool {
    crate::reaction::valid_target(uid, by)
}

/// Is a pin's end plausible: none, or after the moment it was made. A pin that ended before it
/// began is no pin anyone chose; it is dropped as malformed.
pub fn valid_until(at_ms: i64, until_ms: Option<i64>) -> bool {
    until_ms.is_none_or(|u| u > at_ms)
}

/// Does a pin stand at `now_ms`: pinned, and its end (if it has one) not reached yet.
pub fn is_live(pinned: bool, until_ms: Option<i64>, now_ms: i64) -> bool {
    pinned && until_ms.is_none_or(|u| u > now_ms)
}

/// One pin state as last-writer-wins compares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinWord<'a> {
    pub at_ms: i64,
    pub pinned: bool,
    pub until_ms: Option<i64>,
    /// Who said it.
    pub by: &'a str,
}

impl PinWord<'_> {
    /// The tuple the order is taken on: time first; at one time a pin over an unpin, a later end
    /// over an earlier one (no end counts as the latest), then the larger author id.
    fn key(&self) -> (i64, bool, i64, &str) {
        (self.at_ms, self.pinned, self.until_ms.unwrap_or(i64::MAX), self.by)
    }
}

/// Does `word` win over `old` — the last-writer-wins rule. A later time wins; equal times break
/// the same way on every device ([`PinWord::key`]). An equal word is not newer: the second copy
/// of a pin changes nothing.
pub fn newer(word: PinWord<'_>, old: PinWord<'_>) -> bool {
    word.key() > old.key()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(at_ms: i64, pinned: bool, until_ms: Option<i64>, by: &str) -> PinWord<'_> {
        PinWord { at_ms, pinned, until_ms, by }
    }

    #[test]
    fn a_duration_is_its_days_from_the_pin_and_forever_has_no_end() {
        assert_eq!(PinDuration::Day.until(1_000), Some(1_000 + DAY_MS));
        assert_eq!(PinDuration::Week.until(0), Some(7 * DAY_MS));
        assert_eq!(PinDuration::Month.until(0), Some(30 * DAY_MS));
        assert_eq!(PinDuration::Forever.until(5), None);
    }

    #[test]
    fn a_pin_stands_until_its_end_and_an_unpin_never_does() {
        assert!(is_live(true, None, i64::MAX - 1));
        assert!(is_live(true, Some(10), 9));
        assert!(!is_live(true, Some(10), 10), "the end itself is past");
        assert!(!is_live(false, None, 0));
        assert!(!is_live(false, Some(10), 0));
    }

    #[test]
    fn an_end_before_the_pin_is_malformed() {
        assert!(valid_until(5, None));
        assert!(valid_until(5, Some(6)));
        assert!(!valid_until(5, Some(5)));
        assert!(!valid_until(5, Some(-1)));
    }

    #[test]
    fn the_later_word_wins_and_a_tie_breaks_the_same_way_everywhere() {
        assert!(newer(w(2, false, None, "a"), w(1, true, None, "b")), "a later unpin wins");
        assert!(!newer(w(1, true, None, "b"), w(2, false, None, "a")), "an older pin loses");
        // Ties: both orders of arrival agree.
        for (x, y) in [
            (w(5, true, None, "a"), w(5, false, None, "b")),
            (w(5, true, Some(9), "a"), w(5, true, None, "a")),
            (w(5, true, Some(9), "a"), w(5, true, Some(9), "b")),
        ] {
            assert_ne!(newer(x, y), newer(y, x), "exactly one of {x:?} / {y:?} wins");
        }
        assert!(!newer(w(5, true, None, "a"), w(5, true, None, "a")), "the same word twice is no change");
    }

    #[test]
    fn a_target_needs_both_ids() {
        assert!(valid_target("uid", "u-1"));
        assert!(!valid_target("", "u-1"));
        assert!(!valid_target("uid", ""));
    }
}
