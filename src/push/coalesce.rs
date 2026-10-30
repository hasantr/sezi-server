//! Coalescing wakes per device: one wake in flight is enough until the device has come for it.
//!
//! Measured on the live relay ZH (2026-10-30): one phone got 1,125 wakes in 24 h, in bursts of up
//! to 41 a minute — a peer's re-pair recovery fan-out is several envelopes to the same device, and
//! every one of them was its own wake. A wake carries nothing but "come and fetch"; the drain it
//! starts fetches EVERYTHING pending. So a second wake while the first one's drain has not begun
//! is pure cost: a background start the OS may cut short, and a hit on the shared relay's rate
//! limit, which answers 429 past six a minute per token.
//!
//! **The rule** ([`gate`]): a wake to a device is skipped when a wake to that same device went out
//! within the last [`WAKE_COALESCE_MS`] AND the device has not connected since the moment that
//! wake was for. Otherwise it is sent. Two halves, each closing one way to lose a message:
//!
//! - **"has not connected since"** is what the first debounce lacked (20 s, removed: a follow-up
//!   message arriving just after a drain finished got no wake, and so no delivery and no
//!   notification). A device that connected after the last wake's moment gets a new wake at once.
//! - **the window** is a lost push's retry: past it, the next envelope wakes again, seen or not.
//!   The inbox's backstop alarm (`alarm_ops.rs`) still covers a row nothing else woke.
//!
//! **Which moment.** A mark is not "when the wake was sent" but `covers_ms`: the moment from which
//! the wake's drain must be the device's NEXT connection — taken by the caller before the envelope
//! is stored. Comparing a connection against it, not against the send, closes a race inside the
//! inbox: an envelope stored just before the device connects, whose wake is decided just after,
//! would otherwise leave a fresh mark behind a drain that already happened and silence the next
//! message. Here that connection is at or after `covers_ms`, so the mark coalesces nothing.
//!
//! **A mark is written only after a push went out.** A wake still in flight (or one that failed —
//! a 429 from the shared relay, a token query error, push switched off) marks nothing, so it
//! cannot silence an envelope that arrived while it was in flight: that envelope is woken too. A
//! burst therefore costs one push plus those that land during the first send's round trip, not
//! one per envelope.
//!
//! **Urgent bypasses it** ([`WakeAsk::urgent`]). The sender flags the call signals that start or
//! stop a ring (a 1:1 invite, a ringing group join, end/reject/settled, a session's leave). Behind
//! an earlier wake that brought no connection — the OS refused the background start, the
//! Honor/Xiaomi case — an ordinary envelope can wait for the next envelope or the backstop
//! (30 s grace + a 90 s alarm), but a 45 s ring cannot. An urgent wake goes out whatever the mark
//! says, and marks like any other, so an ordinary envelope right behind it coalesces.
//!
//! **Where it lives.** In the recipient's inbox Durable Object (`inbox_do/wake_gate.rs`), the one
//! place that sees both: every wake is sent from there, and every connection (`/sync`, the only
//! way a device fetches `pending`) is accepted there. Its own SQLite, so a decision costs no
//! subrequest at all and a skipped wake costs nothing but a local read.

/// How long one wake stands in for the next ones to the same, unseen device.
pub(crate) const WAKE_COALESCE_MS: i64 = 30_000;

/// The mark of a device-blind wake (a row with no device, from before device addressing): every
/// device's connection counts as seen for it.
pub(crate) const BLIND_KEY: &str = "*";

/// What the sender asked of an envelope's wake: the send's `silent` and `urgent` flags, read at
/// each door (HTTP `/messages/send`, 1:1 and group; the WS `send` frame).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WakeIntent {
    /// Control traffic: stored, delivered on the next connection, no wake.
    Silent,
    Ordinary,
    /// A ring starting or stopping: past the gate.
    Urgent,
}

impl WakeIntent {
    /// Both flags absent is an ordinary wake — every client before them. `urgent` implies a
    /// wake: a body claiming both is urgent, because a ring that wakes nobody is exactly the
    /// failure the flag exists to prevent.
    pub(crate) fn from_flags(silent: bool, urgent: bool) -> Self {
        match (silent, urgent) {
            (_, true) => WakeIntent::Urgent,
            (true, false) => WakeIntent::Silent,
            (false, false) => WakeIntent::Ordinary,
        }
    }
    pub(crate) fn silent(self) -> bool {
        self == WakeIntent::Silent
    }
    pub(crate) fn urgent(self) -> bool {
        self == WakeIntent::Urgent
    }
}

/// What one wake is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WakeAsk {
    /// The moment the wake must cover from, taken before its envelope was stored.
    pub(crate) covers_ms: i64,
    /// The sender flagged it (a ring starting or stopping): past the gate.
    pub(crate) urgent: bool,
}

impl WakeAsk {
    pub(crate) fn ordinary(covers_ms: i64) -> Self {
        Self { covers_ms, urgent: false }
    }
}

/// One device's state in the gate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WakeMark {
    /// The `covers_ms` of the latest wake that went out. None = none outstanding.
    pub(crate) woke_for_ms: Option<i64>,
    /// When the device last connected (ms). None = never, as far as this inbox knows.
    pub(crate) seen_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    Send,
    /// The wake for `age_ms` ago is still to be fetched.
    Coalesced { age_ms: i64 },
}

/// The rule. A clock that went backwards (a mark in the future) sends: coalescing must never
/// outlive its window, whatever the clock does.
pub(crate) fn gate(mark: WakeMark, now_ms: i64) -> Gate {
    let Some(woke_for) = mark.woke_for_ms else {
        return Gate::Send;
    };
    let age_ms = now_ms - woke_for;
    if !(0..WAKE_COALESCE_MS).contains(&age_ms) {
        return Gate::Send;
    }
    // A connection at or after the wake's moment fetched what that wake was for (a tie counts
    // as seen: when in doubt, wake).
    if mark.seen_ms.is_some_and(|seen| seen >= woke_for) {
        return Gate::Send;
    }
    Gate::Coalesced { age_ms }
}

/// The gate's storage. Synchronous: the inbox's SQLite answers without leaving the isolate.
pub(crate) trait WakeMarks {
    /// One mark per key, in order; a key never marked reads as the default.
    fn read(&self, keys: &[String]) -> Vec<WakeMark>;
    /// A push to these keys went out, covering from `covers_ms`. A mark never moves back: two
    /// wakes finishing out of order leave the later moment.
    fn mark(&self, keys: &[String], covers_ms: i64);
}

#[cfg(test)]
#[path = "coalesce_tests.rs"]
mod tests;
