//! Live location (Hasan, 2026-11-09): Telegram's model — a location message that keeps moving for
//! a while the sender chose (15 minutes, an hour, eight hours), in a 1:1 and in a group alike.
//!
//! **The start** is an ordinary visible [`crate::inner::InnerMessage::Location`] carrying
//! `live_until_ms`, the share's end on the sender's clock. A build that predates live location
//! reads it as a plain one-shot location: an internally tagged variant ignores a field it does
//! not know (no `deny_unknown_fields` anywhere on `InnerMessage`), so the first fix is what it
//! shows.
//!
//! **An update** is its own invisible message, [`crate::inner::InnerMessage::LiveLocationUpdate`],
//! naming the start message the way a reaction names its target (`msg_uid` + author). Updates are
//! LIVE — a lost one is replaced by the next — and only the STOP (with the last position) must
//! arrive. Every device keeps the latest position per message, last writer wins by the sender's
//! `at_ms` ([`accept`]); a stop is final.
//!
//! **Believed** only from the start message's author, and only inside its window: an update said
//! after `live_until_ms` + [`GRACE_MS`] is late and dropped ([`within_window`]). A share never
//! runs past [`MAX_LIVE_MS`] from its start, whatever `live_until_ms` claims ([`effective_until`]).
//!
//! **Expiry needs no message**: at `live_until_ms` every device reads the share as ended by its
//! own clock, as a pin's end. Pure rules only; the kernel finds the target, decides who is
//! believed and sends (`kernel/live_location.rs`).

/// One minute in milliseconds.
pub const MINUTE_MS: i64 = 60 * 1000;

/// The longest a live share runs: the longest duration offered.
pub const MAX_LIVE_MS: i64 = 8 * 60 * MINUTE_MS;

/// How late past its end an update is still believed — the sender's and the receiver's clocks
/// and a slow relay, not a second life for the share.
pub const GRACE_MS: i64 = 2 * MINUTE_MS;

/// The sender sends no two updates closer than this (Hasan, 2026-11-09: "no more often than every
/// ~15 s"). A stop is never held back.
pub const MIN_INTERVAL_MS: i64 = 15 * 1000;

/// A fix this far from the last one sent is worth sending (once [`MIN_INTERVAL_MS`] has passed).
/// Ten metres is about what a phone's balanced fix wanders while lying still; less would send
/// noise every 15 s from a desk.
pub const MOVED_M: f64 = 10.0;

/// Without moving, a fix is still sent this often, so the others see "updated a minute ago"
/// rather than wonder whether the share died.
pub const HEARTBEAT_MS: i64 = 2 * MINUTE_MS;

/// How long a live share runs, chosen when it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveDuration {
    FifteenMinutes,
    OneHour,
    EightHours,
}

impl LiveDuration {
    /// Its length in milliseconds.
    pub fn ms(self) -> i64 {
        match self {
            LiveDuration::FifteenMinutes => 15 * MINUTE_MS,
            LiveDuration::OneHour => 60 * MINUTE_MS,
            LiveDuration::EightHours => MAX_LIVE_MS,
        }
    }
}

/// The share's real end: what the start message says, but never more than [`MAX_LIVE_MS`] after
/// the message was sent (`started_ms`, the receiver's copy's time) — a claim of a week is eight
/// hours here.
pub fn effective_until(started_ms: i64, live_until_ms: i64) -> i64 {
    live_until_ms.min(started_ms.saturating_add(MAX_LIVE_MS + GRACE_MS))
}

/// Is a position plausible WGS84: finite, latitude within ±90, longitude within ±180, and an
/// accuracy (when given) finite and not negative.
pub fn valid_position(latitude: f64, longitude: f64, accuracy: Option<f64>) -> bool {
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
        && accuracy.is_none_or(|a| a.is_finite() && a >= 0.0)
}

/// Was an update said (`at_ms`, the sender's clock) inside a share ending at `until_ms`.
pub fn within_window(at_ms: i64, until_ms: i64) -> bool {
    at_ms <= until_ms.saturating_add(GRACE_MS)
}

/// One word about a share, as [`accept`] compares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveWord {
    /// The sender's clock when it was said.
    pub at_ms: i64,
    /// The share was stopped by its author.
    pub stopped: bool,
}

/// What a device does with an arriving word, given the one it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accept {
    /// Older than what is held, a copy of it, or anything after a stop: nothing changes.
    Ignore,
    /// Take its position and its state.
    Take,
    /// A stop older than the position held: the share ends, the newer position stays.
    StopOnly,
}

/// The last-writer-wins rule. A stop is final — nothing after it moves the share again, so a
/// reordered update cannot bring a stopped share back to life; otherwise a later `at_ms` wins,
/// and an equal one only when it is the stop.
pub fn accept(held: Option<LiveWord>, word: LiveWord) -> Accept {
    let Some(held) = held else { return Accept::Take };
    if held.stopped {
        return Accept::Ignore;
    }
    if word.at_ms > held.at_ms || (word.at_ms == held.at_ms && word.stopped) {
        return Accept::Take;
    }
    if word.stopped {
        return Accept::StopOnly;
    }
    Accept::Ignore
}

/// A position, as the rate limit compares two.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    pub latitude: f64,
    pub longitude: f64,
    pub at_ms: i64,
}

/// Great-circle distance in metres (haversine, the mean Earth radius): plenty for "did it move
/// ten metres".
pub fn distance_m(a: Fix, b: Fix) -> f64 {
    const R: f64 = 6_371_000.0;
    let (la1, la2) = (a.latitude.to_radians(), b.latitude.to_radians());
    let dla = la2 - la1;
    let dlo = (b.longitude - a.longitude).to_radians();
    let h = (dla / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (dlo / 2.0).sin().powi(2);
    2.0 * R * h.sqrt().min(1.0).asin()
}

/// Should the sender send `fix` now, given the last one it sent: never sooner than
/// [`MIN_INTERVAL_MS`] after it, then when it moved [`MOVED_M`] or [`HEARTBEAT_MS`] has passed.
/// The first fix of a share always goes.
pub fn should_send(last: Option<Fix>, fix: Fix) -> bool {
    let Some(last) = last else { return true };
    let since = fix.at_ms - last.at_ms;
    since >= MIN_INTERVAL_MS && (since >= HEARTBEAT_MS || distance_m(last, fix) >= MOVED_M)
}

#[cfg(test)]
#[path = "live_location_tests.rs"]
mod tests;
