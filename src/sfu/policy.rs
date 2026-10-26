//! The SFU's rules, pure: may this room's call go through the SFU, how much a usage report may
//! count, when the owner is warned, which remote tracks a member may pull. The handlers in
//! `mod.rs` only read D1 and call Cloudflare around these.

/// The owner's route for group calls (board R6-Group-SFU frame 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRoute {
    /// Every group call through the SFU — the default (Hasan, 2026-10-16).
    Server,
    /// Direct while the room has at most [`CROWDED_ABOVE`] members, the SFU above.
    Crowded,
    /// Never the SFU.
    Direct,
}

impl OwnerRoute {
    /// An unknown or absent value is the default, `Server`.
    pub fn parse(s: Option<&str>) -> Self {
        match s.map(str::trim) {
            Some("crowded") => Self::Crowded,
            Some("direct") => Self::Direct,
            _ => Self::Server,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Crowded => "crowded",
            Self::Direct => "direct",
        }
    }

    pub fn valid(s: &str) -> bool {
        matches!(s, "server" | "crowded" | "direct")
    }
}

/// The most people with video in a call through the SFU (Hasan, 2026-10-16; direct stays 6).
pub const MAX_VIDEO: u32 = 50;

/// `crowded`: up to this many members a group call stays direct.
pub const CROWDED_ABOVE: u32 = 4;

/// The default monthly cap: the whole free tier Cloudflare gives SFU and TURN together.
pub const DEFAULT_CAP_GB: i64 = 1000;

/// One GB as Cloudflare bills it (decimal).
pub const GB: i64 = 1_000_000_000;

/// The fastest a member can plausibly receive: 50 people's middle layers plus audio, rounded up.
/// A report is clamped to what this rate could carry in the elapsed time.
pub const MAX_RECEIVE_BITS_PER_SEC: i64 = 60_000_000;

/// The longest gap one report may account for; a member offline for an hour does not get to
/// claim an hour at full rate when it comes back.
pub const MAX_REPORT_GAP_SECS: i64 = 300;

/// Whether a call in this room may go through the SFU now, and if not, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub available: bool,
    pub route: OwnerRoute,
    /// `group_direct` · `owner_direct` · `not_configured` · `capped`.
    pub reason: Option<&'static str>,
}

/// The decision, in the order a person would want it explained: the group's own choice first
/// (it holds whatever the server has), then the owner's, then whether the SFU exists, then the
/// month's budget.
pub fn decide(
    configured: bool,
    route: OwnerRoute,
    group_direct: bool,
    used_bytes: i64,
    cap_gb: i64,
) -> Decision {
    let reason = if group_direct {
        Some("group_direct")
    } else if route == OwnerRoute::Direct {
        Some("owner_direct")
    } else if !configured {
        Some("not_configured")
    } else if cap_gb > 0 && used_bytes >= cap_gb.saturating_mul(GB) {
        Some("capped")
    } else {
        None
    };
    Decision { available: reason.is_none(), route, reason }
}

/// A call already going on through the SFU is finished through it: past the month's limit its
/// late joiners and rejoiners still get a session, as the members in it go on receiving (the
/// limit stops NEW calls — review 2026-10-16, finding 4). Never a way the group or the owner
/// turned off, nor an SFU that is not configured.
pub fn admits_running_call(d: &Decision, call_is_running: bool) -> bool {
    d.available || (call_is_running && d.reason == Some("capped"))
}

/// How recently a session of a call must have reported media for the call to count as going on
/// (`admits_running_call`): members report every 30 s while anything arrives.
pub const RUNNING_CALL_WINDOW_SECS: i64 = 15 * 60;

/// How long past its first session a call is still "going on" for [`admits_running_call`]: a
/// lesson, not a month. Without a bound, a member reporting a few bytes every quarter hour could
/// keep one call id open through the SFU past the limit for the rest of the month (review
/// 2026-10-16, second pass).
pub const RUNNING_CALL_MAX_AGE_SECS: i64 = 4 * 60 * 60;

/// Whether a call counts as going on: some session of it reported media in the window
/// (`reporting`), and its first session opened less than [`RUNNING_CALL_MAX_AGE_SECS`] ago.
pub fn call_is_running(reporting: i64, first_at: Option<i64>, now: i64) -> bool {
    reporting > 0 && first_at.is_some_and(|t| now - t <= RUNNING_CALL_MAX_AGE_SECS)
}

/// Does this group's `settings_json` keep its calls direct (`"call_route": "direct"`)? Anything
/// else — no bag, no key, another value, a broken bag — follows the server.
pub fn group_is_direct(settings_json: Option<&str>) -> bool {
    settings_json
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("call_route").and_then(|r| r.as_str()).map(|r| r == "direct"))
        .unwrap_or(false)
}

/// How many of a reported `bytes` count: never negative, never more than
/// [`MAX_RECEIVE_BITS_PER_SEC`] could carry in the seconds since the last report (at most
/// [`MAX_REPORT_GAP_SECS`]). No time, nothing: until 2026-10-26 a report always counted at least
/// one second, so a member posting reports back to back was credited 7.5 MB each, as fast as the
/// relay answered. A report that counts nothing moves no clock (`usage`); members report every
/// 30 s, so a real one never meets this.
pub fn clamp_report(bytes: i64, elapsed_secs: i64) -> i64 {
    let secs = elapsed_secs.clamp(0, MAX_REPORT_GAP_SECS);
    bytes.clamp(0, MAX_RECEIVE_BITS_PER_SEC / 8 * secs)
}

/// Which warnings a report crossed: (`80 %`, `100 %`). Each fires once a month — the caller
/// passes whether it already did.
pub fn crossed(
    after: i64,
    cap_gb: i64,
    warned_80: bool,
    warned_100: bool,
) -> (bool, bool) {
    if cap_gb <= 0 {
        return (false, false);
    }
    let cap = cap_gb.saturating_mul(GB);
    let w80 = !warned_80 && after >= cap / 10 * 8;
    let w100 = !warned_100 && after >= cap;
    (w80, w100)
}

/// May a `tracks/new` body pull what it names? Every `remote` track must name a session of the
/// same room and call (`allowed`); local tracks and other fields pass. A body that is not a
/// `{tracks: [...]}` object is refused.
pub fn remote_tracks_ok(body: &serde_json::Value, allowed: &[String]) -> bool {
    let Some(tracks) = body.get("tracks").and_then(|t| t.as_array()) else {
        // A body with only a session description (a renegotiation-style push) has no tracks to
        // check; anything else malformed is refused.
        return body.is_object() && body.get("tracks").is_none();
    };
    tracks.iter().all(|t| match t.get("location").and_then(|l| l.as_str()) {
        Some("remote") => t
            .get("sessionId")
            .and_then(|s| s.as_str())
            .is_some_and(|s| allowed.iter().any(|a| a == s)),
        Some("local") => true,
        _ => false,
    })
}

/// An app id or token as pasted: bounded, no control characters (it lands in a URL path or an
/// `Authorization` header, where a newline would forge another header).
pub fn credential_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
