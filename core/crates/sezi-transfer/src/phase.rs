//! The attachment phase: the state an attachment is persisted in, its DB spelling, and the rule for
//! which transitions are allowed.
//!
//! The enum, the DB strings and the rank table live in ONE module on purpose. When they sat a crate
//! apart each, `Decrypting` came to share a rank with `Downloading` and silently blocked its own
//! transition.

use serde::{Deserialize, Serialize};

use crate::progress::TransferStep;

/// Which phase a transfer is in. This type IS the one Dart sees: the root crate declares
/// `#[frb(mirror(AttachmentPhase))]` in `attach_progress`, and FRB exports it under this name. Variant
/// `name`s are matched on the Dart side with `enum.byName`, so renaming one here is a Dart-visible
/// change rather than a refactor. Until #37 there was a hand-written `AttachmentPhaseTag` duplicate in
/// between; the mirror declaration replaced it, and `mirror_coverage_tests` guards the coverage.
///
/// Also the string in the attachment row's `phase` TEXT column ([`AttachmentPhase::as_db_str`]) AND what the monotonic guard ranks ([`phase_rank`]), all three of
/// which now sit in this one module. It is the ONLY attachment phase vocabulary as of task #35;
/// there used to be a second, narrower one in `events`, which meant the guard ranked a lossy
/// projection of the state it was guarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentPhase {
    /// Nothing has started yet. Also the guard's assumption for an attachment it has not seen — see
    /// `phase_rank`, where it is the floor every other phase advances from.
    Queued,
    Compressing,
    Encrypting,
    Uploading,
    SendingEnvelope,
    AwaitingPeer,
    /// SENDER side: the blob is shared over iroh and we are waiting for the peer to fetch it. Distinct
    /// from `AwaitingReceiverConsent`, which is the RECEIVER waiting for its own user — the two used to
    /// collapse onto one event phase because the UI shows them the same way, which hid the fact that
    /// they belong to opposite ends of a transfer.
    Sharing,
    /// Receiver side: a P2pBlobOffer arrived, but the user's size/type policy does
    /// not auto-download it. Waits until the user taps "Download" in the UI.
    AwaitingReceiverConsent,
    Downloading,
    Decrypting,
    /// An inbound or outbound transfer paused by the user or by a network drop.
    /// The partial state is persisted on the AttachmentMeta; the UI offers a
    /// "Resume" button.
    Paused,
    Ready,
    Delivered,
    Failed,
    Cancelled,
    /// Migration v5 — an attachment backfilled from the old SharedPreferences blob
    /// has a `p2p_ticket`, but the message is old enough that the iroh peer is
    /// probably unreachable. The UI shows a "past archive" badge; tapping it means
    /// a best-effort dial, or an error.
    LegacyP2p,
    /// Migration v5 — an old message had `phase=ready` with a `local_path` set, but
    /// by boot the file is gone from disk (app cache cleared, or the temp folder
    /// wiped after a phone reboot). The UI shows "the downloaded copy is gone"; with
    /// a `mediaId` it can be re-fetched from CF.
    DownloadedMissing,
}

impl AttachmentPhase {
    /// Every variant, in `phase_rank` order. Tests iterate this rather than keeping their own list,
    /// which once left a test named "all_variants" covering fifteen of seventeen.
    ///
    /// Exactly what the compiler enforces: the declared length catches a REMOVED or miscounted entry
    /// (E0308), and [`phase_rank`]'s exhaustive match catches an ADDED one. Extending this array is
    /// still a hand edit — Rust has no variant count — and `phase_rank` is the prompt for it.
    pub const ALL: [AttachmentPhase; 17] = [
        Self::Queued,
        Self::AwaitingReceiverConsent,
        Self::Compressing,
        Self::Encrypting,
        Self::Uploading,
        Self::Downloading,
        Self::Decrypting,
        Self::SendingEnvelope,
        Self::Sharing,
        Self::LegacyP2p,
        Self::AwaitingPeer,
        Self::Paused,
        Self::Ready,
        Self::Delivered,
        Self::Cancelled,
        Self::Failed,
        Self::DownloadedMissing,
    ];
}

/// Transport step → persisted phase. Total by construction: the compiler rejects a new
/// `TransferStep` that is not mapped here, so a transport cannot invent a phase.
impl From<TransferStep> for AttachmentPhase {
    fn from(step: TransferStep) -> Self {
        match step {
            TransferStep::Encrypting => Self::Encrypting,
            TransferStep::Decrypting => Self::Decrypting,
            TransferStep::Uploading => Self::Uploading,
            TransferStep::Downloading => Self::Downloading,
        }
    }
}


impl AttachmentPhase {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            AttachmentPhase::Queued => "queued",
            AttachmentPhase::Compressing => "compressing",
            AttachmentPhase::Encrypting => "encrypting",
            AttachmentPhase::Uploading => "uploading",
            AttachmentPhase::SendingEnvelope => "sending_envelope",
            AttachmentPhase::AwaitingPeer => "awaiting_peer",
            AttachmentPhase::Sharing => "sharing",
            AttachmentPhase::AwaitingReceiverConsent => "awaiting_receiver_consent",
            AttachmentPhase::Downloading => "downloading",
            AttachmentPhase::Decrypting => "decrypting",
            AttachmentPhase::Paused => "paused",
            AttachmentPhase::Ready => "ready",
            AttachmentPhase::Delivered => "delivered",
            AttachmentPhase::Failed => "failed",
            AttachmentPhase::Cancelled => "cancelled",
            AttachmentPhase::LegacyP2p => "legacy_p2p",
            AttachmentPhase::DownloadedMissing => "downloaded_missing",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "queued" => Some(Self::Queued),
            "compressing" => Some(Self::Compressing),
            "encrypting" => Some(Self::Encrypting),
            "uploading" => Some(Self::Uploading),
            "sending_envelope" => Some(Self::SendingEnvelope),
            "awaiting_peer" => Some(Self::AwaitingPeer),
            "sharing" => Some(Self::Sharing),
            "awaiting_receiver_consent" => Some(Self::AwaitingReceiverConsent),
            "downloading" => Some(Self::Downloading),
            "decrypting" => Some(Self::Decrypting),
            "paused" => Some(Self::Paused),
            "ready" => Some(Self::Ready),
            "delivered" => Some(Self::Delivered),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "legacy_p2p" => Some(Self::LegacyP2p),
            "downloaded_missing" => Some(Self::DownloadedMissing),
            _ => None,
        }
    }
}

// Hand-written rather than derived: the snake_case string form is what stabilises the value
// between the DB column and payload_json.
impl Serialize for AttachmentPhase {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_db_str())
    }
}

impl<'de> Deserialize<'de> for AttachmentPhase {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        AttachmentPhase::from_db_str(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown AttachmentPhase: {s}")))
    }
}


/// The phases that FREEZE an attachment: once one is reached, no later or duplicate event can
/// disturb it.
fn is_terminal(p: AttachmentPhase) -> bool {
    use AttachmentPhase::{Cancelled, Delivered, DownloadedMissing, Failed, Ready};
    matches!(p, Ready | Delivered | Failed | Cancelled | DownloadedMissing)
}

/// The monotonic transition rule `advance_attachment_phase` gates on. Terminal is frozen, a
/// same-phase transition is a no-op, and otherwise rank must increase.
///
/// Terminal and `Paused` are reachable from EVERY live phase and deliberately escape the rank
/// comparison: a user or a dropped connection can interrupt at any point, so ranking `Paused` would
/// make a pause at 50% look like going backwards and the event would be rejected.
pub fn should_advance_phase(cur: AttachmentPhase, new: AttachmentPhase) -> bool {
    if is_terminal(cur) {
        return false; // terminal is frozen
    }
    if cur == new {
        return false; // idempotent
    }
    if is_terminal(new) || new == AttachmentPhase::Paused {
        return true;
    }
    phase_rank(new) > phase_rank(cur)
}

/// Attachment phase ordering rank, for the monotonic guard.
///
/// The sender path (Uploading→SendingEnvelope→Sharing→AwaitingPeer) and the receiver path
/// (AwaitingReceiverConsent→Downloading→Decrypting) share ONE rank space. Safe because a single
/// attachment_key never sees both — sender and receiver rows have separate local_ids — so the pairs
/// sharing a number can never be compared. The gaps of ten leave room to insert a phase without
/// renumbering; a packed 0..6 table is how `Decrypting` once collided with `Downloading`.
///
/// Terminal phases and `Paused` never reach this comparison (see [`should_advance_phase`]); their
/// values exist only so the match is total.
///
/// ⚠ ADDING A VARIANT: the compiler brings you here first, then two places in THIS module that it
/// does NOT check — [`AttachmentPhase::ALL`] (bump its declared length) and `as_db_str`/`from_db_str`.
pub fn phase_rank(p: AttachmentPhase) -> u8 {
    use AttachmentPhase::*;
    match p {
        Queued => 0,
        // RECEIVER: the offer arrived, the user has not accepted yet — below the download. Reaches
        // the DB only through `att_repo::upsert`, never through this guard.
        AwaitingReceiverConsent => 10,
        Compressing => 20,
        Encrypting => 30,
        Uploading => 40,
        Downloading => 40,
        // RECEIVER: bytes are in, the file is being unwrapped. MUST outrank `Downloading` — at the
        // same rank the `Downloading → Decrypting` transition is rejected and never recorded.
        Decrypting => 50,
        // SENDER: uploaded, the envelope is going out.
        SendingEnvelope => 50,
        // SENDER: the blob is offered over iroh. `LegacyP2p` is the migration-time equivalent (an old
        // row still carrying a p2p_ticket), so it means the same thing and ranks the same.
        Sharing => 60,
        LegacyP2p => 60,
        AwaitingPeer => 70,
        Paused => 80,
        Ready => 200,
        Delivered => 201,
        Cancelled => 202,
        Failed => 203,
        DownloadedMissing => 204,
    }
}
