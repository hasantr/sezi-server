//! Several co-presence events in ONE envelope ([`InnerMessage::ActivityBatch`]).
//!
//! One send per peer may be in flight at a time (an Olm session is a ratchet), and each one costs
//! a round trip to the relay — ~200 ms from a phone to a relay on a Raspberry Pi behind a
//! Cloudflare tunnel (measured 2026-10-24). A drawing or a piano emits dozens of events a second,
//! so sending them one per envelope left them queueing behind each other without bound. The
//! sender instead folds whatever waits for the same peer into one batch while a send is in flight
//! (`kernel/activity_batch.rs`); the receiver unpacks it and takes each event through exactly the
//! path a single [`InnerMessage::Activity`] takes — the scope check, the per-sender seq dedup.
//!
//! **Only to a peer that said it reads batches.** An older client decodes the unknown kind as
//! `InnerMessage::Unknown` and every event in it would be lost, so a current sender marks each of
//! its own `Activity` events `reads_batch: true` and batches only to a peer whose every device
//! has been seen saying so; to anybody else it keeps sending singles exactly as before.

use serde::{Deserialize, Serialize};

use crate::inner::{ActivityEvent, ActivityWireScope, InnerMessage};

/// The most a batch's events may weigh, serialised. The relay refuses an envelope over 64 KiB, and
/// an event travels JSON-escaped inside an Olm message that is then base64-encoded (4/3), so this
/// leaves the envelope well under the limit with room for the Olm and JSON framing.
pub const MAX_ACTIVITY_BATCH_BYTES: usize = 32 * 1024;

/// One event of a batch — the fields of [`InnerMessage::Activity`], without the capability flag
/// (a batch's sender reads batches by definition).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityBatchItem {
    pub plugin_id: String,
    pub activity_id: String,
    pub seq: u64,
    pub event: ActivityEvent,
    pub payload: String,
    pub scope: ActivityWireScope,
}

impl ActivityBatchItem {
    /// The event a single `Activity` carries, or `None` for any other kind.
    pub fn from_single(inner: &InnerMessage) -> Option<Self> {
        let InnerMessage::Activity { plugin_id, activity_id, seq, event, payload, scope, .. } = inner
        else {
            return None;
        };
        Some(Self {
            plugin_id: plugin_id.clone(),
            activity_id: activity_id.clone(),
            seq: *seq,
            event: event.clone(),
            payload: payload.clone(),
            scope: scope.clone(),
        })
    }

    /// What this event weighs inside a batch, serialised.
    pub fn wire_len(&self) -> usize {
        serde_json::to_vec(self).map(|v| v.len()).unwrap_or(usize::MAX)
    }
}

/// The weight of a batch's events, serialised — what [`MAX_ACTIVITY_BATCH_BYTES`] bounds.
pub fn batch_wire_len(events: &[ActivityBatchItem]) -> usize {
    events.iter().map(|e| e.wire_len().saturating_add(1)).fold(0, usize::saturating_add)
}

#[cfg(test)]
#[path = "activity_batch_tests.rs"]
mod tests;
