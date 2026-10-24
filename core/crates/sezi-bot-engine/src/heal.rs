//! When a session between the bot and a member breaks, and who mends it.
//!
//! The kernel's rules, unchanged, because the far end IS a kernel:
//!
//! - **The lower id initiates** (`kernel/inbound.rs` `self_heal_session`, `inbound_receipts.rs`
//!   on `delivery_failed`). Only the side whose user id sorts lower sends the PreKey pair-ack that
//!   re-pairs the two; the higher side waits for it. Two sides that both initiated would each open
//!   a session the other is not using — the glare storm.
//! - **At most one re-pair per 20 s per member** (`pair_ack_retry.rs`, `PAIR_ACK_WINDOW_MS`). A
//!   failure inside the window emits nothing: the session is already retired, so the next frame
//!   that fails, or the bot's own next send (which opens a fresh session with a claimed key),
//!   mends it.
//! - **A failure retires the session, it does not delete it** (INV-11): a frame already in flight
//!   on the old session must still be readable, so it moves to the archive.
//! - **A gap (a message key already used or skipped past) on the HIGHER side keeps the session**:
//!   it is healthy and keeps reading later messages; the lower sender's re-pair replaces it.
//! - **`delivery_failed` wipes the user**, archive included — the relay's forward names no device,
//!   and a reset that left archived sessions behind would still decrypt. This is the kernel's
//!   sender-side rule.

use crate::{BotStore, Effect, Envelope};

/// The window inside which a member is re-paired at most once (the kernel's `PAIR_ACK_WINDOW_MS`).
pub const REPAIR_WINDOW_MS: i64 = 20_000;

/// Why a frame could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The current session is fine; this message's key was already used or ratcheted past.
    Gap,
    /// No session reads it, or one opened from it failed.
    Broken,
}

/// The answer to a frame the bot could not read: `delivery_failed` to the sender, and the
/// re-pair when the bot is the lower side.
pub(crate) fn undecryptable(
    store: &mut impl BotStore,
    me: &str,
    env: &Envelope,
    failure: Failure,
    now_ms: i64,
) -> Vec<Effect> {
    let mut effects = vec![Effect::Ack { remote_id: env.remote_id, success: false, uid: None }];
    let lower = me < env.sender_id.as_str();
    if failure == Failure::Gap && !lower {
        return effects;
    }
    store.retire_current(&env.sender_id, &env.sender_device_id);
    if lower {
        effects.extend(repair(store, &env.sender_id, now_ms));
    }
    effects
}

/// A member could not read something the bot sent them.
pub(crate) fn on_delivery_failed(
    store: &mut impl BotStore,
    me: &str,
    from: &str,
    now_ms: i64,
) -> Vec<Effect> {
    store.wipe_user(from);
    if me < from {
        repair(store, from, now_ms).into_iter().collect()
    } else {
        Vec::new()
    }
}

/// A [`Effect::Repair`] unless one went out for this user inside the window.
fn repair(store: &mut impl BotStore, user_id: &str, now_ms: i64) -> Option<Effect> {
    if let Some(at) = store.last_repair_at(user_id) {
        if now_ms.saturating_sub(at) < REPAIR_WINDOW_MS {
            return None;
        }
    }
    store.set_last_repair_at(user_id, now_ms);
    Some(Effect::Repair { user_id: user_id.to_owned() })
}

#[cfg(test)]
#[path = "heal_tests.rs"]
mod tests;
