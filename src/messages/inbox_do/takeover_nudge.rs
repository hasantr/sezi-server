//! `POST /takeover-nudge {user_id, device_id}` → 204: a takeover was filed or approved on this
//! account (`devices/takeover.rs` `notify_primary`). Every open socket gets `takeover_update` — the
//! primary's client reads the authoritative list (`GET /devices/takeover/against-me`) and shows the
//! refuse prompt — and the primary device gets an URGENT wake, which the coalescing gate never
//! holds (`push::coalesce`): a living primary's six-hour window to refuse must not wait behind an
//! earlier unfetched wake. The gate's semantics are untouched; this only asks with `urgent`.
//!
//! A frame an older client does not know is dropped by it (`frame_to_event` answers `None`).

use serde::Deserialize;
use worker::*;

use super::UserInbox;

/// The frame every open socket of the account gets.
pub(crate) const TAKEOVER_UPDATE_FRAME: &str = r#"{"type":"takeover_update"}"#;

#[derive(Deserialize)]
struct NudgeBody {
    user_id: String,
    device_id: String,
}

impl UserInbox {
    pub(super) async fn takeover_nudge(&self, mut req: Request) -> Result<Response> {
        let body: NudgeBody = req.json().await?;
        for socket in self.state.get_websockets() {
            let _ = socket.send_with_str(TAKEOVER_UPDATE_FRAME);
        }
        let ask = crate::push::coalesce::WakeAsk { covers_ms: crate::utils::now_ms() as i64, urgent: true };
        // It carries nothing: the drain asks the relay what is open (`push::carry`).
        let none = crate::push::carry::Carried::none();
        self.wake_after_notify(Some(body.user_id), Some(body.device_id), ask, none);
        Response::empty().map(|r| r.with_status(204))
    }
}

#[cfg(test)]
mod tests {
    /// The nudge's wake is the urgent one: a takeover notice must never be coalesced away.
    #[test]
    fn the_takeover_wake_is_urgent_and_goes_to_the_primary() {
        let src = include_str!("takeover_nudge.rs");
        let body = &src[src.find("async fn takeover_nudge").unwrap()..src.find("#[cfg(test)]").unwrap()];
        assert!(body.contains(concat!("urgent: ", "true")));
        assert!(body.contains(concat!("wake_after_notify(Some(body.user_id), ", "Some(body.device_id)")));
        assert!(body.contains("TAKEOVER_UPDATE_FRAME"));
    }
}
