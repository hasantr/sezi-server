//! Which device ids a sender is allowed to address on a 1:1 send.
//!
//! **The hole this closes.** Both send paths — HTTP `messages::handlers::send` and the hot
//! `inbox_do/ws.rs` socket — used to gate the recipient device with `device_revoked` alone, and
//! `device_revoked` answers **false for a device that does not exist**: it reads
//! `SELECT revoked_at ... LIMIT 1` and treats a missing row as "not revoked". A device id is just
//! a string on the wire, so any authorized sender could aim envelopes at ids they invented. Each
//! one became a `pending` row in the victim's inbox that no device would ever ack, and `pending`
//! is capped at `PENDING_MAX_ROWS` (10 000) with **oldest-first** eviction — so 10 000 envelopes
//! addressed to `deadbeefdeadbeef` push the victim's real undelivered backlog out of their own
//! inbox. Under the per-user rate limit (300 sends/60 s, 100 envelopes each) that is minutes of
//! work, and every message evicted this way is lost.
//!
//! **The fix is to resolve the set once and judge against it.** `devices` is authoritative: every
//! entry of a signed device list gets a row from `validate_and_store_signed_list`, and a device
//! removed from the list is *revoked in place*, never deleted. So a missing row means the device
//! was never published — an invention — and a present row with `revoked_at` means a real device
//! the sender's ~2 min cache has not caught up with. The two deserve different answers, and
//! collapsing them was the bug.
//!
//! One query per send, instead of one per envelope. The old shape asked D1 separately for every
//! device in the batch, so this is also strictly fewer subrequests (see `messages::budget`).

use crate::d1util::d1_text;
use serde::Deserialize;
use worker::*;

/// The stable wire code both transports answer with when a send names a device that was never
/// published. HTTP returns it with 400; the WS send arm returns it in a `send_err` frame.
pub(crate) const UNKNOWN_DEVICE_CODE: &str = "unknown_recipient_device";

/// What the server knows about one device id a sender named as a 1:1 target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceVerdict {
    /// Published and not revoked — deliver.
    Active,
    /// Published, then revoked. SKIP this device and deliver to the others; the sender's device
    /// cache is merely stale, which is normal and not an error (D-M12 behaviour, unchanged).
    Revoked,
    /// No such device was ever published for this account. REJECT the request — the sender is
    /// either badly broken or fabricating targets, and either way there is no inbox to fill.
    Unknown,
}

/// The recipient's published devices, resolved once per send.
pub(crate) struct RecipientDevices {
    /// `(device_id, revoked)` for every row the account owns. At most `MAX_DEVICES` (5), so a
    /// linear scan is cheaper than any map.
    rows: Vec<(String, bool)>,
}

impl RecipientDevices {
    pub(crate) fn verdict(&self, device_id: &str) -> DeviceVerdict {
        match self.rows.iter().find(|(id, _)| id == device_id) {
            Some((_, true)) => DeviceVerdict::Revoked,
            Some((_, false)) => DeviceVerdict::Active,
            None => DeviceVerdict::Unknown,
        }
    }

    /// Build from raw rows. Separated from the query so the judgement is testable without D1.
    pub(crate) fn from_rows(rows: Vec<(String, bool)>) -> Self {
        Self { rows }
    }

    /// The batch's targets, when EVERY one of them is a revoked device — nothing in it can be
    /// delivered, and only a fresh device list on the sender's side changes that. `None` when at
    /// least one target is deliverable (an active device, or a device-blind envelope), or when the
    /// batch names none. Unknown ids are the caller's to refuse first ([`UNKNOWN_DEVICE_CODE`]).
    ///
    /// Until the lab run of 2026-10-14 such a batch fell through the per-device skip with nothing
    /// acked and was answered `502 do_notify_failed`, which the sender treats as transient: the op
    /// walked its backoff ladder on the conversation's lane, every retry refused the same way.
    pub(crate) fn all_revoked<'a>(
        &self,
        targets: impl IntoIterator<Item = Option<&'a str>>,
    ) -> Option<Vec<String>> {
        let mut stale = Vec::new();
        for target in targets {
            let device = target?;
            if self.verdict(device) != DeviceVerdict::Revoked {
                return None;
            }
            stale.push(device.to_string());
        }
        (!stale.is_empty()).then_some(stale)
    }

    /// The relay's refusal of a batch whose every target is revoked ([`Self::all_revoked`]), or
    /// `None` when the batch goes ahead. Both transports answer through it, so the exact status,
    /// body and frame are what the host tests below read.
    pub(crate) fn stale_refusal<'a>(
        &self,
        targets: impl IntoIterator<Item = Option<&'a str>>,
    ) -> Option<StaleRefusal> {
        self.all_revoked(targets).map(|stale_devices| StaleRefusal { stale_devices })
    }
}

/// What a 1:1 batch naming only revoked devices is answered ([`DEVICES_STALE_CODE`]).
#[derive(Debug)]
pub(crate) struct StaleRefusal {
    stale_devices: Vec<String>,
}

impl StaleRefusal {
    /// Not transient (no 5xx): the sender refetches the device list instead of backing off.
    pub(crate) const HTTP_STATUS: u16 = 409;

    /// `handlers::send`'s body.
    pub(crate) fn http_body(&self) -> serde_json::Value {
        serde_json::json!({ "error": DEVICES_STALE_CODE, "stale_devices": self.stale_devices })
    }

    /// The socket send arm's `send_err` frame for the send `reff`.
    pub(crate) fn ws_frame(&self, reff: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "send_err",
            "ref": reff,
            "code": DEVICES_STALE_CODE,
            "stale_devices": self.stale_devices,
        })
    }
}

/// The stable wire code both transports answer with when every device a 1:1 batch names was
/// revoked ([`RecipientDevices::all_revoked`]): HTTP `409 {"error":"devices_stale",
/// "stale_devices":[…]}`, and the WS send arm a `send_err` frame with `code: "devices_stale"` and
/// the same `stale_devices`. Non-transient: the sender refetches the recipient's device list and
/// retries at once. A batch with any deliverable target is unchanged — revoked ones are skipped.
pub(crate) const DEVICES_STALE_CODE: &str = "devices_stale";

/// Every `devices` row for one account, revoked ones included — the revoked half is exactly what
/// tells an invented id apart from a stale one.
pub(crate) async fn load_recipient_devices(
    db: &D1Database,
    user_id: &str,
) -> Result<RecipientDevices> {
    #[derive(Deserialize)]
    struct Row {
        device_id: String,
        revoked_at: Option<i64>,
    }
    let rows: Vec<Row> = db
        .prepare("SELECT device_id, revoked_at FROM devices WHERE user_id = ?")
        .bind(&[d1_text(user_id)])?
        .all()
        .await?
        .results()?;
    Ok(RecipientDevices::from_rows(
        rows.into_iter()
            .map(|r| (r.device_id, r.revoked_at.is_some()))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two 1:1 send transports. `include_str!` resolves relative to THIS file.
    const HTTP_SEND_SRC: &str = include_str!("handlers.rs");
    const WS_SEND_SRC: &str = include_str!("inbox_do/ws.rs");

    /// The bug existed in BOTH transports at once, because each grew its own per-device gate and
    /// each reached for `device_revoked`. That is a shape no test over a single path can see, so
    /// the guard names both files and fails if either one stops consulting the published set.
    #[test]
    fn both_send_transports_judge_devices_against_the_published_set() {
        for (name, src) in [
            ("messages/handlers.rs", HTTP_SEND_SRC),
            ("messages/inbox_do/ws.rs", WS_SEND_SRC),
        ] {
            assert!(
                src.contains(concat!("load_recipient_", "devices")),
                "{name} no longer resolves the recipient's device set — an invented device id is \
                 accepted again"
            );
            assert!(
                src.contains(concat!("UNKNOWN_DEVICE", "_CODE")),
                "{name} resolves the set but never refuses an unknown device"
            );
        }
    }

    fn fixture() -> RecipientDevices {
        RecipientDevices::from_rows(vec![
            ("live-1".into(), false),
            ("live-2".into(), false),
            ("gone".into(), true),
        ])
    }

    /// The attack: an id that was never published. It used to read as "not revoked" and get a
    /// `pending` row; now it is refused before anything is written.
    #[test]
    fn a_fabricated_device_id_is_unknown_not_merely_unrevoked() {
        assert_eq!(fixture().verdict("deadbeefdeadbeef"), DeviceVerdict::Unknown);
        assert_eq!(fixture().verdict(""), DeviceVerdict::Unknown);
    }

    /// A revoked device is NOT the same answer. The sender's cache is allowed to be a couple of
    /// minutes stale, so that device is skipped and its siblings still get the message.
    #[test]
    fn a_revoked_device_stays_a_skip_and_does_not_fail_the_request() {
        assert_eq!(fixture().verdict("gone"), DeviceVerdict::Revoked);
    }

    /// A batch naming only revoked devices is the typed `devices_stale`, listing them; one with
    /// anything deliverable is not, and neither is an empty or a device-blind one.
    #[test]
    fn a_batch_of_revoked_devices_only_is_stale() {
        let devs = RecipientDevices::from_rows(vec![
            ("live-1".into(), false),
            ("gone".into(), true),
            ("gone-2".into(), true),
        ]);
        assert_eq!(
            devs.all_revoked([Some("gone"), Some("gone-2")]),
            Some(vec!["gone".to_string(), "gone-2".to_string()])
        );
        assert_eq!(devs.all_revoked([Some("gone"), Some("live-1")]), None);
        assert_eq!(devs.all_revoked([Some("gone"), None]), None);
        assert_eq!(devs.all_revoked(std::iter::empty()), None);
    }

    /// What both transports answer a batch of revoked devices, as the client reads it: HTTP 409
    /// with the code and the devices, and on the socket a `send_err` frame carrying the same.
    ///
    /// The handlers themselves cannot run on the host — `handlers::send` takes a `worker::Request`,
    /// a `RouteContext` and a D1 binding, and `inbox_do/ws.rs` a live `WebSocket`, all of which
    /// exist only inside the Workers runtime — so the answer is built here, by the one function
    /// both call, and the source check below pins that they do and build nothing of their own.
    #[test]
    fn a_batch_of_revoked_devices_is_answered_409_devices_stale_on_both_transports() {
        let devs = fixture();
        let refusal = devs.stale_refusal([Some("gone")]).expect("refused");
        assert_eq!(StaleRefusal::HTTP_STATUS, 409);
        assert_eq!(
            refusal.http_body(),
            serde_json::json!({ "error": "devices_stale", "stale_devices": ["gone"] })
        );
        assert_eq!(
            refusal.ws_frame("op-1"),
            serde_json::json!({
                "type": "send_err",
                "ref": "op-1",
                "code": "devices_stale",
                "stale_devices": ["gone"],
            })
        );
        assert!(devs.stale_refusal([Some("gone"), Some("live-1")]).is_none(), "a mixed batch goes ahead");
        for (name, src) in [
            ("messages/handlers.rs", HTTP_SEND_SRC),
            ("messages/inbox_do/ws.rs", WS_SEND_SRC),
        ] {
            assert!(
                src.contains(concat!("stale_", "refusal(")),
                "{name} no longer answers a batch of revoked devices through stale_refusal"
            );
            assert!(
                !src.contains(concat!("DEVICES_STALE", "_CODE")),
                "{name} builds its own devices_stale answer instead of the tested one"
            );
        }
    }

    #[test]
    fn a_published_unrevoked_device_is_delivered_to() {
        assert_eq!(fixture().verdict("live-1"), DeviceVerdict::Active);
        assert_eq!(fixture().verdict("live-2"), DeviceVerdict::Active);
    }

    /// An account that has not published a device list yet owns no rows, so every id is unknown.
    /// The 1:1 path never reaches that state — it already rejects an envelope with no `device_id`,
    /// and the bootstrap bundle reports `device_id: null` — but the answer must still be refusal
    /// rather than blanket acceptance.
    #[test]
    fn an_account_with_no_published_devices_accepts_no_device_id() {
        let none = RecipientDevices::from_rows(vec![]);
        assert_eq!(none.verdict("anything"), DeviceVerdict::Unknown);
    }
}
