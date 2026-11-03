//! A queue longer than one flush, handed over page by page (2026-11-03).
//!
//! A flush sends at most [`FLUSH_PAGE`] pending rows to a socket, then `sync_idle` — `more: true`
//! when the page was full. Until 2026-11-03 nothing sent the next page until the device
//! reconnected or the 90 s alarm ran (`flush_pending_to_all`, which says no `sync_idle` at all):
//! a phone back from a week away took minutes to receive two thousand messages, its foreground
//! never heard the queue was drained (`core` `kernel/notify_gate.rs` waited out its 20 s
//! fallback), and a background drain never completed.
//!
//! Now the socket remembers the last row id of a full page ([`Attachment::page_hi`]), and the
//! ack that leaves none of that page's rows pending for this device flushes the next page, with
//! its own `sync_idle`. A row the client deliberately leaves un-acked (a frame it rolled back, a
//! drain leaving it for the foreground) stops the paging there; the alarm and the next connect
//! deliver it as before. Compatible with every app: an older one acks as it always did, gets the
//! next page sooner, and ignores — or ends its drain on — the `sync_idle` it already knew.

use super::*;

/// The most rows one flush hands a socket (`select_pending_for_device`'s `LIMIT`).
pub(crate) const FLUSH_PAGE: usize = 500;

/// The `sync_idle` frame that closes a flush of `flushed` rows.
pub(crate) fn sync_idle_frame(flushed: usize) -> String {
    serde_json::json!({
        "type": "sync_idle",
        "flushed": flushed,
        "more": flushed >= FLUSH_PAGE,
    })
    .to_string()
}

/// What a flush leaves on the socket: the last row id of a full page, whose acks open the next
/// page; `None` when the page was the end of the queue.
pub(crate) fn page_hi_after_flush(row_ids: &[i64]) -> Option<i64> {
    if row_ids.len() >= FLUSH_PAGE {
        row_ids.iter().copied().max()
    } else {
        None
    }
}

/// Is the next page due: a full page is outstanding and none of its rows is still pending?
pub(crate) fn next_page_due(page_hi: Option<i64>, still_pending_of_page: i64) -> bool {
    page_hi.is_some() && still_pending_of_page == 0
}

impl UserInbox {
    /// Remember on `ws` where its last flush stopped (see the module doc).
    pub(crate) fn note_flush_page(&self, ws: &WebSocket, row_ids: &[i64]) {
        let page_hi = page_hi_after_flush(row_ids);
        if let Ok(Some(mut att)) = ws.deserialize_attachment::<Attachment>() {
            if att.page_hi != page_hi {
                att.page_hi = page_hi;
                let _ = ws.serialize_attachment(att);
            }
        }
    }

    /// After an ack on `ws`: flush the next page once the full page before it is all acked.
    pub(crate) fn flush_next_page_if_due(&self, ws: &WebSocket) {
        let Ok(Some(att)) = ws.deserialize_attachment::<Attachment>() else {
            return;
        };
        let Some(hi) = att.page_hi else {
            return;
        };
        #[derive(Deserialize)]
        struct CountRow {
            n: i64,
        }
        let pending = self
            .state
            .storage()
            .sql()
            .exec_raw(
                "SELECT COUNT(*) AS n FROM pending WHERE id <= ? AND (device_id = ? OR device_id IS NULL)",
                Some(vec![JsValue::from_f64(hi as f64), JsValue::from_str(&att.device_id)]),
            )
            .ok()
            .and_then(|c| c.to_array::<CountRow>().ok())
            .and_then(|rows| rows.into_iter().next())
            // A count that cannot be read is no reason to send anything twice: the alarm still
            // delivers the rest.
            .map_or(1, |r| r.n);
        if next_page_due(Some(hi), pending) {
            self.flush_pending_to(ws);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_page_says_more_and_is_remembered() {
        let ids: Vec<i64> = (1..=FLUSH_PAGE as i64).collect();
        assert_eq!(page_hi_after_flush(&ids), Some(FLUSH_PAGE as i64));
        let frame: serde_json::Value = serde_json::from_str(&sync_idle_frame(ids.len())).unwrap();
        assert_eq!(frame["type"], "sync_idle");
        assert_eq!(frame["more"], true);
    }

    #[test]
    fn the_last_page_says_no_more_and_leaves_nothing_to_page() {
        let ids: Vec<i64> = (501..=620).collect();
        assert_eq!(page_hi_after_flush(&ids), None);
        assert_eq!(page_hi_after_flush(&[]), None);
        let frame: serde_json::Value = serde_json::from_str(&sync_idle_frame(ids.len())).unwrap();
        assert_eq!(frame["more"], false);
        assert_eq!(frame["flushed"], 120);
    }

    #[test]
    fn the_next_page_waits_for_every_row_of_the_page() {
        assert!(!next_page_due(None, 0), "no full page outstanding");
        assert!(!next_page_due(Some(500), 3), "rows of the page still un-acked");
        assert!(next_page_due(Some(500), 0));
    }

    #[test]
    fn an_attachment_from_before_keeps_reading() {
        let old = r#"{"userId":"u","deviceId":"d","lastSeenMs":5}"#;
        let att: Attachment = serde_json::from_str(old).unwrap();
        assert_eq!(att.page_hi, None);
    }
}
