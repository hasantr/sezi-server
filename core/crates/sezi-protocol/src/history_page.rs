//! Older history on demand (Hasan, 2026-11-01): a linked device that scrolls past the oldest
//! message it holds in a conversation asks my primary for the next older page, the WhatsApp way.
//!
//! Two invisible self-Olm controls carry it ([`crate::inner::InnerMessage::HistoryPageRequest`] and
//! [`crate::inner::InnerMessage::HistoryPageAnswer`]); this module holds the pieces they share. The
//! page itself never rides on the request's lane: the primary builds it, compresses it, encrypts
//! it under a fresh key (`sezi-file`'s XChaCha20 STREAM, as attachments are) and uploads it to the
//! relay's media store, scoped to my own user; the answer carries only where it is and its key.
//! Without a blob store the page travels inline instead, cut into [`HistoryPagePart`]s.

use serde::{Deserialize, Serialize};

/// Where a page ends: the oldest message it holds, as the PRIMARY orders its conversation —
/// `(sent_at, local_id)` descending. The next request asks for what lies strictly below it.
///
/// A linked device's first request has no primary-side id to give, only the `sent_at` of the
/// oldest row it holds: `local_id: None` then asks for everything at or below that moment, and
/// the overlap is absorbed by the importer's dedup. Every later request names the cursor the
/// previous answer handed back, so a burst of messages sharing one second cannot loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryCursor {
    pub sent_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_id: Option<String>,
}

impl HistoryCursor {
    /// Is a row with this `(sent_at, local_id)` older than the cursor, i.e. on the next page?
    /// Inclusive of the moment when the cursor has no id (see the type doc).
    pub fn admits(&self, sent_at: i64, local_id: &str) -> bool {
        match &self.local_id {
            None => sent_at <= self.sent_at,
            Some(id) => sent_at < self.sent_at || (sent_at == self.sent_at && local_id < id.as_str()),
        }
    }
}

/// One piece of a page sent inline (no blob store on the relay): the compressed, signed page cut
/// into parts of at most [`INLINE_PART_BYTES`] of base64 each. `index` counts from 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryPagePart {
    pub index: u32,
    pub total: u32,
    pub data_b64: String,
}

/// How many messages one page holds at most.
pub const PAGE_MAX_ROWS: usize = 200;

/// The serialized rows one uploaded page holds at most, before compression. A page is cut at
/// whichever of this and [`PAGE_MAX_ROWS`] comes first, and always holds at least one row.
pub const PAGE_MAX_BYTES: usize = 2 * 1024 * 1024;

/// The same cap for a page that travels inline: every part is a self-Olm envelope of its own.
pub const INLINE_PAGE_MAX_BYTES: usize = 192 * 1024;

/// The base64 one inline part carries — the M4 chunk budget (`state_transfer.rs`), which keeps a
/// self-Olm envelope under the relay's 64 KB send limit.
pub const INLINE_PART_BYTES: usize = 22 * 1024;

/// What a page may inflate to on the asking device; anything larger is refused unread.
pub const PAGE_MAX_INFLATED: usize = 24 * 1024 * 1024;

/// The parts one inline page may have; an answer claiming more is refused.
pub const INLINE_MAX_PARTS: u32 = 64;

/// Cut `data` into inline parts of at most [`INLINE_PART_BYTES`] of base64 each (never zero
/// parts: an empty input is one empty part).
pub fn split_inline(data: &[u8]) -> Vec<HistoryPagePart> {
    // base64 grows by 4/3: this many raw bytes fill one part.
    let raw = INLINE_PART_BYTES / 4 * 3;
    let chunks: Vec<&[u8]> = if data.is_empty() { vec![&[]] } else { data.chunks(raw).collect() };
    let total = chunks.len() as u32;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| HistoryPagePart {
            index: i as u32,
            total,
            data_b64: vodozemac::base64_encode(c),
        })
        .collect()
}

/// Put inline parts back together: `None` until every index `0..total` is there (duplicates are
/// fine), or when they disagree on `total`, or one does not decode.
pub fn join_inline(parts: &[HistoryPagePart]) -> Option<Vec<u8>> {
    let total = parts.first()?.total;
    if total == 0 || total > INLINE_MAX_PARTS || parts.iter().any(|p| p.total != total) {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..total {
        let p = parts.iter().find(|p| p.index == i)?;
        out.extend(vodozemac::base64_decode(&p.data_b64).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_without_an_id_admits_its_own_moment() {
        let c = HistoryCursor { sent_at: 10, local_id: None };
        assert!(c.admits(10, "z"));
        assert!(c.admits(9, "a"));
        assert!(!c.admits(11, "a"));
    }

    #[test]
    fn a_cursor_with_an_id_admits_only_what_lies_strictly_below_it() {
        let c = HistoryCursor { sent_at: 10, local_id: Some("m".into()) };
        assert!(c.admits(10, "l"));
        assert!(!c.admits(10, "m"));
        assert!(!c.admits(10, "n"));
        assert!(c.admits(9, "z"));
    }

    #[test]
    fn inline_parts_round_trip_in_any_order_and_wait_for_the_last() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut parts = split_inline(&data);
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|p| p.data_b64.len() <= INLINE_PART_BYTES));
        let last = parts.pop().unwrap();
        assert_eq!(join_inline(&parts), None, "a missing part keeps the page waiting");
        parts.insert(0, last);
        parts.push(parts[1].clone());
        assert_eq!(join_inline(&parts).as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn parts_that_disagree_are_refused() {
        let mut parts = split_inline(&[1u8; 40_000]);
        parts[1].total = 9;
        assert_eq!(join_inline(&parts), None);
        assert_eq!(split_inline(&[]).len(), 1);
    }
}
