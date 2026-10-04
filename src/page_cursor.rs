//! Keyset pagination plumbing shared by the admin and group lists: an opaque cursor, the page
//! size and the query string. (`admin/library.rs` predates this and keeps its own typed codec.)
//!
//! A cursor is base64url of a tiny JSON object naming the last row's sort key. It is opaque on the
//! wire so a list can change its key without a client noticing; a client stores `next` verbatim
//! and sends it back as `?cursor=`. Anything that does not decode is refused (400 `bad_cursor`)
//! rather than silently restarting from the first page, which would loop a client forever.

use serde::{de::DeserializeOwned, Serialize};
use worker::Request;

use crate::utils::{b64u_decode, b64u_encode};

/// Longest cursor accepted; a real one is well under 200 characters.
const MAX_CURSOR_LEN: usize = 512;

pub(crate) fn encode<T: Serialize>(key: &T) -> String {
    b64u_encode(&serde_json::to_vec(key).unwrap_or_default())
}

pub(crate) fn decode<T: DeserializeOwned>(raw: &str) -> Option<T> {
    if raw.len() > MAX_CURSOR_LEN {
        return None;
    }
    serde_json::from_slice(&b64u_decode(raw).ok()?).ok()
}

/// `?limit=`, clamped to `1..=max`, `default` when absent or unparsable.
pub(crate) fn limit(raw: Option<&str>, default: i64, max: i64) -> i64 {
    raw.and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(1, max)
}

/// One query-string parameter.
pub(crate) fn query(req: &Request, name: &str) -> Option<String> {
    req.url()
        .ok()?
        .query_pairs()
        .find_map(|(k, v)| (k == name).then(|| v.into_owned()))
}

/// The `?cursor=` of a request: `Ok(None)` on the first page, `Err(())` for a cursor this server
/// did not issue.
pub(crate) fn from_request<T: DeserializeOwned>(req: &Request) -> Result<Option<T>, ()> {
    match query(req, "cursor").filter(|c| !c.is_empty()) {
        None => Ok(None),
        Some(raw) => decode(&raw).map(Some).ok_or(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Key {
        t: i64,
        id: String,
    }

    #[test]
    fn a_cursor_round_trips_and_rubbish_is_refused() {
        let key = Key {
            t: 1_780_000_000,
            id: "6f1c1f0e".into(),
        };
        assert_eq!(decode::<Key>(&encode(&key)), Some(key));
        assert_eq!(decode::<Key>("not a cursor"), None);
        assert_eq!(decode::<Key>(&b64u_encode(b"{\"x\":1}")), None);
        assert_eq!(decode::<Key>(&"A".repeat(600)), None);
    }

    #[test]
    fn the_page_size_is_clamped() {
        assert_eq!(limit(None, 50, 200), 50);
        assert_eq!(limit(Some("0"), 50, 200), 1);
        assert_eq!(limit(Some("9999"), 50, 200), 200);
        assert_eq!(limit(Some("x"), 50, 200), 50);
    }
}
