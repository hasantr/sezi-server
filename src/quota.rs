//! Quota **phase 1a** — upload storage quota ENFORCEMENT, reading the shadow
//! counters introduced in 0022.
//!
//! **FAIL-OPEN discipline:** if a cap or a counter CANNOT be read (DB error, missing
//! row, migration not applied) traffic is NOT cut off. An upload is rejected ONLY
//! when a cap is actually set (non-null) and `used + size > cap`. A NULL cap means
//! unlimited, so no existing server gets a surprise outage until its owner sets a
//! cap. The server stays DUMB and E2E-blind: only size metadata (content-length) is
//! counted, never content.

use crate::d1util::d1_text;
use serde::Deserialize;
use worker::*;

/// The upload quota decision — PURE and testable (no DB). A `None` cap means
/// unlimited. Overflow is `used + size > cap`, so an exact fit is ALLOWED (`>`, not
/// `>=`). Returns the scope that rejected the upload — server total is checked before
/// per-user — or `None` to allow it.
pub fn decide_upload(
    server_used: i64,
    user_used: i64,
    size: i64,
    max_server: Option<i64>,
    max_user: Option<i64>,
) -> Option<&'static str> {
    if let Some(cap) = max_server {
        if server_used + size > cap {
            return Some("server_storage");
        }
    }
    if let Some(cap) = max_user {
        if user_used + size > cap {
            return Some("user_storage");
        }
    }
    None
}

#[derive(Deserialize)]
struct CapsRow {
    max_storage_bytes: Option<i64>,
    max_user_storage_bytes: Option<i64>,
}

#[derive(Deserialize)]
struct ServerBytesRow {
    media_bytes: i64,
}

#[derive(Deserialize)]
struct UserBytesRow {
    bytes: i64,
}

/// Pre-upload quota check — reads the caps and counters from D1 and delegates the
/// decision to `decide_upload`. Every read is fail-open: a failing cap SELECT or a
/// missing row means the cap is unknown → allow; a failing counter read means 0
/// (rejecting is still correct if size alone exceeds the cap, since size is known
/// exactly from content-length). When both caps are NULL the counters are NEVER read
/// — the fast path on a default install costs exactly one extra SELECT per upload.
pub async fn check_upload(db: &D1Database, uploader_id: &str, size: i64) -> Option<&'static str> {
    let caps = match db
        .prepare(
            "SELECT max_storage_bytes, max_user_storage_bytes \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first::<CapsRow>(None)
        .await
    {
        Ok(Some(row)) => row,
        // Missing row / DB error / 0023 not applied → cap unknown → allow.
        _ => return None,
    };
    if caps.max_storage_bytes.is_none() && caps.max_user_storage_bytes.is_none() {
        return None; // fast path: no cap set → no need to read counters
    }

    // A counter is read only when its cap is set (no pointless D1 queries);
    // decide_upload ignores the counter for a None cap anyway, so 0 is harmless.
    let server_used = if caps.max_storage_bytes.is_some() {
        db.prepare("SELECT media_bytes FROM server_stats WHERE id = 1 LIMIT 1")
            .first::<ServerBytesRow>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.media_bytes)
            .unwrap_or(0)
    } else {
        0
    };
    let user_used = if caps.max_user_storage_bytes.is_some() {
        match db
            .prepare("SELECT bytes FROM user_storage WHERE user_id = ? LIMIT 1")
            .bind(&[d1_text(uploader_id)])
        {
            Ok(stmt) => stmt
                .first::<UserBytesRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.bytes)
                .unwrap_or(0),
            Err(_) => 0,
        }
    } else {
        0
    };

    decide_upload(
        server_used,
        user_used,
        size,
        caps.max_storage_bytes,
        caps.max_user_storage_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::decide_upload;

    #[test]
    fn under_the_cap_is_allowed() {
        assert_eq!(decide_upload(100, 50, 10, Some(200), Some(100)), None);
    }

    #[test]
    fn a_server_overage_is_rejected() {
        assert_eq!(
            decide_upload(195, 0, 10, Some(200), None),
            Some("server_storage")
        );
    }

    #[test]
    fn a_user_overage_is_rejected() {
        assert_eq!(
            decide_upload(0, 95, 10, Some(1000), Some(100)),
            Some("user_storage")
        );
    }

    #[test]
    fn a_null_cap_is_unlimited() {
        assert_eq!(decide_upload(1 << 52, 1 << 52, 1 << 40, None, None), None);
    }

    #[test]
    fn exactly_at_the_limit_still_fits() {
        // used + size == cap → ALLOWED (the comparison is `>`, not `>=`).
        assert_eq!(decide_upload(190, 90, 10, Some(200), Some(100)), None);
    }
}
