use crate::auth::jwt::{token_identity, verify_access_token};
use crate::d1util::d1_text;
use crate::respond::json_err;
use serde::Deserialize;
use worker::{Env, Request, Response, Result};

pub(crate) const ACCOUNT_DEVICE_ACTIVE_SQL: &str =
    "SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE id = ?)
            AND EXISTS(SELECT 1 FROM devices
              WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL)
          THEN 1 ELSE 0 END AS active";

const ACCOUNT_EXISTS_SQL: &str = "SELECT 1 AS n FROM users WHERE id = ? LIMIT 1";

/// Extract the bearer token from the request headers.
pub fn extract_bearer(req: &Request) -> Option<String> {
    let auth = req.headers().get("authorization").ok().flatten()?;
    // Check the BYTE prefix, never `split_at(7)`: byte 7 of a multi-byte header ("Bearé…")
    // is not a char boundary and slicing there panics — a DoS on every authenticated route.
    // Past an ASCII "Bearer " prefix, `auth[7..]` is guaranteed safe.
    let bytes = auth.as_bytes();
    if bytes.len() < 8 || !bytes[..7].eq_ignore_ascii_case(b"Bearer ") {
        return None;
    }
    Some(auth[7..].trim().to_string())
}

/// Has a device been REVOKED (dropped from the device list, so `devices.revoked_at`
/// is SET)? Called on live-token paths — message send and WS delivery, plus key
/// publish, plugin log/blob and push registration — so a stolen device is rejected
/// before its access token's 15 minute TTL runs out. One query per request, no polling.
///
/// A device with no `devices` row is NOT revoked — that is the registration bootstrap window,
/// before the first `PUT /devices/list` creates any row, and `put_list` depends on it.
pub async fn device_revoked(env: &Env, user_id: &str, device_id: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct RevRow {
        revoked_at: Option<i64>,
    }
    let db = env.d1("DB")?;
    let rev: Option<RevRow> = db
        .prepare("SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
        .bind(&[
            crate::d1util::d1_text(user_id),
            crate::d1util::d1_text(device_id),
        ])?
        .first(None)
        .await?;
    Ok(rev.and_then(|r| r.revoked_at).is_some())
}

/// Positive active-session check for already-open channels. Unlike
/// `device_revoked`, a missing account/device is NOT treated as active. This is
/// used by hot WS send/read paths after account removal or device-list churn.
pub async fn account_device_active(env: &Env, user_id: &str, device_id: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct ActiveRow {
        active: i64,
    }
    let db = env.d1("DB")?;
    let row: Option<ActiveRow> = db
        .prepare(ACCOUNT_DEVICE_ACTIVE_SQL)
        .bind(&[d1_text(user_id), d1_text(user_id), d1_text(device_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.active != 0).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::{ACCOUNT_DEVICE_ACTIVE_SQL, ACCOUNT_EXISTS_SQL};
    use rusqlite::{params, Connection, OptionalExtension};

    /// A portable check of the query behind `device_revoked`, which the 1:1 send path
    /// (handlers.rs + ws.rs) uses to gate the RECIPIENT device: revoked_at set → revoked
    /// (delivery skipped); NULL or missing row → not revoked (delivered).
    #[test]
    fn device_revoked_sql_detects_revoked_recipient_device() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE devices(user_id TEXT, device_id TEXT, revoked_at INTEGER);")
            .unwrap();
        c.execute(
            "INSERT INTO devices(user_id,device_id,revoked_at) VALUES('u','d',NULL)",
            [],
        )
        .unwrap();
        let revoked = |user: &str, dev: &str| -> bool {
            let r: Option<Option<i64>> = c
                .query_row(
                    "SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1",
                    params![user, dev],
                    |row| row.get(0),
                )
                .optional()
                .unwrap();
            r.flatten().is_some()
        };
        assert!(!revoked("u", "d"), "an active recipient device is NOT revoked → it gets delivery");
        c.execute("UPDATE devices SET revoked_at=123 WHERE device_id='d'", [])
            .unwrap();
        assert!(
            revoked("u", "d"),
            "D-M12: a revoked recipient device is detected → the 1:1 delivery is skipped"
        );
        assert!(
            !revoked("u", "missing"),
            "a device absent from the list is not revoked (allow; an empty device_id returns false early)"
        );
    }

    fn active(c: &Connection, user: &str, device: &str) -> i64 {
        c.query_row(
            ACCOUNT_DEVICE_ACTIVE_SQL,
            params![user, user, device],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn open_channel_requires_existing_account_and_active_device() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE users(id TEXT PRIMARY KEY);
             CREATE TABLE devices(user_id TEXT, device_id TEXT, revoked_at INTEGER);",
        )
        .unwrap();
        c.execute("INSERT INTO users(id) VALUES('u')", []).unwrap();
        assert_eq!(active(&c, "u", "d"), 0, "missing device fails closed");
        c.execute(
            "INSERT INTO devices(user_id,device_id,revoked_at) VALUES('u','d',NULL)",
            [],
        )
        .unwrap();
        assert_eq!(active(&c, "u", "d"), 1);
        c.execute("UPDATE devices SET revoked_at=1", []).unwrap();
        assert_eq!(active(&c, "u", "d"), 0);
        c.execute("UPDATE devices SET revoked_at=NULL", []).unwrap();
        c.execute("DELETE FROM users", []).unwrap();
        assert_eq!(active(&c, "u", "d"), 0, "removed account fails closed");
    }

    #[test]
    fn bootstrap_exception_still_requires_a_live_account() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE users(id TEXT PRIMARY KEY);")
            .unwrap();
        let exists = |user: &str| {
            c.query_row(ACCOUNT_EXISTS_SQL, params![user], |_| Ok(()))
                .is_ok()
        };
        assert!(!exists("fresh"));
        c.execute("INSERT INTO users(id) VALUES('fresh')", [])
            .unwrap();
        assert!(exists("fresh"));
        c.execute("DELETE FROM users WHERE id='fresh'", []).unwrap();
        assert!(!exists("fresh"), "removed account cannot bootstrap again");
    }
}

/// Sensitive account routes need more than a valid stateless JWT: the account
/// must still exist and the token-bound device must still be present and active.
#[derive(Clone, Debug)]
pub struct ActiveAuth {
    pub user_id: String,
    /// Never optional: `jwt::verify_access_token` refuses a token that names no device.
    pub device_id: String,
}

fn auth_from_token(env: &Env, token: &str) -> std::result::Result<ActiveAuth, Response> {
    let (user_id, device_id) =
        token_identity(env, token).map_err(|_| json_err(401, "invalid_token").unwrap())?;
    Ok(ActiveAuth { user_id, device_id })
}

async fn account_exists(env: &Env, user_id: &str) -> std::result::Result<bool, Response> {
    #[derive(Deserialize)]
    struct ExistsRow {
        #[serde(rename = "n")]
        #[allow(dead_code)]
        n: i64,
    }

    let db = env
        .d1("DB")
        .map_err(|_| json_err(503, "auth_check_unavailable").unwrap())?;
    let row: Option<ExistsRow> = db
        .prepare(ACCOUNT_EXISTS_SQL)
        .bind(&[d1_text(user_id)])
        .map_err(|_| json_err(503, "auth_check_unavailable").unwrap())?
        .first(None)
        .await
        .map_err(|_| json_err(503, "auth_check_unavailable").unwrap())?;
    Ok(row.is_some())
}

/// Validate a bearer token against current server membership and its bound
/// device. This is shared by HTTP handlers and the WebSocket upgrade path so a
/// removed account cannot keep a stateless JWT alive on either transport.
pub async fn validate_active_token(
    env: &Env,
    token: &str,
) -> std::result::Result<ActiveAuth, Response> {
    let auth = auth_from_token(env, token)?;
    if !account_exists(env, &auth.user_id).await? {
        return Err(json_err(401, "inactive_account").unwrap());
    }

    if !account_device_active(env, &auth.user_id, &auth.device_id)
        .await
        .map_err(|_| json_err(503, "auth_check_unavailable").unwrap())?
    {
        return Err(json_err(401, "inactive_device").unwrap());
    }

    Ok(auth)
}

/// How stale `devices.last_seen_at` may get before it is written again.
///
/// Fifteen minutes is the resolution the question deserves — "today, or three weeks ago?" — and it
/// is also the rhythm of the two callers below, so in practice almost every call writes.
const SEEN_THROTTLE_MS: i64 = 15 * 60 * 1000;

/// Record that this device was here, at most once per [`SEEN_THROTTLE_MS`].
///
/// **Called from exactly two places, and NOT from `validate_active_token`** — calling it there
/// puts a D1 round trip behind every endpoint that gates on an active session, for a field that
/// only decorates a device row. The two callers answer the same question for a fraction of that:
/// the `/sync` upgrade ("this device connected") and `/auth/refresh` (an active session does it
/// every quarter of an hour). A device in use hits both; one that is not hits neither.
///
/// The read IS the throttle: `WHERE last_seen_at IS NULL OR last_seen_at < ?` makes the write its
/// own condition, so nothing round-trips to decide whether to write. NULL is deliberate — it is
/// what a device predating the column looks like. MILLISECONDS, matching `devices.added_at`; the
/// same table's `revoked_at` is in SECONDS and is not the one to copy.
pub(crate) async fn touch_device_seen(
    env: &Env,
    user_id: &str,
    device_id: &str,
) -> Result<()> {
    let now = crate::utils::now_ms() as i64;
    env.d1("DB")?
        .prepare(
            "UPDATE devices SET last_seen_at = ?
              WHERE user_id = ? AND device_id = ?
                AND (last_seen_at IS NULL OR last_seen_at < ?)",
        )
        .bind(&[
            crate::d1util::d1_int(now),
            d1_text(user_id),
            d1_text(device_id),
            crate::d1util::d1_int(now - SEEN_THROTTLE_MS),
        ])?
        .run()
        .await?;
    Ok(())
}

/// Fresh registration bootstrap needs to read the account's own, initially
/// missing device list before an active device row exists. Membership is still
/// checked so the same narrow exception cannot be reused after a kick/leave.
pub async fn require_existing_account_auth(
    req: &Request,
    env: &Env,
) -> std::result::Result<ActiveAuth, Response> {
    let token =
        extract_bearer(req).ok_or_else(|| json_err(401, "unauthorized").unwrap())?;
    let auth = auth_from_token(env, &token)?;
    if !account_exists(env, &auth.user_id).await? {
        return Err(json_err(401, "inactive_account").unwrap());
    }
    Ok(auth)
}

pub async fn require_active_auth(
    req: &Request,
    env: &Env,
) -> std::result::Result<ActiveAuth, Response> {
    let token =
        extract_bearer(req).ok_or_else(|| json_err(401, "unauthorized").unwrap())?;
    validate_active_token(env, &token).await
}

/// Authentication required. Returns the user_id on success, or a ready-made
/// Response on failure.
pub fn require_auth(req: &Request, env: &Env) -> std::result::Result<String, Response> {
    let token = match extract_bearer(req) {
        Some(t) => t,
        None => return Err(json_err(401, "unauthorized").unwrap()),
    };
    match verify_access_token(env, &token) {
        Ok(uid) => Ok(uid),
        Err(_) => Err(json_err(401, "invalid_token").unwrap()),
    }
}

/// Authentication that also yields the device the token is bound to.
///
/// The device-addressing routes (key publish, OTK pool, message send, push, plugin log/blob)
/// reach for this instead of `require_auth` plus a second verification: one verification, and
/// no absent-device branch — `verify_access_token` already refuses a token that names no device.
pub fn require_auth_device(
    req: &Request,
    env: &Env,
) -> std::result::Result<(String, String), Response> {
    let token = extract_bearer(req).ok_or_else(|| json_err(401, "unauthorized").unwrap())?;
    token_identity(env, &token).map_err(|_| json_err(401, "invalid_token").unwrap())
}

#[derive(Deserialize)]
struct RoleRow {
    role: String,
}

/// Authentication plus a DB check that role ∈ {owner, admin}: an owner can perform
/// every admin action.
pub async fn require_admin(user_id: &str, env: &Env) -> std::result::Result<(), Response> {
    match fetch_role(user_id, env).await {
        Ok(Some(role)) if role == "admin" || role == "owner" => Ok(()),
        Ok(Some(_)) => Err(json_err(403, "admin_required").unwrap()),
        Ok(None) => Err(json_err(401, "user_not_found").unwrap()),
        Err(resp) => Err(resp),
    }
}

/// Authentication plus a DB check that role = owner, for founder-only operations
/// such as assigning roles.
pub async fn require_owner(user_id: &str, env: &Env) -> std::result::Result<(), Response> {
    match fetch_role(user_id, env).await {
        Ok(Some(role)) if role == "owner" => Ok(()),
        Ok(Some(_)) => Err(json_err(403, "owner_required").unwrap()),
        Ok(None) => Err(json_err(401, "user_not_found").unwrap()),
        Err(resp) => Err(resp),
    }
}

/// Read a user's role from the DB. On failure it returns a ready-made Response.
pub(crate) async fn fetch_role(
    user_id: &str,
    env: &Env,
) -> std::result::Result<Option<String>, Response> {
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return Err(json_err(500, "db").unwrap()),
    };
    let stmt = match db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[wasm_bindgen::JsValue::from_str(user_id)])
    {
        Ok(s) => s,
        Err(_) => return Err(json_err(500, "db_bind").unwrap()),
    };
    let row: Result<Option<RoleRow>> = stmt.first(None).await;
    match row {
        Ok(opt) => Ok(opt.map(|r| r.role)),
        Err(_) => Err(json_err(500, "db_query").unwrap()),
    }
}
