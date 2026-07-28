use crate::auth::jwt::{device_id_from_token, verify_access_token};
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
    // Hardening #15: `split_at(7)` PANICS when byte 7 is not a char boundary (a
    // multi-byte UTF-8 header such as "Bearé…"), which would be a DoS on every
    // authenticated route. Checking the byte prefix instead is safe: if the first 7
    // bytes are ASCII "Bearer " then byte 7 is definitely a char boundary, so
    // `auth[7..]` cannot panic.
    let bytes = auth.as_bytes();
    if bytes.len() < 8 || !bytes[..7].eq_ignore_ascii_case(b"Bearer ") {
        return None;
    }
    Some(auth[7..].trim().to_string())
}

/// Has a device been REVOKED (dropped from the device list, so `devices.revoked_at`
/// is SET)? Called on live-token paths — message send and WS delivery, plus key
/// publish, plugin log/blob and push registration — so a stolen device is rejected
/// before its access token's 15 minute TTL runs out. refresh/relogin are already
/// revocation-aware; this closes the live-token send/session surface. Event driven:
/// one query per request, with NO polling loop. An empty `device_id` returns `false`
/// (a legacy device-less token), which is the SAME exemption refresh/relogin grant —
/// needed for migration compatibility.
pub async fn device_revoked(env: &Env, user_id: &str, device_id: &str) -> Result<bool> {
    if device_id.is_empty() {
        return Ok(false);
    }
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

    /// D-M12: a portable check of the query behind `device_revoked`. The 1:1 send path
    /// (handlers.rs + ws.rs) uses it to gate whether the RECIPIENT device is revoked:
    /// revoked_at set → revoked (delivery skipped); NULL or missing row → not revoked
    /// (delivered).
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
/// must still exist and a token-bound device must still be present and active.
/// Legacy device-less JWTs remain accepted for upgrade compatibility; contact
/// request creation applies the stricter active-device proof on top.
#[derive(Clone, Debug)]
pub struct ActiveAuth {
    pub user_id: String,
    pub device_id: Option<String>,
}

fn token_identity(
    env: &Env,
    token: &str,
) -> std::result::Result<ActiveAuth, Response> {
    let user_id = verify_access_token(env, token)
        .map_err(|_| json_err(401, "invalid_token").unwrap())?;
    let device_id = device_id_from_token(env, token)
        .map_err(|_| json_err(401, "invalid_token").unwrap())?;
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
    let auth = token_identity(env, token)?;
    if !account_exists(env, &auth.user_id).await? {
        return Err(json_err(401, "inactive_account").unwrap());
    }

    if let Some(device) = auth.device_id.as_deref() {
        if device.is_empty() {
            return Err(json_err(401, "inactive_device").unwrap());
        }
        if !account_device_active(env, &auth.user_id, device)
            .await
            .map_err(|_| json_err(503, "auth_check_unavailable").unwrap())?
        {
            return Err(json_err(401, "inactive_device").unwrap());
        }
    }

    Ok(auth)
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
    let auth = token_identity(env, &token)?;
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
