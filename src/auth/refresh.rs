use crate::auth::hashing::sha256_hex;
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::{b64u_encode, now_secs, random_bytes};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
    /// This device's device_id, as the caller believes it to be.
    ///
    /// Deliberately still optional, and deliberately NOT the binding — see
    /// `check_device_claim`. The session's device comes from the stored row, so a caller that
    /// cannot name its own device can still refresh; the field only ever REFUSES. Core's
    /// `run_token_refresh` sends `None` when it fails to re-derive the device from a corrupt
    /// identity blob, and that request must keep working: refusing it would strand the client
    /// with no way to renew a token it holds legitimately.
    #[serde(default)]
    device_id: Option<String>,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;

/// May a refresh naming `claim` renew a token ISSUED to `row`?
///
/// **The row is the authority; the claim can only refuse.** Never
/// `body.device_id.or(row.device_id)`: device ids are public — `GET /devices/list/:user_id`
/// serves them — so a refresh token bound to a just-revoked device could name a live sibling
/// instead, the revocation check would interrogate the sibling and pass, and
/// `sign_access_token` would mint an access token CLAIMING the sibling. That is a forged device
/// identity on every path that trusts the token's device claim (message send's
/// `sender_device_id` binding, the OTK pool scope, `plugin_blob::gate`).
///
/// `Err(())` = the claim CONTRADICTS the row (→ 403). No claim at all is fine; the row still
/// decides, and the row is still what gets the revocation check.
fn check_device_claim(row: &str, claim: Option<&str>) -> std::result::Result<(), ()> {
    // `''` is not a device. Normalising it here stops `device_id: ""` from reading as
    // agreement with a real binding.
    match claim.filter(|d| !d.is_empty()) {
        Some(c) if c != row => Err(()),
        _ => Ok(()),
    }
}

pub async fn refresh(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: RefreshBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.refresh_token.len() < 20 || body.refresh_token.len() > 200 {
        return json_err(400, "bad_request");
    }

    let now = now_secs();
    let old_hash = sha256_hex(&body.refresh_token);
    let db = ctx.env.d1("DB")?;

    #[derive(Deserialize)]
    struct Row {
        user_id: String,
        expires_at: i64,
        /// The device this refresh token was issued to. Read as `Option` only because the D1
        /// column is nullable; every mint site writes one, so a NULL row is refused below
        /// rather than granted a device-less session.
        device_id: Option<String>,
    }
    let row: Option<Row> = db
        .prepare(
            "SELECT user_id, expires_at, device_id FROM refresh_tokens
             WHERE token_hash = ? AND revoked = 0 LIMIT 1",
        )
        .bind(&[d1_text(&old_hash)])?
        .first(None)
        .await?;
    let row = match row {
        Some(r) if (r.expires_at as u64) > now => r,
        _ => return json_err(401, "invalid_refresh"),
    };

    let user_id = row.user_id;
    // A row that names no device cannot exist: `auth::verify`, this handler, `auth::relogin` and
    // `devices::link` all bind one. Refusing is the honest answer — the alternative is minting a
    // device-less access token, which is the very thing every route downstream stopped
    // accommodating.
    let device_id = match row.device_id.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => d,
        None => return json_err(401, "invalid_refresh"),
    };
    // The stored row decides which device this session belongs to; the body may only reject.
    // See `check_device_claim` for what a caller-chosen device_id would buy an attacker.
    if check_device_claim(device_id, body.device_id.as_deref()).is_err() {
        return json_err(403, "device_mismatch");
    }
    // A REMOVED device must not RESURRECT its session through /auth/refresh (parity with
    // relogin.rs). Revoked → 401, so it gets no new access token and the session dies within
    // the access TTL (15 min). Defence on top of the token deletion, covering every refresh.
    {
        #[derive(Deserialize)]
        struct RevRow {
            revoked_at: Option<i64>,
        }
        let rev: Option<RevRow> = db
            .prepare("SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
            .bind(&[d1_text(&user_id), d1_text(device_id)])?
            .first(None)
            .await?;
        if rev.and_then(|r| r.revoked_at).is_some() {
            return json_err(401, "device_revoked");
        }
    }
    let access_token = sign_access_token(&ctx.env, &user_id, device_id)?;
    let new_refresh = b64u_encode(&random_bytes(32));
    let new_hash = sha256_hex(&new_refresh);
    // ROTATION IS ONE WRITE. A standalone revoke UPDATE, with the successor INSERTed later,
    // strands a caller whenever anything in between fails — `sign_access_token` on a broken key,
    // a D1 error, an isolate eviction, a dropped response — leaving a permanently logged-out
    // device holding a 30-day token the server already revoked. A D1 batch is an implicit
    // transaction, so the old token is revoked IF AND ONLY IF its replacement exists. Order
    // inside the batch is revoke-then-insert: both commit or neither does, so the order cannot
    // strand anyone, but it reads the way rotation means.
    //
    // The revoke also sits BEHIND the device checks: a refresh refused with 403
    // `device_mismatch` or 401 `device_revoked` issues no successor AND burns no token.
    // Refusing a request and destroying the credential it presented are not the same act.
    db.batch(vec![
        db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")
            .bind(&[d1_text(&old_hash)])?,
        db.prepare(
            "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
             VALUES (?, ?, ?, 0, ?, ?)",
        )
        .bind(&[
            d1_text(&new_hash),
            d1_text(&user_id),
            d1_int((now + REFRESH_TTL_SEC) as i64),
            d1_int(now as i64),
            d1_text(device_id),
        ])?,
    ])
    .await?;

    // The heartbeat of a session that is actually being used — a device renews here about every
    // quarter of an hour, which is exactly the resolution the devices screen wants. Best-effort:
    // a failed note must not fail a refresh. See `middleware::touch_device_seen`.
    if let Err(e) =
        crate::auth::middleware::touch_device_seen(&ctx.env, &user_id, device_id).await
    {
        worker::console_log!("last_seen touch failed on refresh for {device_id}: {e}");
    }

    Response::from_json(&serde_json::json!({
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SEC,
    }))
}

#[cfg(test)]
mod tests {
    use super::check_device_claim;
    use rusqlite::{params, Connection};

    /// `include_str!` binds at compile time and resolves relative to THIS file — the
    /// `groups_tests.rs` trick. Because this module is INLINE in `refresh.rs`, `SRC` contains the
    /// test source too, so every needle below is assembled with `concat!` and cannot match itself.
    const SRC: &str = include_str!("refresh.rs");

    /// The needle for the revoke statement, split so it does not appear literally in `SRC`.
    fn revoke_needle() -> String {
        concat!("UPDATE refresh_tokens SET revoked", " = 1 WHERE token_hash = ?").to_string()
    }

    /// `SRC` up to this test module. The rusqlite tests below run the very statements the guard
    /// counts, so without the cut every needle would find its own fixtures and the count would
    /// measure the tests instead of the handler.
    fn handler_src() -> &'static str {
        let marker = concat!("#[cfg(", "test)]");
        &SRC[..SRC.find(marker).expect("the test module marker moved")]
    }

    fn rotation_schema() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE refresh_tokens (
                 token_hash TEXT PRIMARY KEY,
                 user_id TEXT NOT NULL,
                 expires_at INTEGER NOT NULL,
                 revoked INTEGER NOT NULL DEFAULT 0,
                 created_at INTEGER NOT NULL,
                 device_id TEXT
             );
             INSERT INTO refresh_tokens VALUES ('old', 'u', 9999, 0, 1, 'dev-a');",
        )
        .unwrap();
        c
    }

    fn revoked_flag(c: &Connection, hash: &str) -> i64 {
        c.query_row(
            "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
            params![hash],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// The stranding hazard: revoking the old token in a standalone UPDATE and INSERTing the
    /// successor later leaves a client holding a revoked token with no replacement — permanently
    /// logged out while still holding a 30-day credential — whenever anything in between fails.
    ///
    /// Portable rusqlite stands in for D1, whose `batch` is an implicit transaction: revoke and
    /// issue either both land or neither does.
    #[test]
    fn a_failed_successor_insert_leaves_the_old_token_usable() {
        let mut c = rotation_schema();
        // The successor collides with a row that already exists → the INSERT fails mid-batch.
        c.execute(
            "INSERT INTO refresh_tokens VALUES ('taken', 'u', 9999, 0, 1, 'dev-a')",
            [],
        )
        .unwrap();
        let tx = c.transaction().unwrap();
        tx.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
            params!["old"],
        )
        .unwrap();
        let insert = tx.execute(
            "INSERT INTO refresh_tokens VALUES ('taken', 'u', 9999, 0, 2, 'dev-a')",
            [],
        );
        assert!(insert.is_err(), "the successor write must be the failing half");
        drop(tx); // no commit → rollback, which is what a failed D1 batch does
        assert_eq!(
            revoked_flag(&c, "old"),
            0,
            "no successor was issued, so the client's existing token must still work"
        );
    }

    /// The success path still rotates: the old token dies exactly when its replacement is born.
    #[test]
    fn a_successful_rotation_revokes_the_old_token_and_issues_the_new_one() {
        let mut c = rotation_schema();
        let tx = c.transaction().unwrap();
        tx.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
            params!["old"],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO refresh_tokens VALUES ('new', 'u', 9999, 0, 2, 'dev-a')",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(revoked_flag(&c, "old"), 1);
        assert_eq!(revoked_flag(&c, "new"), 0);
    }

    /// Source guard: the two writes must stay in ONE batch. A behavioural test cannot see this —
    /// the bug was never inside a statement, it was the gap BETWEEN two of them — so the
    /// assertion is over the source, the `groups_tests.rs` shape.
    #[test]
    fn the_rotation_writes_stay_inside_a_single_batch() {
        let src = handler_src();
        let revoke = revoke_needle();
        assert_eq!(
            src.matches(&revoke).count(),
            1,
            "expected exactly one revoke statement in refresh.rs"
        );
        let batch_at = src
            .find("db.batch(vec![")
            .expect("the rotation batch is gone — the revoke and the insert have been split apart");
        assert!(
            src.find(&revoke).unwrap() > batch_at,
            "the revoke escaped the batch and runs on its own again"
        );
        assert_eq!(
            src.matches(concat!(".run", "()")).count(),
            0,
            "a standalone statement execution in refresh.rs means a rotation write left the batch"
        );
    }

    /// The whole point: whatever the caller asks for, the session's device is the stored one.
    #[test]
    fn the_body_can_never_substitute_the_issued_binding() {
        // The attack: a token issued to a revoked device, naming a live sibling.
        assert_eq!(check_device_claim("revoked", Some("live")), Err(()));
        // Agreement is fine, and changes nothing.
        assert_eq!(check_device_claim("dev-a", Some("dev-a")), Ok(()));
        // No claim at all: the row still decides, and still gets the revocation check. Core
        // sends exactly this when it cannot re-derive its own device_id from the identity blob,
        // which is why the field stayed optional here and nowhere else.
        assert_eq!(check_device_claim("dev-a", None), Ok(()));
    }

    /// `''` is not a device, and must not read as agreement with a real binding.
    #[test]
    fn the_empty_sentinel_is_not_a_device() {
        assert_eq!(
            check_device_claim("dev-a", Some("")),
            Ok(()),
            "an empty claim is no claim; it must not read as agreement with dev-a either"
        );
    }
}
