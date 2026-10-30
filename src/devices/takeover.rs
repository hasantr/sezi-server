//! The escrowed root, the relay's half (`docs/PRIMARY_DEVICE_LOSS_PLAN.md` §3-§4): a linked device
//! takes over a lost primary only after a server admin approves it with the code the device shows.
//!
//! Routes, all on the caller's own account:
//!   `PUT    /devices/escrow`                 PRIMARY: store R for one of my linked devices
//!   `POST   /devices/takeover`               LINKED (with an escrow): file a request, one-time key
//!   `GET    /devices/takeover`               LINKED: my latest request; once approved, R sealed to
//!                                            the request's one-time key
//!   `DELETE /devices/takeover`               LINKED: cancel my open request
//!   `GET    /devices/takeover/against-me`    PRIMARY: requests open on my account
//!   `POST   /devices/takeover/refuse`        PRIMARY: refuse one ("whatever the admin did")
//! and the admin's two (`takeover_admin.rs`). Every refusal is a stable `error` code.
//!
//! What the relay can and cannot do here: it holds R and never the copy (that went over self-Olm),
//! so it cannot open the account; it decides WHEN R is released, which is why release needs an
//! admin's coded approval, ends with a refusal from a live primary, and dies with the device.

use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::{b64_decode, now_ms};
use serde::Deserialize;
use worker::*;

/// A request lapses a day after it was filed.
pub(crate) const TAKEOVER_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// The third wrong code ends a request.
pub(crate) const MAX_WRONG_CODES: i64 = 3;
/// How long an approval waits before `R` is released when the account's primary was seen
/// recently (Hasan, 2026-10-30): the time a living primary has to refuse.
pub(crate) const RELEASE_HOLD_MS: i64 = 6 * 60 * 60 * 1000;
/// "Seen recently": within this long before the approval.
pub(crate) const PRIMARY_SEEN_RECENTLY_MS: i64 = 24 * 60 * 60 * 1000;

// ── SQL, named so the contract tests run the very statements the handlers do ──────────────────

/// The caller's device role, when the device is active.
pub(crate) const DEVICE_ROLE_SQL: &str = "SELECT role FROM devices
  WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL LIMIT 1";

pub(crate) const UPSERT_ESCROW_SQL: &str = "INSERT INTO device_escrow
    (user_id, device_id, escrow_id, r_b64, updated_at) VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(user_id, device_id) DO UPDATE SET
    escrow_id = excluded.escrow_id, r_b64 = excluded.r_b64, updated_at = excluded.updated_at";

pub(crate) const ESCROW_OF_SQL: &str = "SELECT escrow_id, r_b64 FROM device_escrow
  WHERE user_id = ? AND device_id = ? LIMIT 1";

/// A newer request, or the device's own cancel, closes whatever it had open.
pub(crate) const CLOSE_OPEN_OF_DEVICE_SQL: &str = "UPDATE takeover_requests
  SET state = 'cancelled', decided_at = ?
  WHERE user_id = ? AND device_id = ? AND state IN ('pending', 'approved')";

pub(crate) const INSERT_REQUEST_SQL: &str = "INSERT INTO takeover_requests
    (id, user_id, device_id, one_time_pub_b64, state, wrong_codes, created_at, expires_at)
  VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)";

pub(crate) const LATEST_OF_DEVICE_SQL: &str =
    "SELECT id, state, one_time_pub_b64, expires_at, wrong_codes, release_at, released_at
  FROM takeover_requests WHERE user_id = ? AND device_id = ? ORDER BY created_at DESC LIMIT 1";

/// The account's primary device and when the relay last saw it.
pub(crate) const PRIMARY_OF_SQL: &str = "SELECT device_id, last_seen_at FROM devices
  WHERE user_id = ? AND role = 'primary' AND revoked_at IS NULL LIMIT 1";

/// The old primary's relay session, ended the first time `R` is handed out — gated on that, so a
/// second read or a lost race deletes nothing. Each binds (request id, user id, user id); the
/// last statement stamps the release.
pub(crate) const END_OLD_PRIMARY_SQL: [&str; 4] = [
    "DELETE FROM refresh_tokens WHERE user_id = ?2 AND device_id IN
       (SELECT device_id FROM devices WHERE user_id = ?3 AND role = 'primary' AND revoked_at IS NULL)
       AND EXISTS (SELECT 1 FROM takeover_requests WHERE id = ?1 AND state = 'approved' AND released_at IS NULL)",
    "DELETE FROM one_time_prekeys WHERE user_id = ?2 AND consumed = 0 AND device_id IN
       (SELECT device_id FROM devices WHERE user_id = ?3 AND role = 'primary' AND revoked_at IS NULL)
       AND EXISTS (SELECT 1 FROM takeover_requests WHERE id = ?1 AND state = 'approved' AND released_at IS NULL)",
    "DELETE FROM push_tokens WHERE user_id = ?2 AND device_id IN
       (SELECT device_id FROM devices WHERE user_id = ?3 AND role = 'primary' AND revoked_at IS NULL)
       AND EXISTS (SELECT 1 FROM takeover_requests WHERE id = ?1 AND state = 'approved' AND released_at IS NULL)",
    "UPDATE takeover_requests SET released_at = CAST(strftime('%s','now') AS INTEGER) * 1000
       WHERE id = ?1 AND user_id = ?2 AND user_id = ?3 AND state = 'approved' AND released_at IS NULL",
];

pub(crate) const OPEN_AGAINST_USER_SQL: &str = "SELECT r.id AS id, r.device_id AS device_id,
    d.label AS label, r.state AS state, r.created_at AS created_at, r.expires_at AS expires_at,
    r.release_at AS release_at
  FROM takeover_requests r
  LEFT JOIN devices d ON d.user_id = r.user_id AND d.device_id = r.device_id
  WHERE r.user_id = ? AND r.state IN ('pending', 'approved') AND r.expires_at > ?
  ORDER BY r.created_at DESC LIMIT 10";

/// A refusal ends a pending or an approved request — whatever the admin did.
pub(crate) const REFUSE_SQL: &str = "UPDATE takeover_requests
  SET state = 'refused', decided_by = ?, decided_at = ?
  WHERE id = ? AND user_id = ? AND state IN ('pending', 'approved') AND expires_at > ?";

/// One request's state, read back on my own account only — another account's request id answers
/// nothing, so a refusal cannot probe for one.
pub(crate) const MY_STATE_OF_SQL: &str =
    "SELECT state FROM takeover_requests WHERE id = ? AND user_id = ? LIMIT 1";

/// What a request reads as at `now`: an open one past its day is `expired`, an approved one
/// whose release is still held is `held`.
pub(crate) fn effective_state(state: &str, expires_at: i64, release_at: Option<i64>, now: i64) -> &str {
    match state {
        "pending" | "approved" if now >= expires_at => "expired",
        "approved" if release_at.is_some_and(|r| now < r) => "held",
        s => s,
    }
}

/// When an approval made at `now` may release `R`: at once when the account's primary has not
/// been seen for a day (or ever), else after the hold — the living primary's time to refuse.
pub(crate) fn release_at(primary_last_seen: Option<i64>, now: i64) -> i64 {
    match primary_last_seen {
        Some(seen) if seen > 0 && now - seen < PRIMARY_SEEN_RECENTLY_MS => now + RELEASE_HOLD_MS,
        _ => now,
    }
}

#[derive(Deserialize)]
pub(crate) struct PrimaryRow {
    pub(crate) device_id: String,
    #[serde(default)]
    pub(crate) last_seen_at: Option<i64>,
}

/// The account's primary, if it has one.
pub(crate) async fn primary_of(db: &D1Database, user_id: &str) -> Result<Option<PrimaryRow>> {
    db.prepare(PRIMARY_OF_SQL).bind(&[d1_text(user_id)])?.first(None).await
}

/// Tell the account's primary that a request on its account was filed or approved: a frame to its
/// open socket and an URGENT wake past the coalescing gate (`realtime::nudge_takeover`). The
/// client reads the authoritative list back (`against-me`); this carries nothing.
pub(crate) async fn notify_primary(env: &Env, db: &D1Database, user_id: &str) {
    match primary_of(db, user_id).await {
        Ok(Some(p)) => crate::realtime::nudge_takeover_best_effort(env, user_id, &p.device_id).await,
        Ok(None) => {}
        Err(e) => console_warn!("takeover: primary lookup failed user={user_id}: {e:?}"),
    }
}

/// Is `b64` 32 bytes — a secret `R`, or a Curve25519 public key?
pub(crate) fn is_32_bytes_b64(b64: &str) -> bool {
    b64_decode(b64).is_ok_and(|b| b.len() == 32)
}

/// An id a client chose (an escrow id): short, and only characters that need no escaping.
pub(crate) fn is_plain_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[derive(Deserialize)]
struct RoleRow {
    role: String,
}

/// The caller device's role, when it is an active device of its account.
pub(crate) async fn device_role(db: &D1Database, user_id: &str, device_id: &str) -> Result<Option<String>> {
    let row: Option<RoleRow> = db
        .prepare(DEVICE_ROLE_SQL)
        .bind(&[d1_text(user_id), d1_text(device_id)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.role))
}

#[derive(Deserialize)]
struct EscrowPut {
    device_id: String,
    escrow_id: String,
    r_b64: String,
}

/// `PUT /devices/escrow` — the primary stores R for one of its linked devices. 403 `not_primary`,
/// 404 `no_such_device` (not an active linked device of mine), 400 `bad_escrow`.
pub async fn put_escrow(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("takeover:escrow:{}", auth.user_id), 30, 3600).await {
        return json_err(429, "rate_limited");
    }
    let body: EscrowPut = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if !is_32_bytes_b64(&body.r_b64) || !is_plain_id(&body.escrow_id) || body.device_id.len() > 64 {
        return json_err(400, "bad_escrow");
    }
    let db = ctx.env.d1("DB")?;
    if device_role(&db, &auth.user_id, &auth.device_id).await?.as_deref() != Some("primary") {
        return json_err(403, "not_primary");
    }
    if device_role(&db, &auth.user_id, &body.device_id).await?.as_deref() != Some("linked") {
        return json_err(404, "no_such_device");
    }
    db.prepare(UPSERT_ESCROW_SQL)
        .bind(&[
            d1_text(&auth.user_id),
            d1_text(&body.device_id),
            d1_text(&body.escrow_id),
            d1_text(&body.r_b64),
            d1_int(now_ms() as i64),
        ])?
        .run()
        .await?;
    Response::from_json(&serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct TakeoverPost {
    one_time_pub_b64: String,
}

#[derive(Deserialize)]
struct EscrowRow {
    escrow_id: String,
    r_b64: String,
}

/// `POST /devices/takeover` — a linked device asks to become the primary. 403 `not_linked`, 409
/// `no_escrow` (the primary never stored R for it), 400 `bad_key`. A newer request replaces an
/// open one. The answer carries no code: the device derives it, and the relay checks it.
pub async fn request_takeover(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("takeover:req:{}", auth.user_id), 6, 3600).await {
        return json_err(429, "rate_limited");
    }
    let body: TakeoverPost = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if !is_32_bytes_b64(&body.one_time_pub_b64) {
        return json_err(400, "bad_key");
    }
    let db = ctx.env.d1("DB")?;
    if device_role(&db, &auth.user_id, &auth.device_id).await?.as_deref() != Some("linked") {
        return json_err(403, "not_linked");
    }
    let escrow: Option<EscrowRow> = db
        .prepare(ESCROW_OF_SQL)
        .bind(&[d1_text(&auth.user_id), d1_text(&auth.device_id)])?
        .first(None)
        .await?;
    if escrow.is_none() {
        return json_err(409, "no_escrow");
    }
    let now = now_ms() as i64;
    let id = format!("tko-{}", uuid::Uuid::new_v4().simple());
    let expires_at = now + TAKEOVER_TTL_MS;
    db.batch(vec![
        db.prepare(CLOSE_OPEN_OF_DEVICE_SQL)
            .bind(&[d1_int(now), d1_text(&auth.user_id), d1_text(&auth.device_id)])?,
        db.prepare(INSERT_REQUEST_SQL).bind(&[
            d1_text(&id),
            d1_text(&auth.user_id),
            d1_text(&auth.device_id),
            d1_text(&body.one_time_pub_b64),
            d1_int(now),
            d1_int(expires_at),
        ])?,
    ])
    .await?;
    // The relay tells the primary itself: the requester's own notice is a courtesy a hostile
    // client can skip.
    notify_primary(&ctx.env, &db, &auth.user_id).await;
    Response::from_json(&serde_json::json!({
        "request_id": id,
        "state": "pending",
        "expires_at": expires_at,
    }))
}

#[derive(Deserialize)]
struct LatestRow {
    id: String,
    state: String,
    one_time_pub_b64: String,
    expires_at: i64,
    wrong_codes: i64,
    #[serde(default)]
    release_at: Option<i64>,
    #[serde(default)]
    released_at: Option<i64>,
}

/// `GET /devices/takeover` — my latest request, 404 `no_request` when there is none. Approved and
/// in its day, it carries `sealed_share_b64`: `{escrow_id, r_b64}` sealed to the request's one-time
/// key (`sezi_protocol::takeover`). Read again, it is sealed again; only the requester opens it.
pub async fn takeover_status(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let row: Option<LatestRow> = db
        .prepare(LATEST_OF_DEVICE_SQL)
        .bind(&[d1_text(&auth.user_id), d1_text(&auth.device_id)])?
        .first(None)
        .await?;
    let Some(row) = row else {
        return json_err(404, "no_request");
    };
    let state = effective_state(&row.state, row.expires_at, row.release_at, now_ms() as i64).to_string();
    let mut out = serde_json::json!({
        "request_id": row.id,
        "state": state,
        "expires_at": row.expires_at,
        "wrong_codes": row.wrong_codes,
        "release_at": row.release_at,
    });
    // `held` seals nothing: the primary may still refuse.
    if state == "approved" {
        // The first release ends the old primary's relay session (its refresh tokens, unconsumed
        // one-time keys and push tokens), once.
        if row.released_at.is_none() {
            let mut stmts = Vec::with_capacity(END_OLD_PRIMARY_SQL.len());
            for sql in END_OLD_PRIMARY_SQL {
                stmts.push(db.prepare(sql).bind(&[
                    d1_text(&row.id),
                    d1_text(&auth.user_id),
                    d1_text(&auth.user_id),
                ])?);
            }
            db.batch(stmts).await?;
        }
        let escrow: Option<EscrowRow> = db
            .prepare(ESCROW_OF_SQL)
            .bind(&[d1_text(&auth.user_id), d1_text(&auth.device_id)])?
            .first(None)
            .await?;
        if let Some(e) = escrow {
            let share = sezi_protocol::takeover::ReleasedShare { escrow_id: e.escrow_id, r_b64: e.r_b64 };
            let plain = serde_json::to_vec(&share).map_err(|e| Error::RustError(e.to_string()))?;
            match sezi_protocol::takeover::seal_to_one_time_key(&row.one_time_pub_b64, &plain) {
                Ok(sealed) => out["sealed_share_b64"] = serde_json::json!(sealed),
                Err(_) => return json_err(500, "seal_failed"),
            }
        }
    }
    Response::from_json(&out)
}

/// `DELETE /devices/takeover` — cancel my open request (none open is not an error).
pub async fn cancel_takeover(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    ctx.env
        .d1("DB")?
        .prepare(CLOSE_OPEN_OF_DEVICE_SQL)
        .bind(&[d1_int(now_ms() as i64), d1_text(&auth.user_id), d1_text(&auth.device_id)])?
        .run()
        .await?;
    Response::from_json(&serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct AgainstRow {
    id: String,
    device_id: String,
    label: Option<String>,
    state: String,
    created_at: i64,
    expires_at: i64,
    #[serde(default)]
    release_at: Option<i64>,
}

/// `GET /devices/takeover/against-me` — the primary reads the requests open on its account, so it
/// can refuse one. 403 `not_primary`.
pub async fn takeovers_against_me(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    if device_role(&db, &auth.user_id, &auth.device_id).await?.as_deref() != Some("primary") {
        return json_err(403, "not_primary");
    }
    let rows: Vec<AgainstRow> = db
        .prepare(OPEN_AGAINST_USER_SQL)
        .bind(&[d1_text(&auth.user_id), d1_int(now_ms() as i64)])?
        .all()
        .await?
        .results()?;
    Response::from_json(&serde_json::json!({
        "requests": rows.iter().map(|r| serde_json::json!({
            "request_id": r.id,
            "device_id": r.device_id,
            "label": r.label,
            "state": r.state,
            "requested_at": r.created_at,
            "expires_at": r.expires_at,
            "release_at": r.release_at,
        })).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct RefusePost {
    request_id: String,
}

#[derive(Deserialize)]
pub(crate) struct StateRow {
    pub(crate) state: String,
}

/// `POST /devices/takeover/refuse` — the primary ends a request on its account, approved or not.
/// 403 `not_primary`, 409 `not_open` (decided, expired, or not mine).
pub async fn refuse_takeover(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let body: RefusePost = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    if device_role(&db, &auth.user_id, &auth.device_id).await?.as_deref() != Some("primary") {
        return json_err(403, "not_primary");
    }
    let now = now_ms() as i64;
    db.prepare(REFUSE_SQL)
        .bind(&[
            d1_text(&auth.user_id),
            d1_int(now),
            d1_text(&body.request_id),
            d1_text(&auth.user_id),
            d1_int(now),
        ])?
        .run()
        .await?;
    // Read back rather than trusting D1's change count across versions.
    let row: Option<StateRow> = db
        .prepare(MY_STATE_OF_SQL)
        .bind(&[d1_text(&body.request_id), d1_text(&auth.user_id)])?
        .first(None)
        .await?;
    match row {
        Some(r) if r.state == "refused" => Response::from_json(&serde_json::json!({ "state": "refused" })),
        _ => json_err(409, "not_open"),
    }
}

#[cfg(test)]
#[path = "takeover_tests.rs"]
mod tests;
