//! The admin's side of a takeover (`docs/PRIMARY_DEVICE_LOSS_PLAN.md` §4.3):
//!   `GET  /admin/takeovers`              the pending requests of OTHER accounts
//!   `POST /admin/takeovers/:id/approve`  approve one with the code its device shows
//!
//! An admin's own request is never theirs to approve — it is not listed for them and the approval
//! refuses it — so on a one-admin server an admin who lost their primary has the `.szbak` and
//! nothing else, which is what the next-steps card's "second admin" is for.
//!
//! The code is checked here and never served: the admin's screen has none to show, and must hear
//! it from whoever holds the device. Three wrong codes end the request.
//!
//! **The hold** (Hasan, 2026-10-30): an approval of an account whose primary the relay saw within
//! the last day does not release `R` for six hours — the request reads `held` until then, and the
//! primary, told at once (`takeover::notify_primary`, an urgent wake), can still refuse. A primary
//! not seen for a day releases at once. The first release ends the old primary's relay session
//! (`takeover::END_OLD_PRIMARY_SQL`). It cannot end more than that: the old machine holds the same
//! account, and a revived one can sign in again with it (the stolen-primary case, §5.3).

use crate::auth::middleware::{require_active_auth, require_admin};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_ms;
use serde::Deserialize;
use worker::*;

use super::takeover::{notify_primary, primary_of, release_at, MAX_WRONG_CODES, StateRow, TAKEOVER_TTL_MS};

pub(crate) const ADMIN_LIST_SQL: &str = "SELECT r.id AS id, r.user_id AS user_id,
    u.display_name AS display_name, u.email AS email, u.role AS user_role,
    r.device_id AS device_id, d.label AS label, d.added_at AS linked_at,
    r.created_at AS created_at, r.expires_at AS expires_at, r.wrong_codes AS wrong_codes,
    (SELECT p.last_seen_at FROM devices p
      WHERE p.user_id = r.user_id AND p.role = 'primary' AND p.revoked_at IS NULL
      LIMIT 1) AS primary_last_seen,
    EXISTS (SELECT 1 FROM push_tokens pt JOIN devices p
              ON p.user_id = pt.user_id AND p.device_id = pt.device_id
            WHERE pt.user_id = r.user_id AND p.role = 'primary' AND p.revoked_at IS NULL)
      AS primary_has_push
  FROM takeover_requests r
  JOIN users u ON u.id = r.user_id
  LEFT JOIN devices d ON d.user_id = r.user_id AND d.device_id = r.device_id
  WHERE r.state = 'pending' AND r.expires_at > ? AND r.user_id != ?
  ORDER BY r.created_at DESC LIMIT 50";

pub(crate) const REQUEST_BY_ID_SQL: &str = "SELECT user_id, one_time_pub_b64, state, expires_at,
    wrong_codes FROM takeover_requests WHERE id = ? LIMIT 1";

/// One wrong code: counted, and the third ends the request. Every right-hand side reads the OLD
/// row (SQLite), so `wrong_codes + 1` is this attempt's count in both places.
pub(crate) const WRONG_CODE_SQL: &str = "UPDATE takeover_requests
  SET wrong_codes = wrong_codes + 1,
      state = CASE WHEN wrong_codes + 1 >= ? THEN 'failed' ELSE state END,
      decided_at = CASE WHEN wrong_codes + 1 >= ? THEN ? ELSE decided_at END
  WHERE id = ? AND state = 'pending'";

/// The approval itself: only a pending request in its day, never the approver's own. It sets when
/// `R` may be released (`takeover::release_at`) and gives the device a day from then to finish.
/// Binds: approver, now, release_at, release_at + TTL, id, now, approver.
pub(crate) const APPROVE_SQL: &str = "UPDATE takeover_requests
  SET state = 'approved', decided_by = ?, decided_at = ?, release_at = ?,
      expires_at = MAX(expires_at, ?)
  WHERE id = ? AND state = 'pending' AND expires_at > ? AND user_id != ?";

pub(crate) const STATE_BY_ID_SQL: &str = "SELECT state FROM takeover_requests WHERE id = ? LIMIT 1";

/// What an approval with this code does to a request, decided before anything is written.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Approve,
    WrongCode,
    /// The approver's own request (`self_approval`).
    OwnRequest,
    /// Decided, cancelled or past its day (`not_open`).
    NotOpen,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verdict(
    request_id: &str,
    req_user: &str,
    one_time_pub_b64: &str,
    state: &str,
    expires_at: i64,
    approver: &str,
    typed_code: &str,
    now: i64,
) -> Verdict {
    if super::takeover::effective_state(state, expires_at, None, now) != "pending" {
        return Verdict::NotOpen;
    }
    if req_user == approver {
        return Verdict::OwnRequest;
    }
    if sezi_protocol::takeover::code_matches(request_id, one_time_pub_b64, typed_code) {
        Verdict::Approve
    } else {
        Verdict::WrongCode
    }
}

#[derive(Deserialize)]
struct ListRow {
    id: String,
    user_id: String,
    display_name: Option<String>,
    email: Option<String>,
    user_role: Option<String>,
    device_id: String,
    label: Option<String>,
    linked_at: Option<i64>,
    created_at: i64,
    expires_at: i64,
    wrong_codes: i64,
    primary_last_seen: Option<i64>,
    /// Whether the primary has a push token: without one a closed app cannot be told of the
    /// request during the hold. D1 answers EXISTS as 0/1.
    #[serde(default)]
    primary_has_push: i64,
}

/// `GET /admin/takeovers` → `{requests: [...]}`: who, which device, when it was linked, when the
/// primary was last seen (the screen warns when that is recent: the "lost" device is alive).
pub async fn list_takeovers(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&auth.user_id, &ctx.env).await {
        return Ok(resp);
    }
    let rows: Vec<ListRow> = ctx
        .env
        .d1("DB")?
        .prepare(ADMIN_LIST_SQL)
        .bind(&[d1_int(now_ms() as i64), d1_text(&auth.user_id)])?
        .all()
        .await?
        .results()?;
    Response::from_json(&serde_json::json!({
        "requests": rows.iter().map(|r| serde_json::json!({
            "request_id": r.id,
            "user_id": r.user_id,
            "display_name": r.display_name,
            "email": r.email,
            "requester_is_admin": matches!(r.user_role.as_deref(), Some("admin" | "owner")),
            "device_id": r.device_id,
            "device_label": r.label,
            "linked_at": r.linked_at,
            "requested_at": r.created_at,
            "expires_at": r.expires_at,
            "wrong_codes": r.wrong_codes,
            "primary_last_seen": r.primary_last_seen,
            "primary_has_push": r.primary_has_push != 0,
        })).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct ApproveBody {
    code: String,
}

#[derive(Deserialize)]
struct RequestRow {
    user_id: String,
    one_time_pub_b64: String,
    state: String,
    expires_at: i64,
    wrong_codes: i64,
}

/// `POST /admin/takeovers/:id/approve {code}` → `{state: "approved"}`. 404 `no_request`, 409
/// `not_open`, 403 `self_approval`, 403 `wrong_code` with `attempts_left` (0 = the request ended).
pub async fn approve_takeover(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&auth.user_id, &ctx.env).await {
        return Ok(resp);
    }
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("takeover:approve:{}", auth.user_id), 20, 60).await {
        return json_err(429, "rate_limited");
    }
    let Some(id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request");
    };
    let body: ApproveBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let row: Option<RequestRow> = db.prepare(REQUEST_BY_ID_SQL).bind(&[d1_text(&id)])?.first(None).await?;
    let Some(row) = row else {
        return json_err(404, "no_request");
    };
    let now = now_ms() as i64;
    match verdict(&id, &row.user_id, &row.one_time_pub_b64, &row.state, row.expires_at, &auth.user_id, &body.code, now) {
        Verdict::NotOpen => json_err(409, "not_open"),
        Verdict::OwnRequest => json_err(403, "self_approval"),
        Verdict::WrongCode => {
            db.prepare(WRONG_CODE_SQL)
                .bind(&[
                    d1_int(MAX_WRONG_CODES),
                    d1_int(MAX_WRONG_CODES),
                    d1_int(now),
                    d1_text(&id),
                ])?
                .run()
                .await?;
            let left = (MAX_WRONG_CODES - row.wrong_codes - 1).max(0);
            let resp = Response::from_json(&serde_json::json!({ "error": "wrong_code", "attempts_left": left }))?;
            Ok(resp.with_status(403))
        }
        Verdict::Approve => {
            // A primary seen within a day holds the release for six hours: its time to refuse.
            let seen = primary_of(&db, &row.user_id).await?.and_then(|p| p.last_seen_at);
            let release = release_at(seen, now);
            db.prepare(APPROVE_SQL)
                .bind(&[
                    d1_text(&auth.user_id),
                    d1_int(now),
                    d1_int(release),
                    d1_int(release + TAKEOVER_TTL_MS),
                    d1_text(&id),
                    d1_int(now),
                    d1_text(&auth.user_id),
                ])?
                .run()
                .await?;
            let after: Option<StateRow> = db.prepare(STATE_BY_ID_SQL).bind(&[d1_text(&id)])?.first(None).await?;
            match after {
                Some(s) if s.state == "approved" => {
                    notify_primary(&ctx.env, &db, &row.user_id).await;
                    Response::from_json(&serde_json::json!({ "state": "approved", "release_at": release }))
                }
                _ => json_err(409, "not_open"),
            }
        }
    }
}
