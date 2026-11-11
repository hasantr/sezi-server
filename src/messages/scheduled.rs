//! `POST /messages/scheduled` and `DELETE /messages/scheduled/:id` — a scheduled message handed to
//! the relay and taken back (`docs/SCHEDULED_MESSAGES_PLAN.md`). The rules are
//! `scheduled_rules.rs`; the hold and the release live in the SENDER's own inbox Durable Object
//! (`inbox_do/scheduled.rs`), whose alarm releases it at its time.
//!
//! Both routes act only on the caller's OWN inbox (the object named by the caller), so only the account that
//! scheduled a message can take it back, and there is no route that lists or reads anyone's
//! schedules (`cancel_reaches_only_the_callers_own_inbox`).

use crate::auth::middleware::require_active_auth;
use crate::d1util::d1_text;
use crate::messages::scheduled_rules::{self as rules, Conversation, PutBody, Refusal};
use crate::respond::json_err;
use serde::Deserialize;
use std::collections::HashSet;
use worker::*;

fn refused(r: Refusal) -> Result<Response> {
    json_err(r.status, r.code)
}

/// The active devices of `users`: `(user, device)`.
pub(crate) async fn active_devices(db: &D1Database, users: &[&str]) -> Result<HashSet<(String, String)>> {
    #[derive(Deserialize)]
    struct Row {
        user_id: String,
        device_id: String,
    }
    let mut out = HashSet::new();
    // One statement per `MAX_BOUND_PARAMS` users, not one per user: a room's release asks once.
    for chunk in users.chunks(crate::d1util::MAX_BOUND_PARAMS) {
        let sql = format!(
            "SELECT user_id, device_id FROM devices WHERE revoked_at IS NULL AND user_id IN ({})",
            crate::d1util::marks(chunk.len())
        );
        let binds: Vec<_> = chunk.iter().map(|u| d1_text(u)).collect();
        let rows: Vec<Row> = db.prepare(&sql).bind(&binds)?.all().await?.results()?;
        out.extend(rows.into_iter().map(|r| (r.user_id, r.device_id)));
    }
    Ok(out)
}

/// The users a held message may still go to in `conversation`: a room's active members, or — while
/// the two may still write to each other — the two of a 1:1.
pub(crate) async fn allowed_users(db: &D1Database, sender_id: &str, conversation: &Conversation<'_>) -> Result<HashSet<String>> {
    match conversation {
        Conversation::Room(group_id) => {
            #[derive(Deserialize)]
            struct Row {
                user_id: String,
            }
            let rows: Vec<Row> = db
                .prepare("SELECT user_id FROM group_members WHERE group_id = ? AND status = 'active'")
                .bind(&[d1_text(group_id)])?
                .all()
                .await?
                .results()?;
            Ok(rows.into_iter().map(|r| r.user_id).collect())
        }
        Conversation::Direct(recipient) => {
            let allowed = matches!(
                crate::contacts::direct_decision(db, sender_id, recipient).await,
                Ok(crate::contacts::DirectDecision::Allowed)
            );
            Ok(if allowed { [sender_id.to_string(), recipient.to_string()].into_iter().collect() } else { HashSet::new() })
        }
    }
}

async fn own_inbox(env: &Env, user_id: &str) -> Result<Stub> {
    env.durable_object("USER_INBOX")?.id_from_name(user_id)?.get_stub()
}

async fn post_own(env: &Env, user_id: &str, path: &str, body: String) -> Result<Response> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let req = Request::new_with_init(&format!("https://do.sezgi{path}"), &init)?;
    own_inbox(env, user_id).await?.fetch_with_request(req).await
}

/// `POST /messages/scheduled`: hand a scheduled message over.
pub async fn put(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (sender_id, token_device) = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => (auth.user_id, auth.device_id),
        Err(resp) => return Ok(resp),
    };
    // The send bucket: a schedule is a send made ahead of time.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &super::handlers::send_rate_limit_key(&sender_id), 300, 60).await {
        return json_err(429, "rate_limited");
    }
    let body: PutBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if token_device != body.sender_device_id {
        return json_err(403, "device_mismatch");
    }
    let now_ms = crate::utils::now_ms() as i64;
    let conversation = match rules::check_put(&body, &sender_id, now_ms) {
        Ok(c) => c,
        Err(r) => return refused(r),
    };
    let db = match ctx.env.d1("DB") {
        Ok(db) => db,
        Err(_) => return json_err(503, "authorization_unavailable"),
    };
    if crate::auth::middleware::device_revoked(&ctx.env, &sender_id, &body.sender_device_id).await? {
        return json_err(401, "device_revoked");
    }
    // Every target user may receive it now: a member of the room (the sender too), or the two of
    // a 1:1 that may write to each other.
    let allowed = allowed_users(&db, &sender_id, &conversation).await?;
    if !allowed.contains(&sender_id) {
        return match conversation {
            Conversation::Room(_) => json_err(403, "scheduled/not-member"),
            Conversation::Direct(_) => json_err(403, "scheduled/not-allowed"),
        };
    }
    if body.targets.iter().any(|t| !allowed.contains(&t.user_id)) {
        return json_err(400, "scheduled/bad-target");
    }
    // Every target device is one of its user's active devices: an invented id is refused whole.
    let users: Vec<&str> = body.targets.iter().map(|t| t.user_id.as_str()).collect();
    let devices = active_devices(&db, &users).await?;
    let unknown = body
        .targets
        .iter()
        .any(|t| t.device_ids.iter().any(|d| !devices.contains(&(t.user_id.clone(), d.clone()))));
    if unknown {
        return json_err(400, "scheduled/bad-target");
    }
    // The fan-out width a release will store, charged NOW against the same weighted bucket a room
    // send pays (`group_fanout.rs`): a schedule is a send made ahead, and a release whose time has
    // come (≤ `MAX_LATE_MS` past) is a send made at once (review finding 9).
    let width: usize = body.targets.iter().map(|t| t.device_ids.len()).sum();
    if !crate::ratelimit::check_rate_limit_weighted_env(&ctx.env, &rules::fanout_bucket(&sender_id), 6000, 60, width).await {
        return json_err(429, "rate_limited");
    }
    let (recipient_id, group_id) = match conversation {
        Conversation::Direct(r) => (Some(r), None),
        Conversation::Room(g) => (None, Some(g)),
    };
    let held = serde_json::json!({
        "schedule_id": body.schedule_id,
        "sender_id": sender_id,
        "sender_device_id": body.sender_device_id,
        "recipient_id": recipient_id,
        "group_id": group_id,
        "release_at": body.release_at_ms,
        "envelope_b64": body.envelope_b64,
        "targets_json": serde_json::to_string(&body.targets).unwrap_or_default(),
    })
    .to_string();
    let resp = post_own(&ctx.env, &sender_id, "/scheduled-put", held).await?;
    crate::respond::passthrough(resp).await
}

/// `DELETE /messages/scheduled/:id`: take one back. 204 also when it is no longer held.
pub async fn cancel(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, device_id) = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => (auth.user_id, auth.device_id),
        Err(resp) => return Ok(resp),
    };
    let Some(id) = ctx.param("id").cloned() else {
        return json_err(400, "bad_request");
    };
    if !rules::valid_schedule_id(&id) {
        return json_err(400, "bad_request");
    }
    if crate::auth::middleware::device_revoked(&ctx.env, &user_id, &device_id).await? {
        return json_err(401, "device_revoked");
    }
    let body = serde_json::json!({ "schedule_id": id }).to_string();
    let resp = post_own(&ctx.env, &user_id, "/scheduled-cancel", body).await?;
    crate::respond::passthrough(resp).await
}

#[cfg(test)]
mod tests {
    /// T12, guarded at source: both routes reach the CALLER's own inbox and nothing else — the
    /// object is named by the authenticated user, never by anything the body or the path says.
    #[test]
    fn cancel_reaches_only_the_callers_own_inbox() {
        const SRC: &str = include_str!("scheduled.rs");
        let production = &SRC[..SRC.find(concat!("#[cfg(", "test)]")).unwrap()];
        assert_eq!(production.matches(concat!("id_from_name", "(")).count(), 1, "one way to an inbox");
        assert!(production.contains(concat!("id_from_name", "(user_id)")));
        assert!(production.contains(concat!("post_own(&ctx.env, &sender_id, ", "\"/scheduled-put\"")));
        assert!(production.contains(concat!("post_own(&ctx.env, &user_id, ", "\"/scheduled-cancel\"")));
        assert!(!production.contains(concat!("get_async", "(")), "no route reads schedules");
    }
}
