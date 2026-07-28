//! contacts/requests (contact request create/list/respond/revoke) — split out of
//! contacts/mod.rs as a PURE MOVE. The shared helpers (active/cursor/revision/policy/
//! contact_change_stmt) and the imports come from mod.rs through `use super::*`; the
//! pub handlers are re-exported from mod.rs.
use super::*;

#[derive(Deserialize, Default)]
pub(super) struct CreateRequestBody {
    pub(super) request_id: String,
    pub(super) target_user_id: String,
    pub(super) device_id: String,
    pub(super) server_fingerprint: String,
    pub(super) issued_at: i64,
    pub(super) nonce: String,
    pub(super) signature_b64: String,
}

#[derive(Deserialize)]
struct DeviceKeyRow {
    ed_pub: Vec<u8>,
}

pub(super) fn request_transcript(source: &str, body: &CreateRequestBody) -> String {
    format!(
        "sezgi-contact-request-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        body.server_fingerprint,
        body.request_id,
        source,
        body.target_user_id,
        body.device_id,
        body.issued_at,
        body.nonce
    )
}

async fn verify_request_signature(
    db: &D1Database,
    env: &Env,
    auth: &ActiveAuth,
    body: &CreateRequestBody,
) -> std::result::Result<(), Response> {
    if auth.device_id.as_deref() != Some(body.device_id.as_str()) {
        return Err(json_err(403, "active_device_required").unwrap());
    }
    let expected = match crate::server::handlers::server_instance_fingerprint(env) {
        Ok(v) => v,
        Err(_) => return Err(json_err(503, "server_identity_unavailable").unwrap()),
    };
    if body.server_fingerprint != expected {
        return Err(json_err(403, "wrong_server").unwrap());
    }
    let now = now_secs() as i64;
    if body.issued_at < now - 300 || body.issued_at > now + 300 {
        return Err(json_err(400, "stale_proof").unwrap());
    }
    let key: Option<DeviceKeyRow> = db
        .prepare(
            "SELECT ed_pub FROM devices
              WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL LIMIT 1",
        )
        .bind(&[d1_text(&auth.user_id), d1_text(&body.device_id)])
        .map_err(|_| json_err(503, "device_check_unavailable").unwrap())?
        .first(None)
        .await
        .map_err(|_| json_err(503, "device_check_unavailable").unwrap())?;
    let Some(key) = key else {
        return Err(json_err(403, "active_device_required").unwrap());
    };
    let key_arr: [u8; 32] = key
        .ed_pub
        .as_slice()
        .try_into()
        .map_err(|_| json_err(403, "invalid_device_key").unwrap())?;
    let verifying = VerifyingKey::from_bytes(&key_arr)
        .map_err(|_| json_err(403, "invalid_device_key").unwrap())?;
    let signature = b64_decode(&body.signature_b64)
        .ok()
        .and_then(|v| <[u8; 64]>::try_from(v.as_slice()).ok())
        .map(|v| ed25519_dalek::Signature::from_bytes(&v))
        .ok_or_else(|| json_err(400, "bad_signature").unwrap())?;
    // verify_strict: aligned with the core's vodozemac verify_strict (see contact_qr.rs).
    verifying
        .verify_strict(
            request_transcript(&auth.user_id, body).as_bytes(),
            &signature,
        )
        .map_err(|_| json_err(403, "signature_invalid").unwrap())
}

#[derive(Deserialize)]
struct RequestRow {
    request_id: String,
    source_user_id: String,
    target_user_id: String,
    source_device_id: String,
    server_fingerprint: String,
    issued_at: i64,
    nonce_hash: String,
    status: String,
    trust: String,
    created_at: i64,
    expires_at: i64,
    responded_at: Option<i64>,
    grant_applied: i64,
    peer_id: String,
    display_name: Option<String>,
    role: String,
    profile_revision: i64,
}

fn request_json(row: &RequestRow, caller: &str) -> serde_json::Value {
    let peer = ProfileRow {
        user_id: row.peer_id.clone(),
        display_name: row.display_name.clone(),
        role: row.role.clone(),
        profile_revision: row.profile_revision,
        sort_name: String::new(),
    };
    serde_json::json!({
        "request_id": row.request_id,
        "direction": if row.source_user_id == caller { "outgoing" } else { "incoming" },
        "peer": profile_json(&peer),
        "status": row.status,
        "trust": row.trust,
        "created_at": row.created_at,
        "expires_at": row.expires_at,
        "responded_at": row.responded_at,
    })
}

pub(super) async fn expire_requests(db: &D1Database, account: &str, now: i64) -> Result<()> {
    #[derive(Deserialize)]
    struct ExpiredRow {
        request_id: String,
        source_user_id: String,
        target_user_id: String,
    }
    let rows: Vec<ExpiredRow> = db
        .prepare(
            "SELECT request_id, source_user_id, target_user_id FROM contact_requests
              WHERE status = 'pending' AND expires_at <= ?
                AND (source_user_id = ? OR target_user_id = ?)
              ORDER BY expires_at ASC LIMIT 100",
        )
        .bind(&[d1_int(now), d1_text(account), d1_text(account)])?
        .all()
        .await?
        .results()?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmts = Vec::with_capacity(rows.len() * 3);
    for row in rows {
        stmts.push(
            db.prepare(
                "UPDATE contact_requests SET status='expired', responded_at=?
                  WHERE request_id=? AND status='pending' AND expires_at<=?",
            )
            .bind(&[d1_int(now), d1_text(&row.request_id), d1_int(now)])?,
        );
        for (owner, peer) in [
            (&row.source_user_id, &row.target_user_id),
            (&row.target_user_id, &row.source_user_id),
        ] {
            stmts.push(
                db.prepare(
                    "INSERT INTO contact_revisions
                       (event_id, account_id, peer_id, entity, entity_id, action, created_at)
                     SELECT ?, ?, ?, 'request', request_id, 'upsert', ?
                       FROM contact_requests WHERE request_id=? AND status='expired'",
                )
                .bind(&[
                    d1_text(&random_b64u(18)),
                    d1_text(owner),
                    d1_text(peer),
                    d1_int(now),
                    d1_text(&row.request_id),
                ])?,
            );
        }
    }
    db.batch(stmts).await?;
    Ok(())
}

async fn fetch_request(
    db: &D1Database,
    request_id: &str,
    caller: &str,
) -> Result<Option<RequestRow>> {
    db.prepare(
        "SELECT r.request_id, r.source_user_id, r.target_user_id, r.source_device_id,
                r.server_fingerprint, r.issued_at, r.nonce_hash, r.status, r.trust,
                r.created_at, r.expires_at, r.responded_at, r.grant_applied,
                CASE WHEN r.source_user_id = ? THEN r.target_user_id ELSE r.source_user_id END AS peer_id,
                u.display_name, u.role, u.profile_revision
           FROM contact_requests r
           JOIN users u ON u.id = CASE WHEN r.source_user_id = ? THEN r.target_user_id ELSE r.source_user_id END
          WHERE r.request_id = ? AND (r.source_user_id = ? OR r.target_user_id = ?) LIMIT 1",
    )
    .bind(&[
        d1_text(caller), d1_text(caller), d1_text(request_id), d1_text(caller), d1_text(caller),
    ])?
    .first(None)
    .await
}

pub async fn create_request(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let body: CreateRequestBody = match req.json().await {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_request"),
    };
    if uuid::Uuid::parse_str(&body.request_id).is_err()
        || uuid::Uuid::parse_str(&body.target_user_id).is_err()
        || body.target_user_id == auth.user_id
        || body.device_id.is_empty()
        || body.device_id.len() > 64
        || !(16..=128).contains(&body.nonce.len())
        || body.signature_b64.len() > 256
    {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    expire_requests(&db, &auth.user_id, now_secs() as i64).await?;
    // Idempotent replay is checked before freshness: a transport retry of an
    // already committed signed request remains successful after the 5m window.
    if let Some(existing) = fetch_request(&db, &body.request_id, &auth.user_id).await? {
        let same = existing.source_user_id == auth.user_id
            && existing.target_user_id == body.target_user_id
            && existing.source_device_id == body.device_id
            && existing.server_fingerprint == body.server_fingerprint
            && existing.issued_at == body.issued_at
            && existing.nonce_hash == sha256_hex(&body.nonce);
        if !same {
            return json_err(409, "request_id_conflict");
        }
        return Response::from_json(&request_json(&existing, &auth.user_id));
    }
    if let Err(resp) = verify_request_signature(&db, &ctx.env, &auth, &body).await {
        return Ok(resp);
    }
    let pol = policy(&db).await?;
    if pol.dm_policy == "contacts_only" {
        return json_err(403, "contact_requests_disabled");
    }
    // Directory privacy is authoritative for unsolicited discovery. A hidden
    // target can still be reached through an already active common group.
    #[derive(Deserialize)]
    struct TargetGate {
        exists_user: i64,
        visible: i64,
        common_group: i64,
        blocked: i64,
        granted: i64,
    }
    let gate: Option<TargetGate> = db
        .prepare(
            "SELECT
               EXISTS(SELECT 1 FROM users WHERE id = ?) AS exists_user,
               EXISTS(SELECT 1 FROM users u WHERE u.id = ? AND
                 ((? = 'all_members' AND u.directory_visibility != 'hidden') OR
                  (? = 'opt_in' AND u.directory_visibility = 'visible'))) AS visible,
               EXISTS(SELECT 1 FROM group_members a JOIN group_members b ON b.group_id = a.group_id
                 WHERE a.user_id = ? AND b.user_id = ? AND a.status='active' AND b.status='active') AS common_group,
               EXISTS(SELECT 1 FROM contact_blocks b WHERE
                 (b.blocker_user_id = ? AND b.blocked_user_id = ?) OR
                 (b.blocker_user_id = ? AND b.blocked_user_id = ?)) AS blocked,
               EXISTS(SELECT 1 FROM contact_grants g WHERE
                 g.user_low = CASE WHEN ? < ? THEN ? ELSE ? END AND
                 g.user_high = CASE WHEN ? < ? THEN ? ELSE ? END AND
                 g.revoked_at IS NULL) AS granted",
        )
        .bind(&[
            d1_text(&body.target_user_id),
            d1_text(&body.target_user_id),
            d1_text(&pol.directory_mode),
            d1_text(&pol.directory_mode),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&auth.user_id),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&body.target_user_id),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&body.target_user_id),
            d1_text(&auth.user_id),
        ])?
        .first(None)
        .await?;
    let Some(gate) = gate else {
        return json_err(404, "not_found");
    };
    if gate.exists_user == 0 {
        return json_err(404, "not_found");
    }
    if gate.blocked != 0 || (gate.visible == 0 && gate.common_group == 0) {
        return json_err(403, "contact_not_authorized");
    }
    if gate.granted != 0 {
        return json_err(409, "already_contact");
    }
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("contact:request:{}", auth.user_id),
        12,
        3600,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let now = now_secs() as i64;
    let source_event = random_b64u(18);
    let target_event = random_b64u(18);
    let nonce_hash = sha256_hex(&body.nonce);
    // Request row and both account revision rows commit atomically. Conditional
    // SELECTs mean a conflicting request_id/pair cannot emit a false change;
    // a concurrent identical retry may only emit a harmless duplicate nudge.
    db.batch(vec![
        db.prepare(
            "INSERT OR IGNORE INTO contact_requests
               (request_id, source_user_id, target_user_id, source_device_id,
                server_fingerprint, issued_at, nonce_hash, signature_b64, status,
                trust, created_at, expires_at, responded_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'server_asserted', ?, ?, NULL)
            ",
        )
        .bind(&[
            d1_text(&body.request_id),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&body.device_id),
            d1_text(&body.server_fingerprint),
            d1_int(body.issued_at),
            d1_text(&nonce_hash),
            d1_text(&body.signature_b64),
            d1_int(now),
            d1_int(now + REQUEST_TTL_SEC),
        ])?,
        db.prepare(
            "INSERT INTO contact_revisions
               (event_id,account_id,peer_id,entity,entity_id,action,created_at)
             SELECT ?,source_user_id,target_user_id,'request',request_id,'upsert',?
               FROM contact_requests
              WHERE request_id=? AND source_user_id=? AND target_user_id=?
                AND source_device_id=? AND server_fingerprint=? AND issued_at=? AND nonce_hash=?",
        )
        .bind(&[
            d1_text(&source_event),
            d1_int(now),
            d1_text(&body.request_id),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&body.device_id),
            d1_text(&body.server_fingerprint),
            d1_int(body.issued_at),
            d1_text(&nonce_hash),
        ])?,
        db.prepare(
            "INSERT INTO contact_revisions
               (event_id,account_id,peer_id,entity,entity_id,action,created_at)
             SELECT ?,target_user_id,source_user_id,'request',request_id,'upsert',?
               FROM contact_requests
              WHERE request_id=? AND source_user_id=? AND target_user_id=?
                AND source_device_id=? AND server_fingerprint=? AND issued_at=? AND nonce_hash=?",
        )
        .bind(&[
            d1_text(&target_event),
            d1_int(now),
            d1_text(&body.request_id),
            d1_text(&auth.user_id),
            d1_text(&body.target_user_id),
            d1_text(&body.device_id),
            d1_text(&body.server_fingerprint),
            d1_int(body.issued_at),
            d1_text(&nonce_hash),
        ])?,
    ])
    .await?;
    let Some(row) = fetch_request(&db, &body.request_id, &auth.user_id).await? else {
        return json_err(409, "request_pending");
    };
    let same = row.source_user_id == auth.user_id
        && row.target_user_id == body.target_user_id
        && row.source_device_id == body.device_id
        && row.server_fingerprint == body.server_fingerprint
        && row.issued_at == body.issued_at
        && row.nonce_hash == nonce_hash;
    if !same {
        return json_err(409, "request_id_conflict");
    }
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &row.source_user_id).await;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &row.target_user_id).await;
    Response::from_json(&request_json(&row, &auth.user_id))
}

pub async fn list_requests(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;
    expire_requests(&db, &auth.user_id, now).await?;
    let limit = limit_param(&req);
    let scope = query_param(&req, "scope").unwrap_or_else(|| "all".into());
    if !matches!(scope.as_str(), "all" | "incoming" | "outgoing") {
        return json_err(400, "bad_scope");
    }
    let status = query_param(&req, "status").unwrap_or_default();
    if !status.is_empty()
        && !matches!(
            status.as_str(),
            "pending" | "accepted" | "declined" | "expired" | "revoked"
        )
    {
        return json_err(400, "bad_status");
    }
    let cursor: Option<TimeCursor> = decode_cursor(query_param(&req, "cursor"));
    if query_param(&req, "cursor").is_some() && cursor.is_none() {
        return json_err(400, "bad_cursor");
    }
    let (has_cursor, cursor_time, cursor_id) = cursor
        .map(|c| (1_i64, c.created_at, c.id))
        .unwrap_or((0, i64::MAX, String::new()));
    let rows: Vec<RequestRow> = db
        .prepare(
            "SELECT r.request_id, r.source_user_id, r.target_user_id, r.source_device_id,
                    r.server_fingerprint, r.issued_at, r.nonce_hash, r.status, r.trust,
                    r.created_at, r.expires_at, r.responded_at, r.grant_applied,
                    CASE WHEN r.source_user_id = ? THEN r.target_user_id ELSE r.source_user_id END AS peer_id,
                    u.display_name, u.role, u.profile_revision
               FROM contact_requests r
               JOIN users u ON u.id = CASE WHEN r.source_user_id = ? THEN r.target_user_id ELSE r.source_user_id END
              WHERE (r.source_user_id = ? OR r.target_user_id = ?)
                AND (? = 'all' OR (? = 'incoming' AND r.target_user_id = ?)
                  OR (? = 'outgoing' AND r.source_user_id = ?))
                AND (? = '' OR r.status = ?)
                AND (? = 0 OR r.created_at < ? OR (r.created_at = ? AND r.request_id < ?))
              ORDER BY r.created_at DESC, r.request_id DESC LIMIT ?",
        )
        .bind(&[
            d1_text(&auth.user_id), d1_text(&auth.user_id),
            d1_text(&auth.user_id), d1_text(&auth.user_id),
            d1_text(&scope), d1_text(&scope), d1_text(&auth.user_id),
            d1_text(&scope), d1_text(&auth.user_id),
            d1_text(&status), d1_text(&status),
            d1_int(has_cursor), d1_int(cursor_time), d1_int(cursor_time), d1_text(&cursor_id),
            d1_int((limit + 1) as i64),
        ])?
        .all().await?.results()?;
    let has_more = rows.len() > limit;
    let page = &rows[..rows.len().min(limit)];
    let next_cursor = if has_more {
        page.last().and_then(|r| {
            encode_cursor(&TimeCursor {
                created_at: r.created_at,
                id: r.request_id.clone(),
            })
        })
    } else {
        None
    };
    let requests: Vec<_> = page
        .iter()
        .map(|r| request_json(r, &auth.user_id))
        .collect();
    Response::from_json(&serde_json::json!({ "requests": requests, "next_cursor": next_cursor }))
}

#[derive(Deserialize, Default)]
struct RespondBody {
    action: String,
}

pub async fn respond_request(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let request_id = match ctx.param("id") {
        Some(v) => v.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: RespondBody = match req.json().await {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_request"),
    };
    if !matches!(body.action.as_str(), "accept" | "decline") {
        return json_err(400, "bad_request");
    }
    let status = if body.action == "accept" {
        "accepted"
    } else {
        "declined"
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;
    expire_requests(&db, &auth.user_id, now).await?;
    let source_event = random_b64u(18);
    let target_event = random_b64u(18);
    let mut stmts = vec![db
        .prepare(
            "UPDATE contact_requests SET status = ?, responded_at = ?
              WHERE request_id = ? AND target_user_id = ? AND status = 'pending' AND expires_at > ?
                AND NOT EXISTS (SELECT 1 FROM contact_blocks b WHERE
                  (b.blocker_user_id = source_user_id AND b.blocked_user_id = target_user_id) OR
                  (b.blocker_user_id = target_user_id AND b.blocked_user_id = source_user_id))",
        )
        .bind(&[
            d1_text(status),
            d1_int(now),
            d1_text(&request_id),
            d1_text(&auth.user_id),
            d1_int(now),
        ])?];
    if status == "accepted" {
        stmts.push(db.prepare(APPLY_ACCEPTED_GRANT_SQL).bind(&[
            d1_int(now),
            d1_text(&request_id),
            d1_text(&auth.user_id),
        ])?);
        // Same implicit D1 transaction as the CAS and grant INSERT. Once this
        // marker flips, later accept retries cannot reopen a grant revoked by
        // either account.
        stmts.push(
            db.prepare(MARK_GRANT_APPLIED_SQL)
                .bind(&[d1_text(&request_id), d1_text(&auth.user_id)])?,
        );
        stmts.push(db.prepare(
            "INSERT INTO contact_revisions
               (event_id, account_id, peer_id, entity, entity_id, action, created_at)
             SELECT ?, source_user_id, target_user_id, 'grant', 'request:' || request_id, 'upsert', ?
               FROM contact_requests WHERE request_id = ? AND target_user_id = ?
                 AND status = 'accepted' AND grant_applied = 1",
        ).bind(&[d1_text(&random_b64u(18)), d1_int(now), d1_text(&request_id), d1_text(&auth.user_id)])?);
        stmts.push(db.prepare(
            "INSERT INTO contact_revisions
               (event_id, account_id, peer_id, entity, entity_id, action, created_at)
             SELECT ?, target_user_id, source_user_id, 'grant', 'request:' || request_id, 'upsert', ?
               FROM contact_requests WHERE request_id = ? AND target_user_id = ?
                 AND status = 'accepted' AND grant_applied = 1",
        ).bind(&[d1_text(&random_b64u(18)), d1_int(now), d1_text(&request_id), d1_text(&auth.user_id)])?);
    }
    // Conditional revision rows: a wrong source or terminal-state conflict does
    // not emit a misleading event. Idempotent retries may emit a harmless nudge.
    stmts.push(db.prepare(
        "INSERT INTO contact_revisions (event_id, account_id, peer_id, entity, entity_id, action, created_at)
         SELECT ?, source_user_id, target_user_id, 'request', request_id, 'upsert', ?
           FROM contact_requests WHERE request_id = ? AND target_user_id = ? AND status = ?",
    ).bind(&[d1_text(&source_event), d1_int(now), d1_text(&request_id), d1_text(&auth.user_id), d1_text(status)])?);
    stmts.push(db.prepare(
        "INSERT INTO contact_revisions (event_id, account_id, peer_id, entity, entity_id, action, created_at)
         SELECT ?, target_user_id, source_user_id, 'request', request_id, 'upsert', ?
           FROM contact_requests WHERE request_id = ? AND target_user_id = ? AND status = ?",
    ).bind(&[d1_text(&target_event), d1_int(now), d1_text(&request_id), d1_text(&auth.user_id), d1_text(status)])?);
    db.batch(stmts).await?;
    let Some(row) = fetch_request(&db, &request_id, &auth.user_id).await? else {
        return json_err(404, "not_found");
    };
    if row.target_user_id != auth.user_id {
        return json_err(403, "forbidden");
    }
    if row.status != status {
        return json_err(409, "request_state_conflict");
    }
    if status == "accepted" && row.grant_applied == 0 {
        return json_err(409, "request_state_conflict");
    }
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &row.source_user_id).await;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &row.target_user_id).await;
    Response::from_json(&request_json(&row, &auth.user_id))
}

pub async fn revoke_request(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let request_id = match ctx.param("id") {
        Some(v) => v.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;
    db.batch(vec![
        db.prepare("UPDATE contact_requests SET status='revoked', responded_at=? WHERE request_id=? AND source_user_id=? AND status='pending'")
            .bind(&[d1_int(now), d1_text(&request_id), d1_text(&auth.user_id)])?,
        db.prepare("INSERT INTO contact_revisions (event_id,account_id,peer_id,entity,entity_id,action,created_at) SELECT ?,source_user_id,target_user_id,'request',request_id,'upsert',? FROM contact_requests WHERE request_id=? AND source_user_id=? AND status='revoked'")
            .bind(&[d1_text(&random_b64u(18)),d1_int(now),d1_text(&request_id),d1_text(&auth.user_id)])?,
        db.prepare("INSERT INTO contact_revisions (event_id,account_id,peer_id,entity,entity_id,action,created_at) SELECT ?,target_user_id,source_user_id,'request',request_id,'upsert',? FROM contact_requests WHERE request_id=? AND source_user_id=? AND status='revoked'")
            .bind(&[d1_text(&random_b64u(18)),d1_int(now),d1_text(&request_id),d1_text(&auth.user_id)])?,
    ]).await?;
    let Some(row) = fetch_request(&db, &request_id, &auth.user_id).await? else {
        return json_err(404, "not_found");
    };
    if row.source_user_id != auth.user_id {
        return json_err(403, "forbidden");
    }
    if row.status != "revoked" {
        return json_err(409, "request_state_conflict");
    }
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &row.source_user_id).await;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &row.target_user_id).await;
    Response::from_json(&request_json(&row, &auth.user_id))
}
