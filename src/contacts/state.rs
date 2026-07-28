//! contacts/state (blocks + contact state/changes) — split out of contacts/mod.rs as a
//! PURE MOVE. The shared helpers (active/cursor/revision/policy/contact_change_stmt)
//! and the imports come from mod.rs through `use super::*`; the pub handlers are
//! re-exported from mod.rs.
use super::*;
use super::requests::expire_requests;

#[derive(Deserialize, Default)]
struct BlockBody {
    target_user_id: String,
}
#[derive(Deserialize)]
struct BlockRow {
    user_id: String,
    created_at: i64,
    display_name: Option<String>,
    role: String,
    profile_revision: i64,
}

pub async fn list_blocks(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let revision = contact_revision(&db, &auth.user_id).await?;
    let rows:Vec<BlockRow>=db.prepare("SELECT b.blocked_user_id AS user_id,b.created_at,u.display_name,u.role,u.profile_revision FROM contact_blocks b JOIN users u ON u.id=b.blocked_user_id WHERE b.blocker_user_id=? ORDER BY b.created_at DESC LIMIT 500")
        .bind(&[d1_text(&auth.user_id)])?.all().await?.results()?;
    let blocks:Vec<_>=rows.iter().map(|r|serde_json::json!({"user_id":r.user_id,"display_name":r.display_name,"avatar_ref":serde_json::Value::Null,"role":r.role,"profile_revision":r.profile_revision,"created_at":r.created_at})).collect();
    Response::from_json(&serde_json::json!({"blocks":blocks,"revision":revision}))
}

pub async fn block(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let body: BlockBody = match req.json().await {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_request"),
    };
    if uuid::Uuid::parse_str(&body.target_user_id).is_err() || body.target_user_id == auth.user_id {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    #[derive(Deserialize)]
    struct E {
        #[allow(dead_code)]
        n: i64,
    }
    let exists: Option<E> = db
        .prepare("SELECT 1 AS n FROM users WHERE id=? LIMIT 1")
        .bind(&[d1_text(&body.target_user_id)])?
        .first(None)
        .await?;
    if exists.is_none() {
        return json_err(404, "not_found");
    }
    let now = now_secs() as i64;
    let low = if auth.user_id < body.target_user_id {
        &auth.user_id
    } else {
        &body.target_user_id
    };
    let high = if auth.user_id < body.target_user_id {
        &body.target_user_id
    } else {
        &auth.user_id
    };
    db.batch(vec![
        db.prepare("INSERT OR IGNORE INTO contact_blocks(blocker_user_id,blocked_user_id,created_at) VALUES(?,?,?)").bind(&[d1_text(&auth.user_id),d1_text(&body.target_user_id),d1_int(now)])?,
        db.prepare("UPDATE contact_grants SET revoked_at=COALESCE(revoked_at,?),revoked_by=COALESCE(revoked_by,?) WHERE user_low=? AND user_high=?").bind(&[d1_int(now),d1_text(&auth.user_id),d1_text(low),d1_text(high)])?,
        db.prepare("UPDATE contact_requests SET status='revoked',responded_at=? WHERE status='pending' AND ((source_user_id=? AND target_user_id=?) OR (source_user_id=? AND target_user_id=?))").bind(&[d1_int(now),d1_text(&auth.user_id),d1_text(&body.target_user_id),d1_text(&body.target_user_id),d1_text(&auth.user_id)])?,
        contact_change_stmt(&db, ContactChange { event_id: &random_b64u(18), account: &auth.user_id, peer: Some(&body.target_user_id), entity: "block", entity_id: &format!("{}:{}",auth.user_id,body.target_user_id), action: "upsert", now })?,
        contact_change_stmt(&db, ContactChange { event_id: &random_b64u(18), account: &body.target_user_id, peer: Some(&auth.user_id), entity: "authorization", entity_id: &format!("{}:{}",auth.user_id,body.target_user_id), action: "upsert", now })?,
        db.prepare("INSERT INTO directory_revisions(event_id,user_id,change_type,profile_revision,created_at) SELECT ?,id,'upsert',profile_revision,? FROM users WHERE id=?")
            .bind(&[d1_text(&random_b64u(18)),d1_int(now),d1_text(&auth.user_id)])?,
        db.prepare("INSERT INTO directory_revisions(event_id,user_id,change_type,profile_revision,created_at) SELECT ?,id,'upsert',profile_revision,? FROM users WHERE id=?")
            .bind(&[d1_text(&random_b64u(18)),d1_int(now),d1_text(&body.target_user_id)])?,
    ]).await?;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &auth.user_id).await;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &body.target_user_id).await;
    Response::from_json(
        &serde_json::json!({"ok":true,"user_id":body.target_user_id,"revision":contact_revision(&db,&auth.user_id).await?}),
    )
}

pub async fn unblock(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let target = match ctx.param("user_id") {
        Some(v) => v.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;
    let entity_id = format!("{}:{}", auth.user_id, target);
    let block_event = random_b64u(18);
    db.batch(vec![
        db.prepare("DELETE FROM contact_blocks WHERE blocker_user_id=? AND blocked_user_id=?").bind(&[d1_text(&auth.user_id),d1_text(&target)])?,
        contact_change_stmt(&db, ContactChange { event_id: &block_event, account: &auth.user_id, peer: Some(&target), entity: "block", entity_id: &entity_id, action: "tombstone", now })?,
        contact_change_stmt(&db, ContactChange { event_id: &random_b64u(18), account: &target, peer: Some(&auth.user_id), entity: "authorization", entity_id: &entity_id, action: "upsert", now })?,
        db.prepare("INSERT INTO contact_tombstones(account_id,entity,entity_id,peer_id,revision,deleted_at) SELECT ?,'block',?,?,revision,? FROM contact_revisions WHERE event_id=? ON CONFLICT(account_id,entity,entity_id) DO UPDATE SET peer_id=excluded.peer_id,revision=excluded.revision,deleted_at=excluded.deleted_at")
            .bind(&[d1_text(&auth.user_id),d1_text(&entity_id),d1_text(&target),d1_int(now),d1_text(&block_event)])?,
        db.prepare("INSERT INTO directory_revisions(event_id,user_id,change_type,profile_revision,created_at) SELECT ?,id,'upsert',profile_revision,? FROM users WHERE id=?")
            .bind(&[d1_text(&random_b64u(18)),d1_int(now),d1_text(&auth.user_id)])?,
        db.prepare("INSERT INTO directory_revisions(event_id,user_id,change_type,profile_revision,created_at) SELECT ?,id,'upsert',profile_revision,? FROM users WHERE id=?")
            .bind(&[d1_text(&random_b64u(18)),d1_int(now),d1_text(&target)])?,
    ]).await?;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &auth.user_id).await;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &target).await;
    Response::from_json(
        &serde_json::json!({"ok":true,"user_id":target,"revision":contact_revision(&db,&auth.user_id).await?}),
    )
}

pub async fn contact_state(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let target = match ctx.param("user_id") {
        Some(v) => v.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    #[derive(Deserialize)]
    struct S {
        grant_id: Option<String>,
        source: Option<String>,
        trust: Option<String>,
        created_at: Option<i64>,
        blocked_by_me: i64,
        dm_policy: String,
        common_group: i64,
        target_exists: i64,
    }
    let s:Option<S>=db.prepare("SELECT EXISTS(SELECT 1 FROM users WHERE id=?1) AS target_exists,COALESCE((SELECT dm_policy FROM server_settings WHERE id=1),'members') AS dm_policy,EXISTS(SELECT 1 FROM contact_blocks WHERE blocker_user_id=?2 AND blocked_user_id=?1) AS blocked_by_me,EXISTS(SELECT 1 FROM group_members a JOIN group_members b ON b.group_id=a.group_id WHERE a.user_id=?2 AND b.user_id=?1 AND a.status='active' AND b.status='active') AS common_group,g.grant_id,g.source,g.trust,g.created_at FROM (SELECT 1) x LEFT JOIN contact_grants g ON g.user_low=CASE WHEN ?2<?1 THEN ?2 ELSE ?1 END AND g.user_high=CASE WHEN ?2<?1 THEN ?1 ELSE ?2 END AND g.revoked_at IS NULL LIMIT 1")
        .bind(&[d1_text(&target),d1_text(&auth.user_id)])?.first(None).await?;
    let Some(s) = s else {
        return json_err(404, "not_found");
    };
    if s.target_exists == 0 {
        return json_err(404, "not_found");
    }
    let grant=s.grant_id.as_ref().map(|id|serde_json::json!({"grant_id":id,"source":s.source,"trust":s.trust,"created_at":s.created_at}));
    // Inbound block is intentionally excluded from this introspection response.
    let can_message = s.blocked_by_me == 0
        && crate::contact_grant::direct_message_allowed(
            &s.dm_policy,
            s.grant_id.is_some(),
            s.common_group != 0,
        );
    Response::from_json(
        &serde_json::json!({"user_id":target,"grant":grant,"blocked":s.blocked_by_me!=0,"can_message":can_message,"authorization":"server_asserted"}),
    )
}

#[derive(Deserialize)]
struct ContactChangeRow {
    revision: i64,
    entity: String,
    entity_id: String,
    peer_id: Option<String>,
    action: String,
}
pub async fn contact_changes(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let since = query_param(&req, "since_revision")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(0);
    let limit = limit_param(&req);
    let db = ctx.env.d1("DB")?;
    expire_requests(&db, &auth.user_id, now_secs() as i64).await?;
    let rows:Vec<ContactChangeRow>=db.prepare("SELECT revision,entity,entity_id,peer_id,action FROM contact_revisions WHERE account_id=? AND revision>? ORDER BY revision ASC LIMIT ?")
        .bind(&[d1_text(&auth.user_id),d1_int(since),d1_int((limit+1)as i64)])?.all().await?.results()?;
    let has_more = rows.len() > limit;
    let page = &rows[..rows.len().min(limit)];
    let changes:Vec<_>=page.iter().map(|r|serde_json::json!({"revision":r.revision,"entity":r.entity,"entity_id":r.entity_id,"peer_id":r.peer_id,"action":r.action})).collect();
    let next_revision = page.last().map(|r| r.revision).unwrap_or(since);
    Response::from_json(
        &serde_json::json!({"changes":changes,"next_revision":next_revision,"has_more":has_more}),
    )
}
