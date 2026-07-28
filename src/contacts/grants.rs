//! contacts/grants (grant list/revoke) — split out of contacts/mod.rs as a PURE MOVE.
//! The shared helpers (active/cursor/revision/policy/contact_change_stmt) and the
//! imports come from mod.rs through `use super::*`; the pub handlers are re-exported
//! from mod.rs.
use super::*;

#[derive(Deserialize)]
struct GrantRow {
    grant_id: String,
    peer_id: String,
    source: String,
    trust: String,
    created_at: i64,
    display_name: Option<String>,
    role: String,
    profile_revision: i64,
}

fn grant_json(r: &GrantRow) -> serde_json::Value {
    let p = ProfileRow {
        user_id: r.peer_id.clone(),
        display_name: r.display_name.clone(),
        role: r.role.clone(),
        profile_revision: r.profile_revision,
        sort_name: String::new(),
    };
    serde_json::json!({"grant_id":r.grant_id,"peer":profile_json(&p),"source":r.source,"trust":r.trust,"created_at":r.created_at})
}

pub async fn list_grants(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let revision = contact_revision(&db, &auth.user_id).await?;
    let rows:Vec<GrantRow>=db.prepare(
        "SELECT g.grant_id, CASE WHEN g.user_low=? THEN g.user_high ELSE g.user_low END AS peer_id,
                g.source,g.trust,g.created_at,u.display_name,u.role,u.profile_revision
           FROM contact_grants g JOIN users u ON u.id=CASE WHEN g.user_low=? THEN g.user_high ELSE g.user_low END
          WHERE (g.user_low=? OR g.user_high=?) AND g.revoked_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM contact_blocks b WHERE
              (b.blocker_user_id=g.user_low AND b.blocked_user_id=g.user_high) OR
              (b.blocker_user_id=g.user_high AND b.blocked_user_id=g.user_low))
          ORDER BY lower(COALESCE(u.display_name,'')),u.id LIMIT 500"
    ).bind(&[d1_text(&auth.user_id),d1_text(&auth.user_id),d1_text(&auth.user_id),d1_text(&auth.user_id)])?.all().await?.results()?;
    let grants: Vec<_> = rows.iter().map(grant_json).collect();
    Response::from_json(&serde_json::json!({"grants":grants,"revision":revision}))
}

pub async fn revoke_grant(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let grant_id = match ctx.param("id") {
        Some(v) => v.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;
    #[derive(Deserialize)]
    struct G {
        user_low: String,
        user_high: String,
        revoked_at: Option<i64>,
    }
    let g:Option<G>=db.prepare("SELECT user_low,user_high,revoked_at FROM contact_grants WHERE grant_id=? AND (user_low=? OR user_high=?) LIMIT 1")
        .bind(&[d1_text(&grant_id),d1_text(&auth.user_id),d1_text(&auth.user_id)])?.first(None).await?;
    let Some(g) = g else {
        return json_err(404, "not_found");
    };
    let peer = if g.user_low == auth.user_id {
        &g.user_high
    } else {
        &g.user_low
    };
    if g.revoked_at.is_none() {
        let low_event = random_b64u(18);
        let high_event = random_b64u(18);
        db.batch(vec![
            db.prepare("UPDATE contact_grants SET revoked_at=?,revoked_by=? WHERE grant_id=? AND revoked_at IS NULL")
                .bind(&[d1_int(now),d1_text(&auth.user_id),d1_text(&grant_id)])?,
            contact_change_stmt(&db, ContactChange { event_id: &low_event, account: &g.user_low, peer: Some(&g.user_high), entity: "grant", entity_id: &grant_id, action: "tombstone", now })?,
            contact_change_stmt(&db, ContactChange { event_id: &high_event, account: &g.user_high, peer: Some(&g.user_low), entity: "grant", entity_id: &grant_id, action: "tombstone", now })?,
            db.prepare("INSERT INTO contact_tombstones(account_id,entity,entity_id,peer_id,revision,deleted_at) SELECT ?, 'grant', ?, ?, revision, ? FROM contact_revisions WHERE event_id=? ON CONFLICT(account_id,entity,entity_id) DO UPDATE SET peer_id=excluded.peer_id,revision=excluded.revision,deleted_at=excluded.deleted_at")
                .bind(&[d1_text(&g.user_low),d1_text(&grant_id),d1_text(&g.user_high),d1_int(now),d1_text(&low_event)])?,
            db.prepare("INSERT INTO contact_tombstones(account_id,entity,entity_id,peer_id,revision,deleted_at) SELECT ?, 'grant', ?, ?, revision, ? FROM contact_revisions WHERE event_id=? ON CONFLICT(account_id,entity,entity_id) DO UPDATE SET peer_id=excluded.peer_id,revision=excluded.revision,deleted_at=excluded.deleted_at")
                .bind(&[d1_text(&g.user_high),d1_text(&grant_id),d1_text(&g.user_low),d1_int(now),d1_text(&high_event)])?,
        ]).await?;
    }
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &g.user_low).await;
    crate::realtime::nudge_contact_update_best_effort(&ctx.env, &g.user_high).await;
    Response::from_json(&serde_json::json!({"ok":true,"grant_id":grant_id,"peer_id":peer}))
}
