//! contacts/directory (directory listing + visibility) — SAF-TAŞIMA ile contacts/mod.rs'ten ayrıştırıldı. Paylaşılan
//! yardımcılar (active/cursor/revision/policy/contact_change_stmt) + import'lar
//! `use super::*` ile mod.rs'ten gelir. pub handler'lar mod.rs'te re-export edilir.
use super::*;

/// GET /directory — virtual, privacy-filtered stable-cursor page.
pub async fn directory(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    // Capture revision BEFORE the page. Concurrent changes may appear both in
    // the page and the next delta (safe duplicate), but can never be skipped.
    let revision = directory_revision(&db).await?;
    let mode = policy(&db).await?.directory_mode;
    if mode == "off" {
        return Response::from_json(&serde_json::json!({
            "items": [], "next_cursor": serde_json::Value::Null, "revision": revision
        }));
    }
    let limit = limit_param(&req);
    let cursor: Option<NameCursor> = decode_cursor(query_param(&req, "cursor"));
    if query_param(&req, "cursor").is_some() && cursor.is_none() {
        return json_err(400, "bad_cursor");
    }
    let (has_cursor, cursor_name, cursor_id) = cursor
        .map(|c| (1_i64, c.name, c.id))
        .unwrap_or_else(|| (0, String::new(), String::new()));
    let rows: Vec<ProfileRow> = db
        .prepare(
            "SELECT u.id AS user_id, u.display_name, u.role, u.profile_revision,
                    lower(COALESCE(u.display_name, '')) AS sort_name
               FROM users u
              WHERE u.id != ?
                AND ((? = 'all_members' AND u.directory_visibility != 'hidden')
                  OR (? = 'opt_in' AND u.directory_visibility = 'visible'))
                AND NOT EXISTS (
                  SELECT 1 FROM contact_blocks b
                   WHERE (b.blocker_user_id = ? AND b.blocked_user_id = u.id)
                      OR (b.blocker_user_id = u.id AND b.blocked_user_id = ?)
                )
                AND (? = 0 OR lower(COALESCE(u.display_name, '')) > ?
                  OR (lower(COALESCE(u.display_name, '')) = ? AND u.id > ?))
              ORDER BY lower(COALESCE(u.display_name, '')) ASC, u.id ASC
              LIMIT ?",
        )
        .bind(&[
            d1_text(&auth.user_id),
            d1_text(&mode),
            d1_text(&mode),
            d1_text(&auth.user_id),
            d1_text(&auth.user_id),
            d1_int(has_cursor),
            d1_text(&cursor_name),
            d1_text(&cursor_name),
            d1_text(&cursor_id),
            d1_int((limit + 1) as i64),
        ])?
        .all()
        .await?
        .results()?;
    let has_more = rows.len() > limit;
    let page = &rows[..rows.len().min(limit)];
    let next_cursor = if has_more {
        page.last().and_then(|r| {
            encode_cursor(&NameCursor {
                name: r.sort_name.clone(),
                id: r.user_id.clone(),
            })
        })
    } else {
        None
    };
    let items: Vec<_> = page.iter().map(profile_json).collect();
    Response::from_json(&serde_json::json!({
        "items": items, "next_cursor": next_cursor, "revision": revision
    }))
}

#[derive(Deserialize)]
struct DirectoryChangeRow {
    revision: i64,
    change_type: String,
    user_id: Option<String>,
    display_name: Option<String>,
    role: Option<String>,
    profile_revision: Option<i64>,
    effective_visible: i64,
}

/// GET /directory/changes — revision pull is authoritative; WS is optional.
pub async fn directory_changes(req: Request, ctx: RouteContext<()>) -> Result<Response> {
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
    let mode = policy(&db).await?.directory_mode;
    let rows: Vec<DirectoryChangeRow> = db
        .prepare(
            "SELECT dr.revision, dr.change_type, dr.user_id,
                    u.display_name, u.role, u.profile_revision,
                    CASE WHEN dr.change_type = 'upsert' AND u.id IS NOT NULL AND u.id != ?
                      AND ((? = 'all_members' AND u.directory_visibility != 'hidden')
                        OR (? = 'opt_in' AND u.directory_visibility = 'visible'))
                      AND NOT EXISTS (
                        SELECT 1 FROM contact_blocks b
                         WHERE (b.blocker_user_id = ? AND b.blocked_user_id = u.id)
                            OR (b.blocker_user_id = u.id AND b.blocked_user_id = ?)
                      ) THEN 1 ELSE 0 END AS effective_visible
               FROM directory_revisions dr
               LEFT JOIN users u ON u.id = dr.user_id
              WHERE dr.revision > ?
              ORDER BY dr.revision ASC LIMIT ?",
        )
        .bind(&[
            d1_text(&auth.user_id),
            d1_text(&mode),
            d1_text(&mode),
            d1_text(&auth.user_id),
            d1_text(&auth.user_id),
            d1_int(since),
            d1_int((limit + 1) as i64),
        ])?
        .all()
        .await?
        .results()?;
    let has_more = rows.len() > limit;
    let page = &rows[..rows.len().min(limit)];
    let mut changes = Vec::with_capacity(page.len());
    for r in page {
        if r.change_type == "reset" {
            changes.push(serde_json::json!({
                "revision": r.revision, "type": "reset", "user_id": serde_json::Value::Null,
                "profile": serde_json::Value::Null
            }));
        } else if r.effective_visible != 0 {
            let profile = ProfileRow {
                user_id: r.user_id.clone().unwrap_or_default(),
                display_name: r.display_name.clone(),
                role: r.role.clone().unwrap_or_else(|| "member".into()),
                profile_revision: r.profile_revision.unwrap_or(1),
                sort_name: String::new(),
            };
            changes.push(serde_json::json!({
                "revision": r.revision, "type": "upsert", "user_id": profile.user_id,
                "profile": profile_json(&profile)
            }));
        } else {
            changes.push(serde_json::json!({
                "revision": r.revision, "type": "tombstone", "user_id": r.user_id,
                "profile": serde_json::Value::Null
            }));
        }
    }
    let next_revision = page.last().map(|r| r.revision).unwrap_or(since);
    Response::from_json(&serde_json::json!({
        "changes": changes, "next_revision": next_revision, "has_more": has_more
    }))
}

#[derive(Deserialize, Default)]
struct VisibilityBody {
    visibility: String,
}

#[derive(Deserialize)]
struct VisibilityRow {
    directory_visibility: String,
    profile_revision: i64,
}

pub async fn get_visibility(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let row: Option<VisibilityRow> = db
        .prepare("SELECT directory_visibility, profile_revision FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&auth.user_id)])?
        .first(None)
        .await?;
    let Some(row) = row else {
        return json_err(401, "inactive_account");
    };
    Response::from_json(&serde_json::json!({
        "visibility": row.directory_visibility,
        "profile_revision": row.profile_revision,
        "revision": directory_revision(&db).await?,
    }))
}

pub async fn set_visibility(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match active(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let body: VisibilityBody = match req.json().await {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_request"),
    };
    if !matches!(body.visibility.as_str(), "inherit" | "visible" | "hidden") {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    let now = now_secs() as i64;
    let event_id = random_b64u(18);
    let mut stmts = vec![
        db.prepare(
            "UPDATE users
                SET directory_visibility = ?, profile_revision = profile_revision + 1
              WHERE id = ? AND directory_visibility != ?",
        )
        .bind(&[
            d1_text(&body.visibility),
            d1_text(&auth.user_id),
            d1_text(&body.visibility),
        ])?,
        db.prepare(
            "INSERT INTO directory_revisions
               (event_id, user_id, change_type, profile_revision, created_at)
             SELECT ?, id, 'upsert', profile_revision, ? FROM users WHERE id = ?",
        )
        .bind(&[d1_text(&event_id), d1_int(now), d1_text(&auth.user_id)])?,
    ];
    if body.visibility == "hidden" {
        stmts.push(
            db.prepare(
                "INSERT INTO directory_tombstones(user_id, revision, deleted_at)
                 SELECT ?, revision, ? FROM directory_revisions WHERE event_id = ?
                 ON CONFLICT(user_id) DO UPDATE SET
                   revision=excluded.revision, deleted_at=excluded.deleted_at",
            )
            .bind(&[d1_text(&auth.user_id), d1_int(now), d1_text(&event_id)])?,
        );
    } else {
        stmts.push(
            db.prepare("DELETE FROM directory_tombstones WHERE user_id = ?")
                .bind(&[d1_text(&auth.user_id)])?,
        );
    }
    db.batch(stmts).await?;
    #[derive(Deserialize)]
    struct ResultRow {
        directory_visibility: String,
        profile_revision: i64,
        revision: i64,
    }
    let row: Option<ResultRow> = db
        .prepare(
            "SELECT u.directory_visibility, u.profile_revision, dr.revision
               FROM users u JOIN directory_revisions dr ON dr.event_id = ?
              WHERE u.id = ? LIMIT 1",
        )
        .bind(&[d1_text(&event_id), d1_text(&auth.user_id)])?
        .first(None)
        .await?;
    let Some(row) = row else {
        return json_err(503, "directory_update_failed");
    };
    Response::from_json(&serde_json::json!({
        "visibility": row.directory_visibility,
        "profile_revision": row.profile_revision,
        "revision": row.revision,
    }))
}
