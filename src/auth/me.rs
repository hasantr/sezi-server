use crate::auth::middleware::require_existing_account_auth;
use crate::d1util::d1_text;
use crate::respond::json_err;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct UserRow {
    id: String,
    email: String,
    display_name: Option<String>,
    role: String,
    created_at: i64,
    last_seen_at: Option<i64>,
}

pub async fn me(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // This read-only profile fetch can race the device-list PUT during bootstrap. The
    // positive membership check still shuts out a deleted account, while a fresh
    // registration whose first device row does not exist yet is not left without its
    // cached role/name by a spurious 401.
    let user_id = match require_existing_account_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    me_response(&ctx.env, &user_id).await
}

pub(crate) async fn me_response(env: &Env, user_id: &str) -> Result<Response> {
    let db = env.d1("DB")?;
    let row: Option<UserRow> = db
        .prepare(
            "SELECT id, email, display_name, role, created_at, last_seen_at
             FROM users WHERE id = ? LIMIT 1",
        )
        .bind(&[d1_text(user_id)])?
        .first(None)
        .await?;
    let u = match row {
        Some(u) => u,
        None => return json_err(404, "not_found"),
    };
    Response::from_json(&serde_json::json!({
        "id": u.id,
        "email": u.email,
        "display_name": u.display_name,
        "role": u.role,
        "created_at": u.created_at,
        "last_seen_at": u.last_seen_at,
    }))
}
