use crate::auth::hashing::sha256_hex;
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{b64u_encode, now_secs, random_bytes};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
    // M2-S1 (opsiyonel): bu cihazın device_id'si. Verilmezse eski refresh
    // satırından devralınır (yoksa NULL = legacy). Eski gövde AYNEN çalışır.
    #[serde(default)]
    device_id: Option<String>,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;

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
        // M2-S1: eski satırdaki device_id (legacy satırlarda NULL).
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

    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")
        .bind(&[d1_text(&old_hash)])?
        .run()
        .await?;

    let user_id = row.user_id;
    // device_id: gövdede verildiyse onu kullan, yoksa eski satırdan devral.
    let device_id = body.device_id.or(row.device_id);
    // M2-S3.5: ÇIKARILAN cihaz /auth/refresh ile oturumu DİRİLTMESİN (relogin.rs
    // paritesi). device_id'li token + o cihaz revoke ise 401 → cihaz yeni access-token
    // alamaz → oturum access-TTL (15dk) içinde düşer. NULL device_id (legacy/birincil)
    // → ayırt edilemez → atla (birincili kilitleme). Yeni-build cihazlar device_id'li
    // token alır → bu kapı revoke'u uçtan-uca tamamlar (eski token-delete'e ek savunma).
    if let Some(dev) = device_id.as_deref() {
        #[derive(Deserialize)]
        struct RevRow {
            revoked_at: Option<i64>,
        }
        let rev: Option<RevRow> = db
            .prepare("SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
            .bind(&[d1_text(&user_id), d1_text(dev)])?
            .first(None)
            .await?;
        if rev.and_then(|r| r.revoked_at).is_some() {
            return json_err(401, "device_revoked");
        }
    }
    let access_token = sign_access_token(&ctx.env, &user_id, device_id.as_deref())?;
    let new_refresh = b64u_encode(&random_bytes(32));
    let new_hash = sha256_hex(&new_refresh);
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&new_hash),
        d1_text(&user_id),
        d1_int((now + REFRESH_TTL_SEC) as i64),
        d1_int(now as i64),
        d1_opt_text(device_id.as_deref()),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SEC,
    }))
}
