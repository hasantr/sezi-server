use crate::auth::jwt::device_id_from_token;
use crate::auth::middleware::{device_revoked, extract_bearer, require_auth};
use crate::d1util::{d1_int, d1_text};
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RegisterBody {
    fcm_token: String,
    device_id: String,
    platform: String, // "android" | "ios"
}

pub async fn register(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // SAĞLAMLAŞTIRMA (2026-06-25, Codex HIGH + denetim #10): token'daki `device_id`
    // claim'i ile body.device_id EŞLEŞMELİ → kullanıcı kendi kimliğiyle BAŞKA cihaz
    // adına push-token register edemez (cihaz kimliğine bürünme + yanlış-cihaz uyandırma).
    // Claim YOK (legacy device-less token) → eski davranış (geriye-uyum).
    let claim_dev = extract_bearer(&req)
        .and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    let body: RegisterBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.fcm_token.len() < 20
        || body.fcm_token.len() > 4096
        || body.device_id.is_empty()
        || body.device_id.len() > 128
        || (body.platform != "android" && body.platform != "ios")
    {
        return json_err(400, "bad_request");
    }
    if let Some(cd) = &claim_dev {
        if cd != &body.device_id {
            return json_err(403, "device_mismatch");
        }
    }
    // Çıkarılmış (revoked) cihaz push-token register edemez. FAIL-CLOSED (W7, 2026-07-02
    // Codex-flag): eskiden `.unwrap_or(false)` = D1 hatasında "revoked değil" varsayıp
    // register'a İZİN veriyordu (fail-OPEN) → send-yolu (`handlers.rs:167` `?`) + WS-upgrade
    // (`lib.rs:262` Err→503) fail-closed'ıyla ÇELİŞİYORDU: iptal-edilmiş cihaz D1-hata
    // penceresinde push-token kaydedip wake alabilirdi. Aynı fail-closed pariteye getir.
    match device_revoked(&ctx.env, &user_id, &body.device_id).await {
        Ok(true) => return json_err(403, "device_revoked"),
        Ok(false) => {}
        Err(_) => return json_err(503, "revoke_check_unavailable"),
    }
    let now = now_secs();
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "INSERT INTO push_tokens (user_id, device_id, fcm_token, platform, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, device_id) DO UPDATE SET
            fcm_token = excluded.fcm_token,
            platform = excluded.platform,
            last_seen_at = excluded.last_seen_at",
    )
    .bind(&[
        d1_text(&user_id),
        d1_text(&body.device_id),
        d1_text(&body.fcm_token),
        d1_text(&body.platform),
        d1_int(now as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;
    no_content()
}

#[derive(Deserialize)]
struct UnregisterBody {
    device_id: String,
}

pub async fn unregister(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let body: UnregisterBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.device_id.is_empty() || body.device_id.len() > 128 {
        return json_err(400, "bad_request");
    }
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM push_tokens WHERE user_id = ? AND device_id = ?")
        .bind(&[d1_text(&user_id), d1_text(&body.device_id)])?
        .run()
        .await?;
    no_content()
}
