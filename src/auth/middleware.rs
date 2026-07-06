use crate::auth::jwt::verify_access_token;
use crate::respond::json_err;
use serde::Deserialize;
use worker::{Env, Request, Response, Result};

/// Bearer token'ı header'dan al.
pub fn extract_bearer(req: &Request) -> Option<String> {
    let auth = req.headers().get("authorization").ok().flatten()?;
    // Sağlamlaştırma #15: `split_at(7)` byte-7 char-boundary DEĞİLSE (çok-baytlı UTF-8 başlık,
    // ör. "Bearé…") PANIC eder → her auth'lu route'ta DoS. Byte-prefix ile güvenli kontrol:
    // ilk 7 byte ASCII "Bearer " ise byte-7 KESİN char-boundary → `auth[7..]` panic-siz.
    let bytes = auth.as_bytes();
    if bytes.len() < 8 || !bytes[..7].eq_ignore_ascii_case(b"Bearer ") {
        return None;
    }
    Some(auth[7..].trim().to_string())
}

/// Bir cihaz İPTAL edilmiş mi (device-list'ten düşürülüp `devices.revoked_at` SET)?
/// CANLI-TOKEN yollarında (send / WS-upgrade) çağrılır → çalınan cihaz, elindeki
/// access-token TTL'i (15dk) DOLMADAN da reddedilir (refresh/relogin zaten iptal-aware;
/// bu, canlı-token gönderim/oturum yüzeyini kapatır). Event-driven: her istek/upgrade
/// BİR KEZ sorgular (polling/döngü YOK). `device_id` boş → `false` (legacy device-less
/// token; refresh/relogin ile SİMETRİK muafiyet — migration uyumu).
pub async fn device_revoked(env: &Env, user_id: &str, device_id: &str) -> Result<bool> {
    if device_id.is_empty() {
        return Ok(false);
    }
    #[derive(Deserialize)]
    struct RevRow {
        revoked_at: Option<i64>,
    }
    let db = env.d1("DB")?;
    let rev: Option<RevRow> = db
        .prepare("SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
        .bind(&[
            crate::d1util::d1_text(user_id),
            crate::d1util::d1_text(device_id),
        ])?
        .first(None)
        .await?;
    Ok(rev.and_then(|r| r.revoked_at).is_some())
}

/// Auth zorunlu. Başarıda user_id, hatada hazır Response döner.
pub fn require_auth(req: &Request, env: &Env) -> std::result::Result<String, Response> {
    let token = match extract_bearer(req) {
        Some(t) => t,
        None => return Err(json_err(401, "unauthorized").unwrap()),
    };
    match verify_access_token(env, &token) {
        Ok(uid) => Ok(uid),
        Err(_) => Err(json_err(401, "invalid_token").unwrap()),
    }
}

#[derive(Deserialize)]
struct RoleRow {
    role: String,
}

/// Auth + role∈{owner,admin} DB kontrol. owner her admin işini yapar.
pub async fn require_admin(user_id: &str, env: &Env) -> std::result::Result<(), Response> {
    match fetch_role(user_id, env).await {
        Ok(Some(role)) if role == "admin" || role == "owner" => Ok(()),
        Ok(Some(_)) => Err(json_err(403, "admin_required").unwrap()),
        Ok(None) => Err(json_err(401, "user_not_found").unwrap()),
        Err(resp) => Err(resp),
    }
}

/// Auth + role=owner DB kontrol. Rol atama gibi kurucu-only işlemler için.
pub async fn require_owner(user_id: &str, env: &Env) -> std::result::Result<(), Response> {
    match fetch_role(user_id, env).await {
        Ok(Some(role)) if role == "owner" => Ok(()),
        Ok(Some(_)) => Err(json_err(403, "owner_required").unwrap()),
        Ok(None) => Err(json_err(401, "user_not_found").unwrap()),
        Err(resp) => Err(resp),
    }
}

/// Bir kullanıcının rolünü DB'den oku. Hata durumunda hazır Response döner.
pub(crate) async fn fetch_role(
    user_id: &str,
    env: &Env,
) -> std::result::Result<Option<String>, Response> {
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return Err(json_err(500, "db").unwrap()),
    };
    let stmt = match db
        .prepare("SELECT role FROM users WHERE id = ? LIMIT 1")
        .bind(&[wasm_bindgen::JsValue::from_str(user_id)])
    {
        Ok(s) => s,
        Err(_) => return Err(json_err(500, "db_bind").unwrap()),
    };
    let row: Result<Option<RoleRow>> = stmt.first(None).await;
    match row {
        Ok(opt) => Ok(opt.map(|r| r.role)),
        Err(_) => Err(json_err(500, "db_query").unwrap()),
    }
}
