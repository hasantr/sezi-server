//! `GET /plugin-policy` (üye) + `POST /admin/plugin-policy` (admin/owner) —
//! server-çapı eklenti kullanılabilirlik politikası.
//!
//! MODEL: DEFAULT herkes ENABLED. `server_plugin_policy` (0027) tablosunda YALNIZ
//! DISABLED eklentiler satır tutar (satır varlığı = disabled). Boş tablo = hepsi açık.
//!
//! - **GET /plugin-policy** — auth: `require_auth` (HERHANGİ aktif üye; admin DEĞİL).
//!   Her client, eklenti-picker'ını filtrelemek için okur. Dönüş: `{"disabled":[...]}`.
//! - **POST /admin/plugin-policy** — auth: `require_admin` (admin|owner). Body:
//!   `{"plugin_id":"...","disabled":true|false}`. true → INSERT OR REPLACE (disable);
//!   false → DELETE (enable). Dönüş: `{"ok":true,"disabled":[...]}` (güncel liste).
//!
//! Emsal: cf_config/fcm_config admin self-service deseni + stats.rs require_admin GET;
//! plugin_epoch_floor'un "tablo yok → fail-open" okuma disiplini.

use crate::auth::middleware::{require_admin, require_auth};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// Güncel DISABLED plugin_id listesini oku (deterministik alfabetik sıra → stabil
/// wire + test). Tablo YOKSA (migration henüz uygulanmadı) / D1 hatası → boş liste
/// (fail-open; plugin_log::epoch_floor deseni) — picker "hepsi açık" görür.
async fn read_disabled(db: &D1Database) -> Vec<String> {
    #[derive(Deserialize)]
    struct Row {
        plugin_id: String,
    }
    let rows = db
        .prepare("SELECT plugin_id FROM server_plugin_policy ORDER BY plugin_id ASC")
        .all()
        .await
        .and_then(|r| r.results::<Row>());
    match rows {
        Ok(rows) => rows.into_iter().map(|r| r.plugin_id).collect(),
        Err(_) => Vec::new(),
    }
}

/// `GET /plugin-policy` — aktif üye okur (client picker filtreleme). Admin DEĞİL:
/// her üye kendi picker'ını gizlemek için görmeli. Rate 600/5dk (media-download eş).
pub async fn get_plugin_policy(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // KV binding OPSİYONEL (şablon-diyeti): yoksa limitsiz devam — bkz. ratelimit.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plugpol:get:{user_id}"), 600, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    let db = ctx.env.d1("DB")?;
    let disabled = read_disabled(&db).await;
    Response::from_json(&serde_json::json!({ "disabled": disabled }))
}

#[derive(Deserialize, Default)]
struct PolicyBody {
    plugin_id: Option<String>,
    disabled: Option<bool>,
}

/// plugin_id doğrulaması: boş-değil, ≤128 char, [A-Za-z0-9._-] (slug / ters-DNS id).
/// Sıkı charset = SQL/log-enjeksiyon + kontrol-karakteri DoS koruması (cf_config
/// field_ok sınıfı; PRIMARY KEY olduğu için ekstra sıkı).
fn plugin_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// `POST /admin/plugin-policy` — admin|owner bir eklentiyi server-çapı disable/enable.
pub async fn set_plugin_policy(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // require_admin — owner DAHİL (owner her admin işini yapar; middleware ile tutarlı).
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: PolicyBody = req.json().await.unwrap_or_default();
    let plugin_id = match body.plugin_id.as_deref().map(str::trim) {
        Some(p) if plugin_id_ok(p) => p.to_string(),
        _ => return json_err(400, "bad_request"),
    };
    let Some(disabled) = body.disabled else {
        return json_err(400, "bad_request");
    };

    let db = ctx.env.d1("DB")?;
    if disabled {
        // Satır varlığı = disabled. INSERT OR REPLACE → idempotent (tekrar-disable
        // yalnız disabled_at damgasını tazeler).
        db.prepare(
            "INSERT OR REPLACE INTO server_plugin_policy (plugin_id, disabled_at) VALUES (?, ?)",
        )
        .bind(&[d1_text(&plugin_id), d1_int(now_secs() as i64)])?
        .run()
        .await?;
    } else {
        // enable = satırı KALDIR (default'a dön). Yok-satır DELETE = no-op (idempotent).
        db.prepare("DELETE FROM server_plugin_policy WHERE plugin_id = ?")
            .bind(&[d1_text(&plugin_id)])?
            .run()
            .await?;
    }

    // Güncel liste ile yanıtla → client tek round-trip'te state'i tazeler.
    let disabled_list = read_disabled(&db).await;
    Response::from_json(&serde_json::json!({ "ok": true, "disabled": disabled_list }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_id_dogrulama() {
        // Geçerli: slug, ters-DNS, tire/altçizgi/nokta, tam-128.
        assert!(plugin_id_ok("echo"));
        assert!(plugin_id_ok("com.sezi.arena"));
        assert!(plugin_id_ok("my-plugin_2"));
        assert!(plugin_id_ok(&"a".repeat(128)));
        // Boş → red.
        assert!(!plugin_id_ok(""));
        // 128 üstü → red (DoS/PRIMARY-KEY şişme koruması).
        assert!(!plugin_id_ok(&"a".repeat(129)));
        // Yasak karakter (boşluk/enjeksiyon/kontrol/unicode/path) → red.
        assert!(!plugin_id_ok("bad id"));
        assert!(!plugin_id_ok("drop;table"));
        assert!(!plugin_id_ok("a\nb"));
        assert!(!plugin_id_ok("emoji😀"));
        assert!(!plugin_id_ok("path/traversal"));
    }
}
