//! The SFU's configuration — the TURN way (`turn.rs`): per key, env FIRST, D1 `server_config`
//! second, so an owner who prefers secrets keeps them out of the app and one without a shell
//! pastes them into it (`PATCH /admin/sfu-config`).
//!
//! WRITE-ONLY for the token: it can open sessions on the owner's Cloudflare account and so spend
//! its budget; nothing reads it back out. It cannot read media — every frame is sealed by the
//! members (docs/F3_GROUP_SFU.md).

use super::policy::{OwnerRoute, DEFAULT_CAP_GB};
use serde::Deserialize;
use worker::*;

pub const KEY_APP_ID: &str = "sfu_app_id";
pub const KEY_APP_TOKEN: &str = "sfu_app_token";
pub const KEY_ROUTE: &str = "sfu_route";
pub const KEY_CAP_GB: &str = "sfu_cap_gb";

fn normalize(v: String) -> Option<String> {
    let t = v.trim();
    (!t.is_empty()).then(|| t.to_string())
}

pub(crate) async fn read(db: &D1Database, key: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Row {
        value: String,
    }
    let row: Option<Row> = db
        .prepare("SELECT value FROM server_config WHERE key = ? LIMIT 1")
        .bind(&[crate::d1util::d1_text(key)])
        .ok()?
        .first(None)
        .await
        .ok()?;
    normalize(row?.value)
}

async fn env_or_db(env: &Env, db: &D1Database, env_key: &str, db_key: &str) -> Option<String> {
    if let Some(v) = crate::utils::env_text(env, env_key).and_then(normalize) {
        return Some(v);
    }
    read(db, db_key).await
}

/// The CF Realtime SFU app: `(app id, token)`, or None while either half is missing.
pub async fn app(env: &Env, db: &D1Database) -> Option<(String, String)> {
    let id = env_or_db(env, db, "SFU_APP_ID", KEY_APP_ID).await?;
    let token = env_or_db(env, db, "SFU_APP_TOKEN", KEY_APP_TOKEN).await?;
    Some((id, token))
}

pub async fn route(env: &Env, db: &D1Database) -> OwnerRoute {
    OwnerRoute::parse(env_or_db(env, db, "SFU_ROUTE", KEY_ROUTE).await.as_deref())
}

/// The monthly cap in GB; `0` = no cap. Unset or unreadable → [`DEFAULT_CAP_GB`].
pub async fn cap_gb(env: &Env, db: &D1Database) -> i64 {
    env_or_db(env, db, "SFU_CAP_GB", KEY_CAP_GB)
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(DEFAULT_CAP_GB)
}

/// Whether an app is configured — `/admin/stats` and the PATCH answer. Fails to false.
pub async fn is_configured(env: &Env) -> bool {
    match env.d1("DB") {
        Ok(db) => app(env, &db).await.is_some(),
        Err(_) => false,
    }
}
