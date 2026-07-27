//! Backend health monitoring (Faz 3, plan e) — two channels:
//!   1. **Scheduled probe:** the daily maintenance run (`maintenance::run_daily`) calls
//!      `probe_all`, which runs `probe()` (PUT+GET+DELETE on `probe/<uuid>`) against EVERY backend
//!      with `state!='disabled'` and records `last_health_*`. The owner can also trigger it by
//!      hand: `POST /admin/storage/:id/probe` (admin/storage.rs, sharing `write_health`).
//!   2. **Opportunistic marking:** when real traffic gets an `Err` out of put/get, router.rs calls
//!      `write_health(false)` (best-effort, truncated to 120 chars, secret-free) → the panel turns
//!      red without waiting for the cron.
//!
//! `write_health` is the ONE choke-point: the probe endpoint, the router's opportunistic mark, the
//! daily probe and cleanup's aggregated mark all write through it → health-write behaviour cannot
//! diverge.

use serde::Deserialize;
use worker::*;

use super::build_store;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::utils::now_secs;

/// Best-effort write of `last_health_at/ok/err` (shared by the probe and the opportunistic mark).
/// Errors are swallowed: a health write never breaks a real op (upload/download/maintenance).
pub async fn write_health(env: &Env, store_id: &str, ok: bool, err: Option<&str>) {
    let Ok(db) = env.d1("DB") else {
        return;
    };
    let now = now_secs() as i64;
    if let Ok(stmt) = db
        .prepare(
            "UPDATE storage_backends SET last_health_at=?, last_health_ok=?, \
             last_health_err=?, updated_at=? WHERE store_id=?",
        )
        .bind(&[
            d1_int(now),
            d1_int(ok as i64),
            d1_opt_text(err),
            d1_int(now),
            d1_text(store_id),
        ])
    {
        let _ = stmt.run().await;
    }
}

/// The daily scheduled probe (plan e, channel 1): read every backend with `state!='disabled'`
/// from D1, run a live `probe()` against each (3 subrequests per backend) and record
/// `last_health_*`. A build_store failure (Lite without the binding / an s3 config that fails to
/// parse) is marked unhealthy too, since a get for a blob on that backend will 503 (plan f#9).
/// There are only ever a handful of backends, so this is cheap for the daily run. Failures do NOT
/// break the rest of maintenance (run_daily logs and continues).
pub async fn probe_all(env: &Env) -> Result<()> {
    #[derive(Deserialize)]
    struct Row {
        store_id: String,
        kind: String,
        config_json: String,
    }
    let db = env.d1("DB")?;
    let rows: Vec<Row> = db
        .prepare(
            "SELECT store_id, kind, config_json FROM storage_backends WHERE state != 'disabled'",
        )
        .all()
        .await?
        .results()?;
    for r in rows {
        let (ok, err): (bool, Option<String>) = match build_store(env, &r.kind, &r.config_json) {
            Ok(store) => match store.probe().await {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e.to_string().chars().take(120).collect())),
            },
            // A build_store Err is already a short reason (binding_missing / s3-parse /
            // unsupported_kind).
            Err(e) => (false, Some(e)),
        };
        write_health(env, &r.store_id, ok, err.as_deref()).await;
    }
    Ok(())
}
