//! Depo sağlık-izleme (Faz 3, plan e) — iki kanal:
//!   1. **Programlı probe:** günlük bakım (`maintenance::run_daily`) `probe_all` çağırır →
//!      `state!='disabled'` HER depoya `probe()` (PUT+GET+DELETE `probe/<uuid>`) + `last_health_*`.
//!      Owner elle de tetikler: `POST /admin/storage/:id/probe` (admin/storage.rs, `write_health` ORTAK).
//!   2. **Fırsatçı işaretleme:** gerçek trafikte put/get `Err` verince `write_health(false)`
//!      (router.rs; best-effort, 120-char kırpık, secret'sız) → panel cron beklemeden kızarır.
//!
//! `write_health` TEK choke-point: probe endpoint'i, router fırsatçı-işaret, günlük probe,
//! cleanup agregeli-işaret hepsi buradan yazar → sağlık-yazımı davranışı ayrışamaz.

use serde::Deserialize;
use worker::*;

use super::build_store;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::utils::now_secs;

/// `last_health_at/ok/err` best-effort yaz (probe + fırsatçı-işaretleme ORTAK). Hata
/// yutulur: sağlık-yazımı hiçbir gerçek op'u (upload/download/bakım) kırmaz.
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

/// Günlük programlı probe (plan e kanal-1): `state!='disabled'` TÜM depoları D1'den oku,
/// her birine canlı `probe()` (3 subrequest/depo) + `last_health_*` yaz. build_store-fail
/// (Lite binding-yok / s3 config-parse-fail) da unhealthy işaretlenir (o depoda blob olan
/// get 503 verecek — plan f#9). Depo sayısı bir avuç → günlük bakımda ucuz. Hata bakımın
/// kalanını KIRMAZ (run_daily logla-devam).
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
            // build_store Err zaten kısa neden (binding_missing / s3-parse / unsupported_kind).
            Err(e) => (false, Some(e)),
        };
        write_health(env, &r.store_id, ok, err.as_deref()).await;
    }
    Ok(())
}
