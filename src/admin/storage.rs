//! `/admin/storage` — Takılabilir-Depolama yönetim endpoint'leri (Faz 2, 2026-07-08).
//! Owner CLIENT'tan harici blob-deposu (B2 / ikinci-R2 / MinIO / S3-uyumlu) bağlar,
//! sınar, düzenler, kaldırır ("sıfır-CLI" felsefesi; cf/fcm-config emsali).
//!
//! GÜVENLİK SÖZLEŞMESİ (cf_config.rs/fcm_config.rs ile birebir):
//! - **Kapılar (plan e):** GET/probe = `require_admin`; POST/PATCH/DELETE/drain =
//!   `require_owner` (depo kimlik-bilgisi güçlü secret → yalnız sunucu sahibi
//!   ekler/değiştirir/siler/boşaltır).
//! - **WRITE-ONLY:** `config_json` (secret `secret_access_key` içerir) HİÇBİR cevapta
//!   dönmez — GET/PATCH/probe yalnız kimlik/durum/sağlık/sayaç taşır. Secret buradan
//!   yalnız YAZILIR (rotasyon = PATCH config alanı; okunmaz).
//! - **http:// endpoint yalnız dev:** `ENV!="prod"` (wrangler-dev + MinIO); prod'da
//!   `https` zorunlu (plan Faz 0 notu; ortadaki-adam koruması).
//! - **Ekleme = CANLI probe:** POST + PATCH-config, kaydetmeden ÖNCE PUT/GET/DELETE
//!   round-trip'iyle kimlik-bilgisini doğrular → owner "kaydettim ama çalışmıyor" tuzağına
//!   düşmez (fcm service-account erken-doğrulama emsali).

use serde::Deserialize;
use serde_json::json;
use worker::*;

use crate::auth::middleware::{require_admin, require_auth, require_owner};
use crate::d1util::{d1_int, d1_opt_int, d1_text};
use crate::respond::json_err;
use crate::storage::{
    build_store, invalidate_storage_cache, validate_s3_config, write_health, BlobStore, S3Config,
    S3Store, PRIMARY_STORE_ID,
};
use crate::utils::{now_secs, random_bytes, var_or};

// ── GET /admin/storage (require_admin) — depo listesi (secret'siz) ─────────────

#[derive(Deserialize)]
struct ListRow {
    store_id: String,
    kind: String,
    label: String,
    state: String,
    priority: i64,
    max_bytes: Option<i64>,
    used_bytes: i64,
    object_count: i64,
    last_health_at: Option<i64>,
    last_health_ok: Option<i64>,
    last_health_err: Option<String>,
}

pub async fn list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    // config_json BİLİNÇLİ SELECT-DIŞI: secret asla cevaba girmez (write-only).
    let rows: Vec<ListRow> = db
        .prepare(
            "SELECT store_id, kind, label, state, priority, max_bytes, used_bytes, \
             object_count, last_health_at, last_health_ok, last_health_err \
             FROM storage_backends ORDER BY priority ASC",
        )
        .all()
        .await?
        .results()?;
    // Faz 4: draining depolar için kalan-envanter sayısı (3 meta-tablo UNION sayımı —
    // taşıma motorunun bitiş-tespitiyle AYNI kaynak: storage/drain.rs). Draining depo
    // yoksa EK SORGU YOK (boş liste → boş map). Hata → boş map (liste yine döner;
    // alan null kalmaz, draining depo 0 gösterir — bir sonraki GET düzelir).
    let draining_ids: Vec<String> = rows
        .iter()
        .filter(|r| r.state == "draining")
        .map(|r| r.store_id.clone())
        .collect();
    let remaining = crate::storage::drain::remaining_counts(&db, &draining_ids)
        .await
        .unwrap_or_default();
    let stores: Vec<_> = rows
        .iter()
        .map(|r| {
            json!({
                "store_id": r.store_id,
                "kind": r.kind,
                "label": r.label,
                "state": r.state,
                "priority": r.priority,
                "max_bytes": r.max_bytes,
                "used_bytes": r.used_bytes,
                "object_count": r.object_count,
                "last_health_at": r.last_health_at,
                "last_health_ok": r.last_health_ok.map(|v| v != 0),
                "last_health_err": r.last_health_err,
                // Faz 4: yalnız draining depoda sayı, diğerlerinde null (taşıma-yok).
                "draining_remaining": (r.state == "draining")
                    .then(|| remaining.get(&r.store_id).copied().unwrap_or(0)),
            })
        })
        .collect();
    Response::from_json(&json!({ "stores": stores }))
}

// ── POST /admin/storage (require_owner) — ekle: doğrula + canlı probe + INSERT ──

#[derive(Deserialize)]
struct AddBody {
    kind: String,
    label: String,
    config: S3Config,
    #[serde(default)]
    max_bytes: Option<i64>,
    #[serde(default)]
    priority: Option<i64>,
}

pub async fn add(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: AddBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.kind != "s3" {
        return json_err(400, "unsupported_kind");
    }
    if !label_ok(&body.label) {
        return field_err("label");
    }
    let allow_http = var_or(&ctx.env, "ENV", "prod") != "prod";
    if let Err(field) = validate_s3_config(&body.config, allow_http) {
        return field_err(field);
    }
    let priority = match resolve_priority(&ctx.env, body.priority).await {
        Ok(p) => p,
        Err(resp) => return Ok(resp),
    };
    let max_bytes = body.max_bytes.filter(|&n| n > 0);

    // CANLI probe — kaydetmeden ÖNCE kimlik-bilgisini uçtan-uca doğrula.
    let store = BlobStore::S3(S3Store::from_config(body.config.clone()));
    if let Err(e) = store.probe().await {
        return probe_failed(&e);
    }

    let store_id = format!("s3-{}", hex8());
    let config_json = serde_json::to_string(&body.config).unwrap_or_else(|_| "{}".into());
    let now = now_secs() as i64;
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "INSERT INTO storage_backends \
         (store_id, kind, label, state, priority, max_bytes, used_bytes, object_count, \
          config_json, last_health_at, last_health_ok, last_health_err, created_at, updated_at) \
         VALUES (?, 's3', ?, 'active', ?, ?, 0, 0, ?, ?, 1, NULL, ?, ?)",
    )
    .bind(&[
        d1_text(&store_id),
        d1_text(body.label.trim()),
        d1_int(priority),
        d1_opt_int(max_bytes),
        d1_text(&config_json),
        d1_int(now),
        d1_int(now),
        d1_int(now),
    ])?
    .run()
    .await?;
    invalidate_storage_cache();
    Response::from_json(&json!({ "store_id": store_id }))
}

// ── PATCH /admin/storage/:id (require_owner) — label/state/priority/max_bytes/config ──

#[derive(Deserialize, Default)]
struct PatchBody {
    label: Option<String>,
    state: Option<String>,
    priority: Option<i64>,
    /// None=koru, Some(0)=temizle(NULL/sınırsız), Some(n>0)=set.
    max_bytes: Option<i64>,
    config: Option<ConfigPatch>,
}

#[derive(Deserialize)]
struct ConfigPatch {
    endpoint: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    prefix: Option<String>,
    storage_class: Option<String>,
}

#[derive(Deserialize)]
struct ExistingRow {
    kind: String,
    label: String,
    state: String,
    priority: i64,
    max_bytes: Option<i64>,
    config_json: String,
}

pub async fn update(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let body: PatchBody = req.json().await.unwrap_or_default();

    let db = ctx.env.d1("DB")?;
    let existing: Option<ExistingRow> = db
        .prepare(
            "SELECT kind, label, state, priority, max_bytes, config_json \
             FROM storage_backends WHERE store_id = ? LIMIT 1",
        )
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let existing = match existing {
        Some(r) => r,
        None => return json_err(404, "not_found"),
    };

    // Alan-bazlı efektif değerler (yok=koru).
    let label = match &body.label {
        Some(v) if label_ok(v) => v.trim().to_string(),
        Some(_) => return field_err("label"),
        None => existing.label,
    };
    let state = match &body.state {
        Some(v) if state_ok(v) => v.clone(),
        Some(_) => return field_err("state"),
        None => existing.state,
    };
    let priority = match body.priority {
        Some(p) if (0..=1_000_000).contains(&p) => p,
        Some(_) => return field_err("priority"),
        None => existing.priority,
    };
    let max_bytes = match body.max_bytes {
        None => existing.max_bytes,
        Some(0) => None,               // temizle → sınırsız
        Some(n) if n > 0 => Some(n),
        Some(_) => return field_err("max_bytes"),
    };

    // Config rotasyonu (yalnız s3; r2_binding'in config'i yok). Değiştiyse yeniden probe.
    let (config_json, health_reprobed) = match &body.config {
        None => (existing.config_json, false),
        Some(patch) => {
            if existing.kind != "s3" {
                return field_err("config");
            }
            let merged = match merge_config(&existing.config_json, patch) {
                Ok(c) => c,
                Err(field) => return field_err(field),
            };
            let allow_http = var_or(&ctx.env, "ENV", "prod") != "prod";
            if let Err(field) = validate_s3_config(&merged, allow_http) {
                return field_err(field);
            }
            let store = BlobStore::S3(S3Store::from_config(merged.clone()));
            if let Err(e) = store.probe().await {
                return probe_failed(&e);
            }
            (serde_json::to_string(&merged).unwrap_or_else(|_| "{}".into()), true)
        }
    };

    let now = now_secs() as i64;
    // Config yeniden-probe edildiyse sağlığı taze-yeşil işaretle.
    if health_reprobed {
        db.prepare(
            "UPDATE storage_backends SET label=?, state=?, priority=?, max_bytes=?, \
             config_json=?, last_health_at=?, last_health_ok=1, last_health_err=NULL, updated_at=? \
             WHERE store_id=?",
        )
        .bind(&[
            d1_text(&label),
            d1_text(&state),
            d1_int(priority),
            d1_opt_int(max_bytes),
            d1_text(&config_json),
            d1_int(now),
            d1_int(now),
            d1_text(&id),
        ])?
        .run()
        .await?;
    } else {
        db.prepare(
            "UPDATE storage_backends SET label=?, state=?, priority=?, max_bytes=?, updated_at=? \
             WHERE store_id=?",
        )
        .bind(&[
            d1_text(&label),
            d1_text(&state),
            d1_int(priority),
            d1_opt_int(max_bytes),
            d1_int(now),
            d1_text(&id),
        ])?
        .run()
        .await?;
    }
    invalidate_storage_cache();
    Response::from_json(&json!({ "ok": true }))
}

// ── DELETE /admin/storage/:id (require_owner) — yalnız boş depo ────────────────

#[derive(Deserialize)]
struct CountOnlyRow {
    object_count: i64,
}

pub async fn remove(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    // r2-primary silinemez (binding-default) — owner isterse `disabled` yapabilir (PATCH).
    if id == PRIMARY_STORE_ID {
        return json_err(400, "cannot_delete_primary");
    }
    let db = ctx.env.d1("DB")?;
    let row: Option<CountOnlyRow> = db
        .prepare("SELECT object_count FROM storage_backends WHERE store_id = ? LIMIT 1")
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let row = match row {
        Some(r) => r,
        None => return json_err(404, "not_found"),
    };
    // Yalnız boş depo silinir (Faz 4 drain dolu-depoyu boşaltana kadar). object_count
    // = D1-envanter gerçeği (reconcile besler); >0 → 409 (client "önce boşalt" der).
    if row.object_count > 0 {
        return json_err(409, "store_not_empty");
    }
    db.prepare("DELETE FROM storage_backends WHERE store_id = ?")
        .bind(&[d1_text(&id)])?
        .run()
        .await?;
    invalidate_storage_cache();
    Response::from_json(&json!({ "ok": true }))
}

// ── POST /admin/storage/:id/probe (require_admin) — elle health-check ──────────

#[derive(Deserialize)]
struct ProbeRow {
    kind: String,
    config_json: String,
}

pub async fn probe(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let row: Option<ProbeRow> = db
        .prepare("SELECT kind, config_json FROM storage_backends WHERE store_id = ? LIMIT 1")
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let row = match row {
        Some(r) => r,
        None => return json_err(404, "not_found"),
    };

    // Depoyu kur (router/günlük-probe ile ORTAK build_store) + canlı probe.
    let (ok, err): (bool, Option<String>) = match build_store(&ctx.env, &row.kind, &row.config_json)
    {
        Ok(s) => match s.probe().await {
            Ok(()) => (true, None),
            Err(e) => (false, Some(truncate(&e.to_string(), 120))),
        },
        // build_store Err zaten kısa neden (binding_missing / s3-parse / unsupported_kind).
        Err(e) => (false, Some(e)),
    };

    // last_health_* yaz (probe + fırsatçı-işaretleme ORTAK choke-point; best-effort).
    write_health(&ctx.env, &id, ok, err.as_deref()).await;

    Response::from_json(&json!({ "ok": ok, "error": err }))
}

// ── POST /admin/storage/:id/drain (require_owner) — depoyu boşaltmaya al (Faz 4) ──

#[derive(Deserialize)]
struct StateRow {
    state: String,
}

/// Depoyu `draining`'e al: yerleştirmeden çıkar (router yalnız `active`'e yazar;
/// okuma/silme taşınana dek SÜRER) + taşıma job'unu uyandır. Motor (storage/drain.rs)
/// 2dk-cron + lazy sırtında ≤4 blob/koşum taşır; envanter 0 → depo otomatik `disabled`.
/// r2-primary DE drain edilebilir (plan e: "R2'den tamamen çıkmak isteyene").
/// Hedef-pinleme v1'de YOK (plan c.4 `{target_store_id?}` opsiyoneli): hedef daima
/// kalan aktif depolardan sığan-ilk (put_new politikası) → body okunmaz.
/// İdempotent: zaten-draining depoya tekrar POST → yalnız uyandırma + güncel kalan.
pub async fn drain(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    let row: Option<StateRow> = db
        .prepare("SELECT state FROM storage_backends WHERE store_id = ? LIMIT 1")
        .bind(&[d1_text(&id)])?
        .first(None)
        .await?;
    let row = match row {
        Some(r) => r,
        None => return json_err(404, "not_found"),
    };
    if row.state != "draining" {
        // Kör-uç muhafızı: taşınacak HEDEF yoksa (başka hiç 'active' depo yok) drain
        // asla ilerleyemez + yeni upload'lar da 503'e düşerdi → 409 (owner önce hedef
        // depo ekler/aktifler). max_bytes-doluluk yerleştirme-anında zorlanır (put_new).
        #[derive(Deserialize)]
        struct NRow {
            n: i64,
        }
        let others = db
            .prepare(
                "SELECT COUNT(*) AS n FROM storage_backends \
                 WHERE state = 'active' AND store_id != ?",
            )
            .bind(&[d1_text(&id)])?
            .first::<NRow>(None)
            .await?
            .map(|r| r.n)
            .unwrap_or(0);
        if others == 0 {
            return json_err(409, "no_active_target");
        }
        let now = now_secs() as i64;
        db.prepare(
            "UPDATE storage_backends SET state = 'draining', updated_at = ? WHERE store_id = ?",
        )
        .bind(&[d1_int(now), d1_text(&id)])?
        .run()
        .await?;
        invalidate_storage_cache();
    }
    // Taşıma job'unu uyandır: damga 0 → lazy-yol ilk uygun istekte (≤60sn) claim'ler;
    // cron'lu kurulumda zaten ≤2dk'da koşar. İdempotent-tekrar zararsız.
    crate::maintenance::wake_storage_move(&ctx.env).await;
    let remaining = crate::storage::drain::remaining_counts(&db, std::slice::from_ref(&id))
        .await?
        .get(&id)
        .copied()
        .unwrap_or(0);
    Response::from_json(&json!({ "ok": true, "draining_remaining": remaining }))
}

// ── Yardımcılar ───────────────────────────────────────────────────────────────

/// Etiket: boş-değil, ≤120 char, kontrol-karakteri yok (cf_config `field_ok` deseni).
fn label_ok(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.len() <= 120 && !t.chars().any(|c| c.is_control())
}

/// PATCH/POST state: yalnız active/readonly/disabled (draining = ayrı drain endpoint, Faz 4).
fn state_ok(s: &str) -> bool {
    matches!(s, "active" | "readonly" | "disabled")
}

/// Yeni depo önceliği: owner verdiyse (0..=1_000_000) onu, yoksa mevcut MAX+10
/// (r2-primary=0 → yeni depolar hep sonra yazılır; owner PATCH ile öne alabilir).
async fn resolve_priority(
    env: &Env,
    requested: Option<i64>,
) -> std::result::Result<i64, Response> {
    if let Some(p) = requested {
        if (0..=1_000_000).contains(&p) {
            return Ok(p);
        }
        return Err(field_err("priority").unwrap());
    }
    #[derive(Deserialize)]
    struct MaxRow {
        n: Option<i64>,
    }
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return Err(json_err(500, "db").unwrap()),
    };
    let max_priority = db
        .prepare("SELECT MAX(priority) AS n FROM storage_backends")
        .first::<MaxRow>(None)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.n)
        .unwrap_or(0);
    Ok(max_priority + 10)
}

/// Mevcut `config_json`'a PATCH alanlarını uygula (yok=koru; prefix/storage_class
/// ''=temizle; diğerleri boş=validate reddeder). Merge sonrası validate + probe çağıran yapar.
fn merge_config(
    existing_json: &str,
    patch: &ConfigPatch,
) -> std::result::Result<S3Config, &'static str> {
    let mut cfg: S3Config =
        serde_json::from_str(existing_json).map_err(|_| "config_corrupt")?;
    if let Some(v) = &patch.endpoint {
        cfg.endpoint = v.trim().to_string();
    }
    if let Some(v) = &patch.region {
        cfg.region = v.trim().to_string();
    }
    if let Some(v) = &patch.bucket {
        cfg.bucket = v.trim().to_string();
    }
    if let Some(v) = &patch.access_key_id {
        cfg.access_key_id = v.trim().to_string();
    }
    if let Some(v) = &patch.secret_access_key {
        // '' → boş secret → validate `secret_invalid` (secret temizlenemez).
        cfg.secret_access_key = v.trim().to_string();
    }
    if let Some(v) = &patch.prefix {
        cfg.prefix = v.clone(); // '' → prefix temizle
    }
    if let Some(v) = &patch.storage_class {
        cfg.storage_class = if v.trim().is_empty() {
            None
        } else {
            Some(v.trim().to_string())
        };
    }
    Ok(cfg)
}

/// 400 + hangi alanın hatalı olduğu (secret DEĞERİ sızmaz; yalnız alan-adı).
fn field_err(field: &str) -> Result<Response> {
    let resp = Response::from_json(&json!({ "error": "bad_request", "field": field }))?;
    Ok(resp.with_status(400))
}

/// 422 probe_failed + kısa detay (secret'siz, 200-char kırpık — plan e/g sözleşmesi).
fn probe_failed(e: &Error) -> Result<Response> {
    let resp = Response::from_json(&json!({
        "error": "probe_failed",
        "detail": truncate(&e.to_string(), 200),
    }))?;
    Ok(resp.with_status(422))
}

fn hex8() -> String {
    hex::encode(random_bytes(4))
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_dogrulama() {
        assert!(label_ok("B2 — kişisel"));
        assert!(!label_ok("   "));
        assert!(!label_ok("a\nb"));
        assert!(!label_ok(&"x".repeat(121)));
    }

    #[test]
    fn state_dogrulama() {
        assert!(state_ok("active"));
        assert!(state_ok("readonly"));
        assert!(state_ok("disabled"));
        // draining PATCH'ten set edilemez (Faz 4 drain endpoint'i).
        assert!(!state_ok("draining"));
        assert!(!state_ok("bogus"));
    }

    #[test]
    fn merge_config_alan_bazli() {
        let existing = r#"{"endpoint":"https://old","region":"r1","bucket":"b1","access_key_id":"k1","secret_access_key":"s1","prefix":"p/","storage_class":"STANDARD"}"#;
        // Yalnız endpoint değiştir; gerisi korunur.
        let patch = ConfigPatch {
            endpoint: Some("https://new".into()),
            region: None,
            bucket: None,
            access_key_id: None,
            secret_access_key: None,
            prefix: None,
            storage_class: None,
        };
        let m = merge_config(existing, &patch).unwrap();
        assert_eq!(m.endpoint, "https://new");
        assert_eq!(m.region, "r1");
        assert_eq!(m.secret_access_key, "s1", "secret korunur (rotasyon opsiyonel)");
        assert_eq!(m.prefix, "p/");
        // storage_class '' → temizle; prefix '' → temizle.
        let patch = ConfigPatch {
            endpoint: None,
            region: None,
            bucket: None,
            access_key_id: None,
            secret_access_key: None,
            prefix: Some("".into()),
            storage_class: Some("".into()),
        };
        let m = merge_config(existing, &patch).unwrap();
        assert_eq!(m.prefix, "");
        assert!(m.storage_class.is_none());
        // Bozuk mevcut config → config_corrupt. (S3Config secret taşır → Debug/PartialEq
        // türetilmez [sızıntı riski]; assert_eq yerine matches!.)
        assert!(matches!(merge_config("not json", &patch), Err("config_corrupt")));
    }
}
