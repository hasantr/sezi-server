//! `/admin/storage` — pluggable-storage management endpoints (Faz 2, 2026-07-08).
//! From the CLIENT, the owner attaches, tests, edits and removes an external blob
//! store (B2 / a second R2 / MinIO / any S3-compatible target) — the "zero CLI"
//! philosophy, following cf-config and fcm-config.
//!
//! SECURITY CONTRACT (identical to cf_config.rs / fcm_config.rs):
//! - **Gates (plan e):** GET and probe use `require_admin`; POST/PATCH/DELETE/drain
//!   use `require_owner`, because store credentials are strong secrets and only the
//!   server's owner may add, change, delete or drain a store.
//! - **WRITE-ONLY:** `config_json` (which contains the `secret_access_key`) is
//!   returned in NO response — GET/PATCH/probe carry only identity, state, health
//!   and counters. The secret is only ever written here; rotation means PATCHing
//!   the config field, never reading it back.
//! - **http:// endpoints are dev-only:** allowed when `ENV != "prod"`
//!   (wrangler-dev + MinIO); in prod `https` is mandatory (plan Faz 0 note,
//!   man-in-the-middle protection).
//! - **Adding means a LIVE probe:** POST and a config PATCH verify the credentials
//!   with a PUT/GET/DELETE round-trip BEFORE persisting, so the owner never falls
//!   into "I saved it but it does not work" (same early-validation idea as the fcm
//!   service account).

use serde::Deserialize;
use serde_json::json;
use worker::*;

use crate::auth::middleware::{require_admin, require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_opt_int, d1_text};
use crate::respond::json_err;
use crate::storage::{
    build_store, invalidate_storage_cache, validate_s3_config, write_health, BlobStore, S3Config,
    S3Store, PRIMARY_STORE_ID,
};
use crate::utils::{now_secs, random_bytes, var_or};

// ── GET /admin/storage (require_admin) — store list, secret-free ───────────────

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
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    // config_json is DELIBERATELY not selected: the secret never reaches a response
    // (write-only).
    let rows: Vec<ListRow> = db
        .prepare(
            "SELECT store_id, kind, label, state, priority, max_bytes, used_bytes, \
             object_count, last_health_at, last_health_ok, last_health_err \
             FROM storage_backends ORDER BY priority ASC",
        )
        .all()
        .await?
        .results()?;
    // Faz 4: remaining-inventory count for draining stores — a UNION count over the
    // 3 metadata tables, the SAME source the move engine uses to detect completion
    // (storage/drain.rs). With no draining store there is NO extra query (empty list
    // → empty map). On error we return an empty map: the list still renders, the
    // field is not null, a draining store just shows 0 and the next GET corrects it.
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
                // Faz 4: a count only for a draining store, null otherwise (nothing
                // is being moved).
                "draining_remaining": (r.state == "draining")
                    .then(|| remaining.get(&r.store_id).copied().unwrap_or(0)),
            })
        })
        .collect();
    Response::from_json(&json!({ "stores": stores }))
}

// ── POST /admin/storage (require_owner) — add: validate + live probe + INSERT ───

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
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
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

    // LIVE probe — verify the credentials end to end BEFORE persisting them.
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
    /// None = keep, Some(0) = clear (NULL / unlimited), Some(n>0) = set.
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
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
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

    // Per-field effective values (absent = keep).
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
        Some(0) => None,               // cleared → unlimited
        Some(n) if n > 0 => Some(n),
        Some(_) => return field_err("max_bytes"),
    };

    // Config rotation (s3 only; an r2_binding store has no config). If it changed,
    // probe again.
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
    // If the config was re-probed, stamp health as freshly green.
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

// ── DELETE /admin/storage/:id (require_owner) — empty stores only ──────────────

#[derive(Deserialize)]
struct CountOnlyRow {
    object_count: i64,
}

pub async fn remove(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    // r2-primary cannot be deleted (it is the binding default); an owner who wants
    // it out of rotation can PATCH it to `disabled`.
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
    // Only an empty store may be deleted; draining a full one is Faz 4's job.
    // object_count is the D1 inventory truth (maintained by reconcile); > 0 → 409, and
    // the client tells the owner to drain it first.
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

// ── POST /admin/storage/:id/probe (require_admin) — manual health check ────────

#[derive(Deserialize)]
struct ProbeRow {
    kind: String,
    config_json: String,
}

pub async fn probe(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
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

    // Build the store (build_store is SHARED with the router and the daily probe)
    // and probe it live.
    let (ok, err): (bool, Option<String>) = match build_store(&ctx.env, &row.kind, &row.config_json)
    {
        Ok(s) => match s.probe().await {
            Ok(()) => (true, None),
            Err(e) => (false, Some(truncate(&e.to_string(), 120))),
        },
        // A build_store Err is already a short reason (binding_missing / s3-parse /
        // unsupported_kind).
        Err(e) => (false, Some(e)),
    };

    // Write last_health_* through the choke-point SHARED by this probe and
    // opportunistic marking (best-effort).
    write_health(&ctx.env, &id, ok, err.as_deref()).await;

    Response::from_json(&json!({ "ok": ok, "error": err }))
}

// ── POST /admin/storage/:id/drain (require_owner) — start emptying a store (Faz 4) ──

#[derive(Deserialize)]
struct StateRow {
    state: String,
}

/// Move a store to `draining`: take it out of placement (the router only writes to
/// `active` stores, while reads and deletes KEEP working until the data has moved)
/// and wake the move job. The engine (storage/drain.rs) rides the 2-minute cron plus
/// the lazy path and moves at most `MOVE_BATCH` (4) blobs per run; when the inventory
/// reaches 0 the store is automatically set to `disabled`. r2-primary can be drained
/// too (plan e: "for whoever wants to leave R2 entirely"). Target pinning is NOT in
/// v1 (the optional `{target_store_id?}` from plan c.4): the target is always the
/// first remaining active store with room (the put_new policy), so the body is not
/// read at all. Idempotent — POSTing again to an already-draining store just wakes
/// the job and returns the current remaining count.
pub async fn drain(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
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
        // Dead-end guard: with no TARGET to move to (no other 'active' store) the
        // drain could never progress and new uploads would start failing with 503,
        // so answer 409 and let the owner add or activate a target store first.
        // max_bytes fullness is enforced at placement time (put_new).
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
    // Wake the move job: zeroing the stamp lets the lazy path claim it on the first
    // eligible request (within ~60s), and a cron-enabled deployment runs it within
    // 2 minutes anyway. Repeating this is harmless (idempotent).
    crate::maintenance::wake_storage_move(&ctx.env).await;
    let remaining = crate::storage::drain::remaining_counts(&db, std::slice::from_ref(&id))
        .await?
        .get(&id)
        .copied()
        .unwrap_or(0);
    Response::from_json(&json!({ "ok": true, "draining_remaining": remaining }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Label: non-empty, ≤120 chars, no control characters (cf_config's `field_ok`
/// pattern).
fn label_ok(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.len() <= 120 && !t.chars().any(|c| c.is_control())
}

/// State accepted by PATCH/POST: active/readonly/disabled only. `draining` is set
/// exclusively by the separate drain endpoint (Faz 4).
fn state_ok(s: &str) -> bool {
    matches!(s, "active" | "readonly" | "disabled")
}

/// Priority for a new store: whatever the owner passed (0..=1_000_000), otherwise
/// the current MAX + 10. Since r2-primary is 0, new stores are always written after
/// it; an owner can move one to the front with PATCH.
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

/// Apply the PATCH fields onto the existing `config_json`: absent = keep, '' clears
/// prefix/storage_class, and an empty value for any other field is rejected by
/// validation. The caller runs validate + probe on the merge result.
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
        // '' → empty secret → validation returns `secret_invalid`; the secret cannot
        // be cleared.
        cfg.secret_access_key = v.trim().to_string();
    }
    if let Some(v) = &patch.prefix {
        cfg.prefix = v.clone(); // '' → clear the prefix
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

/// 400 plus which field was invalid. The secret VALUE never leaks — only the field
/// name is reported.
fn field_err(field: &str) -> Result<Response> {
    let resp = Response::from_json(&json!({ "error": "bad_request", "field": field }))?;
    Ok(resp.with_status(400))
}

/// 422 probe_failed plus a short detail: secret-free and truncated to 200 chars
/// (the plan e/g contract).
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
    fn label_validation() {
        assert!(label_ok("B2 — café"));
        assert!(!label_ok("   "));
        assert!(!label_ok("a\nb"));
        assert!(!label_ok(&"x".repeat(121)));
    }

    #[test]
    fn state_validation() {
        assert!(state_ok("active"));
        assert!(state_ok("readonly"));
        assert!(state_ok("disabled"));
        // draining cannot be set through PATCH (that is the Faz 4 drain endpoint).
        assert!(!state_ok("draining"));
        assert!(!state_ok("bogus"));
    }

    #[test]
    fn merge_config_is_field_by_field() {
        let existing = r#"{"endpoint":"https://old","region":"r1","bucket":"b1","access_key_id":"k1","secret_access_key":"s1","prefix":"p/","storage_class":"STANDARD"}"#;
        // Change only the endpoint; everything else is preserved.
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
        assert_eq!(m.secret_access_key, "s1", "the secret is preserved (rotation is optional)");
        assert_eq!(m.prefix, "p/");
        // storage_class '' → clear; prefix '' → clear.
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
        // Corrupt stored config → config_corrupt. (S3Config carries a secret, so it
        // derives neither Debug nor PartialEq to avoid leaking it — hence matches!
        // instead of assert_eq!.)
        assert!(matches!(merge_config("not json", &patch), Err("config_corrupt")));
    }
}
