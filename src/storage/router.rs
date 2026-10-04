//! `StorageRouter` — placement + resolution. **Handlers talk to NOTHING ELSE** (single
//! choke-point). `from_env` loads D1 `storage_backends` → multi-backend resolution.
//!
//! - **60s per-isolate config cache** (the maintenance.rs CHECK_EVERY_SECS pattern): only the
//!   D1 config snapshot is cached (plain data — no JsValue, no bindings), so the hot path
//!   costs no D1 round-trip per request. The live `BlobStore` handles (R2 binding / S3Store)
//!   are rebuilt per request for next to nothing (a binding lookup never hits the network; an
//!   S3Store is just a struct). An `/admin/storage` mutation drops its own isolate's cache
//!   IMMEDIATELY via `invalidate_storage_cache`; other isolates catch up within the TTL.
//! - **A single backend behaves exactly as a plain R2 install:** with no S3 rows (just the
//!   `r2-primary` default) reads and writes resolve to R2. If D1 is unreadable or the table is
//!   missing → fall back to a single `r2-primary` (active when the binding exists; on Lite
//!   any_available=false).
//! - **Placement:** priority overflow + per-backend max_bytes enforcement + fall through to
//!   the next eligible backend on PUT failure (degraded write) + opportunistic health marking
//!   (put/get Err → last_health_ok=0). `readonly`/`disabled` are EXCLUDED from placement
//!   (readonly still serves reads/deletes). `storage_orphans` cleanup and drain live in
//!   maintenance.rs / drain.rs.
//! - **One class-specific rule — the library pin (0041):** while any store has
//!   `library_pin = 1`, `StorageClass::Library` is placed on pinned stores ONLY, and refused
//!   (429/503) rather than spilled when none of them can take it. Every other class ignores the
//!   pin. See `pinned_only`.

use std::cell::RefCell;

use serde::Deserialize;
use worker::*;

use super::health::write_health;
use super::{build_store, BlobObject, BlobStore, StorageClass, PRIMARY_STORE_ID};
use crate::utils::now_secs;

/// Per-isolate config cache TTL (same cadence as maintenance.rs `CHECK_EVERY_SECS`).
const CACHE_TTL_SECS: u64 = 60;

/// Why `put_new` found no placement (the caller maps it via `placement_err_response`).
pub enum PlacementError {
    /// There ARE active backends but all of them are at `max_bytes` → 429
    /// `quota_exceeded/server_storage` (the client already understands this quota contract —
    /// op_result treats it as nonretryable).
    AllFull,
    /// Active backends with room were tried and EVERY one failed the PUT (degraded writes
    /// exhausted) → 503 `upload_failed` (retryable op).
    AllFailed,
    /// No writable (`active`) backend at all (everything readonly/disabled) → 503
    /// `upload_failed`. The `any_available` gate normally catches this first; this covers the
    /// readonly-only edge.
    NoActive,
}

/// `PlacementError` → HTTP response (shared by all three upload handlers → the mapping lives
/// in one place).
pub fn placement_err_response(e: PlacementError) -> Result<Response> {
    match e {
        PlacementError::AllFull => {
            let resp = Response::from_json(
                &serde_json::json!({ "error": "quota_exceeded", "scope": "server_storage" }),
            )?;
            Ok(resp.with_status(429))
        }
        PlacementError::AllFailed | PlacementError::NoActive => {
            crate::respond::json_err(503, "upload_failed")
        }
    }
}

/// Plain-data snapshot of a D1 `storage_backends` row (cacheable: contains no JsValue).
/// The live `BlobStore` is built from it per request.
#[derive(Clone, Deserialize)]
struct StoreConfig {
    store_id: String,
    kind: String, // 'r2_binding' | 's3'
    state: String,
    // No `priority` field on purpose: ordering is the SQL's job (`ORDER BY priority`), and
    // `admin/storage.rs` surfaces priority to the owner panel from its own query.
    max_bytes: Option<i64>,
    // Usage estimate at placement time, for per-backend cap enforcement (best-effort; fed by
    // the daily reconcile + media_added/removed; the cached snapshot may be stale — soft cap).
    #[serde(default)]
    used_bytes: i64,
    config_json: String,
    /// 1 = the group library is placed here (0041). Defaulted so a config cached from before the
    /// migration still deserializes.
    #[serde(default)]
    library_pin: i64,
}

struct CachedConfig {
    fetched_at: u64,
    stores: Vec<StoreConfig>,
}

thread_local! {
    /// Last D1 config snapshot (memoized per isolate; WASM is single-threaded, so the
    /// RefCell cannot race).
    static CONFIG_CACHE: RefCell<Option<CachedConfig>> = const { RefCell::new(None) };
}

/// Called after an `/admin/storage` mutation (POST/PATCH/DELETE) → drop THIS isolate's
/// config cache so the next `from_env` reloads from D1. Other isolates catch up within their
/// own 60s TTL.
pub fn invalidate_storage_cache() {
    CONFIG_CACHE.with(|c| *c.borrow_mut() = None);
}

/// Identity/policy metadata of one backend inside the router (loaded from D1).
pub struct StoreMeta {
    pub store_id: String,
    pub state: String,
    // No `priority` here: the drain relies on the SQL's own `ORDER BY priority` plus
    // `classify_placement`, and the panel reads priority from its own D1 query in
    // `admin/storage.rs`. Adding the field back is one line if a reader ever appears.
    /// NULL = unlimited; when set, placement enforces `used_bytes + size <= max_bytes`.
    pub max_bytes: Option<i64>,
    /// Usage estimate at placement time (best-effort, from the cache — soft cap).
    pub used_bytes: i64,
    /// The group library is pinned here (`library_pin = 1`).
    pub library_pin: bool,
}

/// Priority-ordered backend list. Handlers only ever call `put_new/get/delete/any_available`
/// and never learn which backend they hit.
pub struct StorageRouter {
    /// Kept for opportunistic health marking (put/get Err → last_health_ok=0; best-effort).
    env: Env,
    stores: Vec<(StoreMeta, BlobStore)>,
    /// Is ANY configured store pinned for the library — counted from the config rows BEFORE the
    /// live stores are built. A pinned S3 store whose config fails to build is absent from
    /// `stores`, and deciding from `stores` would quietly spill the library onto R2 the moment
    /// the campus store's credentials broke; counted here, the pin still holds and the upload
    /// is refused instead.
    library_pinned: bool,
}

impl StorageRouter {
    /// Build the router: take the config from the isolate cache if it is fresh, otherwise load
    /// D1 `storage_backends` (and cache it) → build the live `BlobStore`s in priority order.
    pub async fn from_env(env: &Env) -> Result<Self> {
        let now = now_secs();
        // 1. Read the cache SYNCHRONOUSLY (clone out and release the borrow before any await).
        let cached: Option<Vec<StoreConfig>> = CONFIG_CACHE.with(|c| {
            let g = c.borrow();
            match g.as_ref() {
                Some(cc) if now.saturating_sub(cc.fetched_at) < CACHE_TTL_SECS => {
                    Some(cc.stores.clone())
                }
                _ => None,
            }
        });
        // 2. Stale or empty → load from D1 and cache it.
        let configs = match cached {
            Some(v) => v,
            None => {
                let v = load_configs(env).await;
                CONFIG_CACHE.with(|c| {
                    *c.borrow_mut() = Some(CachedConfig {
                        fetched_at: now,
                        stores: v.clone(),
                    })
                });
                v
            }
        };
        // 3. Build the live BlobStores (cheap: a binding lookup plus an S3Store struct).
        let library_pinned = configs.iter().any(|c| c.library_pin != 0);
        let stores = build_stores(env, configs);
        Ok(StorageRouter {
            env: env.clone(),
            stores,
            library_pinned,
        })
    }

    /// The placement slots `classify_placement` sees, in priority order.
    fn slots(&self) -> impl Iterator<Item = PlacementSlot<'_>> {
        self.stores.iter().map(|(m, _)| PlacementSlot {
            state: &m.state,
            max_bytes: m.max_bytes,
            used_bytes: m.used_bytes,
            pinned: m.library_pin,
        })
    }

    /// Is media storage CONFIGURED at all — i.e. is there at least one usable backend?
    /// `disabled` backends do NOT count (fully closed); `active/readonly/draining` do (reads
    /// keep working at minimum). On an install with no R2 binding but an active S3 this is
    /// true → capabilities report `media=true`. No non-disabled backend → 503
    /// `media_not_configured`.
    pub fn any_available(&self) -> bool {
        self.stores.iter().any(|(m, _)| m.state != "disabled")
    }

    /// Place a new blob → returns the store_id it was written to (the caller records it in the
    /// meta row). POLICY: among the `active` backends in priority order, write to the FIRST
    /// one where `used_bytes + size <= max_bytes`; on a PUT failure mark health and fall
    /// through to the NEXT eligible backend (degraded write). All full → `AllFull` (→ 429
    /// quota); every attempt failed the PUT → `AllFailed` (→ 503); no active backend →
    /// `NoActive`. With a lone r2-primary (max_bytes NULL) this is just "write to the first
    /// backend". The one class-specific rule is the library pin (`pinned_only`).
    pub async fn put_new(
        &self,
        class: StorageClass,
        key: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> std::result::Result<String, PlacementError> {
        let size = bytes.len() as i64;
        let plan = classify_placement(self.slots(), size, pinned_only(&class, self.library_pinned));
        let candidates = match plan {
            Placement::Candidates(idxs) => idxs,
            Placement::AllFull => return Err(PlacementError::AllFull),
            Placement::NoActive => return Err(PlacementError::NoActive),
        };
        // Try the eligible active backends in priority order; the first success wins.
        // PUT failure → opportunistic health mark + fall through to the next (degraded write).
        for idx in candidates {
            let (meta, store) = &self.stores[idx];
            match store.put(key, bytes.clone(), content_type).await {
                Ok(()) => return Ok(meta.store_id.clone()),
                Err(e) => {
                    write_health(&self.env, &meta.store_id, false, Some(&short(&e))).await;
                    console_warn!("storage: put fail {} → fallback: {e:?}", meta.store_id);
                }
            }
        }
        Err(PlacementError::AllFailed)
    }

    /// Place a blob WITHOUT the per-candidate clone `put_new` makes.
    ///
    /// `put_new` falls through to the next backend when a PUT fails, and to keep the bytes for
    /// that second attempt it clones them — on EVERY attempt, including the only one a
    /// single-backend install makes. At 50 MiB that is affordable; a 30 MB instrument pack in a
    /// 128 MB isolate would be held twice for nothing. This one MOVES the bytes into the first
    /// eligible backend and reports the failure instead, which is the right trade for an object
    /// the operator uploads by hand and can simply upload again.
    pub async fn put_once(
        &self,
        class: StorageClass,
        key: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> std::result::Result<String, PlacementError> {
        let size = bytes.len() as i64;
        let plan = classify_placement(self.slots(), size, pinned_only(&class, self.library_pinned));
        let idx = match plan {
            Placement::Candidates(idxs) => idxs[0],
            Placement::AllFull => return Err(PlacementError::AllFull),
            Placement::NoActive => return Err(PlacementError::NoActive),
        };
        let (meta, store) = &self.stores[idx];
        match store.put(key, bytes, content_type).await {
            Ok(()) => Ok(meta.store_id.clone()),
            Err(e) => {
                write_health(&self.env, &meta.store_id, false, Some(&short(&e))).await;
                console_warn!("storage: put_once fail {} → {e:?}", meta.store_id);
                Err(PlacementError::AllFailed)
            }
        }
    }

    /// Stream a blob out of the backend recorded in store_id — the `get` twin for an object too
    /// big to hold in memory. `offset` is the start byte of an open-ended range (0 = the whole
    /// object). Health marking matches `get`.
    pub async fn get_stream(
        &self,
        store_id: &str,
        key: &str,
        offset: u64,
    ) -> Result<Option<super::BlobStream>> {
        let store = self.resolve(store_id)?;
        match store.get_stream(key, offset).await {
            Ok(v) => Ok(v),
            Err(e) => {
                write_health(&self.env, store_id, false, Some(&short(&e))).await;
                Err(e)
            }
        }
    }

    /// Read from the backend recorded in store_id. Unknown store_id → Err: either the blob's
    /// backend is missing from this isolate's cache (the ≤60s window after it was added) or its
    /// config failed to parse. A genuine backend error → health mark + Err (the caller returns
    /// 503 `storage_backend_unavailable`, retryable).
    pub async fn get(&self, store_id: &str, key: &str) -> Result<Option<BlobObject>> {
        let store = self.resolve(store_id)?;
        match store.get(key).await {
            Ok(v) => Ok(v),
            Err(e) => {
                write_health(&self.env, store_id, false, Some(&short(&e))).await;
                Err(e)
            }
        }
    }

    /// Delete from the backend recorded in store_id (idempotent — the BlobStore::delete
    /// contract). NO opportunistic health mark here: delete is reached both singly (ack) and in
    /// BULK (cleanup ≤500 / orphan retry ≤50), and a per-row health write would blow up those
    /// batches. The bulk path writes its own aggregated health mark (maintenance.rs); the
    /// single ack path propagates the Err to the caller, which KEEPS the meta row so the delete
    /// is retried.
    pub async fn delete(&self, store_id: &str, key: &str) -> Result<()> {
        self.resolve(store_id)?.delete(key).await
    }

    fn resolve(&self, store_id: &str) -> Result<&BlobStore> {
        self.stores
            .iter()
            .find(|(m, _)| m.store_id == store_id)
            .map(|(_, s)| s)
            .ok_or_else(|| Error::RustError(format!("unknown_store:{store_id}")))
    }
}

/// `worker::Error` → 120-char blurb for health `last_health_err` (truncated, secret-free).
fn short(e: &Error) -> String {
    e.to_string().chars().take(120).collect()
}

// ── Placement policy (PURE — unit-tested; independent of the worker types) ───────

/// A backend as placement sees it (state + cap/usage + the library pin).
struct PlacementSlot<'a> {
    state: &'a str,
    max_bytes: Option<i64>,
    used_bytes: i64,
    pinned: bool,
}

/// Does this placement consider pinned stores ONLY? For the library, while any store is pinned
/// (0041): a pin that spilled onto unpinned stores whenever the pinned ones were full or down
/// would place recordings exactly where the operator said they must not go, silently, at the
/// moment nobody is looking. Every other class ignores the pin.
fn pinned_only(class: &StorageClass, any_pinned: bool) -> bool {
    matches!(class, StorageClass::Library) && any_pinned
}

/// Placement classification (the pure core of put_new).
#[derive(Debug, PartialEq)]
enum Placement {
    /// INDICES of the backends to try (in priority order; all of them, for PUT fallback).
    Candidates(Vec<usize>),
    /// Active backends exist but NONE has room (all at max_bytes) → 429 quota.
    AllFull,
    /// No `active` backend at all (everything readonly/disabled) → 503.
    NoActive,
}

/// Pick the placement candidates out of the priority-ordered slots. Returns the indices of
/// the backends that are `active` AND (`max_bytes` NULL || `used_bytes + size <= max_bytes`),
/// in input order (= priority order). Overflow: first one full → falls to the second.
///
/// `pinned_only` narrows the field to pinned slots BEFORE anything else is decided, so "all
/// full" and "none active" are answered about the pinned stores alone — the library is refused
/// with the same two errors every class already maps, never placed elsewhere.
fn classify_placement<'a>(
    slots: impl Iterator<Item = PlacementSlot<'a>>,
    size: i64,
    pinned_only: bool,
) -> Placement {
    let mut candidates = Vec::new();
    let mut any_active = false;
    for (idx, s) in slots.enumerate() {
        if pinned_only && !s.pinned {
            continue; // the library is pinned elsewhere
        }
        if s.state != "active" {
            continue; // readonly/draining/disabled → excluded from placement
        }
        any_active = true;
        let fits = match s.max_bytes {
            None => true,
            Some(cap) => s.used_bytes.saturating_add(size) <= cap,
        };
        if fits {
            candidates.push(idx);
        }
    }
    if !candidates.is_empty() {
        Placement::Candidates(candidates)
    } else if any_active {
        Placement::AllFull // active backends exist, none of them has room
    } else {
        Placement::NoActive
    }
}

/// Load D1 `storage_backends` in priority order. FAULT-TOLERANT: missing table / D1 error /
/// no rows → fall back to a single `r2-primary` (active when the binding exists; with no
/// binding build_stores yields nothing → any_available false).
async fn load_configs(env: &Env) -> Vec<StoreConfig> {
    let Ok(db) = env.d1("DB") else {
        return fallback_configs();
    };
    let rows: Vec<StoreConfig> = match db
        .prepare(
            "SELECT store_id, kind, state, priority, max_bytes, used_bytes, config_json, \
             library_pin FROM storage_backends ORDER BY priority ASC",
        )
        .all()
        .await
    {
        Ok(res) => res.results().unwrap_or_default(),
        Err(_) => return fallback_configs(),
    };
    if rows.is_empty() {
        return fallback_configs();
    }
    rows
}

/// Fallback: `r2-primary` only (covers the missing-table window and D1 errors). Note this
/// ignores an r2-primary that is actually `disabled` in D1: if D1 cannot be read, the safest
/// assumption is to try the R2 binding as active.
fn fallback_configs() -> Vec<StoreConfig> {
    vec![StoreConfig {
        store_id: PRIMARY_STORE_ID.to_string(),
        kind: "r2_binding".to_string(),
        state: "active".to_string(),
        max_bytes: None,
        used_bytes: 0,
        config_json: "{}".to_string(),
        library_pin: 0,
    }]
}

/// Build the live `BlobStore`s from the config snapshot. A backend that cannot be built is
/// SKIPPED (opportunistic degrade): r2_binding with no MEDIA binding → skip; s3 whose config
/// fails to parse → log and skip (a get for a blob on that backend hits resolve Err → 503).
/// `disabled` backends are loaded too so reads/deletes keep working — put_new filters on
/// `active` anyway.
fn build_stores(env: &Env, configs: Vec<StoreConfig>) -> Vec<(StoreMeta, BlobStore)> {
    let mut out = Vec::new();
    for cfg in configs {
        match build_store(env, &cfg.kind, &cfg.config_json) {
            Ok(store) => out.push((
                StoreMeta {
                    store_id: cfg.store_id,
                    state: cfg.state,
                    max_bytes: cfg.max_bytes,
                    used_bytes: cfg.used_bytes,
                    library_pin: cfg.library_pin != 0,
                },
                store,
            )),
            Err(e) => {
                // A missing binding is silently normal; an s3 parse failure is an owner
                // mistake → warn.
                if cfg.kind != "r2_binding" {
                    console_warn!("storage: could not build '{}' ({}): {e}", cfg.store_id, cfg.kind);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(state: &str, max: Option<i64>, used: i64) -> PlacementSlot<'_> {
        PlacementSlot {
            state,
            max_bytes: max,
            used_bytes: used,
            pinned: false,
        }
    }

    fn pinned(state: &str, max: Option<i64>, used: i64) -> PlacementSlot<'_> {
        PlacementSlot {
            pinned: true,
            ..slot(state, max, used)
        }
    }

    /// The class-agnostic placement every class but a pinned library gets.
    fn plain<'a>(slots: impl Iterator<Item = PlacementSlot<'a>>, size: i64) -> Placement {
        classify_placement(slots, size, false)
    }

    #[test]
    fn a_single_unlimited_active_store_is_picked_first() {
        // A lone r2-primary (max NULL) → always the first candidate.
        let p = plain([slot("active", None, 0)].into_iter(), 100);
        assert_eq!(p, Placement::Candidates(vec![0]));
    }

    #[test]
    fn overflow_skips_the_full_store_and_falls_to_the_next() {
        // idx0 is full (0+100 > 10), idx1 has room → only idx1 qualifies.
        let p = plain(
            [slot("active", Some(10), 0), slot("active", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::Candidates(vec![1]));
    }

    #[test]
    fn two_fitting_stores_are_both_candidates_in_priority_order() {
        // Both have room → both qualify (for PUT fallback); input (= priority) order is kept.
        let p = plain(
            [slot("active", Some(1000), 0), slot("active", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::Candidates(vec![0, 1]));
    }

    #[test]
    fn exactly_at_the_ceiling_still_fits() {
        // used + size == cap → FITS (<=).
        let p = plain([slot("active", Some(100), 0)].into_iter(), 100);
        assert_eq!(p, Placement::Candidates(vec![0]));
        // used + size == cap+1 → DOES NOT FIT.
        let p = plain([slot("active", Some(99), 0)].into_iter(), 100);
        assert_eq!(p, Placement::AllFull);
    }

    #[test]
    fn readonly_and_disabled_are_excluded_from_placement() {
        // readonly + disabled on their own → NoActive (readonly is not writable).
        let p = plain(
            [slot("readonly", None, 0), slot("disabled", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::NoActive);
        // readonly(0) skipped, active(1) has room → only idx1 (readonly still reads, never writes).
        let p = plain(
            [slot("readonly", None, 0), slot("active", None, 0)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::Candidates(vec![1]));
    }

    #[test]
    fn every_active_store_full_yields_allfull() {
        // Two active backends, both full → AllFull (→ 429 quota).
        let p = plain(
            [slot("active", Some(10), 5), slot("active", Some(20), 20)].into_iter(),
            100,
        );
        assert_eq!(p, Placement::AllFull);
    }

    #[test]
    fn no_store_at_all_yields_noactive() {
        let p = plain(std::iter::empty(), 100);
        assert_eq!(p, Placement::NoActive);
    }

    // ── The library pin (0041) ──────────────────────────────────────────────────────────

    #[test]
    fn only_the_library_honours_the_pin_and_only_while_a_store_is_pinned() {
        assert!(pinned_only(&StorageClass::Library, true));
        assert!(!pinned_only(&StorageClass::Library, false), "nothing pinned → placed as usual");
        for class in [
            StorageClass::Media,
            StorageClass::PluginMedia,
            StorageClass::PluginCode,
        ] {
            assert!(!pinned_only(&class, true), "a pin never steers another class");
        }
    }

    /// r2-primary first in priority, the campus store pinned: the library goes to the campus
    /// store; everything else still goes to R2 first, campus store included as overflow.
    #[test]
    fn a_pinned_library_goes_only_to_pinned_stores() {
        let stores = || [slot("active", None, 0), pinned("active", None, 0)].into_iter();
        assert_eq!(classify_placement(stores(), 100, true), Placement::Candidates(vec![1]));
        assert_eq!(plain(stores(), 100), Placement::Candidates(vec![0, 1]));
    }

    /// Two pinned stores overflow into each other in priority order, and never into R2.
    #[test]
    fn pinned_stores_overflow_among_themselves() {
        let p = classify_placement(
            [
                slot("active", None, 0),
                pinned("active", Some(50), 0),
                pinned("active", None, 0),
            ]
            .into_iter(),
            100,
            true,
        );
        assert_eq!(p, Placement::Candidates(vec![2]));
    }

    /// The pin does not leak under pressure: full pinned stores are AllFull (429) and pinned
    /// stores that cannot be written are NoActive (503), even with an empty R2 beside them.
    #[test]
    fn a_full_or_closed_pin_refuses_rather_than_spilling() {
        let full = [slot("active", None, 0), pinned("active", Some(50), 0)];
        assert_eq!(classify_placement(full.into_iter(), 100, true), Placement::AllFull);
        let closed = [slot("active", None, 0), pinned("readonly", None, 0)];
        assert_eq!(classify_placement(closed.into_iter(), 100, true), Placement::NoActive);
        let draining = [slot("active", None, 0), pinned("draining", None, 0)];
        assert_eq!(classify_placement(draining.into_iter(), 100, true), Placement::NoActive);
    }
}
