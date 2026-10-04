//! Drain/move engine — moves the blobs of a `draining` backend onto the remaining active
//! ones; when its inventory reaches 0 the backend is flipped to `disabled` automatically.
//!
//! RUN PATHS: the 2-minute cron (`lib.rs scheduled`, every invocation) plus the
//! lazy-maintenance piggyback (`maintenance.rs`, claim key `maint_storage_move_at`).
//! At most `MOVE_BATCH` blobs per run — free-plan subrequest budget: ~5 calls per blob
//! (GET+PUT+2×D1+DELETE) → 4 blobs ≈ 20, safely inside the limit. Idempotent per blob: if
//! a run dies halfway the next one picks up where it stopped, because a blob whose meta
//! row still points at the source stays a candidate.
//!
//! GUARANTEES:
//! - **Race protection:** the meta update is CONDITIONAL (`... AND store_id=<source>` +
//!   RETURNING), so a double copy / double accounting is impossible. 0 rows has more than
//!   one cause — ack/TTL deleted the blob meanwhile, a concurrent run moved it, or the
//!   UPDATE hit a transient error — so before orphaning the target copy we check where the
//!   meta row points RIGHT NOW (`race_action`): meta == target → our copy is the canonical
//!   one, LEAVE IT ALONE. A wrong orphan tombstones the canonical blob, which is data loss;
//!   the fail-safe direction is to not orphan.
//! - **Source backend dies:** get-Err → skip the blob (the remaining counter does not drop,
//!   so the panel shows "drain stuck" via `draining_remaining`); the next run resumes once
//!   the backend is back.
//! - **Reads never break:** a blob is read from whatever backend its meta row names (the
//!   router loads draining/disabled backends too) → the old backend until it moves, the new
//!   one afterwards; no 404 window anywhere in the drain.

use std::collections::{BTreeMap, HashMap};

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use super::maint::insert_orphans;
use super::{invalidate_storage_cache, write_health, StorageClass, StorageRouter};
use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;

/// Max blobs moved per run — the free-plan subrequest budget.
const MOVE_BATCH: usize = 4;

/// The meta tables a store's inventory is spread over: media, plugin media, plugin code and the
/// group library. `candidates_sql` and `remaining_sql` repeat the store-id IN-list once per
/// table, and `in_binds_per_table` binds it that many times.
const META_TABLES: usize = 4;

/// A move candidate coming from the meta-table UNION (`candidates_sql`).
#[derive(Deserialize)]
struct MoveRow {
    chan: String, // 'media' | 'plugin_media' | 'plugin_code' | 'library'
    room_id: String,
    blob_id: String,
    size_bytes: i64,
    store_id: String, // source (draining) backend
}

/// Move-engine tick — called by the cron on every invocation and by the winner of the
/// lazy claim. With no draining backend it exits silently after ONE cheap SELECT.
/// Blob-level failures are swallowed and skipped (one bad blob does not kill the rest of
/// the batch); only D1/router setup failures return Err (the caller logs them).
pub(crate) async fn run_storage_move(env: &Env) -> Result<()> {
    let db = env.d1("DB")?;
    #[derive(Deserialize)]
    struct IdRow {
        store_id: String,
    }
    let draining: Vec<IdRow> = db
        .prepare("SELECT store_id FROM storage_backends WHERE state = 'draining' ORDER BY priority ASC")
        .all()
        .await?
        .results()?;
    if draining.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = draining.into_iter().map(|r| r.store_id).collect();

    // Candidates: the OLDEST ≤MOVE_BATCH blobs on a draining backend, over every meta table.
    let rows: Vec<MoveRow> = db
        .prepare(candidates_sql(ids.len()))
        .bind(&in_binds_per_table(&ids))?
        .all()
        .await?
        .results()?;

    if !rows.is_empty() {
        // FRESH config is MANDATORY (the isolate cache may be up to 60s stale): if a stale
        // cache still reports the draining backend as 'active', put_new would write the
        // blob back onto the SOURCE (same key!) and the following source-delete would be
        // DATA LOSS. Invalidating makes from_env re-read D1, which excludes draining
        // backends from placement (router classify_placement).
        invalidate_storage_cache();
        let router = StorageRouter::from_env(env).await?;
        let mut moved: Vec<(String, String, i64)> = Vec::new(); // (source, target, size)
        for row in &rows {
            match move_one(&db, &router, row).await {
                MoveOutcome::Moved { target, size } => {
                    moved.push((row.store_id.clone(), target, size));
                }
                MoveOutcome::Skipped => {}
                // No placement left (remaining backends full/closed): the rest of the batch
                // would hit the same wall → stop; the next run retries, and the frozen
                // remaining counter shows the panel "drain stuck".
                MoveOutcome::NoTarget => break,
            }
        }
        if !moved.is_empty() {
            transfer_counters(&db, &moved).await;
            console_log!("storage drain: moved {} blobs", moved.len());
        }
    }

    // Completion check: a draining backend whose inventory ran empty is flipped to
    // `disabled` and gets a final health note. The UPDATE is conditional
    // (`AND state='draining'`) so an owner PATCH that changed the state meanwhile wins.
    let remaining = remaining_counts(&db, &ids).await?;
    let now = now_secs() as i64;
    for id in &ids {
        if !drain_complete(remaining.get(id).copied().unwrap_or(0)) {
            continue;
        }
        if let Ok(stmt) = db
            .prepare(
                "UPDATE storage_backends SET state = 'disabled', updated_at = ? \
                 WHERE store_id = ? AND state = 'draining'",
            )
            .bind(&[d1_int(now), d1_text(id)])
        {
            let _ = stmt.run().await;
        }
        // Final health note (ok=true so the panel stays green; the text is the "drain
        // finished" breadcrumb).
        write_health(env, id, true, Some("drain_complete")).await;
        invalidate_storage_cache();
        console_log!("storage drain: '{}' is empty → disabled", id);
    }
    Ok(())
}

/// REMAINING inventory count per draining backend (counted over the meta-table UNION).
/// Shared by the completion check, `GET /admin/storage`'s `draining_remaining` and the
/// drain endpoint's response → "remaining" is defined in exactly one place. Every
/// requested id is present in the result (0 when it has no rows).
pub(crate) async fn remaining_counts(
    db: &D1Database,
    store_ids: &[String],
) -> Result<HashMap<String, i64>> {
    let mut out: HashMap<String, i64> = store_ids.iter().map(|s| (s.clone(), 0)).collect();
    if store_ids.is_empty() {
        return Ok(out);
    }
    #[derive(Deserialize)]
    struct Row {
        store_id: String,
        c: i64,
    }
    let rows: Vec<Row> = db
        .prepare(remaining_sql(store_ids.len()))
        .bind(&in_binds_per_table(store_ids))?
        .all()
        .await?
        .results()?;
    for r in rows {
        out.insert(r.store_id, r.c);
    }
    Ok(out)
}

// ── Moving a single blob ──────────────────────────────────────────────────────

enum MoveOutcome {
    /// Moved: meta points at the target; the source copy is deleted (or tombstoned).
    Moved { target: String, size: i64 },
    /// This blob was skipped (source error / phantom meta / race) — the batch continues.
    Skipped,
    /// No target could be placed (remaining backends full/closed) — the batch stops.
    NoTarget,
}

async fn move_one(db: &D1Database, router: &StorageRouter, row: &MoveRow) -> MoveOutcome {
    let Some((key, class)) = key_and_class(&row.chan, &row.room_id, &row.blob_id) else {
        return MoveOutcome::Skipped; // unknown channel (should not happen) — skip
    };
    // 1. Read from the source. Err = backend down / resolve failure: skip the blob
    //    (router.get already marked health); resume when it is back.
    let obj = match router.get(&row.store_id, &key).await {
        Ok(Some(o)) => o,
        Ok(None) => {
            // Phantom meta: the row exists but the blob physically does NOT (a read would
            // 404 too). Drop it with a conditional meta-DELETE so the drain can progress —
            // otherwise `created_at ASC` would keep picking the same phantoms and the drain
            // would wedge forever. Any quota / per-backend counter drift is repaired by the
            // daily reconcile (which recomputes from the meta tables).
            phantom_meta_delete(db, row).await;
            console_warn!("storage drain: missing at the source, meta dropped: {key}");
            return MoveOutcome::Skipped;
        }
        Err(_) => return MoveOutcome::Skipped,
    };
    let size = obj.bytes.len() as i64; // real size; counter transfer uses it, not the (drifty) meta
    // 2. Place onto the remaining backends under the SAME key (the mod.rs key scheme is
    //    backend-agnostic → a move is a copy, the key never changes). put_new only writes
    //    to 'active' backends, so the draining source is not a candidate.
    let target = match router.put_new(class, &key, obj.bytes, &obj.content_type).await {
        Ok(t) => t,
        Err(_) => return MoveOutcome::NoTarget,
    };
    if target == row.store_id {
        // Defence in depth (normally impossible: a draining backend is not 'active'): if
        // target == source, do NOT fall through to the delete — deleting the one key we
        // just wrote would be data loss.
        return MoveOutcome::Skipped;
    }
    // 3. Conditional meta-UPDATE (race protection): only a row that still points at the
    //    source is updated.
    match after_copy(conditional_meta_update(db, row, &target).await) {
        AfterCopy::OrphanTargetCopy => {
            // 0 rows: either the meta was deleted (ack/TTL race), or a concurrent run moved
            // it, or the UPDATE hit a transient error → base the orphan decision on where
            // the meta row points RIGHT NOW.
            if race_action(&meta_store_now(db, row).await, &target)
                == RaceAction::OrphanTargetCopy
            {
                insert_orphans(db, &[(target, key, row.size_bytes)]).await;
            }
            MoveOutcome::Skipped
        }
        AfterCopy::DeleteSource => {
            // 4. Delete from the source; if that fails, tombstone it — the meta already
            //    points at the target, so the leftover source copy is tracked as an orphan
            //    and the move still counts as PROGRESS.
            if router.delete(&row.store_id, &key).await.is_err() {
                insert_orphans(db, &[(row.store_id.clone(), key.clone(), row.size_bytes)]).await;
            }
            MoveOutcome::Moved { target, size }
        }
    }
}

/// Run the conditional meta-UPDATE → did it update exactly 1 row (counted via RETURNING,
/// the claim-winner pattern from maintenance.rs). On error → false (treated as "not
/// updated"; the decision is then made by `race_action` looking at the meta row, so this
/// never orphans in the wrong direction).
async fn conditional_meta_update(db: &D1Database, row: &MoveRow, target: &str) -> bool {
    #[derive(Deserialize)]
    struct Ret {
        #[allow(dead_code)]
        blob_id: String,
    }
    let Some(sql) = meta_update_sql(&row.chan) else {
        return false;
    };
    let mut binds = vec![d1_text(target)];
    binds.extend(key_binds(row));
    let Ok(stmt) = db.prepare(sql).bind(&binds) else {
        return false;
    };
    match stmt.all().await {
        Ok(res) => res.results::<Ret>().map(|r| r.len() == 1).unwrap_or(false),
        Err(_) => false,
    }
}

/// Conditional DELETE of a phantom meta row (best-effort): only a row still pointing at
/// the source is dropped — if a concurrent run moved it meanwhile (meta == target) the row
/// is LEFT ALONE.
async fn phantom_meta_delete(db: &D1Database, row: &MoveRow) {
    let Some(sql) = meta_delete_sql(&row.chan) else {
        return;
    };
    if let Ok(stmt) = db.prepare(sql).bind(&key_binds(row)) {
        let _ = stmt.run().await;
    }
}

/// Which backend does the meta row point at RIGHT NOW? (Input to the post-race orphan
/// decision.)
async fn meta_store_now(db: &D1Database, row: &MoveRow) -> MetaNow {
    #[derive(Deserialize)]
    struct S {
        store_id: String,
    }
    let Some(sql) = meta_select_sql(&row.chan) else {
        return MetaNow::Unknown;
    };
    let binds: Vec<JsValue> = if row.chan == "media" {
        vec![d1_text(&row.blob_id)]
    } else {
        vec![d1_text(&row.room_id), d1_text(&row.blob_id)]
    };
    let Ok(stmt) = db.prepare(sql).bind(&binds) else {
        return MetaNow::Unknown;
    };
    match stmt.first::<S>(None).await {
        Ok(Some(s)) => MetaNow::PointsTo(s.store_id),
        Ok(None) => MetaNow::Gone,
        Err(_) => MetaNow::Unknown,
    }
}

/// Transfer the used_bytes/object_count counters (best-effort; drift is repaired by the
/// daily reconcile). One `db.batch` = one subrequest; clamped at 0 (usage.rs rule).
async fn transfer_counters(db: &D1Database, moved: &[(String, String, i64)]) {
    let now = now_secs() as i64;
    let mut stmts: Vec<D1PreparedStatement> = Vec::new();
    for (store_id, d_bytes, d_count) in counter_deltas(moved) {
        if let Ok(stmt) = db
            .prepare(
                "UPDATE storage_backends SET used_bytes = MAX(0, used_bytes + ?), \
                 object_count = MAX(0, object_count + ?), updated_at = ? WHERE store_id = ?",
            )
            .bind(&[d1_int(d_bytes), d1_int(d_count), d1_int(now), d1_text(&store_id)])
        {
            stmts.push(stmt);
        }
    }
    if !stmts.is_empty() {
        let _ = db.batch(stmts).await;
    }
}

/// Per-channel key binds: media=[blob,source]; plugin_* and library=[room,blob,source] —
/// exactly the WHERE order of `meta_update_sql`/`meta_delete_sql`.
fn key_binds(row: &MoveRow) -> Vec<JsValue> {
    if row.chan == "media" {
        vec![d1_text(&row.blob_id), d1_text(&row.store_id)]
    } else {
        vec![
            d1_text(&row.room_id),
            d1_text(&row.blob_id),
            d1_text(&row.store_id),
        ]
    }
}

/// The IN-list binds repeated once per table (matches candidates_sql/remaining_sql).
fn in_binds_per_table(ids: &[String]) -> Vec<JsValue> {
    let mut binds = Vec::with_capacity(ids.len() * META_TABLES);
    for _ in 0..META_TABLES {
        for id in ids {
            binds.push(d1_text(id));
        }
    }
    binds
}

// ── Pure core (unit-tested; independent of the worker types) ──────────────────

/// Move candidate → (storage key, placement class). The key scheme lives solely in mod.rs
/// (`media_key`/`plugin_media_key`/`code_key`) — every backend uses the SAME key. Unknown
/// channel → None (skip).
fn key_and_class(chan: &str, room_id: &str, blob_id: &str) -> Option<(String, StorageClass)> {
    match chan {
        "media" => Some((super::media_key(blob_id), StorageClass::Media)),
        "plugin_media" => Some((
            super::plugin_media_key(room_id, blob_id),
            StorageClass::PluginMedia,
        )),
        "plugin_code" => Some((super::code_key(room_id, blob_id), StorageClass::PluginCode)),
        // The library's class carries its pin: a part leaving a draining store lands on a pinned
        // store when one is set, exactly as a new upload would.
        "library" => Some((super::library_key(room_id, blob_id), StorageClass::Library)),
        _ => None,
    }
}

/// Channel → conditional meta-UPDATE (race protection: `AND store_id = ?` + RETURNING;
/// binds: [target] + `key_binds`). Unknown channel → None.
fn meta_update_sql(chan: &str) -> Option<&'static str> {
    match chan {
        "media" => Some(
            "UPDATE media_objects SET store_id = ? \
             WHERE blob_id = ? AND store_id = ? RETURNING blob_id",
        ),
        "plugin_media" => Some(
            "UPDATE plugin_media_objects SET store_id = ? \
             WHERE room_id = ? AND blob_id = ? AND store_id = ? RETURNING blob_id",
        ),
        "plugin_code" => Some(
            "UPDATE plugin_code_objects SET store_id = ? \
             WHERE room_id = ? AND blob_id = ? AND store_id = ? RETURNING blob_id",
        ),
        // `object_id AS blob_id`: the RETURNING row is read into the same one-field struct.
        "library" => Some(
            "UPDATE room_library_objects SET store_id = ? \
             WHERE room_id = ? AND object_id = ? AND store_id = ? RETURNING object_id AS blob_id",
        ),
        _ => None,
    }
}

/// Channel → conditional DELETE of a phantom meta row (binds: `key_binds`).
fn meta_delete_sql(chan: &str) -> Option<&'static str> {
    match chan {
        "media" => Some("DELETE FROM media_objects WHERE blob_id = ? AND store_id = ?"),
        "plugin_media" => Some(
            "DELETE FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? AND store_id = ?",
        ),
        "plugin_code" => Some(
            "DELETE FROM plugin_code_objects WHERE room_id = ? AND blob_id = ? AND store_id = ?",
        ),
        "library" => Some(
            "DELETE FROM room_library_objects WHERE room_id = ? AND object_id = ? AND store_id = ?",
        ),
        _ => None,
    }
}

/// Channel → "where does the meta point now" SELECT (binds: media=[blob];
/// plugin_*=[room,blob]).
fn meta_select_sql(chan: &str) -> Option<&'static str> {
    match chan {
        "media" => Some("SELECT store_id FROM media_objects WHERE blob_id = ? LIMIT 1"),
        "plugin_media" => Some(
            "SELECT store_id FROM plugin_media_objects WHERE room_id = ? AND blob_id = ? LIMIT 1",
        ),
        "plugin_code" => Some(
            "SELECT store_id FROM plugin_code_objects WHERE room_id = ? AND blob_id = ? LIMIT 1",
        ),
        "library" => Some(
            "SELECT store_id FROM room_library_objects WHERE room_id = ? AND object_id = ? LIMIT 1",
        ),
        _ => None,
    }
}

/// Conditional-UPDATE result → what to do after the copy (PURE):
/// 1 row = the meta now points at the target → delete the source;
/// 0 rows = suspected race → the fate of the target copy is decided by `race_action`.
#[derive(Debug, PartialEq)]
enum AfterCopy {
    DeleteSource,
    OrphanTargetCopy,
}

fn after_copy(meta_updated: bool) -> AfterCopy {
    if meta_updated {
        AfterCopy::DeleteSource
    } else {
        AfterCopy::OrphanTargetCopy
    }
}

/// State of the meta row observed right after the conditional UPDATE.
#[derive(Debug, PartialEq)]
enum MetaNow {
    /// No row — an ack/TTL race deleted the blob.
    Gone,
    /// Row present, pointing at this backend.
    PointsTo(String),
    /// D1 could not be read (transient error).
    Unknown,
}

/// Decide the fate of the target copy after a 0-row race (PURE): orphan it only on a
/// POSITIVE observation that the meta does NOT point at the target. meta == target → a
/// concurrent run moved it to the same place, our copy is CANONICAL → leave it. Unknown →
/// fail-safe LEAVE IT (a wrong orphan tombstones the canonical blob = data loss; a stray
/// copy merely wastes bytes on the target and loses nothing).
#[derive(Debug, PartialEq)]
enum RaceAction {
    OrphanTargetCopy,
    LeaveTargetCopy,
}

fn race_action(meta_now: &MetaNow, target: &str) -> RaceAction {
    match meta_now {
        MetaNow::Gone => RaceAction::OrphanTargetCopy,
        MetaNow::PointsTo(s) if s == target => RaceAction::LeaveTargetCopy,
        MetaNow::PointsTo(_) => RaceAction::OrphanTargetCopy,
        MetaNow::Unknown => RaceAction::LeaveTargetCopy,
    }
}

/// Completion check (PURE): no inventory left on the draining backend → auto-`disabled`.
fn drain_complete(remaining: i64) -> bool {
    remaining <= 0
}

/// Move-candidate SQL for n draining backends: UNION over the `META_TABLES` meta tables, oldest
/// first, ≤MOVE_BATCH. Binds = `in_binds_per_table` (the id list once per table).
///
/// A table left out of this UNION is the dangerous omission: its blobs are never moved,
/// `remaining_sql` (if it also leaves the table out) reports the store empty, the store flips to
/// `disabled`, and the owner may then delete it with those blobs still on it.
fn candidates_sql(n_stores: usize) -> String {
    let marks = placeholders(n_stores);
    format!(
        "SELECT 'media' AS chan, '' AS room_id, blob_id, size_bytes, store_id, created_at \
           FROM media_objects WHERE store_id IN ({marks}) \
         UNION ALL \
         SELECT 'plugin_media' AS chan, room_id, blob_id, size_bytes, store_id, created_at \
           FROM plugin_media_objects WHERE store_id IN ({marks}) \
         UNION ALL \
         SELECT 'plugin_code' AS chan, room_id, blob_id, size_bytes, store_id, created_at \
           FROM plugin_code_objects WHERE store_id IN ({marks}) \
         UNION ALL \
         SELECT 'library' AS chan, room_id, object_id AS blob_id, size_bytes, store_id, created_at \
           FROM room_library_objects WHERE store_id IN ({marks}) \
         ORDER BY created_at ASC LIMIT {MOVE_BATCH}"
    )
}

/// Remaining-inventory SQL for n backends (counted per store_id). Binds = `in_binds_per_table`.
fn remaining_sql(n_stores: usize) -> String {
    let marks = placeholders(n_stores);
    format!(
        "SELECT store_id, COUNT(*) AS c FROM ( \
           SELECT store_id FROM media_objects WHERE store_id IN ({marks}) \
           UNION ALL SELECT store_id FROM plugin_media_objects WHERE store_id IN ({marks}) \
           UNION ALL SELECT store_id FROM plugin_code_objects WHERE store_id IN ({marks}) \
           UNION ALL SELECT store_id FROM room_library_objects WHERE store_id IN ({marks}) \
         ) t GROUP BY store_id"
    )
}

fn placeholders(n: usize) -> String {
    (0..n).map(|_| "?").collect::<Vec<_>>().join(",")
}

/// List of moved (source, target, size) → per-backend (Δbytes, Δcount): minus on the
/// source, plus on the target; output sorted by store_id for determinism (PURE; consumed by
/// `transfer_counters`).
fn counter_deltas(moved: &[(String, String, i64)]) -> Vec<(String, i64, i64)> {
    let mut map: BTreeMap<&str, (i64, i64)> = BTreeMap::new();
    for (source, target, size) in moved {
        let e = map.entry(source.as_str()).or_insert((0, 0));
        e.0 -= size;
        e.1 -= 1;
        let e = map.entry(target.as_str()).or_insert((0, 0));
        e.0 += size;
        e.1 += 1;
    }
    map.into_iter()
        .map(|(k, (b, c))| (k.to_string(), b, c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The candidate key/class mapping is bit-identical to the mod.rs key scheme
    /// (a move is a copy, the key never changes — the precondition for draining).
    #[test]
    fn candidate_key_and_class_schema() {
        let (k, c) = key_and_class("media", "", "b1").unwrap();
        assert_eq!(k, "media/b1");
        assert!(matches!(c, StorageClass::Media));
        let (k, c) = key_and_class("plugin_media", "r1", "b1").unwrap();
        assert_eq!(k, "plugin-media/r1/b1");
        assert!(matches!(c, StorageClass::PluginMedia));
        let (k, c) = key_and_class("plugin_code", "r1", "b1").unwrap();
        assert_eq!(k, "plugin-code/r1/b1");
        assert!(matches!(c, StorageClass::PluginCode));
        let (k, c) = key_and_class("library", "r1", "b1").unwrap();
        assert_eq!(k, "room-library/r1/b1");
        assert!(
            matches!(c, StorageClass::Library),
            "a moved library part must carry its class, or the pin is ignored on the way out"
        );
        assert!(key_and_class("bogus", "r", "b").is_none());
    }

    /// Candidate SQL: every meta table × n placeholders (matching in_binds_per_table), oldest
    /// first, per-run ceiling MOVE_BATCH.
    #[test]
    fn candidate_sql_placeholder_order_and_limit() {
        let sql = candidates_sql(2);
        assert_eq!(sql.matches('?').count(), META_TABLES * 2, "every table × 2 ids");
        assert!(sql.contains("ORDER BY created_at ASC"));
        assert!(sql.ends_with(&format!("LIMIT {MOVE_BATCH}")));
        assert!(sql.contains("FROM media_objects"));
        assert!(sql.contains("FROM plugin_media_objects"));
        assert!(sql.contains("FROM plugin_code_objects"));
        assert!(sql.contains("FROM room_library_objects"));
    }

    /// Conditional-UPDATE semantics: every channel's SQL is source-conditional
    /// (`AND store_id = ?`) and uses RETURNING (0-row race detection); the phantom DELETE
    /// is conditional too. Unknown channel → None (no unconditional mutation path exists).
    #[test]
    fn the_conditional_update_protects_against_races() {
        for chan in ["media", "plugin_media", "plugin_code", "library"] {
            let sql = meta_update_sql(chan).unwrap();
            assert!(sql.contains("AND store_id = ?"), "{chan}: an unconditional UPDATE is forbidden");
            assert!(
                sql.contains("RETURNING ") && sql.ends_with("blob_id"),
                "{chan}: race detection needs RETURNING, read back as `blob_id`"
            );
            let del = meta_delete_sql(chan).unwrap();
            assert!(del.contains("store_id = ?"), "{chan}: the ghost DELETE is conditional too");
            assert!(meta_select_sql(chan).is_some());
        }
        assert!(meta_update_sql("bogus").is_none());
        assert!(meta_delete_sql("bogus").is_none());
        assert!(meta_select_sql("bogus").is_none());
    }

    /// Conditional-UPDATE result → action: 1 row = delete the source; 0 rows = the target
    /// copy is a suspected orphan (race_action makes the call).
    #[test]
    fn action_after_the_copy() {
        assert_eq!(after_copy(true), AfterCopy::DeleteSource);
        assert_eq!(after_copy(false), AfterCopy::OrphanTargetCopy);
    }

    /// Race decision: meta gone → orphan; meta on a
    /// different backend → orphan; meta == TARGET → canonical, LEAVE IT; D1 unreadable →
    /// fail-safe LEAVE IT (a wrong orphan is the data-loss direction).
    #[test]
    fn the_race_decision_is_fail_safe() {
        assert_eq!(
            race_action(&MetaNow::Gone, "r2-primary"),
            RaceAction::OrphanTargetCopy
        );
        assert_eq!(
            race_action(&MetaNow::PointsTo("s3-x".into()), "r2-primary"),
            RaceAction::OrphanTargetCopy
        );
        assert_eq!(
            race_action(&MetaNow::PointsTo("r2-primary".into()), "r2-primary"),
            RaceAction::LeaveTargetCopy
        );
        assert_eq!(
            race_action(&MetaNow::Unknown, "r2-primary"),
            RaceAction::LeaveTargetCopy
        );
    }

    /// Completion check: 0 remaining → the backend's drain is done (auto-disabled).
    #[test]
    fn completion_detection() {
        assert!(drain_complete(0));
        assert!(!drain_complete(1));
        assert!(!drain_complete(87));
    }

    /// Counter transfer: minus on the source / plus on the target, summed per backend,
    /// ordered by store_id.
    #[test]
    fn counter_transfers_accumulate() {
        let moved = vec![
            ("s3-a".to_string(), "r2-primary".to_string(), 100),
            ("s3-a".to_string(), "r2-primary".to_string(), 50),
            ("s3-a".to_string(), "s3-b".to_string(), 7),
        ];
        let d = counter_deltas(&moved);
        assert_eq!(
            d,
            vec![
                ("r2-primary".to_string(), 150, 2),
                ("s3-a".to_string(), -157, -3),
                ("s3-b".to_string(), 7, 1),
            ]
        );
        assert!(counter_deltas(&[]).is_empty());
    }

    /// The library leg of the move engine against the REAL schema: a candidate names a part by
    /// room and id under `chan = 'library'`, the remaining count sees it, the conditional UPDATE
    /// moves exactly that row and reads back as `blob_id`, a replay from the old source moves
    /// nothing, and the phantom DELETE only ever drops a row still on the store it names.
    #[test]
    fn the_library_leg_runs_against_the_real_schema() {
        use rusqlite::{params, params_from_iter, OptionalExtension};
        let db = crate::test_schema::full_schema();
        let part = "obj-000000000001";
        db.execute_batch(
            "INSERT INTO room_library_objects
               (room_id, object_id, uploader_id, size_bytes, store_id, created_at) VALUES
               ('r1', 'obj-000000000001', 'u1', 700, 's3-old0000', 5),
               ('r1', 'obj-000000000002', 'u1', 300, 'r2-primary', 6);",
        )
        .unwrap();
        let draining = ["s3-old0000".to_string()];
        let binds = || params_from_iter(draining.iter().cycle().take(META_TABLES));

        let candidates: Vec<(String, String, String, i64, String)> = db
            .prepare(&candidates_sql(1))
            .unwrap()
            .query_map(binds(), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            candidates,
            [("library".into(), "r1".into(), part.into(), 700, "s3-old0000".into())]
        );
        let remaining: i64 = db
            .query_row(&remaining_sql(1), binds(), |r| r.get(1))
            .unwrap();
        assert_eq!(remaining, 1, "a store holding a library part is not empty");

        let update = meta_update_sql("library").unwrap();
        let moved = |source: &str| -> Option<String> {
            db.query_row(update, params!["r2-primary", "r1", part, source], |r| r.get("blob_id"))
                .optional()
                .unwrap()
        };
        assert_eq!(moved("s3-old0000").as_deref(), Some(part));
        assert_eq!(moved("s3-old0000"), None, "a second mover finds the row already gone");
        let now: String = db
            .query_row(meta_select_sql("library").unwrap(), params!["r1", part], |r| r.get(0))
            .unwrap();
        assert_eq!(now, "r2-primary");

        let ghost = meta_delete_sql("library").unwrap();
        assert_eq!(db.execute(ghost, params!["r1", part, "s3-old0000"]).unwrap(), 0);
        assert_eq!(db.execute(ghost, params!["r1", part, "r2-primary"]).unwrap(), 1);
    }

    /// Remaining-inventory SQL: placeholders for every meta table + grouping per backend. A
    /// table missing here reports a store holding its blobs as empty, and an empty draining
    /// store is flipped to `disabled` and becomes deletable.
    #[test]
    fn remaining_sql_is_grouped() {
        let sql = remaining_sql(1);
        assert_eq!(sql.matches('?').count(), META_TABLES);
        assert!(sql.contains("GROUP BY store_id"));
        assert!(sql.contains("FROM room_library_objects"));
    }
}
