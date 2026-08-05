//! Lazy maintenance — cron-independent upkeep (part of the 2026-07-06 hardening package).
//!
//! FIELD RATIONALE: the CF free plan caps cron triggers per account. A SECOND sezi-server
//! deployed into the same account fails `wrangler deploy`'s schedules step with
//! "account-plan-limits" and ends up with NO CRON, so the daily GC and the 2-minute
//! fanout drain NEVER run: the retry queue piles up and expired-media/token cleanup
//! stops. The fix is to let maintenance tasks also run piggybacked on requests, making
//! the cron just one way to keep maintenance fresh rather than the ONLY way.
//!
//! TEMPLATE COMPATIBILITY: the template deployment has no `[triggers]` in
//! `wrangler.toml` (account cron limit), so maintenance runs entirely off the lazy path;
//! on a cron-enabled deployment the stamps stay fresh and the lazy path sleeps. The
//! monorepo prod `wrangler.toml` `[triggers]` was left UNTOUCHED — there the cron runs
//! and this module stays quiet.
//!
//! MECHANISM — three timestamps in `server_config` (the 0025 key-value table):
//!   - `maint_drain_at`        = epoch seconds of the last fanout-drain pass
//!   - `maint_daily_at`        = epoch seconds of the last daily GC
//!   - `maint_storage_move_at` = epoch seconds of the last storage-move (drain) tick (phase 4)
//!
//! `scheduled()` refreshes its own stamp on EVERY run, so with a working cron the stamp
//! never goes stale and the lazy path is NEVER triggered (prod stays bit-identical).
//! Without a cron the stamp ages, and the first eligible request runs maintenance in the
//! background via `ctx.wait_until` — the response is never delayed.
//!
//! COST DISCIPLINE: NO extra D1 read per request. An isolate-local `thread_local`
//! last-checked timestamp limits D1 lookups to roughly one per 60s, and even that lookup
//! happens inside `wait_until` (zero added latency on the request critical path).
//!
//! RACE NARROWING (winner pattern): when a stamp looks stale, the stamp is pushed
//! forward FIRST via `UPDATE ... WHERE CAST(value AS INTEGER) <= stale-cutoff RETURNING
//! key`. D1 serializes UPDATEs, so only the FIRST winner gets a row back and the loser
//! skips the work. Failing to win means another isolate is already running it, so each
//! task executes once. (The tasks themselves are also concurrency-safe — see the
//! per-function comments below — the winner pattern merely avoids pointless double work.)

use std::cell::Cell;

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth::hashing::sha256_hex;
use crate::d1util::{d1_blob, d1_int, d1_null, d1_opt_int, d1_opt_text, d1_text};
use crate::utils::now_secs;

/// Isolate-local throttle on D1 lookups: the stamp SELECT runs at most once per this
/// interval, never per request (a WASM isolate is single-threaded, so a thread_local is
/// an isolate-wide memo — the same pattern self_provision uses).
const CHECK_EVERY_SECS: u64 = 60;

/// Lazy drain threshold. The cron interval is 120s but the threshold is DELIBERATELY
/// 300s (2.5×): CF scheduled events are not second-accurate and a cron can be seconds or
/// minutes late. At exactly 120s, cron-enabled PROD would fire the lazy path routinely in
/// the "the stamp just passed 120s, the cron is about to run" window — a double drain is
/// harmless, but it would break the "lazy sleeps on cron-enabled deployments" contract.
/// The 2.5× jitter margin means lazy only wakes when the cron is TRULY dead; on a
/// cron-less deployment the drain cadence is ~5 minutes while traffic exists, which is
/// enough given the retry queue's own backoff buffer.
const DRAIN_LAZY_AFTER_SECS: i64 = 300;

/// Lazy daily-GC threshold: 24h plus a 1h margin (same jitter rationale — the daily
/// "0 4 * * *" cron refreshes the stamp exactly every 86400s, so a threshold with no
/// margin would race on the boundary).
const DAILY_LAZY_AFTER_SECS: i64 = 90_000;

/// Lazy storage-move threshold (pluggable storage phase 4) — SAME rationale and cadence
/// as the drain (2-minute cron × 2.5 jitter margin): on a cron-enabled deployment every
/// scheduled run does a move tick and stamps it, so lazy sleeps; without a cron it runs
/// on a ~5-minute cadence. The drain endpoint pulls the stamp to 0 (`wake_storage_move`)
/// so the START of a move does not wait out the threshold — the first eligible request
/// claims it within the ≤60s throttle window.
const MOVE_LAZY_AFTER_SECS: i64 = 300;

// Compile-time contract lock: the lazy thresholds must not drop BELOW the cron cadences
// (drain "*/2 * * * *" = 120s, daily "0 4 * * *" = 86400s) — if they did, lazy would wake
// routinely on cron-enabled prod (a double run is harmless, but it breaks the "prod is
// bit-identical" contract). The drain/move asserts lock in a 2× margin.
const _: () = assert!(DRAIN_LAZY_AFTER_SECS >= 2 * 120);
const _: () = assert!(DAILY_LAZY_AFTER_SECS > 86_400);
const _: () = assert!(MOVE_LAZY_AFTER_SECS >= 2 * 120);

const KEY_DRAIN: &str = "maint_drain_at";
const KEY_DAILY: &str = "maint_daily_at";
const KEY_MOVE: &str = "maint_storage_move_at";

thread_local! {
    /// Time of the last D1 stamp check (epoch seconds; 0 = this isolate never looked).
    static LAST_CHECK: Cell<u64> = const { Cell::new(0) };
}

// ── fetch-path entry point ──────────────────────────────────────────────────

/// Called from the `#[event(fetch)]` entry point, right after ensure_ready. Its cost on
/// the request critical path is `Date.now()` plus a thread_local comparison — no D1, no
/// await. If the throttle window is open, the stamp check and any resulting maintenance
/// run ENTIRELY in the background via `ctx.wait_until`, so the response is never delayed.
/// BEST-EFFORT: every error is logged and swallowed; the request is never affected.
pub fn maybe_run_lazy(env: &Env, ctx: &Context) {
    let now = now_secs();
    let due = LAST_CHECK.with(|c| {
        if throttle_due(c.get(), now, CHECK_EVERY_SECS) {
            // Advance the marker IMMEDIATELY (single-threaded, so no race): subsequent
            // requests on the same isolate touch D1 not at all for 60s.
            c.set(now);
            true
        } else {
            false
        }
    });
    if !due {
        return;
    }
    let env = env.clone();
    ctx.wait_until(async move { check_and_run(env).await });
}

/// Read the stamps → try the winner pattern for each stale task → run whatever we won.
/// Order: drain first (frequent/cheap), then the storage-move tick, then the daily GC
/// (rare/heavy).
async fn check_and_run(env: Env) {
    let Ok(db) = env.d1("DB") else { return };
    let now = now_secs() as i64;
    let (drain_at, daily_at, move_at) = match read_stamps(&db).await {
        Ok(v) => v,
        // Transient D1 error → try again in the next throttle window.
        Err(_) => return,
    };
    if is_due(now, drain_at, DRAIN_LAZY_AFTER_SECS)
        && claim(&db, KEY_DRAIN, now, now - DRAIN_LAZY_AFTER_SECS).await
    {
        console_log!(
            "maintenance: lazy drain (stamp is {}s old — a cron-less install, or the cron ran late)",
            now - drain_at
        );
        crate::messages::handlers::drain_fanout_retry(&env).await;
        // On a Pi/workerd `wrangler dev` deployment the scheduled event may never fire.
        // Even when the membership row is already gone from D1, if the first UserInbox
        // purge call hit a transient error the account-purge outbox converges off this
        // same lazy drain stamp.
        crate::membership::drain_purge_outbox(&env).await;
    }
    // Pluggable storage phase 4: draining-backend move tick (≤4 blobs per run). On a
    // cron-enabled deployment every scheduled run ticks and stamps, so this sleeps. With
    // no draining backend, run_storage_move returns quietly after its first SELECT (one
    // cheap query).
    if is_due(now, move_at, MOVE_LAZY_AFTER_SECS)
        && claim(&db, KEY_MOVE, now, now - MOVE_LAZY_AFTER_SECS).await
    {
        console_log!(
            "maintenance: lazy storage move (stamp is {}s old)",
            now - move_at
        );
        if let Err(e) = crate::storage::drain::run_storage_move(&env).await {
            let msg = e.to_string();
            let truncated: String = msg.chars().take(80).collect();
            console_log!("storage move error: {}", truncated);
        }
    }
    if is_due(now, daily_at, DAILY_LAZY_AFTER_SECS)
        && claim(&db, KEY_DAILY, now, now - DAILY_LAZY_AFTER_SECS).await
    {
        console_log!(
            "maintenance: lazy daily GC (stamp is {}s old)",
            now - daily_at
        );
        run_daily(&env).await;
    }
}

// ── stamp reads / winner pattern ────────────────────────────────────────────

/// Read all three stamps in ONE SELECT (epoch seconds; a missing row or a corrupt value
/// becomes 0 = "very old" → the task runs once on the first eligible request and gets
/// stamped).
async fn read_stamps(db: &D1Database) -> Result<(i64, i64, i64)> {
    #[derive(Deserialize)]
    struct Row {
        key: String,
        value: String,
    }
    let rows: Vec<Row> = db
        .prepare("SELECT key, value FROM server_config WHERE key IN (?, ?, ?)")
        .bind(&[d1_text(KEY_DRAIN), d1_text(KEY_DAILY), d1_text(KEY_MOVE)])?
        .all()
        .await?
        .results()?;
    let mut drain_at = 0i64;
    let mut daily_at = 0i64;
    let mut move_at = 0i64;
    for r in rows {
        let v = parse_stamp(Some(&r.value));
        match r.key.as_str() {
            KEY_DRAIN => drain_at = v,
            KEY_DAILY => daily_at = v,
            KEY_MOVE => move_at = v,
            _ => {}
        }
    }
    Ok((drain_at, daily_at, move_at))
}

/// Winner pattern: push the stamp forward BEFORE doing the work — `UPDATE ... WHERE
/// CAST(value AS INTEGER) <= stale-cutoff RETURNING key` returns a row only while the
/// stamp is still stale (D1 serializes UPDATEs, so of two concurrent isolates exactly one
/// wins and the loser skips the task). If the row does not exist yet (first boot) it is
/// created with `INSERT OR IGNORE value='0'` first — '0' is below every threshold, hence
/// claimable. On error → false (best-effort: the work is skipped and retried in the next
/// window).
async fn claim(db: &D1Database, key: &str, now: i64, stale_cutoff: i64) -> bool {
    // Make sure the row exists (first boot). Idempotent, and only runs when a stamp is
    // suspected stale.
    if let Ok(stmt) = db
        .prepare("INSERT OR IGNORE INTO server_config (key, value, created_at) VALUES (?, '0', ?)")
        .bind(&[d1_text(key), d1_int(now)])
    {
        let _ = stmt.run().await;
    }
    #[derive(Deserialize)]
    struct KeyRow {
        #[allow(dead_code)]
        key: String,
    }
    let Ok(stmt) = db
        .prepare(
            "UPDATE server_config SET value = ?
             WHERE key = ? AND CAST(value AS INTEGER) <= ?
             RETURNING key",
        )
        .bind(&[
            d1_text(&now.to_string()),
            d1_text(key),
            d1_int(stale_cutoff),
        ])
    else {
        return false;
    };
    match stmt.all().await {
        Ok(res) => res
            .results::<KeyRow>()
            .map(|r| r.len() == 1)
            .unwrap_or(false),
        Err(_) => false,
    }
}

// ── cron-path stamping ──────────────────────────────────────────────────────

/// Called by `scheduled()` on every run (after the drain), so on a cron-enabled
/// deployment `maint_drain_at` stays fresh and the lazy drain never wakes. Best-effort.
pub(crate) async fn stamp_drain(env: &Env) {
    if let Ok(db) = env.d1("DB") {
        stamp(&db, KEY_DRAIN).await;
    }
}

/// Called at the end of `scheduled()`'s daily branch, so the lazy daily GC sleeps.
/// Best-effort.
pub(crate) async fn stamp_daily(env: &Env) {
    if let Ok(db) = env.d1("DB") {
        stamp(&db, KEY_DAILY).await;
    }
}

/// Called by `scheduled()` after every move tick, so the lazy storage-move sleeps on a
/// cron-enabled deployment (the twin of stamp_drain). Best-effort.
pub(crate) async fn stamp_move(env: &Env) {
    if let Ok(db) = env.d1("DB") {
        stamp(&db, KEY_MOVE).await;
    }
}

/// Called by the phase-4 drain endpoint: pulling the move stamp to 0 is the "run now"
/// signal. On a cron-less deployment the first eligible request (within the ≤60s throttle)
/// claims it and starts the move; on a cron-enabled one it would run within ≤2 minutes
/// anyway, and a 0 stamp is harmless there too since claim deduplicates. Best-effort — an
/// error does not break the drain endpoint.
pub(crate) async fn wake_storage_move(env: &Env) {
    let Ok(db) = env.d1("DB") else { return };
    let now = now_secs() as i64;
    if let Ok(stmt) = db
        .prepare("INSERT OR REPLACE INTO server_config (key, value, created_at) VALUES (?, '0', ?)")
        .bind(&[d1_text(KEY_MOVE), d1_int(now)])
    {
        let _ = stmt.run().await;
    }
}

async fn stamp(db: &D1Database, key: &str) {
    let now = now_secs() as i64;
    if let Ok(stmt) = db
        .prepare("INSERT OR REPLACE INTO server_config (key, value, created_at) VALUES (?, ?, ?)")
        .bind(&[d1_text(key), d1_text(&now.to_string()), d1_int(now)])
    {
        let _ = stmt.run().await;
    }
}

// ── daily maintenance set (body SHARED by cron and lazy) ────────────────────

/// The daily GC set — BIT-IDENTICAL to `scheduled()`'s daily branch, because the body was
/// moved here verbatim from lib.rs and both the cron and the lazy path call the SAME
/// function, so their behavior cannot diverge. Everything here is idempotent and
/// concurrency-safe: the cleanup DELETEs affect 0 rows on a second run, gc_fanout_retry is
/// a cutoff DELETE, and reconcile recomputes the truth (the last writer writes the same
/// value).
pub(crate) async fn run_daily(env: &Env) {
    if let Err(e) = cleanup_expired(env).await {
        // Never use the Debug format: the error can carry SQL parameters/bindings
        // (user_id, email, ...). The first 80 chars are enough — the error category shows
        // up, the PII does not.
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("cleanup error: {}", truncated);
    }
    crate::messages::handlers::gc_fanout_retry(env).await;
    // Quota phase 0 (SHADOW): the daily authoritative reconcile — recompute drift in the
    // best-effort storage counters (user_storage/server_stats) from the media tables
    // (self-heal). An error does not break the rest of maintenance: log and continue.
    if let Err(e) = crate::usage::reconcile_storage(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("usage reconcile error: {}", truncated);
    }
    // Pluggable storage phase 1: backfill the plugin-code (plugin-code/) inventory from
    // R2 — until now those blobs had no metadata, so "where does this live" was
    // unanswerable. Idempotent (INSERT OR IGNORE, r2-primary); new put_code calls already
    // write their metadata inline, so this backfill only sweeps up OLD blobs. An error
    // does not break the rest of maintenance.
    if let Err(e) = crate::storage::maint::backfill_plugin_code(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("plugin-code backfill error: {}", truncated);
    }
    // Pluggable storage phase 3 (plan e, channel 1): scheduled probe of every backend
    // whose state != 'disabled', refreshing last_health_* so the panel stays current
    // instead of turning red between crons. An error does not break the rest of maintenance.
    if let Err(e) = crate::storage::probe_all(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("storage probe error: {}", truncated);
    }
    // Pluggable storage phase 3 (plan c.4 / f#4): retry the deletion of orphan-blob
    // tombstones (≤50 per run). A successful delete drops the row; if the backend is still
    // down, retry_count++ and it is tried again the next day.
    if let Err(e) = crate::storage::maint::retry_orphans(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("orphan retry error: {}", truncated);
    }
}

#[derive(Deserialize)]
struct ExpiredMediaRow {
    blob_id: String,
    // Quota phase 0 (SHADOW): size and uploader, needed to decrement the counters for a
    // deleted blob.
    size_bytes: i64,
    uploader_id: String,
    // Pluggable storage: the delete is routed to the blob's own backend (in phase 1 that
    // is always 'r2-primary').
    store_id: String,
}

#[derive(Deserialize)]
struct LegacyInviteAttributionRow {
    token: String,
    email_hint: Option<String>,
    inviter_user_id: Option<String>,
    inviter_ed_pub: Option<Vec<u8>>,
    used_by: Option<String>,
    created_at: i64,
    expires_at: i64,
}

/// Backfill pre-0031 invites (`used = 1, token_hash = NULL`) into the attribution ledger,
/// hashing with Rust SHA-256 so the raw bearer secret is never written to a persistent
/// table. The daily cleanup calls this BEFORE it deletes tokens. Each pass moves at most
/// 10 records in a single D1 batch (at most 30 statements); any remaining legacy `used`
/// rows are protected by the cleanup predicate and migrate on a later pass.
async fn backfill_legacy_invite_attributions(db: &D1Database) -> Result<usize> {
    let rows: Vec<LegacyInviteAttributionRow> = db
        .prepare(
            "SELECT it.token, it.email_hint, it.owner_user_id AS inviter_user_id,
                    u.identity_ed_pub AS inviter_ed_pub, it.used_by,
                    it.created_at, it.expires_at
               FROM invite_tokens it
               LEFT JOIN users u ON u.id = it.owner_user_id
              WHERE it.used = 1 AND it.token_hash IS NULL
              ORDER BY it.created_at ASC LIMIT 10",
        )
        .all()
        .await?
        .results()?;
    let done = rows.len();
    let mut statements = Vec::with_capacity(done * 3);
    for row in rows {
        let token_hash = sha256_hex(&row.token);
        let ed = match row.inviter_ed_pub.as_deref() {
            Some(bytes) => d1_blob(bytes),
            None => d1_null(),
        };
        let verified_at = row.used_by.as_ref().map(|_| row.created_at);
        statements.extend([
            db.prepare(
                "INSERT OR IGNORE INTO invite_attributions
                   (invite_token_hash, email_hint, inviter_user_id, inviter_ed_pub, used_by,
                    created_at, expires_at, redeemed_at, verified_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&[
                d1_text(&token_hash),
                d1_opt_text(row.email_hint.as_deref()),
                d1_opt_text(row.inviter_user_id.as_deref()),
                ed,
                d1_opt_text(row.used_by.as_deref()),
                d1_int(row.created_at),
                d1_int(row.expires_at),
                d1_int(row.created_at),
                d1_opt_int(verified_at),
            ])?,
            db.prepare(
                "UPDATE invite_tokens SET token_hash = ?
                  WHERE token = ? AND token_hash IS NULL",
            )
            .bind(&[d1_text(&token_hash), d1_text(&row.token)])?,
            db.prepare(
                "UPDATE verification_codes SET invite_token_hash = ?
                  WHERE invite_token = ? AND invite_token_hash IS NULL",
            )
            .bind(&[d1_text(&token_hash), d1_text(&row.token)])?,
        ]);
    }
    if !statements.is_empty() {
        db.batch(statements).await?;
    }
    Ok(done)
}

/// Delete source invite tokens — which are authorization secrets — only once their TTL
/// expires. `used = 1` is no longer a reason to GC immediately: the source API row must
/// survive verify's 10-minute code window. The durable inviter/used_by trail lives in the
/// `invite_attributions` ledger from 0031, so after the TTL this row can go safely.
pub(crate) const INVITE_TOKEN_CLEANUP_SQL: &str = "DELETE FROM invite_tokens
      WHERE expires_at < ? AND (used = 0 OR token_hash IS NOT NULL)";
const RECONCILE_INVITE_CLAIMS_SQL: &str = "UPDATE invite_tokens SET used = 1
      WHERE used = 0 AND token_hash IS NOT NULL AND EXISTS (
        SELECT 1 FROM invite_attributions ia
         WHERE ia.invite_token_hash = invite_tokens.token_hash
      )";
/// THE RETENTION WINDOW for CONSUMED one-time prekeys, counted in `one_time_prekeys.id` — not in
/// seconds. The table has no `created_at` column and never had one (migration `0001_init.sql`
/// created it without, `0016_otk_device_unique.sql` rebuilt it and did not add one), so there is
/// nothing to compare a timestamp against. `id` is `INTEGER PRIMARY KEY AUTOINCREMENT`, which is
/// the property that makes it usable as a clock here: AUTOINCREMENT keeps `sqlite_sequence`, so an
/// id is never reused even after the rows carrying it are deleted, and a sweep therefore cannot
/// walk the watermark backwards into re-deleting the keys published after it.
///
/// # A consumed row is not garbage — it is the ledger that keeps a one-time key one-time
///
/// This is the constraint that sets the size. `keys/handlers.rs::replenish` APPENDS under
/// `INSERT OR IGNORE` against `UNIQUE (user_id, device_id, prekey_id)`, and `prekey_id` is derived
/// from the public key itself, so re-publishing a key the server already holds is a silent no-op.
/// That no-op is what stops a key being handed out twice; `devices/handlers.rs` says it in as many
/// words where it deletes a removed device's UNCONSUMED keys — "consumed=1 rows STAY: they are the
/// record that stops a key ever being issued twice."
///
/// Deleting a consumed row deletes that record. Republish the same `prekey_id` afterwards and the
/// IGNORE has nothing to collide with: the row comes back with `consumed = 0`, and `keys/bundle`
/// can hand a second peer a one-time key that was already spent. So the window is not "how long
/// before this is stale" — it is "how far past a spent key a device can still be before a
/// republish of it becomes implausible".
///
/// The only realistic republish is a device whose local store was rewound to before it marked
/// those keys published — the identity-restore case `replenish` already documents as the honest
/// cost of dropping its DELETE. Everything else (a retry, an attach-replenish, a reconnect)
/// republishes keys that are still UNCONSUMED, and unconsumed rows are never touched here.
///
/// # 100,000, against what evidence
///
/// The live relay's whole `one_time_prekeys` table was measured at 648 rows on 2026-07-29 (the row
/// totals in `replenish`'s task-#59 note: 648 → 626). The window is ~150× that entire table, so on
/// a server of that size the sweep never fires at all — which is the intent. It only becomes
/// reachable on a server that has published a hundred thousand one-time keys, and at that point the
/// oldest tombstone is a hundred thousand keys behind the newest.
///
/// It is also 66× the largest unconsumed pool a single ACCOUNT can hold at once (`MAX_DEVICES` = 5
/// devices × `MAX_OTK_POOL` = 300 keys each) and 1,000× the client's `otk_pool_target` of 100. In
/// bytes it is the ceiling this table has never had: ~100 B of payload per row plus index, so on
/// the order of 20 MB, where before it was unbounded.
///
/// ⚠ `MAX_OTK_POOL` is private to `keys/handlers.rs`, so the ratio above is a documented
/// cross-reference and not a compile-time one. Making it `pub(crate)` would let this file assert
/// the relationship the way the cron thresholds below assert theirs.
const OTK_CONSUMED_RETAIN_IDS: i64 = 100_000;

/// Per-run bound on the sweep. This is a cron path, so the work has to be a known quantity rather
/// than "whatever the backlog happens to be".
///
/// Twenty times the media and contact-QR limits in this same function, because it is a different
/// kind of work: those iterate rows to make a network call each (an R2 delete), this is one D1
/// statement with no per-row I/O. Draining a full retention window still takes ten daily passes,
/// which is the point of the assert below — a mis-set window cannot empty the ledger in one run.
const OTK_SWEEP_LIMIT: i64 = 10_000;

// Compile-time contract lock, the twin of the cron-threshold asserts above: one pass must never be
// able to consume a whole retention window. If someone shrinks the window to tune D1 size, this
// stops the ledger being wiped in a single night as a side effect.
const _: () = assert!(OTK_CONSUMED_RETAIN_IDS >= 10 * OTK_SWEEP_LIMIT);

/// Sweep consumed one-time prekeys that are more than `OTK_CONSUMED_RETAIN_IDS` behind the newest
/// key in the table. Binds: retain window, per-run limit.
///
/// `consumed = 1` is the whole filter beyond the window: an UNCONSUMED row is live stock a peer can
/// still be handed, and `devices/handlers.rs` is the only place that may remove one.
///
/// The watermark is `MAX(id)` read inline rather than a stored high-water mark, and the two ways
/// that can be wrong are both safe. An EMPTY table gives `MAX(id) = NULL`, `NULL - ?` is NULL, and
/// `id <= NULL` is NULL for every row — the statement deletes nothing instead of everything. A
/// watermark that REGRESSES (an account deletion took the newest rows with it, `membership.rs`
/// deletes by `user_id`) lowers the cutoff, so fewer rows qualify. This statement can never lower
/// it itself: a row at `MAX(id)` cannot also be at or below `MAX(id) - 100000`.
///
/// `id` is the rowid, so `id <= cutoff` is a rowid range scan that stops at the cutoff and never
/// walks the live tail. `LIMIT` inside the `IN (SELECT …)` rather than on the DELETE is the shape
/// the contact-QR statements above already use; SQLite only accepts `DELETE … LIMIT` when built
/// with `SQLITE_ENABLE_UPDATE_DELETE_LIMIT`, which is not a thing to depend on across D1 and the
/// rusqlite tests both.
pub(crate) const OTK_CONSUMED_CLEANUP_SQL: &str = "DELETE FROM one_time_prekeys
      WHERE id IN (
        SELECT id FROM one_time_prekeys
         WHERE consumed = 1
           AND id <= (SELECT MAX(id) FROM one_time_prekeys) - ?
         ORDER BY id LIMIT ?
      )";

const CONTACT_QR_RETENTION_MS: i64 = 24 * 60 * 60 * 1000;
pub(crate) const CONTACT_QR_CLAIM_CLEANUP_SQL: &str = "DELETE FROM contact_qr_claims
      WHERE offer_id IN (
        SELECT offer_id FROM contact_qr_offers
         WHERE expires_at_ms < ? LIMIT 500
      )";
pub(crate) const CONTACT_QR_OFFER_CLEANUP_SQL: &str = "DELETE FROM contact_qr_offers
      WHERE offer_id IN (
        SELECT offer_id FROM contact_qr_offers
         WHERE expires_at_ms < ? LIMIT 500
      )";

/// Sweep up expired leftovers (moved here from lib.rs verbatim; behavior unchanged).
/// Media is already deleted the moment the recipient acks, so the media leg here is the
/// fallback for "nobody ever fetched it and the retention window elapsed" — that window is
/// `server_settings.retention_days`, which defaults to 30. The remaining legs keep D1 from
/// growing: expired invite_tokens, verification_codes, refresh_tokens, device-link requests
/// and contact-QR records.
async fn cleanup_expired(env: &Env) -> Result<()> {
    let now = now_secs() as i64;
    let db = env.d1("DB")?;

    // 1) expired media: delete from R2 + D1
    let rows: Vec<ExpiredMediaRow> = db
        .prepare("SELECT blob_id, size_bytes, uploader_id, store_id FROM media_objects WHERE expires_at < ? LIMIT 500")
        .bind(&[d1_int(now)])?
        .all()
        .await?
        .results()?;

    if !rows.is_empty() {
        // Delete per backend through the single choke point (StorageRouter). On a lite
        // deployment (no R2 binding) any_available() is false → the blob delete is SKIPPED
        // but the D1 metadata delete and the counter decrement still HAPPEN; otherwise
        // cleanup would Err on every run and the LATER cleanup steps (invite/verification
        // GC) would never be reached.
        // PHASE 3 (plan f#4): a blob that cannot be deleted becomes a `storage_orphans`
        // tombstone — the D1 metadata is STILL deleted so cleanup keeps flowing — and the
        // daily `retry_orphans` tries again, so an orphan blob does not become permanent on
        // an external backend. router.delete does NOT write health marks on the BULK path
        // (≤500 rows × a write each would bloat it), so instead we write ONE aggregated mark
        // per failing backend here.
        let router = crate::storage::StorageRouter::from_env(env).await?;
        let mut orphans: Vec<(String, String, i64)> = Vec::new(); // (store_id, key, size)
        if router.any_available() {
            for row in &rows {
                let key = crate::storage::media_key(&row.blob_id);
                if router.delete(&row.store_id, &key).await.is_err() {
                    orphans.push((row.store_id.clone(), key, row.size_bytes));
                }
            }
        }
        if !orphans.is_empty() {
            crate::storage::maint::insert_orphans(&db, &orphans).await;
            // ONE health mark per failing backend (aggregated; no batch bloat).
            let mut marked: Vec<&str> = Vec::new();
            for (sid, _, _) in &orphans {
                if !marked.contains(&sid.as_str()) {
                    marked.push(sid);
                    crate::storage::write_health(env, sid, false, Some("delete_failed_cleanup"))
                        .await;
                }
            }
        }
        let placeholders: String = (0..rows.len()).map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "DELETE FROM media_objects WHERE blob_id IN ({})",
            placeholders
        );
        let binds: Vec<JsValue> = rows.iter().map(|r| JsValue::from_str(&r.blob_id)).collect();
        db.prepare(&sql).bind(&binds)?.run().await?;
        console_log!("cleanup: {} expired media blobs removed", rows.len());
        // Quota phase 0 (SHADOW, best-effort): subtract the expired-and-deleted media from
        // the storage counters (clamped at 0; an error does not break cleanup, and the daily
        // reconcile repairs it).
        let removed: Vec<(String, i64)> = rows
            .iter()
            .map(|r| (r.uploader_id.clone(), r.size_bytes))
            .collect();
        crate::usage::media_removed(&db, &removed).await;
    }

    // Move pre-0031 used tokens into the hash ledger first; the raw secret is never written
    // to the audit trail. Anything outside this slice is protected by the cleanup predicate.
    let legacy_backfilled = backfill_legacy_invite_attributions(&db).await?;
    if legacy_backfilled > 0 {
        console_log!(
            "cleanup: {} legacy invite attribution hash-backfill",
            legacy_backfilled
        );
    }

    // Self-heal the legacy/API `used` flag from the claim ledger, which is authoritative.
    // If a redeem's claim INSERT succeeded but the follow-up UPDATE hit a transient error,
    // admin/stats/bootstrap must not keep reporting the invite as "unused" forever.
    db.prepare(RECONCILE_INVITE_CLAIMS_SQL).run().await?;

    // 2) expired invite-token secrets. A used token is kept until its TTL expires, so
    // maintenance never cuts the redeem→verify window short. The attribution ledger is
    // independent of the source token and outlives it.
    db.prepare(INVITE_TOKEN_CLEANUP_SQL)
        .bind(&[d1_int(now)])?
        .run()
        .await?;

    // 3) expired verification codes
    db.prepare("DELETE FROM verification_codes WHERE expires_at < ?")
        .bind(&[d1_int(now)])?
        .run()
        .await?;

    // 4) revoked / expired refresh tokens
    db.prepare("DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1")
        .bind(&[d1_int(now)])?
        .run()
        .await?;

    // 5) expired device-link requests (M2-S3.2; consuming one already deletes the row, so
    //    a 'consumed' state is never persisted — lazy GC plus this sweep collect the
    //    expired ones)
    db.prepare("DELETE FROM link_requests WHERE expires_at < ?")
        .bind(&[d1_int(now)])?
        .run()
        .await?;

    // 6) Single-use mutual QR records. They are kept for 24 hours so a client can still read
    // the "expired" state for a while; the capability secret is never written to D1 in the
    // first place. Deleting the claim before the offer leaves no orphan row even on an older
    // D1 deployment with foreign-key enforcement off.
    let qr_cutoff_ms = now
        .saturating_mul(1000)
        .saturating_sub(CONTACT_QR_RETENTION_MS);
    db.prepare(CONTACT_QR_CLAIM_CLEANUP_SQL)
        .bind(&[d1_int(qr_cutoff_ms)])?
        .run()
        .await?;
    db.prepare(CONTACT_QR_OFFER_CLEANUP_SQL)
        .bind(&[d1_int(qr_cutoff_ms)])?
        .run()
        .await?;

    // 7) Consumed one-time prekeys older than the retention window. Until now nothing anywhere
    // deleted them: `keys/bundle` turns one unconsumed row into a consumed one on every fetch by
    // any authorized contact, `replenish` puts the replacement in, and the spent row stayed
    // forever. `MAX_OTK_POOL` bounds the UNCONSUMED pool per device and says so; the consumed side
    // had no ceiling at all.
    //
    // A leg of the daily GC rather than a fourth maintenance stamp. The cadence wanted is exactly
    // the daily one — a window measured in a hundred thousand keys does not need a 2-minute tick —
    // and this function is already the place whose job is "keep D1 from growing", already claimed
    // by the daily winner-claim and already idempotent leg by leg. A separate stamp would buy a
    // cadence nothing needs and a second thing to keep fresh.
    //
    // Last on purpose, so that a failure here cannot skip a leg above it. `?` still propagates:
    // `run_daily` logs and carries on to the rest of the daily set.
    let swept = db
        .prepare(OTK_CONSUMED_CLEANUP_SQL)
        .bind(&[d1_int(OTK_CONSUMED_RETAIN_IDS), d1_int(OTK_SWEEP_LIMIT)])?
        .run()
        .await?;
    // Silent when there is nothing to do, which on a server under the window is every run.
    if let Ok(Some(meta)) = swept.meta() {
        if meta.changes.unwrap_or(0) > 0 {
            console_log!(
                "cleanup: {} consumed one-time prekeys removed (>{} ids behind the newest)",
                meta.changes.unwrap_or(0),
                OTK_CONSUMED_RETAIN_IDS
            );
        }
    }

    Ok(())
}

// ── Pure helpers (unit-tested) ──────────────────────────────────────────────

/// `server_config.value` (TEXT) → epoch seconds. Missing row, empty, corrupt or negative
/// all map to 0, i.e. "very old" = runs on the first eligible request. Claim's SQL side
/// (`CAST(value AS INTEGER)`) also CASTs corrupt text to 0, so both sides agree.
fn parse_stamp(v: Option<&str>) -> i64 {
    v.and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0)
        .max(0)
}

/// Has the stamp crossed the threshold? A stamp in the future (clock skew) is NOT due —
/// saturating arithmetic treats the negative difference as 0. A bogus future stamp cannot
/// lock things up forever, because every successful cron/lazy run pulls the stamp back to
/// now.
fn is_due(now: i64, stamp_at: i64, after: i64) -> bool {
    now.saturating_sub(stamp_at) >= after
}

/// Isolate-local throttle: look if we never looked (0) or the window has elapsed.
/// `now < last` (the clock moved backwards) saturates to 0 → do not look until the window
/// fills again; isolates are short-lived, so there is no risk of a permanent lock.
fn throttle_due(last: u64, now: u64, every: u64) -> bool {
    last == 0 || now.saturating_sub(last) >= every
}

/// The pure-helper and SQL exercises for this module. Split out because `maintenance.rs` was
/// about to cross the 800-line ceiling; `keys/handlers.rs` is the worked example of the move.
#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
