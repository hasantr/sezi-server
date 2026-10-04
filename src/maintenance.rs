//! Lazy maintenance — cron-independent upkeep.
//!
//! WHY: the CF free plan caps cron triggers per account, so a SECOND sezi-server in the
//! same account fails `wrangler deploy`'s schedules step and ends up with NO CRON — the
//! daily GC and the 2-minute fanout drain never run, the retry queue piles up and
//! expired-media/token cleanup stops. Maintenance therefore also runs piggybacked on
//! requests, making the cron one way to keep it fresh rather than the only way. A
//! cron-enabled deployment keeps its stamps fresh and this module stays quiet.
//!
//! MECHANISM — three timestamps in `server_config` (epoch seconds): `maint_drain_at`,
//! `maint_daily_at`, `maint_storage_move_at`. `scheduled()` refreshes its own stamp on
//! every run; without a cron the stamp ages and the first eligible request runs
//! maintenance in the background via `ctx.wait_until`, so no response is delayed.
//!
//! COST: no extra D1 read per request. An isolate-local `thread_local` last-checked
//! timestamp limits D1 lookups to roughly one per 60s, and even that happens inside
//! `wait_until`.
//!
//! WINNER PATTERN: a stale-looking stamp is pushed forward FIRST via
//! `UPDATE … WHERE CAST(value AS INTEGER) <= stale-cutoff RETURNING key`. D1 serializes
//! UPDATEs, so of two concurrent isolates exactly one gets a row back and the loser skips
//! the work. The tasks are individually concurrency-safe anyway; this only avoids
//! pointless double work.

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

/// Lazy drain threshold: 2.5× the 120s cron interval, on purpose. CF scheduled events are
/// not second-accurate, so at exactly 120s a cron-enabled deployment would fire the lazy
/// path routinely in the "stamp just aged out, cron about to run" window. The jitter margin
/// means lazy only wakes when the cron is truly dead; cron-less, the drain cadence is then
/// ~5 minutes while traffic exists, which the retry queue's own backoff absorbs.
const DRAIN_LAZY_AFTER_SECS: i64 = 300;

/// Lazy daily-GC threshold: 24h plus a 1h margin, for the same boundary-race reason.
const DAILY_LAZY_AFTER_SECS: i64 = 90_000;

/// Lazy storage-move threshold — same rationale and cadence as the drain. The drain
/// endpoint pulls this stamp to 0 (`wake_storage_move`) so the START of a move does not
/// wait out the threshold; the first eligible request claims it within ≤60s.
const MOVE_LAZY_AFTER_SECS: i64 = 300;

// Contract lock: a lazy threshold must never drop below its cron cadence (drain
// "*/2 * * * *" = 120s, daily "0 4 * * *" = 86400s), or lazy would wake routinely on a
// cron-enabled deployment.
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
/// await; the stamp check and any resulting work run in `ctx.wait_until`. Best-effort:
/// every error is logged and swallowed, and the request is never affected.
pub fn maybe_run_lazy(env: &Env, ctx: &Context) {
    let now = now_secs();
    let due = LAST_CHECK.with(|c| {
        if throttle_due(c.get(), now, CHECK_EVERY_SECS) {
            // Advance immediately (single-threaded, so no race): later requests on this
            // isolate touch D1 not at all for 60s.
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
        // On a Pi/workerd `wrangler dev` deployment the scheduled event may never fire, so
        // the account-purge outbox converges off this same lazy drain stamp when the first
        // UserInbox purge call hit a transient error.
        crate::membership::drain_purge_outbox(&env).await;
    }
    // Draining-backend move tick (≤4 blobs per run). With no draining backend,
    // run_storage_move returns quietly after one cheap SELECT.
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

/// Push the stamp forward BEFORE doing the work (see the winner pattern in the module
/// docs). A missing row (first boot) is created with `INSERT OR IGNORE value='0'` — '0' is
/// below every threshold, hence claimable. On error → false: the work is skipped and
/// retried in the next window.
async fn claim(db: &D1Database, key: &str, now: i64, stale_cutoff: i64) -> bool {
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

/// Called by `scheduled()` on every run (after the drain), so the lazy drain never wakes
/// on a cron-enabled deployment. Best-effort.
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

/// The twin of stamp_drain, called after every move tick. Best-effort.
pub(crate) async fn stamp_move(env: &Env) {
    if let Ok(db) = env.d1("DB") {
        stamp(&db, KEY_MOVE).await;
    }
}

/// Called by the drain endpoint: pulling the move stamp to 0 is the "run now" signal, so
/// the first eligible request claims it instead of waiting out the threshold. Harmless on
/// a cron-enabled deployment too, since claim deduplicates. Best-effort.
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

/// The daily GC set. The cron and the lazy path call this same function, so they cannot
/// diverge. Every leg is idempotent and concurrency-safe: the cleanup DELETEs affect 0
/// rows on a second run, gc_fanout_retry is a cutoff DELETE, and reconcile recomputes the
/// truth (the last writer writes the same value).
pub(crate) async fn run_daily(env: &Env) {
    if let Err(e) = cleanup_expired(env).await {
        // Never the Debug format: the error can carry SQL bindings (user_id, email, …).
        // 80 chars shows the error category without the PII.
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("cleanup error: {}", truncated);
    }
    crate::messages::handlers::gc_fanout_retry(env).await;
    // Every leg below logs and continues, so one failure does not skip the rest.
    //
    // The group library's retention sweep (≤100 expired parts per run). Before the reconcile, so
    // the counters it recomputes already reflect what the sweep removed.
    if let Err(e) = crate::room_library::sweep_expired(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("library sweep error: {}", truncated);
    }
    //
    // Recompute drift in the best-effort storage counters (user_storage/server_stats)
    // from the media tables.
    if let Err(e) = crate::usage::reconcile_storage(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("usage reconcile error: {}", truncated);
    }
    // Backfill the plugin-code inventory from R2, so "where does this blob live" is
    // answerable for blobs written before put_code started recording it inline.
    // Idempotent (INSERT OR IGNORE, r2-primary).
    if let Err(e) = crate::storage::maint::backfill_plugin_code(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("plugin-code backfill error: {}", truncated);
    }
    // Probe every backend whose state != 'disabled', refreshing last_health_* so the panel
    // stays current instead of turning red between crons.
    if let Err(e) = crate::storage::probe_all(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("storage probe error: {}", truncated);
    }
    // Retry the deletion of orphan-blob tombstones (≤50 per run). A successful delete
    // drops the row; a backend still down bumps retry_count and is tried again tomorrow.
    if let Err(e) = crate::storage::maint::retry_orphans(env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("orphan retry error: {}", truncated);
    }
}

#[derive(Deserialize)]
struct ExpiredMediaRow {
    blob_id: String,
    // Needed to decrement the storage counters for a deleted blob.
    size_bytes: i64,
    uploader_id: String,
    // The delete is routed to the blob's own backend.
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
/// How long an approved or denied join request stays readable by its requester
/// (`GET /join-requests/mine`).
const DECIDED_JOIN_REQUEST_KEEP_SECS: i64 = 30 * 24 * 60 * 60;
/// Binds: the cutoff.
pub(crate) const DECIDED_JOIN_REQUEST_CLEANUP_SQL: &str = "DELETE FROM group_join_requests
      WHERE state != 'pending' AND decided_at < ?";
const RECONCILE_INVITE_CLAIMS_SQL: &str = "UPDATE invite_tokens SET used = 1
      WHERE used = 0 AND token_hash IS NOT NULL AND EXISTS (
        SELECT 1 FROM invite_attributions ia
         WHERE ia.invite_token_hash = invite_tokens.token_hash
      )";
/// Retention window for CONSUMED one-time prekeys, counted in `one_time_prekeys.id` rather than
/// seconds: the table has no `created_at` and never had one. `id` is AUTOINCREMENT, so an id is
/// never reused and a sweep cannot walk the watermark backwards into keys published after it.
///
/// A consumed row is not garbage — it is the ledger that keeps a one-time key one-time.
/// `replenish` appends under `INSERT OR IGNORE` against `UNIQUE (user_id, device_id, prekey_id)`
/// with `prekey_id` derived from the public key, so republishing a key the server holds is a
/// silent no-op, and that no-op is what stops a key being handed out twice. Delete the consumed
/// row and the IGNORE has nothing to collide with: the key comes back `consumed = 0` and
/// `keys/bundle` can hand a spent key to a second peer. So the window asks "how far past a spent
/// key can a device still be before republishing it is implausible", not "when is this stale".
/// The only realistic republish is a device rewound to before it marked those keys published (the
/// identity-restore case in `replenish`); everything else republishes UNCONSUMED keys, which are
/// never touched here.
///
/// 100,000 is ~150× the live relay's entire table as measured (648 rows), so the sweep does not
/// fire at all at that size — the intent. It is also 66× the largest unconsumed pool one account
/// can hold (`MAX_DEVICES` × `MAX_OTK_POOL`) and 1,000× the client's `otk_pool_target`, i.e. a
/// ~20 MB ceiling on a table that had none. ⚠ `MAX_OTK_POOL` is private to `keys/handlers.rs`, so
/// that ratio is documented rather than asserted; making it `pub(crate)` would fix that.
const OTK_CONSUMED_RETAIN_IDS: i64 = 100_000;

/// Per-run bound on the sweep — a cron path needs a known quantity of work, not "whatever the
/// backlog happens to be". Twenty times the media and contact-QR limits below because it is one
/// D1 statement with no per-row I/O, where those make a network call per row.
const OTK_SWEEP_LIMIT: i64 = 10_000;

// Contract lock: one pass must never consume a whole retention window, so shrinking the window to
// tune D1 size cannot wipe the ledger in a single night as a side effect.
const _: () = assert!(OTK_CONSUMED_RETAIN_IDS >= 10 * OTK_SWEEP_LIMIT);

/// Sweep consumed one-time prekeys more than `OTK_CONSUMED_RETAIN_IDS` behind the newest key.
/// Binds: retain window, per-run limit. `consumed = 1` is the whole filter beyond the window —
/// an unconsumed row is live stock, and `devices/handlers.rs` is the only place that may remove one.
///
/// The watermark is an inline `MAX(id)`, and both ways it can be wrong are safe: an EMPTY table
/// gives NULL, so `id <= NULL` matches nothing rather than everything, and a watermark that
/// REGRESSES (an account deletion took the newest rows) only lowers the cutoff. This statement
/// cannot lower it itself — a row at `MAX(id)` cannot also be at or below `MAX(id) - 100000`.
///
/// `LIMIT` sits inside the `IN (SELECT …)`, as in the contact-QR statements: SQLite only accepts
/// `DELETE … LIMIT` when built with `SQLITE_ENABLE_UPDATE_DELETE_LIMIT`, which neither D1 nor the
/// rusqlite tests can be assumed to have.
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

/// Sweep up expired leftovers. Media is already deleted the moment the recipient acks, so
/// the media leg here is the fallback for "nobody ever fetched it and
/// `server_settings.retention_days` elapsed". The rest keeps D1 from growing: expired
/// invite_tokens, verification_codes, refresh_tokens, device-link requests, contact-QR
/// records and consumed one-time prekeys.
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
        // Deletes go per backend through the single choke point (StorageRouter). On a lite
        // deployment (no R2 binding) any_available() is false, so the blob delete is
        // skipped while the D1 metadata delete and counter decrement still happen —
        // otherwise cleanup would Err every run and the legs below it would never be
        // reached. A blob that cannot be deleted becomes a `storage_orphans` tombstone (the
        // D1 metadata still goes) for the daily `retry_orphans`, so it does not become a
        // permanent orphan on an external backend. router.delete writes no health marks on
        // this bulk path (≤500 rows × a write each would bloat it), hence one aggregated
        // mark per failing backend below.
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
        // Best-effort: subtract the deleted media from the storage counters (clamped at 0).
        // An error does not break cleanup, and the daily reconcile repairs it.
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

    // 4b) decided join requests, once the requester has had a month to read the answer. A pending
    //     request never expires: it waits for a group admin however long that takes.
    db.prepare(DECIDED_JOIN_REQUEST_CLEANUP_SQL)
        .bind(&[d1_int(now - DECIDED_JOIN_REQUEST_KEEP_SECS)])?
        .run()
        .await?;

    // 5) expired device-link requests (consuming one already deletes the row, so a
    //    'consumed' state is never persisted; this sweep collects the expired ones)
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

    // 7) Consumed one-time prekeys past the retention window. `MAX_OTK_POOL` bounds the
    // unconsumed pool per device; the consumed side had no ceiling at all. A leg of the daily GC
    // rather than a fourth maintenance stamp: a window measured in a hundred thousand keys does
    // not need a 2-minute tick. Last on purpose, so a failure here cannot skip a leg above it —
    // `?` still propagates and `run_daily` carries on to the rest of the daily set.
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
/// saturating arithmetic treats the negative difference as 0 — and cannot lock things up
/// forever, because every successful run pulls the stamp back to now.
fn is_due(now: i64, stamp_at: i64, after: i64) -> bool {
    now.saturating_sub(stamp_at) >= after
}

/// Isolate-local throttle: look if we never looked (0) or the window has elapsed.
/// `now < last` (the clock moved backwards) saturates to 0 → do not look until the window
/// fills again; isolates are short-lived, so there is no risk of a permanent lock.
fn throttle_due(last: u64, now: u64, every: u64) -> bool {
    last == 0 || now.saturating_sub(last) >= every
}

/// The pure-helper and SQL exercises for this module.
#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
