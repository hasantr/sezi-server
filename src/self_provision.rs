//! Self-provisioning — self-host phase A (the prerequisite for a zero-CLI deploy).
//!
//! Goal: someone who forks the worker on GitHub and installs it into THEIR OWN CF
//! account via Deploy-to-Cloudflare should get a working server WITHOUT ever learning
//! `wrangler secret put` or `wrangler d1 migrations apply`. Two legs:
//!
//! **A1 — Key self-provisioning** (`JWT_SIGNING_KEY` + `ADMIN_INVITE_KEY`):
//! env-first / D1-fallback / GENERATE-and-persist (the durable-key variant of
//! cf_analytics's `resolve_cfg` pattern):
//!   1. If the env secret exists it is used — today's behavior is BIT-IDENTICAL, and an
//!      env-set value ALWAYS wins so a security-conscious owner can move the key into a
//!      secret. This path NEVER touches D1 and needs no memoization (reading env is
//!      synchronous and cheap).
//!   2. Otherwise read D1 `server_config` (0025) and cache it per isolate. The JWT key
//!      is read on EVERY request — a hot path — so a thread_local memo keeps the D1
//!      round-trip out of it (a WASM isolate is single-threaded).
//!   3. Failing that (a fresh fork's first boot) GENERATE the key and persist it to D1.
//!      Race guard: `ON CONFLICT DO NOTHING` plus a re-SELECT after persisting, so two
//!      concurrent cold starts NEVER end up using different keys (D1 is the one truth).
//!
//! SECURITY NOTE: the key sits at rest in D1 (on CF's encrypted disks) — this is the
//! self-host honest-server model. The key is returned by NO endpoint; it stays inside
//! the worker.
//!
//! **A2 — D1 self-migration**: `migrations/*.sql` are embedded via `include_str!`, and
//! on the first request everything missing according to the `_sezi_migrations` tracking
//! table is applied in ONE `db.batch`. (The 2026-07-06 free-plan incident: the Workers
//! free plan caps subrequests at ~50 per request, and the old one-batch-plus-tracking-
//! INSERT-per-file pattern needed ~50+ D1 calls on a fresh install's first boot, so it
//! was cut off midway → deterministic 500s from jwks/verify. A single batch brings the
//! first boot down to ~4 D1 calls and makes the whole pending set all-or-nothing.)
//! wrangler compatibility (CRITICAL): our existing prod applied its migrations with
//! `wrangler d1 migrations apply`, so the records in wrangler's own `d1_migrations`
//! table COUNT as applied and no migration ever re-runs in prod. Extra belt: a benign
//! schema conflict ("duplicate column name" / "already exists") falls back to
//! tolerant-apply (see `apply_one` below). The CLI path keeps working —
//! `wrangler.toml migrations_dir` is still there and self-migration is only an
//! additional safety net.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;

use worker::*;

use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;

// ── Embedded migration list ─────────────────────────────────────────────────
// ORDERED and HAND-MAINTAINED (a deliberately simple choice over a build script): when
// you add a migrations/NNNN_*.sql you must add a line here too. The
// `the_migrations_list_matches_the_folder` unit test catches the omission right after
// compiling — cargo test reads the directory and compares it against this list.
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init", include_str!("../migrations/0001_init.sql")),
    (
        "0002_push_tokens",
        include_str!("../migrations/0002_push_tokens.sql"),
    ),
    (
        "0003_admin_and_settings",
        include_str!("../migrations/0003_admin_and_settings.sql"),
    ),
    (
        "0004_owner_and_invite_tracking",
        include_str!("../migrations/0004_owner_and_invite_tracking.sql"),
    ),
    (
        "0005_retention",
        include_str!("../migrations/0005_retention.sql"),
    ),
    ("0006_groups", include_str!("../migrations/0006_groups.sql")),
    (
        "0007_group_settings",
        include_str!("../migrations/0007_group_settings.sql"),
    ),
    (
        "0008_group_join_consent",
        include_str!("../migrations/0008_group_join_consent.sql"),
    ),
    (
        "0009_turn_usage",
        include_str!("../migrations/0009_turn_usage.sql"),
    ),
    (
        "0010_message_retention",
        include_str!("../migrations/0010_message_retention.sql"),
    ),
    (
        "0011_devices",
        include_str!("../migrations/0011_devices.sql"),
    ),
    (
        "0012_device_addressing_s1",
        include_str!("../migrations/0012_device_addressing_s1.sql"),
    ),
    (
        "0013_device_otk_cut",
        include_str!("../migrations/0013_device_otk_cut.sql"),
    ),
    (
        "0014_device_link",
        include_str!("../migrations/0014_device_link.sql"),
    ),
    (
        "0015_signed_prekeys_device_pk",
        include_str!("../migrations/0015_signed_prekeys_device_pk.sql"),
    ),
    (
        "0016_otk_device_unique",
        include_str!("../migrations/0016_otk_device_unique.sql"),
    ),
    (
        "0017_device_list_highwater",
        include_str!("../migrations/0017_device_list_highwater.sql"),
    ),
    (
        "0018_one_owner",
        include_str!("../migrations/0018_one_owner.sql"),
    ),
    (
        "0019_plugin_epoch_floor",
        include_str!("../migrations/0019_plugin_epoch_floor.sql"),
    ),
    (
        "0020_push_wake_debounce",
        include_str!("../migrations/0020_push_wake_debounce.sql"),
    ),
    (
        "0021_fanout_retry",
        include_str!("../migrations/0021_fanout_retry.sql"),
    ),
    ("0022_quotas", include_str!("../migrations/0022_quotas.sql")),
    (
        "0023_quota_caps",
        include_str!("../migrations/0023_quota_caps.sql"),
    ),
    (
        "0024_cf_config",
        include_str!("../migrations/0024_cf_config.sql"),
    ),
    (
        "0025_server_config",
        include_str!("../migrations/0025_server_config.sql"),
    ),
    (
        "0026_plugin_media",
        include_str!("../migrations/0026_plugin_media.sql"),
    ),
    (
        "0027_server_plugin_policy",
        include_str!("../migrations/0027_server_plugin_policy.sql"),
    ),
    (
        "0028_storage_backends",
        include_str!("../migrations/0028_storage_backends.sql"),
    ),
    (
        "0029_media_scope",
        include_str!("../migrations/0029_media_scope.sql"),
    ),
    (
        "0030_delete_window",
        include_str!("../migrations/0030_delete_window.sql"),
    ),
    (
        "0031_invite_attributions",
        include_str!("../migrations/0031_invite_attributions.sql"),
    ),
    (
        "0032_contacts_directory_v2",
        include_str!("../migrations/0032_contacts_directory_v2.sql"),
    ),
    (
        "0033_contact_qr_v2",
        include_str!("../migrations/0033_contact_qr_v2.sql"),
    ),
    (
        "0034_membership_cleanup_outbox",
        include_str!("../migrations/0034_membership_cleanup_outbox.sql"),
    ),
    (
        "0035_avatar_objects",
        include_str!("../migrations/0035_avatar_objects.sql"),
    ),
    (
        "0036_silent_push",
        include_str!("../migrations/0036_silent_push.sql"),
    ),
];

thread_local! {
    /// Isolate-scoped "migrations have been checked" flag, so we do not hit D1 on every
    /// request (a WASM isolate is single-threaded, so a thread_local is an isolate memo).
    static MIGRATIONS_CHECKED: Cell<bool> = const { Cell::new(false) };
    /// The JWT PKCS8 PEM resolved from or generated for D1. Populated ONLY when there is
    /// no env secret; jwt.rs's `load_signing_key` fallback reads it from here, keeping
    /// the hot path free of D1.
    static JWT_PEM: RefCell<Option<String>> = const { RefCell::new(None) };
    /// The admin-invite key resolved from or generated for D1 (32 bytes, b64url).
    static ADMIN_INVITE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Boot guard — called at the top of `#[event(fetch)]` and `#[event(scheduled)]`.
/// Memoized per isolate: the first call does the work, the rest are no-ops. On an
/// env-secret + wrangler-migrated deployment (our prod) it degenerates to a COMPLETE
/// no-op.
pub async fn ensure_ready(env: &Env) {
    // KEYS FIRST, MIGRATIONS SECOND (the 2026-07-07 free-plan incident): a free CF
    // account has a tight per-request subrequest budget, and when the key path competed
    // with the heavy migration batch inside the SAME request it starved and jwks/verify
    // returned 500 — the migrations created the tables, so bootstrap/welcome worked, but
    // no key could be generated. ensure_keys creates its own `server_config` table and
    // does NOT depend on migration 0025, so it finishes in a handful of subrequests; the
    // migrations run afterwards and even if they exhaust the budget the key is already
    // in place.
    ensure_keys(env).await;
    ensure_migrations(env).await;
}

/// The key leg on its own — needed by the UserInbox DO (`ws_upgrade` token validation):
/// a DO fetch does NOT pass through lib.rs's `#[event(fetch)]`, so the DO has to
/// populate its own isolate's cache. Memoized, and never touches D1 when an env secret
/// exists.
pub async fn ensure_keys(env: &Env) {
    ensure_one_key(
        env,
        "JWT_SIGNING_KEY",
        "jwt_signing_key",
        &JWT_PEM,
        generate_jwt_signing_pem,
        validate_jwt_pem,
    )
    .await;
    ensure_one_key(
        env,
        "ADMIN_INVITE_KEY",
        "admin_invite_key",
        &ADMIN_INVITE,
        generate_admin_invite_key,
        validate_invite_key,
    )
    .await;
}

/// The fallback for jwt.rs's `load_signing_key`: the PEM resolved from or generated for
/// D1 at boot. It is NEVER populated while an env secret exists — in that case jwt.rs
/// takes the env path directly, exactly as it does today.
pub fn cached_jwt_pem() -> Option<String> {
    JWT_PEM.with(|c| c.borrow().clone())
}

/// Resolve ADMIN_INVITE_KEY — env first, then the self-provision cache.
/// NOTE: as of 2026-07 NO code reads this key yet (it is documented in wrangler.toml and
/// referenced by a "harden this gate later" note in bootstrap.rs). Self-provision
/// GENERATES it on a fresh fork anyway so it is ready; the future consumer (the
/// bootstrap gate) will call this function.
#[allow(dead_code)]
pub fn resolve_admin_invite_key(env: &Env) -> Option<String> {
    if let Ok(s) = env.secret("ADMIN_INVITE_KEY") {
        return Some(s.to_string());
    }
    ADMIN_INVITE.with(|c| c.borrow().clone())
}

// ── A1: the key resolution chain ────────────────────────────────────────────

async fn ensure_one_key(
    env: &Env,
    env_name: &str,
    db_key: &str,
    cache: &'static std::thread::LocalKey<RefCell<Option<String>>>,
    generate: fn() -> Result<String>,
    validate: fn(&str) -> bool,
) {
    // 1) env secret → accepted ONLY if non-empty AND it passes validate (then skip D1).
    //    CRITICAL (the 2026-07-07 free-account incident): on the button-deploy runtime
    //    (newer wrangler) an UNSET secret can come back as `Ok("")` where the old runtime
    //    returned `Err`. Checking `is_ok()` let an empty/corrupt value take the env-first
    //    branch and BYPASS self-heal → jwks/verify 500 with "PEM type label invalid". Now
    //    an empty or invalid env secret is IGNORED and self-provision (D1 or generation)
    //    takes over. Prod with a valid env secret is bit-identical: non-empty + validate
    //    → early return.
    if let Ok(s) = env.secret(env_name) {
        let v = s.to_string();
        if !v.trim().is_empty() && validate(&v) {
            return;
        }
    }
    // 2) Isolate cache is populated → done (hot path, no D1 round-trip).
    if cache.with(|c| c.borrow().is_some()) {
        return;
    }
    // 3) Read from D1 (and VALIDATE; a corrupt value is regenerated = self-heal), or
    //    4) generate and persist. On error: console_error and leave the cache empty, so
    //    the NEXT request tries again (self-heal across transient D1 errors). This path
    //    only ever runs on deployments without an env secret anyway.
    match resolve_from_db(env, db_key, generate, validate).await {
        Ok(v) => cache.with(|c| *c.borrow_mut() = Some(v)),
        Err(e) => console_error!("self_provision: {} cozulemedi: {}", db_key, e),
    }
}

/// Read D1 `server_config` and VALIDATE it; if the value is corrupt or missing, generate
/// and persist a new one.
///
/// SELF-HEAL (the 2026-07-06 sezi-server2 incident): an old/broken build had written an
/// INVALID JWT PEM into D1, and current code used it blindly, so every token signature
/// and every jwks request 500'd — registration died halfway, leaving a ghost owner and a
/// permanently wedged server. The rule: a user must NEVER have to clean the worker's
/// internals by hand, so any value read from D1 that FAILS validate is regenerated and
/// overwritten.
async fn resolve_from_db(
    env: &Env,
    db_key: &str,
    generate: fn() -> Result<String>,
    validate: fn(&str) -> bool,
) -> Result<String> {
    let db = env.d1("DB")?;
    // The key path creates `server_config` ITSELF, independently of migration 0025, so
    // ensure_keys can run BEFORE the migrations (see the ordering rationale in
    // ensure_ready). IF NOT EXISTS makes migration 0025 a no-op when it runs later.
    db.prepare(
        "CREATE TABLE IF NOT EXISTS server_config \
         (key TEXT PRIMARY KEY, value TEXT NOT NULL, created_at INTEGER NOT NULL)",
    )
    .run()
    .await?;
    if let Some(v) = read_config(&db, db_key).await? {
        if validate(&v) {
            return Ok(v);
        }
        // Corrupt record → regenerate and INSERT OR REPLACE. Deliberate: ON CONFLICT
        // DO NOTHING would PRESERVE the corrupt record, and here overwriting is mandatory.
        console_warn!(
            "self_provision: {} the D1 record is CORRUPT (it did not validate) → regenerating (self-heal; 2026-07-06 sezi-server2 vakasi)",
            db_key
        );
        let candidate = generate()?;
        // Paranoia: validate even what we just generated, so that if the generator and
        // the validator ever diverge we do not persist a corrupt value into D1.
        if !validate(&candidate) {
            return Err(Error::RustError(format!(
                "self_provision: {db_key} uretilen deger validate'i gecemedi (uretici/dogrulayici uyumsuz?)"
            )));
        }
        db.prepare(
            "INSERT OR REPLACE INTO server_config (key, value, created_at) VALUES (?, ?, ?)",
        )
        .bind(&[
            d1_text(db_key),
            d1_text(&candidate),
            d1_int(now_secs() as i64),
        ])?
        .run()
        .await?;
        console_log!(
            "self_provision: {} regenerated and written to D1 (over the corrupt record)",
            db_key
        );
        // Race note: if two isolates self-heal at the same time, the last writer wins the
        // REPLACE. That is harmless because both values are freshly generated and
        // validated: the loser keeps using its own value, and once isolates recycle
        // everyone converges on the winner in D1. A corrupt record cannot reappear —
        // every value written passed validate.
        return Ok(candidate);
    }

    // A fresh fork's first boot: GENERATE and persist. RACE GUARD: two concurrent cold
    // starts may generate at the same time, so `ON CONFLICT DO NOTHING` lets the first
    // writer win (the loser is a no-op) and a re-SELECT AFTER persisting reads the winning
    // value back. Two instances therefore NEVER use different keys — whatever ends up in
    // use is the single truth stored in D1.
    let candidate = generate()?;
    // Paranoia (same rationale as above): never persist a corrupt value into D1.
    if !validate(&candidate) {
        return Err(Error::RustError(format!(
            "self_provision: {db_key} uretilen deger validate'i gecemedi (uretici/dogrulayici uyumsuz?)"
        )));
    }
    db.prepare(
        "INSERT INTO server_config (key, value, created_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO NOTHING",
    )
    .bind(&[
        d1_text(db_key),
        d1_text(&candidate),
        d1_int(now_secs() as i64),
    ])?
    .run()
    .await?;
    console_log!(
        "self_provision: {} generated and persisted to D1 (fresh install)",
        db_key
    );
    match read_config(&db, db_key).await? {
        // The winner must pass validate too: if an old or broken writer won the race
        // (theoretically possible), do not use its value — fall back to our own fresh one,
        // and the next boot's corrupt-record branch will repair D1.
        Some(winner) if validate(&winner) => Ok(winner),
        Some(_) => {
            console_warn!(
                "self_provision: {} the D1 value that won the race is CORRUPT — using our own fresh value instead (the next boot self-heals eder)",
                db_key
            );
            Ok(candidate)
        }
        // Unexpected (the insert just succeeded) — fall back to our own value.
        None => Ok(candidate),
    }
}

// ── Key validators (pure → unit-tested) ─────────────────────────────────────

/// Is a JWT PEM read from D1 valid? It is checked with the very parser jwt.rs WILL use
/// (`parse_signing_pem`), so "passed validate but blew up while signing" is impossible —
/// it is literally the same function.
fn validate_jwt_pem(v: &str) -> bool {
    crate::auth::jwt::parse_signing_pem(v).is_ok()
}

/// A reasonable gate for the admin-invite key: not empty and not just whitespace is
/// enough — it is an opaque shared secret with no required format.
fn validate_invite_key(v: &str) -> bool {
    !v.trim().is_empty()
}

async fn read_config(db: &D1Database, key: &str) -> Result<Option<String>> {
    #[derive(serde::Deserialize)]
    struct Row {
        value: String,
    }
    let row: Option<Row> = db
        .prepare("SELECT value FROM server_config WHERE key = ? LIMIT 1")
        .bind(&[d1_text(key)])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.value))
}

/// Generate an Ed25519 JWT signing key — the SAME crate as jwt.rs's verifier
/// (ed25519-dalek) and the SAME format (PKCS8 PEM; the `from_pkcs8_pem` round-trip is
/// unit-tested). `LineEnding::LF` produces a PEM with real newlines, so the `"\\n"→"\n"`
/// replacement jwt.rs performs for env secrets is a no-op on this value.
fn generate_jwt_signing_pem() -> Result<String> {
    use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey};
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| Error::RustError(format!("self_provision: rng: {e}")))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::RustError(format!("self_provision: pkcs8 pem encode: {e}")))?;
    Ok(pem.to_string())
}

/// Generate an ADMIN_INVITE_KEY: 32 CSPRNG bytes → base64url, unpadded, 43 chars. In the
/// worker the RNG is getrandom (js feature), the same path utils.rs `random_b64u` uses.
fn generate_admin_invite_key() -> Result<String> {
    Ok(crate::utils::random_b64u(32))
}

// ── A2: self-migration ──────────────────────────────────────────────────────

async fn ensure_migrations(env: &Env) {
    if MIGRATIONS_CHECKED.with(|c| c.get()) {
        return;
    }
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(e) => {
            console_error!("self_provision: D1 binding yok: {}", e);
            return;
        }
    };
    // FAIL-SOFT (not fail-open, but not a 500 either): if a migration fails, keep serving
    // with the CURRENT schema instead of 500ing requests. Rationale: migrations are
    // batch-atomic (there is no half-applied schema), so a failure just means the schema
    // stayed old — endpoints that work on the old schema keep working, and the ones that
    // need the new columns already return a meaningful error. A hard block would look like
    // "the server is dead" to a self-host operator; this way only new features stall and
    // the log explains why.
    //
    // The flag is set ONLY ON SUCCESS (the 2026-07-06 free-plan incident): the old
    // "set before trying" choice left a first boot that got cut off at the subrequest limit
    // POISONED for the whole isolate lifetime — the migrations never finished and were
    // never retried, giving deterministic jwks/verify 500s. New rule: do NOT set the flag
    // on Err, so the next request tries again (migrations are tolerant and batch-atomic,
    // hence SAFE to repeat). The risk of a persistent retry loop beats permanent poisoning
    // after a truncated boot, and once the batch succeeds it is a single shot anyway.
    match run_migrations(&db).await {
        Ok(()) => MIGRATIONS_CHECKED.with(|c| c.set(true)),
        Err(e) => console_error!(
            "self_provision: self-migration stopped (serving on with the existing schema): {}",
            e
        ),
    }
}

async fn run_migrations(db: &D1Database) -> Result<()> {
    // Tracking table — DELIBERATELY named apart from wrangler's `d1_migrations`: wrangler
    // owns its own table and may change its schema, so we stay out of it.
    db.prepare(
        "CREATE TABLE IF NOT EXISTS _sezi_migrations \
         (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)",
    )
    .run()
    .await?;

    #[derive(serde::Deserialize)]
    struct NameRow {
        name: String,
    }

    let mut applied: HashSet<String> = db
        .prepare("SELECT name FROM _sezi_migrations")
        .all()
        .await?
        .results::<NameRow>()?
        .into_iter()
        .map(|r| r.name)
        .collect();

    // wrangler compatibility (CRITICAL): our prod applied its migrations with
    // `wrangler d1 migrations apply`, and wrangler records them in its own `d1_migrations`
    // table with names like "0001_init.sql". COUNT those records as applied, so the first
    // self-migration in prod re-runs NOTHING and the deploy is a no-op. FAIL-OPEN: if the
    // table does not exist (a fresh fork whose DB never met wrangler) just ignore it. The
    // merge happens on every isolate boot via one cheap SELECT, so if someone later applies
    // a migration through the CLI, self-migration sees it as applied too.
    if let Ok(res) = db.prepare("SELECT name FROM d1_migrations").all().await {
        if let Ok(rows) = res.results::<NameRow>() {
            for r in rows {
                applied.insert(normalize_migration_name(&r.name).to_string());
            }
        }
    }

    let pending: Vec<(&str, &str)> = MIGRATIONS
        .iter()
        .filter(|(name, _)| !applied.contains(*name))
        .copied()
        .collect();
    // Prod bit-identity guard: on a wrangler-seeded deployment nothing is pending, so the
    // single batch is NEVER built (early return, preserving today's no-op prod deploy).
    if pending.is_empty() {
        return Ok(());
    }

    // SINGLE BATCH (the 2026-07-06 free-plan subrequest budget): the statements of ALL
    // pending files plus each file's tracking INSERT go into one `db.batch` in file order —
    // one subrequest, one implicit transaction. The old batch-plus-INSERT-per-file pattern
    // cost ~50 D1 calls on a fresh install and got cut off at the Workers free plan's
    // ~50-subrequest gate during the first boot. Atomicity got STRONGER too: the 0017-style
    // trap ("a bare ALTER followed by an UPDATE") is now all-or-nothing across the WHOLE
    // pending set rather than just within a file, so a truncated/half-applied schema is
    // impossible.
    let merged = merge_pending_statements(&pending);
    let mut stmts: Vec<D1PreparedStatement> = Vec::with_capacity(merged.len());
    for m in &merged {
        match m {
            MergedStmt::Sql(s) => stmts.push(db.prepare(s)),
            MergedStmt::Track(name) => stmts.push(
                db.prepare(
                    "INSERT OR IGNORE INTO _sezi_migrations (name, applied_at) VALUES (?, ?)",
                )
                .bind(&[d1_text(name), d1_int(now_secs() as i64)])?,
            ),
        }
    }
    match db.batch(stmts).await {
        Ok(_) => {
            console_log!(
                "self_provision: {} migrations applied in a single batch",
                pending.len()
            );
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if is_benign_schema_conflict(&msg) {
                // A schema conflict (duplicate column / already exists) means either two
                // concurrent cold starts raced, or this DB was wrangler-migrated but its
                // `d1_migrations` table was unreachable. The single batch rolled back and
                // left the schema untouched, so fall back to FILE-BY-FILE tolerant-apply:
                // conflicting files count as applied and genuinely missing ones run. A rare
                // path whose subrequest cost matches the old pattern (≤2 calls per file),
                // which was deemed acceptable.
                console_warn!(
                    "self_provision: single-batch schema conflict ({}) → falling back to a tolerant file-by-file pass",
                    msg
                );
                for &(name, sql) in &pending {
                    apply_one(db, name, sql).await?;
                }
                Ok(())
            } else {
                // A REAL error. A single batch cannot tell us which file blew up, so pass
                // D1's raw error text through verbatim — the SQLite message usually gives
                // the file away via a table/column name — and if per-file diagnosis is
                // needed, the fallback path already reports the file name.
                Err(Error::RustError(format!(
                    "single-batch migration ({} pending): {msg}",
                    pending.len()
                )))
            }
        }
    }
}

/// Apply one migration ATOMICALLY — now called ONLY from the single batch's benign
/// schema-conflict fallback (the main path is `run_migrations`'s single batch; this one
/// takes over when per-file tolerant-apply is needed). A D1 batch is an implicit
/// transaction: if even one statement errors, ALL of it rolls back — the same pattern as
/// devices/handlers.rs. That atomicity closes the 0017-style trap within a file: in a file
/// with "a bare ALTER (duplicate column) followed by an UPDATE", the ALTER's error rolls
/// the WHOLE batch back so the UPDATE NEVER runs on its own. If it did, it would drag the
/// live `device_list_rev` high-water backwards — a data regression, found by the 2026-07-06
/// migration audit. The single-batch main path strengthens this further: all-or-nothing
/// applies to the ENTIRE pending set.
async fn apply_one(db: &D1Database, name: &str, sql: &str) -> Result<()> {
    let statements = split_sql_statements(sql);
    if statements.is_empty() {
        // Defensive: an empty or comment-only file counts as applied (nothing to run).
        return record_applied(db, name).await;
    }
    let stmts: Vec<D1PreparedStatement> = statements.iter().map(|s| db.prepare(s)).collect();
    match db.batch(stmts).await {
        Ok(_) => {
            record_applied(db, name).await?;
            console_log!("self_provision: migration uygulandi: {}", name);
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if is_benign_schema_conflict(&msg) {
                // TOLERANT-APPLY: "duplicate column name" / "already exists" means the
                // schema ALREADY contains this migration — either a wrangler-migrated DB
                // whose `d1_migrations` record was unreachable, or the losing side of a
                // migration race between two concurrent cold starts. The batch rolled back,
                // so the existing schema was NOT touched; count it as applied and continue.
                // (Surveying the embedded files, the only non-idempotent classes are bare
                // ALTER ADD COLUMN — SQLite has no IF NOT EXISTS for it — and the CREATEs
                // without IF NOT EXISTS in 0014/0015/0016; both produce only these two
                // messages.)
                console_warn!(
                    "self_provision: migration treated as already applied ({}): {}",
                    name,
                    msg
                );
                record_applied(db, name).await
            } else {
                // A REAL error: do not record it and STOP the chain (later migrations may
                // depend on this one). The caller behaves fail-soft, and the next isolate
                // boot retries.
                Err(Error::RustError(format!("migration {name}: {msg}")))
            }
        }
    }
}

async fn record_applied(db: &D1Database, name: &str) -> Result<()> {
    db.prepare("INSERT OR IGNORE INTO _sezi_migrations (name, applied_at) VALUES (?, ?)")
        .bind(&[d1_text(name), d1_int(now_secs() as i64)])?
        .run()
        .await?;
    Ok(())
}

// ── Pure helpers (unit-tested) ──────────────────────────────────────────────

/// One item of the single-batch merge: either a raw SQL statement from a migration file,
/// or a marker for that file's `_sezi_migrations` tracking INSERT. The INSERT itself is
/// bound by the caller, which builds the SQL text; only the file name travels through
/// here, so the merge stays PURE and unit-testable.
#[derive(Debug, PartialEq)]
enum MergedStmt {
    Sql(String),
    Track(String),
}

/// Merge the pending files into ONE batch vector. Order contract: file1's statements,
/// file1's track, file2's statements, file2's track, ... A file's track always comes AFTER
/// its own statements: the batch is an implicit transaction anyway, but the order is kept
/// for fallback diagnosis and readability. An empty or comment-only file yields just a
/// track (the same outcome as apply_one's "count as applied" defense). No pending files
/// yields an empty vector.
fn merge_pending_statements(pending: &[(&str, &str)]) -> Vec<MergedStmt> {
    let mut out = Vec::new();
    for &(name, sql) in pending {
        for s in split_sql_statements(sql) {
            out.push(MergedStmt::Sql(s));
        }
        out.push(MergedStmt::Track(name.to_string()));
    }
    out
}

/// wrangler's `d1_migrations.name` is the file name including the ".sql" suffix, while our
/// list is extension-free. Normalize by trimming and stripping ".sql".
fn normalize_migration_name(raw: &str) -> &str {
    let t = raw.trim();
    t.strip_suffix(".sql").unwrap_or(t)
}

/// Split a SQL file into statements. NOT a naive `;` split: migration comments do contain
/// `;` — a real example is 0014's inline column comment, which is written in Turkish and
/// carries a `;` mid-sentence — and a naive split would cut that CREATE TABLE in half.
/// that CREATE TABLE in half.
/// This is a small state machine aware of string literals (including the `''` escape),
/// `--` line comments and `/* */` block comments. Comments are STRIPPED so D1's prepare
/// receives pure SQL, and a `;` only terminates a statement in normal context. Triggers
/// (with `;` inside BEGIN...END) do NOT appear in the migration files; if one is ever
/// added this splitter will not suffice and will have to be revisited then.
fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            cur.push(c);
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    // '' is an escaped single quote → the string continues.
                    cur.push(chars.next().unwrap());
                } else {
                    in_string = false;
                }
            }
            continue;
        }
        match c {
            '\'' => {
                in_string = true;
                cur.push(c);
            }
            '-' if chars.peek() == Some(&'-') => {
                // Line comment: drop everything to end of line, but keep a newline so
                // adjacent tokens do not get glued together.
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
                cur.push('\n');
            }
            '/' if chars.peek() == Some(&'*') => {
                // Block comment: drop everything up to `*/` (none in today's files; defensive).
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                cur.push(' ');
            }
            ';' => {
                let stmt = cur.trim();
                if !stmt.is_empty() {
                    out.push(stmt.to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let tail = cur.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

/// Tolerant-apply classification: ONLY "the schema is already like this" errors are benign.
/// The SQLite messages are "duplicate column name: X" (re-running a bare ALTER ADD COLUMN,
/// which many migrations from 0003 onward use — SQLite has no IF NOT EXISTS for it) and
/// "table/index X already exists" (re-running a CREATE without IF NOT EXISTS, i.e.
/// 0014/0015/0016). A UNIQUE violation, "no such table", a syntax error and the like are
/// REAL errors and are never swallowed.
fn is_benign_schema_conflict(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("duplicate column name") || m.contains("already exists")
}

#[cfg(test)]
#[path = "self_provision_tests.rs"]
mod tests;
