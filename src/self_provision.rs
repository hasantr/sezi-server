//! Self-provisioning — the prerequisite for a zero-CLI deploy: someone who forks the worker into
//! THEIR OWN CF account must get a working server without ever learning `wrangler secret put` or
//! `wrangler d1 migrations apply`. Two legs.
//!
//! **Keys** (`JWT_SIGNING_KEY` + `ADMIN_INVITE_KEY`) resolve env-first, then D1, then
//! generate-and-persist:
//!   1. An env secret ALWAYS wins, so an owner can move the key into a real secret. That path
//!      never touches D1 and needs no memo (reading env is synchronous).
//!   2. Otherwise D1 `server_config`, memoized per isolate — the JWT key is read on every
//!      request, and a WASM isolate is single-threaded so a `thread_local` is enough.
//!   3. Otherwise generate and persist. `ON CONFLICT DO NOTHING` plus a re-SELECT is the race
//!      guard: two concurrent cold starts must not end up on different keys.
//!
//! The key then sits at rest in D1 (CF's encrypted disks) — the self-host honest-server model. No
//! endpoint returns it.
//!
//! **D1 self-migration**: `migrations/*.sql` are embedded with `include_str!` and everything the
//! `_sezi_migrations` table says is missing is applied in ONE `db.batch`. One batch, not a batch
//! plus a tracking INSERT per file: the Workers free plan caps subrequests at ~50 per request, and
//! the per-file shape needed 50+ D1 calls on a fresh install's first boot, was cut off midway and
//! left deterministic 500s. One batch is ~4 calls and makes the pending set all-or-nothing.
//!
//! wrangler compatibility (CRITICAL): a prod that applied its migrations with
//! `wrangler d1 migrations apply` has records in wrangler's own `d1_migrations` table, which COUNT
//! as applied so nothing re-runs. Belt: a benign schema conflict ("duplicate column name" /
//! "already exists") falls back to tolerant-apply (`apply_one`). The CLI path still works;
//! self-migration is only the safety net.

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
    (
        "0037_device_last_seen",
        include_str!("../migrations/0037_device_last_seen.sql"),
    ),
    (
        "0038_instrument_pack",
        include_str!("../migrations/0038_instrument_pack.sql"),
    ),
    (
        "0039_genesis_claim",
        include_str!("../migrations/0039_genesis_claim.sql"),
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
    // KEYS FIRST, MIGRATIONS SECOND. A free CF account's per-request subrequest budget is tight,
    // and with the key path competing against the migration batch in the SAME request the keys
    // starve: the tables get created (so bootstrap/welcome work) while jwks/verify 500s for want
    // of a key. `ensure_keys` creates its own `server_config` and depends on no migration, so it
    // finishes in a handful of subrequests and the key is in place whatever the batch does.
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

/// The fallback for jwt.rs's `load_signing_key`: the PEM resolved from or generated for D1 at
/// boot. Never populated while an env secret exists — jwt.rs takes the env path directly.
pub fn cached_jwt_pem() -> Option<String> {
    JWT_PEM.with(|c| c.borrow().clone())
}

/// Resolve ADMIN_INVITE_KEY — env first, then the self-provision cache. Its consumer is
/// `auth::bootstrap`'s ghost-owner recovery, the one branch of the public `GET /bootstrap` that
/// deletes an owner row and reopens genesis. Generated on a fresh fork, so an installation that
/// never set the secret still has one. `None` means neither source had a key: fail CLOSED.
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
    // An env secret counts ONLY if non-empty AND it validates — `is_ok()` alone is not enough:
    // on the button-deploy runtime an UNSET secret comes back as `Ok("")`, which would take the
    // env-first branch, bypass self-heal, and 500 every jwks/verify with "PEM type label invalid".
    if let Ok(s) = env.secret(env_name) {
        let v = s.to_string();
        if !v.trim().is_empty() && validate(&v) {
            return;
        }
    }
    if cache.with(|c| c.borrow().is_some()) {
        return;
    }
    // On error the cache is left EMPTY so the next request retries — self-heal across a transient
    // D1 error. This path only runs on deployments without an env secret.
    match resolve_from_db(env, db_key, generate, validate).await {
        Ok(v) => cache.with(|c| *c.borrow_mut() = Some(v)),
        Err(e) => console_error!("self_provision: {} cozulemedi: {}", db_key, e),
    }
}

/// Read D1 `server_config` and VALIDATE it; a corrupt or missing value is generated and persisted.
///
/// The validate step is the SELF-HEAL: an invalid JWT PEM written by a broken build and then used
/// blindly 500s every signature and every jwks request, which wedges a server permanently (it has
/// happened, half-way through a registration, leaving a ghost owner). Nobody should have to clean
/// the worker's internals by hand, so a stored value that fails validate is overwritten.
async fn resolve_from_db(
    env: &Env,
    db_key: &str,
    generate: fn() -> Result<String>,
    validate: fn(&str) -> bool,
) -> Result<String> {
    let db = env.d1("DB")?;
    // The key path creates `server_config` ITSELF, so `ensure_keys` can run BEFORE the migrations
    // (ordering rationale in `ensure_ready`). IF NOT EXISTS makes the later migration a no-op.
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
        // INSERT OR REPLACE, deliberately: ON CONFLICT DO NOTHING would PRESERVE the corrupt
        // record, and here overwriting is the whole point.
        console_warn!(
            "self_provision: {} the D1 record is CORRUPT (it did not validate) → regenerating (self-heal; 2026-07-06 sezi-server2 vakasi)",
            db_key
        );
        let candidate = generate()?;
        // Validate even what was just generated: if generator and validator ever diverge, a
        // corrupt value must not reach D1.
        if !validate(&candidate) {
            return Err(Error::RustError(format!(
                "self_provision: {db_key} generated value failed validation (generator/validator mismatch?)"
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
        // Two isolates self-healing at once: last writer wins the REPLACE, harmlessly. Both
        // values validated, the loser keeps using its own, and isolates converge on D1's winner
        // as they recycle.
        return Ok(candidate);
    }

    // A fresh fork's first boot. RACE GUARD: `ON CONFLICT DO NOTHING` lets the first of two
    // concurrent cold starts win, and the re-SELECT AFTER persisting reads the winner back — so
    // two instances never end up on different keys.
    let candidate = generate()?;
    // Same reason as above: never persist a value that does not validate.
    if !validate(&candidate) {
        return Err(Error::RustError(format!(
            "self_provision: {db_key} generated value failed validation (generator/validator mismatch?)"
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
        // The race winner must validate too. If a broken writer won, use our own fresh value and
        // let the next boot's corrupt-record branch repair D1.
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

/// Is a JWT PEM read from D1 valid? Checked with the very parser signing will use, so "passed
/// validate but blew up while signing" is impossible — it is the same function.
fn validate_jwt_pem(v: &str) -> bool {
    crate::auth::jwt::parse_signing_pem(v).is_ok()
}

/// Non-empty is the whole gate: the admin-invite key is an opaque shared secret with no format.
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

/// Generate an Ed25519 JWT signing key — the same crate and format as the verifier (PKCS8 PEM).
/// `LineEnding::LF` gives real newlines, so the `"\\n"→"\n"` fix-up jwt.rs applies to env secrets
/// is a no-op here.
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

/// Generate an ADMIN_INVITE_KEY: 32 CSPRNG bytes → unpadded base64url, 43 chars.
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
            console_error!("self_provision: no D1 binding: {}", e);
            return;
        }
    };
    // FAIL-SOFT: a failed migration keeps serving on the CURRENT schema rather than 500ing.
    // Migrations are batch-atomic, so failure only means the schema stayed old — old endpoints
    // keep working and new ones already answer meaningfully. To a self-host operator a hard block
    // looks like a dead server; this way only new features stall and the log says why.
    //
    // The flag is set ONLY ON SUCCESS. Setting it before trying poisons the whole isolate when a
    // first boot is cut off at the subrequest limit: the migrations never finish and are never
    // retried. Repeating them is safe (tolerant and batch-atomic), so a retry loop is the better
    // risk.
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

    // wrangler compatibility (CRITICAL): wrangler records its own applies in `d1_migrations` as
    // "0001_init.sql". Counting those as applied is what makes the first self-migration on a
    // CLI-migrated DB a no-op. FAIL-OPEN when the table is absent (a fork whose DB never met
    // wrangler). Re-merged on every isolate boot, so a later CLI apply is seen too.
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
    // With nothing pending the batch is never built, so a seeded deployment stays a no-op.
    if pending.is_empty() {
        return Ok(());
    }

    // SINGLE BATCH: every pending file's statements plus its tracking INSERT, in file order, in
    // one `db.batch` — one subrequest, one implicit transaction. This is what fits a fresh
    // install's first boot inside the free plan's ~50-subrequest gate, and it makes the
    // "bare ALTER then UPDATE" trap all-or-nothing across the WHOLE pending set.
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
                // A schema conflict means two cold starts raced, or this DB was wrangler-migrated
                // with its `d1_migrations` unreachable. The batch rolled back untouched, so fall
                // back to file-by-file tolerant-apply — rare, and it costs ≤2 calls per file.
                console_warn!(
                    "self_provision: single-batch schema conflict ({}) → falling back to a tolerant file-by-file pass",
                    msg
                );
                for &(name, sql) in &pending {
                    apply_one(db, name, sql).await?;
                }
                Ok(())
            } else {
                // A REAL error. One batch cannot say which file blew up, so D1's raw text passes
                // through verbatim — its table/column name usually gives the file away.
                Err(Error::RustError(format!(
                    "single-batch migration ({} pending): {msg}",
                    pending.len()
                )))
            }
        }
    }
}

/// Apply one migration ATOMICALLY — called only from the single batch's benign schema-conflict
/// fallback. A D1 batch is an implicit transaction, so one erroring statement rolls all of it
/// back. That is what closes the "bare ALTER (duplicate column) followed by an UPDATE" trap: the
/// ALTER's error takes the UPDATE with it, and an UPDATE that ran alone would drag the live
/// `device_list_rev` high-water backwards.
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
                // TOLERANT-APPLY: "duplicate column name" / "already exists" means the schema
                // ALREADY has this migration. The batch rolled back without touching it, so count
                // it applied. The only non-idempotent statements in the embedded files are bare
                // ALTER ADD COLUMN (SQLite has no IF NOT EXISTS for it) and a few CREATEs without
                // IF NOT EXISTS — both produce exactly these two messages.
                console_warn!(
                    "self_provision: migration treated as already applied ({}): {}",
                    name,
                    msg
                );
                record_applied(db, name).await
            } else {
                // A REAL error: do not record it and STOP the chain — later migrations may depend
                // on this one. The caller is fail-soft and the next isolate boot retries.
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

/// Split a SQL file into statements. NOT a naive `;` split — migration comments contain `;` (0014
/// has one mid-sentence), and a naive split cuts that CREATE TABLE in half. So: a small state
/// machine over string literals (including the `''` escape), `--` line comments and `/* */`
/// blocks; comments are STRIPPED so D1 prepares pure SQL, and a `;` terminates only in normal
/// context. Triggers (a `;` inside BEGIN…END) do not appear in the files; adding one means
/// revisiting this.
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

/// Tolerant-apply classification: ONLY "the schema is already like this" is benign — SQLite's
/// "duplicate column name: X" (a re-run bare ALTER ADD COLUMN) and "table/index X already exists"
/// (a re-run CREATE without IF NOT EXISTS). A UNIQUE violation, "no such table" or a syntax error
/// is a REAL error and is never swallowed.
fn is_benign_schema_conflict(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("duplicate column name") || m.contains("already exists")
}

#[cfg(test)]
#[path = "self_provision_tests.rs"]
mod tests;
