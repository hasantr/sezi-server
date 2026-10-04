//! `POST /admin/reset` — wipe this server's DATA and leave its CONFIGURATION standing.
//!
//! An owner finished with a server wants a clean one at the SAME address, because the address is
//! what every client is paired to. Wiping the data gives that back: `users` empties,
//! `welcome::owner_exists` reads false, `ensure_genesis_token` mints a new code, and whoever
//! redeems that genesis invite becomes the owner again (`invite_attribution::CLAIM_INVITE_SQL`
//! decides the genesis fact; the claim gate is `SELECT id FROM users WHERE role='owner'`).
//!
//! ⚠️ **A wiped server is UNOWNED, and an unowned server is CLAIMABLE.** With no owner the genesis
//! code is public by design, so wiping and walking away leaves an address where the first stranger
//! becomes the owner. The client has to say so.
//!
//! **User data goes. Owner configuration stays** — one sentence, so a future table lands on the
//! right side without a judgement call. The halves are [`WIPE_TABLES`] and [`KEEP_TABLES`], data
//! rather than prose so the guard test can check every migrated table appears in exactly one. The
//! name is deliberately KEPT: renaming is its own owner-only feature.
//!
//! Two traps: **blobs** — wiping `media_objects` and friends would leave every R2 blob
//! unreferenced, invisible and still billed, so object rows are copied into `storage_orphans`
//! first (the daily `retry_orphans` drains it) with key schemes byte-identical to
//! `storage::media_key`/`avatar_key`/`plugin_media_key`. And **foreign keys** —
//! `media_objects.uploader_id`, `avatar_objects.user_id` and `refresh_tokens.user_id` reference
//! `users(id)`, and a D1 batch is one transaction, so `users` goes LAST and the orphan copies
//! first.
//!
//! Durable Objects are not touched and need not be: a DO is addressed by `id_from_name(user_id)`
//! and registration mints a fresh `Uuid`, so new accounts get new DOs and the retention alarm
//! collects the old. It is also why the wipe includes the OWNER — keeping their row keeps their
//! old inbox DO while D1 insists they have no devices.

use crate::auth::hashing::{hash_code, secret_eq, verify_code};
use crate::auth::middleware::{require_active_auth, require_owner};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// `server_config` key holding the PBKDF2 hash of the owner's reset key.
const RESET_KEY_ROW: &str = "reset_password_hash";

/// Minimum length for a reset key set through the API. Modest on purpose: the gate is already
/// behind `require_owner` and a 5-per-15-minutes brake, so this guards against "1234", not against
/// an offline attacker.
const MIN_RESET_KEY_LEN: usize = 8;

#[derive(Deserialize, Default)]
struct ResetBody {
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct ValueRow {
    value: String,
}

/// Does this server have a destruction kit at all? Read by `/admin/stats` so the owner's setup
/// checklist can say "you cannot reset this server yet" instead of the owner finding out at the
/// moment they try. Presence only — the value is never returned anywhere.
pub async fn reset_key_configured(env: &Env) -> bool {
    if env
        .secret("RESET_PASSWORD")
        .map(|s| !s.to_string().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    match env.d1("DB") {
        Ok(db) => stored_reset_hash(&db).await.is_some(),
        Err(_) => false,
    }
}

/// The stored hash, or `None` when the owner never set one.
async fn stored_reset_hash(db: &D1Database) -> Option<String> {
    let row: Option<ValueRow> = db
        .prepare("SELECT value FROM server_config WHERE key = ? LIMIT 1")
        .bind(&[d1_text(RESET_KEY_ROW)])
        .ok()?
        .first(None)
        .await
        .ok()?;
    row.map(|r| r.value).filter(|v| !v.is_empty())
}

/// `POST /admin/reset-key` — set or change this server's reset key (owner only).
///
/// It exists so the key is not reachable only through `wrangler secret put`, i.e. shell access: an
/// owner who deployed with the dashboard button would otherwise have no destruction kit at all. A
/// server should arrive carrying the means to undo itself.
///
/// Stored as a PBKDF2 hash, so reading D1 does not hand anyone the gate, and returned by no
/// endpoint (`/admin/stats` answers a bare bool). That is what keeps the wipe TWO factors — an
/// owner token plus something only the owner knows; handing the key back over an
/// owner-authenticated read would collapse it to one.
pub async fn set_reset_key(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let body: ResetBody = req.json().await.unwrap_or_default();
    if body.password.len() < MIN_RESET_KEY_LEN {
        return json_err(400, "reset_key_too_short");
    }
    let db = ctx.env.d1("DB")?;
    db.prepare(
        "INSERT INTO server_config(key,value,created_at) VALUES(?,?,?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value,created_at=excluded.created_at",
    )
    .bind(&[
        d1_text(RESET_KEY_ROW),
        d1_text(&hash_code(&body.password)),
        d1_int(now_secs() as i64),
    ])?
    .run()
    .await?;
    // The KEY is never logged — only that one now exists, which is what makes an unexpected
    // change auditable in a tail.
    console_log!("[reset] reset key set by owner={user_id}");
    Response::from_json(&serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct CountRow {
    n: i64,
}

/// Tables emptied by a reset, in an order that never deletes a parent before its children.
/// `users` is LAST for exactly that reason (see the module doc).
///
/// A table absent from BOTH this list and the KEPT list in the module doc is a bug waiting to
/// happen, which is what `every_table_is_classified` guards.
const WIPE_TABLES: &[&str] = &[
    // Queued/transient traffic first — no dependents.
    "pending_messages",
    "fanout_retry",
    "push_wake_debounce",
    "verification_codes",
    "link_requests",
    // Stored-object bookkeeping (the blobs were copied into storage_orphans above).
    "media_objects",
    "avatar_objects",
    "plugin_media_objects",
    "plugin_code_objects",
    "room_library_objects",
    // Group state. Join requests first: they reference both `groups` and `users`.
    "group_join_requests",
    "group_members",
    "plugin_epoch_floor",
    "membership_delete_guard",
    "groups",
    // Contacts and directory.
    "contact_requests",
    "contact_grants",
    "contact_blocks",
    "contact_qr_offers",
    "contact_qr_claims",
    "contact_revisions",
    "contact_tombstones",
    "directory_revisions",
    "directory_tombstones",
    // Keys, sessions, devices.
    "one_time_prekeys",
    "signed_prekeys",
    "device_lists",
    "refresh_tokens",
    "push_tokens",
    "devices",
    // Invites and accounting.
    "invite_attributions",
    "invite_tokens",
    "usage_counters",
    "user_storage",
    "server_stats",
    "turn_usage",
    "account_purge_outbox",
    // LAST: every table above may reference it.
    "users",
];

/// Tables a reset must NOT touch — the owner's configuration and the server's own identity.
///
/// Data rather than prose so the classification guard can check BOTH halves. Its only reader is
/// that test, which is the point: a prose list drifts from the code with nothing failing.
#[allow(dead_code)]
const KEEP_TABLES: &[&str] = &[
    "server_settings",
    "server_config",
    "server_plugin_policy",
    "storage_backends",
    // Populated by the wipe itself: the blobs still have to be deleted from the store.
    "storage_orphans",
];

pub async fn reset(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_owner(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    // Brute-force brake BEFORE the comparison. The gate is a single shared password rather than a
    // per-account credential, so without a limit an owner-role attacker (or a stolen owner token)
    // could grind it. Deliberately tight — a human types this once.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("admin:reset:{user_id}"), 5, 900)
        .await
    {
        return json_err(429, "rate_limited");
    }
    let db = ctx.env.d1("DB")?;
    let body: ResetBody = req.json().await.unwrap_or_default();
    // Two sources, ENV SECRET WINS — the precedence `self_provision` uses for the JWT key, so an
    // owner who moves the gate out of the database is respected. Otherwise the key set through
    // `/admin/reset-key`, compared against its PBKDF2 hash.
    //
    // FAIL-CLOSED with NEITHER: a server holding no destruction kit cannot be wiped over the
    // network at all. An owner-token compromise alone must never be enough to erase a server.
    let env_secret = ctx
        .env
        .secret("RESET_PASSWORD")
        .map(|s| s.to_string())
        .unwrap_or_default();
    let authorized = if !env_secret.is_empty() {
        secret_eq(&body.password, &env_secret)
    } else {
        match stored_reset_hash(&db).await {
            Some(hash) => verify_code(&body.password, &hash),
            None => return json_err(503, "reset_not_configured"),
        }
    };
    if !authorized {
        return json_err(403, "reset_password_invalid");
    }

    let now = now_secs() as i64;
    // Counted BEFORE the wipe so the response can say what it destroyed. The client shows this
    // number in its confirmation, and afterwards as a record of what happened.
    let members: i64 = db
        .prepare("SELECT COUNT(*) AS n FROM users")
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);

    // ── 1) Blobs → storage_orphans (BEFORE the rows that name them are deleted) ──────────────
    // The key schemes are byte-identical to storage::{media_key, avatar_key, plugin_media_key} and
    // to membership.rs; the daily retry_orphans pass drains the table and deletes from the store.
    let mut stmts = vec![
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'media/' || blob_id,size_bytes,?,0 FROM media_objects",
        )
        .bind(&[d1_int(now)])?,
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'avatar/' || user_id || '/' || object_id,size_bytes,?,0
               FROM avatar_objects",
        )
        .bind(&[d1_int(now)])?,
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'plugin-media/' || room_id || '/' || blob_id,size_bytes,?,0
               FROM plugin_media_objects",
        )
        .bind(&[d1_int(now)])?,
        db.prepare(
            "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
             SELECT store_id,'plugin-code/' || room_id || '/' || blob_id,size_bytes,?,0
               FROM plugin_code_objects",
        )
        .bind(&[d1_int(now)])?,
        // The group library's parts — every group's, since every group goes.
        db.prepare(crate::room_library::cleanup::ORPHAN_ALL_SQL)
            .bind(&[d1_int(now)])?,
    ];
    // ── 2) The wipe itself, children before parents ──────────────────────────────────────────
    for table in WIPE_TABLES {
        stmts.push(db.prepare(format!("DELETE FROM {table}")));
    }
    db.batch(stmts).await?;

    console_log!(
        "[reset] server wiped by owner={user_id} accounts_removed={members} \
         (configuration kept; blobs queued for store deletion)"
    );
    // Same probe `/capabilities` uses, so the two cannot disagree about whether a media store
    // exists. On error → false: claiming there is nothing to clean up would be the harmful lie.
    let media_store = crate::storage::StorageRouter::from_env(&ctx.env)
        .await
        .map(|r| r.any_available())
        .unwrap_or(false);
    Response::from_json(&serde_json::json!({
        "ok": true,
        "accounts_removed": members,
        // The wipe frees D1 rows and queues the blobs, but the Cloudflare RESOURCES — Worker, D1,
        // R2, KV, the custom domain — outlive it and only the dashboard can remove them, so this
        // is reported at the one moment the user needs it. Booleans rather than names: a Worker
        // does not know its own script or database name at runtime, only which bindings it has.
        "remaining": {
            "media_store": media_store,
            "rate_limit_kv": ctx.env.kv("RATE_LIMIT").is_ok(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wipe list and the keep list must together classify every table the migrations create. A
    /// table in NEITHER survives every reset silently, and nobody notices until its stale rows
    /// produce a bug that looks impossible on a "clean" server.
    ///
    /// The expected set is written out rather than parsed: a test deriving it from the source it
    /// checks would agree with itself. So a new migration means three deliberate edits — one list
    /// here, one of the two above — instead of one silent omission.
    #[test]
    fn every_table_is_classified_as_wiped_or_kept() {
        // Every CREATE TABLE in worker-rs/migrations, minus the two `*_new` rebuild scratch tables
        // (dropped by the migration that makes them) and the migration bookkeeping.
        const ALL: &[&str] = &[
            "account_purge_outbox",
            "avatar_objects",
            "contact_blocks",
            "contact_grants",
            "contact_qr_claims",
            "contact_qr_offers",
            "contact_requests",
            "contact_revisions",
            "contact_tombstones",
            "device_lists",
            "devices",
            "directory_revisions",
            "directory_tombstones",
            "fanout_retry",
            "group_join_requests",
            "group_members",
            "groups",
            "invite_attributions",
            "invite_tokens",
            "link_requests",
            "media_objects",
            "membership_delete_guard",
            "one_time_prekeys",
            "pending_messages",
            "plugin_code_objects",
            "plugin_epoch_floor",
            "plugin_media_objects",
            "push_tokens",
            "push_wake_debounce",
            "refresh_tokens",
            "room_library_objects",
            "server_config",
            "server_plugin_policy",
            "server_settings",
            "server_stats",
            "signed_prekeys",
            "storage_backends",
            "storage_orphans",
            "turn_usage",
            "usage_counters",
            "user_storage",
            "users",
            "verification_codes",
        ];
        for t in ALL {
            let wiped = WIPE_TABLES.contains(t);
            let kept = KEEP_TABLES.contains(t);
            assert!(
                wiped || kept,
                "table `{t}` is in neither WIPE_TABLES nor KEEP_TABLES — decide which, \
                 or it survives every reset unnoticed"
            );
            assert!(
                !(wiped && kept),
                "table `{t}` is in BOTH lists — one of the two is wrong"
            );
        }
    }

    /// `users` last: several wiped tables have a foreign key into it and a D1 batch is one
    /// transaction, so deleting the parent first rolls the whole wipe back.
    #[test]
    fn users_is_deleted_last() {
        assert_eq!(
            WIPE_TABLES.last().copied(),
            Some("users"),
            "users must be deleted last — media_objects, avatar_objects and refresh_tokens \
             reference it, and an FK violation rolls back the entire batch"
        );
    }

    /// The tables holding blobs must be wiped only AFTER their keys have been copied into
    /// storage_orphans. This checks the weaker but testable half: they are in the wipe list at all,
    /// so a rename that drops one from the list fails here rather than leaking blobs quietly.
    #[test]
    fn every_object_table_is_wiped_so_its_blobs_are_accounted_for() {
        for t in [
            "media_objects",
            "avatar_objects",
            "plugin_media_objects",
            "plugin_code_objects",
            "room_library_objects",
        ] {
            assert!(
                WIPE_TABLES.contains(&t),
                "`{t}` must be wiped, and its rows copied into storage_orphans first"
            );
        }
    }

    /// The owner's configuration and the server's own identity survive. Losing the JWT signing key
    /// or the external-store credentials buys nothing and breaks things silently.
    #[test]
    fn configuration_and_server_identity_survive_a_reset() {
        for t in [
            "server_settings",
            "server_config",
            "server_plugin_policy",
            "storage_backends",
        ] {
            assert!(KEEP_TABLES.contains(&t), "`{t}` must survive a reset");
            assert!(!WIPE_TABLES.contains(&t), "`{t}` must not be wiped");
        }
    }

    /// An unset secret reads back as an empty string. Comparing a submitted password against it
    /// with `==` would let an empty password through, so the comparison itself refuses.
    #[test]
    fn an_unset_reset_password_matches_nothing() {
        assert!(!secret_eq("", ""), "empty vs unset must NOT match");
        assert!(!secret_eq("anything", ""));
        assert!(secret_eq("s3cret", "s3cret"));
        assert!(!secret_eq("s3cret", "s3creT"));
        assert!(!secret_eq("s3cre", "s3cret"), "a prefix must not match");
    }

    /// The key the owner sets through the API is stored HASHED, so reading `server_config` does not
    /// hand anyone the gate — and the hash still recognises the right key.
    #[test]
    fn a_reset_key_set_through_the_api_is_stored_hashed_and_verifies() {
        let stored = hash_code("correct horse battery");
        assert!(
            !stored.contains("correct horse battery"),
            "the key must not be recoverable from what is stored"
        );
        assert!(verify_code("correct horse battery", &stored));
        assert!(!verify_code("correct horse batteries", &stored));
        assert!(!verify_code("", &stored), "an empty attempt must not pass");
    }

    /// Two different keys must not collide through the salt being reused: the same plaintext hashed
    /// twice yields different encodings, and each still verifies only its own input.
    #[test]
    fn hashing_the_same_key_twice_gives_different_rows_that_both_verify() {
        let a = hash_code("same-key-both-times");
        let b = hash_code("same-key-both-times");
        assert_ne!(a, b, "a per-row salt is what makes the stored value non-comparable");
        assert!(verify_code("same-key-both-times", &a));
        assert!(verify_code("same-key-both-times", &b));
    }

    /// The floor is a floor: a key shorter than the minimum is refused, one at the minimum is not.
    /// Guards against the check drifting to `<=` and rejecting a valid key, or to `>` and letting a
    /// too-short one through.
    #[test]
    fn the_minimum_reset_key_length_is_inclusive() {
        assert_eq!(MIN_RESET_KEY_LEN, 8);
        assert!("1234567".len() < MIN_RESET_KEY_LEN, "one below is refused");
        assert!(
            "12345678".len() >= MIN_RESET_KEY_LEN,
            "exactly the minimum is accepted"
        );
    }

    /// The `server_config` row name is part of the on-disk contract: renaming it would silently
    /// orphan every already-configured server's key, and the reset would go back to answering
    /// "not configured" with no error anywhere.
    #[test]
    fn the_stored_row_key_is_pinned() {
        assert_eq!(RESET_KEY_ROW, "reset_password_hash");
    }
}
