//! Plugin/feed server log — an append-only ENCRYPTED log per (room, plugin) (Faz-2 / WORKER).
//!
//! `PLUGIN_FEED_LOG_SPEC.md` Faz-2. The server is BLIND: an entry's `ciphertext`/`blob` is opaque
//! and it never reads the signature; it only orders (a server-assigned monotonic `seq`), stores and
//! serves from a cursor. Flow: client → handler (validates JWT + active membership + author
//! binding) → the `PluginRoomLog` DO (id_from_name(room) → atomic seq + insert) → `sync(since)`
//! cursor pull.
//!
//! Security is two-layered: (server-honest) the handler enforces `author_id == JWT.user &&
//! author_device_id == JWT.device`, so a malicious MEMBER cannot forge entries; (zero-trust) the
//! reading CLIENT verifies `sig`, so not even a malicious SERVER can (signing/decryption live in
//! CORE, Faz-3). The DO is nothing but opaque storage plus a sequencer.

use crate::auth::middleware::{device_revoked, require_auth_device};
use crate::groups::group_role;
use crate::messages::inbox_do::sql_no_args;
use crate::respond::json_err;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::*;

/// Base64 ceiling for inline ciphertext (anything larger goes to an R2 blob — a later slice).
/// Sized to the message envelope limit (~22KB raw plus the base64 expansion margin).
const MAX_INLINE_B64: usize = 32 * 1024;
/// B4 (Codex HIGH): ceiling for the blob/meta fields. blob_id/blob_hash/aad/nonce and the hash
/// chain are short references (the real payload lives in R2), so 4KB is more than enough, and it
/// bounds the DO row for EVERY content_kind. The old gate only limited inline entries, which let a
/// `blob` (or any other) kind smuggle arbitrarily large ciphertext and inflate both the DO log and
/// every reader's sync.
const MAX_FIELD_B64: usize = 4 * 1024;
/// Entry limit for one sync page (the receipt_sync pattern; `more` signals continuation).
const SYNC_LIMIT: i64 = 500;

/// One log entry — both the client→handler→DO body and (minus `seq`) the DO row. The server is
/// BLIND: `ciphertext_b64`/`blob_id` are opaque; `author_*` is enforced server-honest and the reader
/// verifies the signature.
#[derive(Deserialize, Serialize, Clone)]
pub struct PluginLogEntry {
    pub plugin_id: String,
    pub author_id: String,
    pub author_device_id: String,
    pub key_epoch: i64,
    pub author_counter: i64,
    pub content_kind: String, // "inline" | "blob"
    #[serde(default)]
    pub ciphertext_b64: Option<String>,
    #[serde(default)]
    pub nonce_b64: Option<String>,
    #[serde(default)]
    pub blob_id: Option<String>,
    #[serde(default)]
    pub blob_hash: Option<String>,
    pub aad_hash: String,
    // No `sig` field: the signature lives INSIDE the ciphertext (server-blind authorship proof,
    // verified when core opens the entry).
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub entry_hash: Option<String>,
    pub uploaded_at_ms: i64,
}

#[derive(Deserialize)]
struct SeqRow {
    last_seq: i64,
}

/// A sync row (seq INCLUDED) — read from the DB and returned to the client as JSON.
#[derive(Deserialize, Serialize)]
struct PluginLogEntryRow {
    seq: i64,
    plugin_id: String,
    author_id: String,
    author_device_id: String,
    key_epoch: i64,
    author_counter: i64,
    content_kind: String,
    ciphertext_b64: Option<String>,
    nonce_b64: Option<String>,
    blob_id: Option<String>,
    blob_hash: Option<String>,
    aad_hash: String,
    prev_hash: Option<String>,
    entry_hash: Option<String>,
    uploaded_at_ms: i64,
}

fn js_opt(o: &Option<String>) -> JsValue {
    match o {
        Some(s) => JsValue::from_str(s),
        None => JsValue::NULL,
    }
}

/// Per-room DO: the append-only encrypted log of ALL plugins in that room. A DO is
/// single-threaded, which makes seq assignment atomic (the UserInbox/receipt pattern).
/// `id_from_name(room_id)` gives one instance per room; `plugin_id` separates the logs inside it.
#[durable_object]
pub struct PluginRoomLog {
    state: State,
    /// Reserved for live push (a cross-DO `plugin_log_update` into the members' UserInboxes) in a
    /// later slice; held now only because `new(state, env)` hands it to us.
    #[allow(dead_code)]
    env: Env,
    initialized: std::cell::Cell<bool>,
}

impl DurableObject for PluginRoomLog {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            initialized: std::cell::Cell::new(false),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.ensure_init().await?;
        let url = req.url()?;
        match url.path() {
            "/append" => self.do_append(req).await,
            "/sync" => self.do_sync(&url).await,
            _ => Response::error("not_found", 404),
        }
    }
}

impl PluginRoomLog {
    async fn ensure_init(&self) -> Result<()> {
        if self.initialized.get() {
            return Ok(());
        }
        let storage = self.state.storage();
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS plugin_log_meta (
                plugin_id TEXT PRIMARY KEY,
                last_seq INTEGER NOT NULL DEFAULT 0,
                head_hash TEXT
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS plugin_log_entries (
                plugin_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                author_id TEXT NOT NULL,
                author_device_id TEXT NOT NULL,
                key_epoch INTEGER NOT NULL,
                author_counter INTEGER NOT NULL,
                content_kind TEXT NOT NULL,
                ciphertext_b64 TEXT,
                nonce_b64 TEXT,
                blob_id TEXT,
                blob_hash TEXT,
                aad_hash TEXT NOT NULL,
                prev_hash TEXT,
                entry_hash TEXT,
                uploaded_at_ms INTEGER NOT NULL,
                PRIMARY KEY (plugin_id, seq)
            )",
            sql_no_args(),
        )?;
        self.initialized.set(true);
        Ok(())
    }

    /// Append: assign an atomic seq, insert the entry, update head_hash. The caller (the handler)
    /// has ALREADY validated the JWT, active membership and author binding → the DO is just opaque
    /// storage plus a sequencer (the trust boundary sits in the handler).
    async fn do_append(&self, mut req: Request) -> Result<Response> {
        let e: PluginLogEntry = match req.json().await {
            Ok(b) => b,
            Err(_) => return Response::error("bad_request", 400),
        };
        let storage = self.state.storage();
        let sql = storage.sql();
        sql.exec_raw(
            "INSERT OR IGNORE INTO plugin_log_meta (plugin_id, last_seq) VALUES (?, 0)",
            Some(vec![JsValue::from_str(&e.plugin_id)]),
        )?;
        // Atomic seq (the receipt.rs pattern: bump and read in one statement → unique, monotonic).
        let seq = match sql.exec_raw(
            "UPDATE plugin_log_meta SET last_seq = last_seq + 1 WHERE plugin_id = ? RETURNING last_seq",
            Some(vec![JsValue::from_str(&e.plugin_id)]),
        ) {
            Ok(c) => c
                .to_array::<SeqRow>()
                .ok()
                .and_then(|r| r.into_iter().next())
                .map(|r| r.last_seq),
            Err(_) => None,
        };
        let Some(seq) = seq else {
            return Response::error("seq_failed", 500);
        };
        sql.exec_raw(
            "INSERT INTO plugin_log_entries (plugin_id, seq, author_id, author_device_id, key_epoch, \
                author_counter, content_kind, ciphertext_b64, nonce_b64, blob_id, blob_hash, aad_hash, \
                prev_hash, entry_hash, uploaded_at_ms) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            Some(vec![
                JsValue::from_str(&e.plugin_id),
                JsValue::from_f64(seq as f64),
                JsValue::from_str(&e.author_id),
                JsValue::from_str(&e.author_device_id),
                JsValue::from_f64(e.key_epoch as f64),
                JsValue::from_f64(e.author_counter as f64),
                JsValue::from_str(&e.content_kind),
                js_opt(&e.ciphertext_b64),
                js_opt(&e.nonce_b64),
                js_opt(&e.blob_id),
                js_opt(&e.blob_hash),
                JsValue::from_str(&e.aad_hash),
                js_opt(&e.prev_hash),
                js_opt(&e.entry_hash),
                JsValue::from_f64(e.uploaded_at_ms as f64),
            ]),
        )?;
        if let Some(eh) = &e.entry_hash {
            let _ = sql.exec_raw(
                "UPDATE plugin_log_meta SET head_hash = ? WHERE plugin_id = ?",
                Some(vec![JsValue::from_str(eh), JsValue::from_str(&e.plugin_id)]),
            );
        }
        Response::from_json(&serde_json::json!({ "seq": seq }))
    }

    /// Sync: the entries after the cursor (`seq > since ORDER BY seq ASC LIMIT 500` + `more`).
    /// The receipt_sync pattern; the client decrypts, verifies and folds `rows`, then advances its
    /// cursor to max(seq).
    async fn do_sync(&self, url: &Url) -> Result<Response> {
        let mut plugin_id = String::new();
        let mut since: i64 = 0;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "plugin" => plugin_id = v.into_owned(),
                "since" => since = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        if plugin_id.is_empty() {
            return Response::error("bad_request", 400);
        }
        let storage = self.state.storage();
        let rows: Vec<PluginLogEntryRow> = match storage.sql().exec_raw(
            "SELECT seq, plugin_id, author_id, author_device_id, key_epoch, author_counter, \
                content_kind, ciphertext_b64, nonce_b64, blob_id, blob_hash, aad_hash, \
                prev_hash, entry_hash, uploaded_at_ms \
             FROM plugin_log_entries WHERE plugin_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
            Some(vec![
                JsValue::from_str(&plugin_id),
                JsValue::from_f64(since as f64),
                JsValue::from_f64(SYNC_LIMIT as f64),
            ]),
        ) {
            Ok(c) => c.to_array().unwrap_or_default(),
            Err(_) => return Response::error("sync_failed", 500),
        };
        let more = rows.len() as i64 == SYNC_LIMIT;
        Response::from_json(&serde_json::json!({ "rows": rows, "more": more }))
    }
}

// ─────────────────────── FORWARD-SECRECY epoch FLOOR (D1; server-blind) ───────────────────────

/// Read a room's EPOCH FLOOR (D1 `plugin_epoch_floor`; 0 when there is no row). The server only
/// ever sees an integer, never a key or any content. Used by the append gate to reject
/// `key_epoch < floor`.
///
/// RESILIENT (fail-open at 0): if the `plugin_epoch_floor` table does not exist yet (migration not
/// applied) or the query errors, return floor=0 (no restriction) and NEVER 500 an append. The worst
/// case is a floor of 0 — forward-secrecy enforcement stays passive until the migration lands —
/// which keeps the data path intact. (Seen in the field: new worker code with the migration pending
/// made every append 500; this closes that.)
pub async fn epoch_floor(db: &D1Database, room_id: &str) -> Result<i64> {
    #[derive(Deserialize)]
    struct FloorRow {
        floor: i64,
    }
    let Ok(stmt) = db
        .prepare("SELECT floor FROM plugin_epoch_floor WHERE room_id = ? LIMIT 1")
        .bind(&[JsValue::from_str(room_id)])
    else {
        return Ok(0);
    };
    match stmt.first::<FloorRow>(None).await {
        Ok(row) => Ok(row.map(|r| r.floor).unwrap_or(0)),
        Err(_) => Ok(0), // missing table / query error → floor=0 (fail-open; append never 500s)
    }
}

/// Raise a room's EPOCH FLOOR by 1 (whenever a member leaves: kick / self-leave / server-level).
/// An atomic UPSERT (starts at 1 when there is no row). FORWARD SECRECY: after removal, an ejected
/// member cannot append new data under an OLD epoch — the append gate rejects anything below the
/// floor with 409. The server stays BLIND.
pub async fn bump_epoch_floor(db: &D1Database, room_id: &str) -> Result<()> {
    db.prepare(
        "INSERT INTO plugin_epoch_floor (room_id, floor) VALUES (?, 1) \
         ON CONFLICT(room_id) DO UPDATE SET floor = floor + 1",
    )
    .bind(&[JsValue::from_str(room_id)])?
    .run()
    .await?;
    Ok(())
}

// ───────────────────────── HTTP handlers (lib.rs router) ─────────────────────────

/// `POST /plugin-log/:room/:plugin/append` — validate JWT + active membership + author binding, then
/// forward to the DO.
pub async fn append(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, device_id) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    // Per-user append rate limit (the message-send pattern; guards against DoS/log inflation).
    // The KV binding is OPTIONAL (template diet): without it we continue unlimited — see
    // ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plog:append:{user_id}"), 300, 60).await {
        return json_err(429, "rate_limited");
    }
    // Device binding: the writer's device is taken from the TOKEN, never from the request body, so a
    // malicious member cannot append as another device. A revoked device is refused below.
    //
    // (This used to be labelled "the S3 token claim". Nothing here touches S3 — `storage/s3.rs` is an
    // unrelated subsystem that arrived later — and the label's original meaning is not recoverable from
    // the code, so it is gone rather than guessed at. An initialism that collides with a real module
    // name is worse than no initialism.)
    if device_revoked(&ctx.env, &user_id, &device_id).await? {
        return json_err(401, "device_revoked");
    }
    let room_id = match ctx.param("room") {
        Some(r) => r.clone(),
        None => return json_err(400, "bad_request"),
    };
    let plugin_id = match ctx.param("plugin") {
        Some(p) => p.clone(),
        None => return json_err(400, "bad_request"),
    };
    // Active-membership gate (E2E: the server cannot see the content, it only gates on the
    // membership table).
    let db = ctx.env.d1("DB")?;
    if group_role(&db, &room_id, &user_id).await?.is_none() {
        return json_err(403, "not_member");
    }
    let entry: PluginLogEntry = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    // Author binding (the server-honest layer): the author must equal the JWT-verified sender, its
    // device, and the plugin named in the path.
    if entry.author_id != user_id
        || entry.author_device_id != device_id
        || entry.plugin_id != plugin_id
    {
        return json_err(403, "author_mismatch");
    }
    // FORWARD-SECRECY (Faz-D) EPOCH-FLOOR gate: the floor was bumped when a member left, so
    // `key_epoch < floor` is an attempt to write new data under an OLD epoch → REJECT with
    // `409 epoch_stale`. Neither the ejected member nor a writer left behind can punch through
    // forward secrecy with a stale epoch after the removal. The client catches the 409 → refreshes
    // membership/device list, rotates, and retries the pending write under the NEW epoch, so nothing
    // is lost. The server stays BLIND: it only compares INTEGERS (key_epoch is plaintext meta).
    let floor = epoch_floor(&db, &room_id).await?;
    if entry.key_epoch < floor {
        return json_err(409, "epoch_stale");
    }
    // Size ceilings (B4 — Codex HIGH). The old gate applied ONLY to inline entries, so a `blob` (or
    // any other) content_kind slipped past every size check and could inflate the DO log and every
    // reader's sync. Now they apply to ALL kinds: inline → ciphertext is mandatory and
    // ≤ MAX_INLINE_B64; any kind → ciphertext ≤ MAX_INLINE_B64 (stops a `blob` kind from smuggling
    // bulk data through the ciphertext field) plus every short field ≤ MAX_FIELD_B64. Together these
    // bound the DO row size (≈ ciphertext + a few fields) deterministically.
    if entry.content_kind == "inline" {
        let len = entry.ciphertext_b64.as_ref().map(|s| s.len()).unwrap_or(0);
        if len == 0 || len > MAX_INLINE_B64 {
            return json_err(400, "bad_size");
        }
    }
    let field_len = |o: &Option<String>| o.as_ref().map(|s| s.len()).unwrap_or(0);
    if field_len(&entry.ciphertext_b64) > MAX_INLINE_B64
        || field_len(&entry.blob_id) > MAX_FIELD_B64
        || field_len(&entry.blob_hash) > MAX_FIELD_B64
        || field_len(&entry.nonce_b64) > MAX_FIELD_B64
        || field_len(&entry.prev_hash) > MAX_FIELD_B64
        || field_len(&entry.entry_hash) > MAX_FIELD_B64
        || entry.aad_hash.len() > MAX_FIELD_B64
        || entry.author_id.len() > MAX_FIELD_B64
        || entry.author_device_id.len() > MAX_FIELD_B64
        || entry.plugin_id.len() > MAX_FIELD_B64
    {
        return json_err(400, "bad_size");
    }
    // Forward to the per-room DO (id_from_name(room) → atomic seq + storage).
    let namespace = ctx.env.durable_object("PLUGIN_ROOM_LOG")?;
    let stub = namespace.id_from_name(&room_id)?.get_stub()?;
    let body = serde_json::to_string(&entry).map_err(|_| Error::RustError("serialize".into()))?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let do_req = Request::new_with_init("https://do.sezgi/append", &init)?;
    stub.fetch_with_request(do_req).await
}

/// `GET /plugin-log/:room/:plugin/sync?since=` — JWT + active membership → the entries after the
/// cursor, from the DO.
pub async fn sync(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, device_id) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    // Device binding + revoked gate (B6 — Codex HIGH: append had it, sync did NOT, so a removed or
    // revoked device could still PULL server-log ciphertext for as long as its access token lived —
    // short, but not zero. Mirror the append pattern: extract the token device, revoked → 401).
    if device_revoked(&ctx.env, &user_id, &device_id).await? {
        return json_err(401, "device_revoked");
    }
    let room_id = match ctx.param("room") {
        Some(r) => r.clone(),
        None => return json_err(400, "bad_request"),
    };
    let plugin_id = match ctx.param("plugin") {
        Some(p) => p.clone(),
        None => return json_err(400, "bad_request"),
    };
    let db = ctx.env.d1("DB")?;
    if group_role(&db, &room_id, &user_id).await?.is_none() {
        return json_err(403, "not_member");
    }
    // `since` comes from the client query — parsed as i64, so it is safe to splice into the DO URL.
    let mut since: i64 = 0;
    let url = req.url()?;
    for (k, v) in url.query_pairs() {
        if k.as_ref() == "since" {
            since = v.parse().unwrap_or(0);
        }
    }
    let namespace = ctx.env.durable_object("PLUGIN_ROOM_LOG")?;
    let stub = namespace.id_from_name(&room_id)?.get_stub()?;
    let do_url = format!("https://do.sezgi/sync?plugin={plugin_id}&since={since}");
    let do_req = Request::new(&do_url, Method::Get)?;
    stub.fetch_with_request(do_req).await
}
