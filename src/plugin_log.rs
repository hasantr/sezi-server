//! Eklenti/feed server-log — per-(room,plugin) append-only ŞİFRELİ log (Faz-2 / WORKER).
//!
//! `PLUGIN_FEED_LOG_SPEC.md` Faz-2. Server KÖR: entry `ciphertext`/`blob` opak, imzayı
//! OKUMAZ; yalnız sıralar (server-atanmış monoton `seq`) + saklar + cursor'dan sunar.
//! Akış: client → handler (JWT+aktif-üye+author-binding doğrula) → `PluginRoomLog` DO
//! (id_from_name(room) → atomik seq + insert) → `sync(since)` cursor-pull.
//!
//! Güvenlik iki-katman: (server-honest) handler `author_id==JWT.user && author_device_id==
//! JWT.device` enforce → kötü-ÜYE forge edemez; (zero-trust) okuyan CLIENT `sig`'i doğrular
//! → kötü-SERVER bile forge edemez (imza/decrypt CORE'da, Faz-3). DO = opak storage+sequencer.

use crate::auth::jwt::device_id_from_token;
use crate::auth::middleware::{device_revoked, extract_bearer, require_auth};
use crate::groups::group_role;
use crate::messages::inbox_do::sql_no_args;
use crate::respond::json_err;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::*;

/// Inline ciphertext base64 tavanı (üstü R2 blob — sonraki dilim). Mesaj envelope
/// sınırıyla uyumlu (~22KB ham → b64 genleşme payı).
const MAX_INLINE_B64: usize = 32 * 1024;
/// B4 (Codex HIGH): blob/meta alan tavanı. blob_id/blob_hash/aad/nonce/hash-zinciri kısa
/// referanslardır (gerçek ağır içerik R2'de); 4KB fazlasıyla yeter → DO satırını HER
/// content_kind'da bağlar (eski gate yalnız inline'ı sınırlıyordu → blob/diğer kind
/// keyfi-büyük ciphertext ile DO log'unu + tüm okuyanların sync'ini şişirebiliyordu).
const MAX_FIELD_B64: usize = 4 * 1024;
/// Tek sync sayfası entry sınırı (receipt_sync deseni; `more` ile devam).
const SYNC_LIMIT: i64 = 500;

/// Bir log entry'si — hem client→handler→DO gövdesi hem (seq dışı) DO satırı. Server KÖR:
/// `ciphertext_b64`/`blob_id` opak; `author_*` server-honest enforce + okuyan imza-doğrular.
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
    // sig YOK: ciphertext İÇİNDE (server-blind authorship-proof; core open'da doğrulanır).
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

/// Sync satırı (seq DAHİL) — DB'den okunup client'a JSON döner.
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

/// Per-room DO: odadaki TÜM eklentilerin append-only şifreli log'u. DO tek-thread →
/// seq atanması atomik (UserInbox/receipt deseni). `id_from_name(room_id)` → oda başına
/// tek instance; `plugin_id` oda-içi log'ları ayırır.
#[durable_object]
pub struct PluginRoomLog {
    state: State,
    /// Canlı-push (cross-DO `plugin_log_update` → üye UserInbox'larına) sonraki dilimde
    /// kullanacak; `new(state, env)` zorunlu aldığı için şimdiden tutulur.
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

    /// Append: atomik seq ata + entry insert + head_hash güncelle. Caller (handler) JWT +
    /// aktif-üyelik + author-binding'i ZATEN doğruladı → DO opak storage+sequencer (güven sınırı handler'da).
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
        // Atomik seq (receipt.rs deseni: tek-statement bump+oku → benzersiz monoton).
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

    /// Sync: cursor'dan sonraki entry'ler (`seq > since ORDER BY seq ASC LIMIT 500` + `more`).
    /// receipt_sync deseni; client `rows`'u decrypt+verify+fold eder, cursor'u max(seq)'e taşır.
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

// ───────────────────────── FORWARD-SECRECY epoch FLOOR (D1; server-kör) ─────────────────────────

/// Bir oda için EPOCH FLOOR'u oku (D1 `plugin_epoch_floor`; satır yoksa 0). Server yalnız
/// integer görür (anahtar/içerik DEĞİL). append-gate `key_epoch < floor` reddinde kullanılır.
///
/// DAYANIKLI (fail-open=0): `plugin_epoch_floor` tablosu YOKSA (migration henüz uygulanmadı)
/// veya sorgu hata verirse → floor=0 (kısıt yok) döner; append'i ASLA 500'leme. Floor en-kötü
/// 0 olur (forward-secrecy enforcement migration gelene dek pasif) → veri-yolu kırılmaz.
/// (Saha: worker yeni-kod + migration-pending → her append 500'lüyordu; bu onu kapatır.)
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
        Err(_) => Ok(0), // tablo yok / sorgu hata → floor=0 (fail-open, append 500'lemez)
    }
}

/// Bir odanın EPOCH FLOOR'unu +1 artır (üye-çıkışında: kick / self-leave / server-level).
/// Atomik UPSERT (satır yoksa 1 ile başlar). FORWARD-SECRECY: çıkarılan üye atılma-SONRASI
/// ESKİ epoch'a yeni-veri append edemez (append-gate floor'un altını 409 reddeder). Server KÖR.
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

// ───────────────────────── HTTP handler'ları (lib.rs router) ─────────────────────────

/// `POST /plugin-log/:room/:plugin/append` — JWT + aktif-üye + author-binding doğrula → DO'ya forward.
pub async fn append(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(u) => u,
        Err(resp) => return Ok(resp),
    };
    // Per-user append rate-limit (mesaj-send deseni; DoS/şişme guard).
    // KV binding OPSİYONEL (şablon-diyeti): yoksa limitsiz devam — bkz. ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plog:append:{user_id}"), 300, 60).await {
        return json_err(429, "rate_limited");
    }
    // Device-binding (S3 token-claim): kötü-üye başka cihaz adına yazamaz.
    let token_device =
        extract_bearer(&req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    let Some(device_id) = token_device else {
        return json_err(403, "device_required");
    };
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
    // Aktif-üyelik kapısı (E2E: server içeriği görmez, yalnız üyelik tablosundan kapılar).
    let db = ctx.env.d1("DB")?;
    if group_role(&db, &room_id, &user_id).await?.is_none() {
        return json_err(403, "not_member");
    }
    let entry: PluginLogEntry = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    // Author-binding (server-honest katman): author = JWT-doğrulı gönderen + cihaz + path-plugin.
    if entry.author_id != user_id
        || entry.author_device_id != device_id
        || entry.plugin_id != plugin_id
    {
        return json_err(403, "author_mismatch");
    }
    // FORWARD-SECRECY (Faz-D) EPOCH-FLOOR kapısı: üye-çıkışında floor++ edildi. `key_epoch < floor`
    // = ESKİ epoch'a yeni-veri yazma denemesi → REDDET (`409 epoch_stale`). Çıkarılan üye (ya da
    // geride-kalan yazar) atılma-SONRASI eski-epoch ile forward-secrecy'yi delemez. Client 409'u
    // yakalar → membership/device-list refresh + rotation → bekleyen yazımı YENİ epoch ile yeniden
    // dener (yazım kaybolmaz). Server KÖR: yalnız INTEGER karşılaştırır (key_epoch plaintext meta).
    let floor = epoch_floor(&db, &room_id).await?;
    if entry.key_epoch < floor {
        return json_err(409, "epoch_stale");
    }
    // Boyut tavanları (B4 — Codex HIGH). Eski gate YALNIZ inline'a uygulanıyordu → blob/diğer
    // content_kind tüm boyut-kontrolünden geçip DO log'unu + tüm okuyanların sync'ini şişirebiliyordu.
    // Artık TÜM kind'lara: inline → ciphertext zorunlu + ≤ MAX_INLINE_B64; her kind → ciphertext
    // ≤ MAX_INLINE_B64 (blob kind'ın ciphertext'le büyük-veri kaçırmasını kes) + kısa alanlar ≤
    // MAX_FIELD_B64. Bu, DO satır boyutunu (≈ ciphertext + birkaç alan) deterministik bağlar.
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
    // Per-room DO'ya forward (id_from_name(room) → atomik seq + storage).
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

/// `GET /plugin-log/:room/:plugin/sync?since=` — JWT + aktif-üye → DO'dan cursor-sonrası entry'ler.
pub async fn sync(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(u) => u,
        Err(resp) => return Ok(resp),
    };
    // Device-binding + revoked gate (B6 — Codex HIGH: append'te VAR ama sync'te YOKtu →
    // çıkarılmış/iptal cihaz, access-token TTL'i (kısa ama sıfır-değil) içinde server-log
    // ciphertext'i ÇEKEBİLİYORDU. append desenini aynala: token-device çıkar + revoked→401).
    let token_device =
        extract_bearer(&req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    let Some(device_id) = token_device else {
        return json_err(403, "device_required");
    };
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
    // `since` client query'sinden — i64 parse (DO URL'ine güvenli enjeksiyon).
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
