use crate::auth::jwt::{device_id_from_token, verify_access_token};
use crate::utils::now_secs;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::*;

mod forward;
mod message;
mod receipt;
mod self_read;
mod ws;

const FLUSH_INTERVAL_MS: i64 = 90 * 1000;
const CLEANUP_INTERVAL_MS: i64 = 24 * 3600 * 1000;
const LAST_CLEANUP_KEY: &str = "last_cleanup_at";

/// W1-backstop: DO storage key — bu inbox'ın sahibi ALICI user_id (alarm
/// stuck-pending FCM-wake için; DO offline'da kendi user'ını başka türlü bilmez).
const RECIPIENT_UID_KEY: &str = "recipient_uid";

/// W1-backstop: bir `pending` satırı bu kadar saniyeden eskiyse VE hâlâ ack'lenmemişse
/// VE `push_wake_at` NULL ise (delivered_live=true idi → immediate-push atılmadı),
/// "canlı-teslim başarısız" say → FCM-wake at. Grace, client'ın ack fırsatını korur
/// (yeni-INSERT satırı hemen pushlamayız); alarm 90sn'de bir tarar → stuck satır
/// 30-120sn içinde wake alır (nadir false-pozitif edge; yaygın offline zaten
/// caller-side immediate-push alır).
const PUSH_BACKSTOP_GRACE_SECS: i64 = 30;

/// M2-S2.2 — tek-seferlik NULL-device backfill bayrağı (DO storage).
/// İlk device-bilen WS bağlantısında `pending.device_id IS NULL` satırlarını
/// O cihazla damgalar; bayrak SET edilince sonraki reconnect'ler RE-STAMP
/// ETMEZ (red-team HIGH #3: her reconnect stale-close → sık reconnect →
/// bayraksız backfill yarış-tehlikesi). N=1'de DO tek-cihaza ait → backfill
/// doğru; çok-cihaz S3.
const DEVICE_BACKFILL_DONE_KEY: &str = "m2_device_backfill_done";

/// Idempotency: aynı (sender_id, envelope_b64) bu süre içinde tekrar
/// gelirse mevcut msg_id döndürülür, duplicate INSERT yapılmaz. Client
/// network glitch retry'si DO storage'a çift kayıt yaratmasın + recipient
/// WS frame'i 2 kez almasın. 60sn yeterli (HTTP timeout 15s + bir-iki retry).
const DEDUP_TTL_SECS: i64 = 60;

/// Dedup vektörü için bellek tavanı. DO uzun ömürlü; spam'a karşı koruma.
const DEDUP_MAX_ENTRIES: usize = 256;

/// Per-user inbox + WebSocket gateway. TS Worker'daki UserInbox'ın birebir
/// portu. SQL storage'da pending mesaj kuyruğu, WS hibernation, periyodik
/// alarm flush + cleanup, ack/typing/delivered/read RPC köprüsü.
#[durable_object]
pub struct UserInbox {
    pub(crate) state: State,
    pub(crate) env: Env,
    pub(crate) initialized: std::cell::Cell<bool>,
    /// Son DEDUP_TTL_SECS içinde işlenen (sender, envelope-hash) çiftleri.
    /// DO restart'ta sıfırlanır; in-memory bilinçli (storage'a yazma maliyeti
    /// yokken DO ömrü zaten saatler-günler mertebesinde). Restart sırasında
    /// kısa süreli duplicate riski açık; client-side `hasIncomingRemoteId`
    /// dedup'ı güvenlik ağı.
    pub(crate) dedup: std::sync::Mutex<Vec<DedupEntry>>,
    /// W1-backstop: ALICI user_id storage'a yazıldı mı (bu DO instance'ında). Alarm,
    /// stuck-pending için `maybe_push_wake` atarken user_id'ye ihtiyaç duyar ama DO
    /// offline'da (WS-attachment yok) kendi user'ını başka türlü bilemez → notify
    /// body'sindeki `recipient_id`'yi bir kez persist ederiz. Cell = redundant-write
    /// önler; DO restart'ta sıfırlanır → restart sonrası ilk notify'da tekrar yazar.
    pub(crate) uid_persisted: std::cell::Cell<bool>,
}

#[derive(Clone)]
pub(crate) struct DedupEntry {
    pub(crate) sender_id: String,
    /// SHA256 ilk 16 byte — collision olasılığı ihmal edilebilir (2^64).
    pub(crate) envelope_hash: [u8; 16],
    pub(crate) msg_id: i64,
    pub(crate) created_at: i64,
    /// W4-a (Codex HIGH): İLK teslimin gerçek `delivered_live` sonucu. Dedup-hit
    /// (W4 in-request retry veya client-retry) bunu döndürür → sabit `true`
    /// varsayımının offline-wake'i sessizce bastırması engellenir.
    pub(crate) delivered_live: bool,
}

#[derive(Deserialize)]
struct NotifyBody {
    sender_id: String,
    envelope_b64: String,
    /// W1-backstop: ALICI user_id (bu DO'nun sahibi). Caller (notify_recipient /
    /// WS-send) zaten biliyor → body'de taşınır → notify_inner persist eder →
    /// alarm stuck-pending FCM-wake'te kullanır. `#[serde(default)]` → eski
    /// gövdeler (alan yok) `None`; o durumda persist atlanır (backstop no-op,
    /// caller-side immediate-push zaten çalışır → regresyon yok).
    #[serde(default)]
    recipient_id: Option<String>,
    /// Grup fan-out'unda (Faz 2) ait olduğu grup; 1:1'de yok (serde default None).
    #[serde(default)]
    group_id: Option<String>,
    /// M2-S2.2: gönderenin cihazı. `#[serde(default)]` → S2.3 fan-out bu alanı
    /// doldurana kadar (ve S2-öncesi /notify gövdeleri için) eksikse `None`.
    #[serde(default)]
    sender_device_id: Option<String>,
    /// M2-S2.2: hedef ALICI cihazı. S2.2'de body bunu HENÜZ taşımaz (S2.3
    /// `notify_recipient` gövdesine ekler) → şimdilik `None` = N=1 primary/uyum;
    /// notify_inner imzası bugünden bu parametreyi alır (S2.2/S2.3 ayrımı).
    #[serde(default)]
    recipient_device_id: Option<String>,
}

#[derive(Deserialize)]
struct ForwardTypingBody {
    sender_id: String,
}

#[derive(Deserialize)]
struct ForwardIdsBody {
    from: String,
    ids: Vec<i64>,
    /// M2-S2.2 — receipt'in scope'landığı cihaz. delivered/failed yönünde
    /// `recipient_device_id` (hangi alıcı cihaz teslim aldı/decrypt edemedi);
    /// read yönünde gönderen `sender_device_id` adıyla yollar (ters-yön
    /// self-heal cihaz-çifti). İkisinden hangisi gelirse `device_for_forward`
    /// onu seçer. `#[serde(default)]` → S2.3 doldurana kadar `None` (N=1 uyum).
    #[serde(default)]
    recipient_device_id: Option<String>,
    #[serde(default)]
    sender_device_id: Option<String>,
    /// #11 Layer-4b: `ids`'e PARALEL msg_uid'ler (gönderenin local_id'si; okuyan E2E
    /// payload'dan sağlar). `apply_receipt` `receipt_state.msg_uid`'e yazar → kardeş
    /// cihaz `oc-{msg_uid}` ile okundu-eşler. Eski client / delivered yolu → boş Vec.
    #[serde(default)]
    uids: Vec<String>,
}

/// Kardeş-okundu durable cursor (2026-06-28): U'nun bir cihazı okuduğu incoming mesajların
/// `msg_uid`'lerini bildirir (peer/grup agnostik — tek global liste). `read_at` server-now.
#[derive(Deserialize)]
struct SelfReadBody {
    uids: Vec<String>,
}

impl ForwardIdsBody {
    /// forward_signal'e geçilecek device boyutu: önce recipient_device_id
    /// (delivered/failed), yoksa sender_device_id (read ters-yön).
    fn device_for_forward(&self) -> Option<&str> {
        self.recipient_device_id
            .as_deref()
            .or(self.sender_device_id.as_deref())
    }
}

#[derive(Deserialize)]
pub(crate) struct PendingRow {
    pub(crate) id: i64,
    pub(crate) sender_id: String,
    pub(crate) envelope_b64: String,
    #[serde(default)]
    pub(crate) group_id: Option<String>,
    /// M2-S2.2: gönderenin cihazı (flush replay frame'i için).
    #[serde(default)]
    pub(crate) sender_device_id: Option<String>,
    pub(crate) created_at: i64,
}

// Sprint 8: forward_queue rows
#[derive(Deserialize)]
pub(crate) struct ForwardIdRow {
    pub(crate) id: i64,
}

#[derive(Deserialize)]
pub(crate) struct ForwardQueueRow {
    pub(crate) id: i64,
    pub(crate) kind: String,
    pub(crate) from_user: String,
    pub(crate) ids_json: String,
    /// M2-S2.2: makbuzu üreten alıcı cihazı (replay payload reconstruction).
    #[serde(default)]
    pub(crate) recipient_device_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Attachment {
    #[serde(rename = "userId")]
    pub(crate) user_id: String,
    /// M2-S2.2: bu WS bağlantısının CİHAZI (JWT device_id claim'inden).
    /// S1-öncesi token (claim'siz) → `None`; per-device flush/ack o durumda
    /// NULL-toleransına düşer. `#[serde(default)]` → eski serialize-edilmiş
    /// attachment'lar (S2-öncesi WS hibernation) sorunsuz parse olur.
    #[serde(rename = "deviceId", default)]
    pub(crate) device_id: Option<String>,
    /// W1 (delivered_live yanlış-pozitif fix): bu socket'ten en son CLIENT→SERVER
    /// frame'inin (ping/ack/read; client 5sn'de bir text-ping atar, ws_conn.rs)
    /// alındığı an (ms). `notify_inner` CANLILIK AYRACI: yalnız son
    /// `WS_LIVENESS_WINDOW_MS` içinde frame gelen socket "gerçekten canlı" sayılır.
    /// Zombie/yarı-açık socket'e (MIUI arka-plan kill sonrası TCP yarı-açık)
    /// `send_with_str` Ok döner ama client ALMAZ → last_seen bayatlar →
    /// delivered_live SET EDİLMEZ → FCM-wake tetiklenir (sessiz teslim-gecikmesi
    /// ve bildirim-kaybı kökü kapanır). `#[serde(default)]` → eski (W1-öncesi)
    /// serialize-edilmiş attachment'lar `None` ile parse olur (ilk ping'te dolar).
    #[serde(rename = "lastSeenMs", default)]
    pub(crate) last_seen_ms: Option<i64>,
}

pub(crate) fn sql_no_args() -> Option<Vec<JsValue>> {
    None
}

impl DurableObject for UserInbox {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            initialized: std::cell::Cell::new(false),
            dedup: std::sync::Mutex::new(Vec::new()),
            uid_persisted: std::cell::Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.ensure_init().await?;
        let url = req.url()?;
        let path = url.path().to_string();
        let method = req.method();

        // WS upgrade (Worker tarafından /sync proxy ediliyor)
        if req
            .headers()
            .get("upgrade")
            .ok()
            .flatten()
            .as_deref()
            .map(|s| s.to_lowercase())
            == Some("websocket".into())
        {
            return self.ws_upgrade(req).await;
        }

        match (method, path.as_str()) {
            (Method::Post, "/notify") => {
                let body: NotifyBody = req.json().await?;
                let (id, delivered_live) = self
                    .notify_inner(
                        &body.sender_id,
                        body.sender_device_id.as_deref(),
                        body.recipient_device_id.as_deref(),
                        body.recipient_id.as_deref(),
                        &body.envelope_b64,
                        body.group_id.as_deref(),
                    )
                    .await?;
                Response::from_json(
                    &serde_json::json!({ "id": id, "delivered_live": delivered_live }),
                )
            }
            (Method::Post, "/forward-typing") => {
                let body: ForwardTypingBody = req.json().await?;
                self.forward_typing_inner(&body.sender_id);
                Response::empty().map(|r| r.with_status(204))
            }
            // Layer-4: delivered/read artık durable `receipt_state` + per-cihaz
            // cursor senk (forward_queue consume-once DEĞİL). recipient_device_id
            // delivered/read için ARTIK kullanılmaz: tik TÜM A-cihazlarına gider,
            // aggregation client-tarafı mdd'de (remote_id ile). ts = server-alış.
            (Method::Post, "/forward-delivered") => {
                let body: ForwardIdsBody = req.json().await?;
                self.apply_receipt(
                    "delivered", &body.from, &body.ids, &body.uids, (now_secs() * 1000) as i64,
                );
                Response::empty().map(|r| r.with_status(204))
            }
            (Method::Post, "/forward-read") => {
                let body: ForwardIdsBody = req.json().await?;
                self.apply_receipt(
                    "read", &body.from, &body.ids, &body.uids, (now_secs() * 1000) as i64,
                );
                Response::empty().map(|r| r.with_status(204))
            }
            (Method::Post, "/forward-delivery-failed") => {
                // Receiver decrypt fail (MAC mismatch) → sender'a bildir.
                // Sender'da mesaj status: failedDelivery → UI 1.5-tik gibi
                // göster + self-heal sonrası auto-retry tetikle.
                let body: ForwardIdsBody = req.json().await?;
                self.forward_signal(
                    "delivery_failed",
                    &body.from,
                    body.device_for_forward(),
                    &body.ids,
                );
                Response::empty().map(|r| r.with_status(204))
            }
            // Ortak-kök #1: receipt-sync HTTP ikizi. WS `receipt_sync` frame'iyle AYNI
            // `receipt_sync_payload` builder → BİT-AYNI {rows,more}. WS-Connected-değil
            // cihaz (HTTP-send fallback) kendi tikini buradan cursor-pull eder → stuck-tik
            // self-heal. SQL-hata → boş batch (cursor ilerlemez, sonraki event re-pull).
            (Method::Get, "/receipt-sync") => {
                let since = url
                    .query_pairs()
                    .find(|(k, _)| k == "since")
                    .and_then(|(_, v)| v.parse::<i64>().ok())
                    .unwrap_or(0);
                let payload = self
                    .receipt_sync_payload(since)
                    .unwrap_or_else(|| serde_json::json!({ "rows": [], "more": false }));
                Response::from_json(&payload)
            }
            // Kardeş-okundu durable cursor (2026-06-28): U'nun cihazı okuduğu msg_uid'leri bildirir
            // → self_read_state set-once + seq bump + diğer U-cihazlarına self_read_update/delta.
            (Method::Post, "/self-read") => {
                let body: SelfReadBody = req.json().await?;
                self.apply_self_read(&body.uids, (now_secs() * 1000) as i64);
                Response::empty().map(|r| r.with_status(204))
            }
            // self-read-sync HTTP ikizi (WS `self_read_sync` frame'iyle AYNI builder). Yeni cihaz
            // cursor=0'dan tüm okundu-durumu çeker → backlog yakınsar.
            (Method::Get, "/self-read-sync") => {
                let since = url
                    .query_pairs()
                    .find(|(k, _)| k == "since")
                    .and_then(|(_, v)| v.parse::<i64>().ok())
                    .unwrap_or(0);
                let payload = self
                    .self_read_sync_payload(since)
                    .unwrap_or_else(|| serde_json::json!({ "rows": [], "more": false }));
                Response::from_json(&payload)
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        self.handle_ws_message(ws, message).await
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let _ = ws.close(Some(code as u16), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        self.ensure_init().await?;
        self.flush_pending_to_all();
        // Sprint 8: forward queue alarm flush — sender reconnect'i kaçırırsa
        // periyodik alarm her halükarda push'a deneyecek (idempotent: tekrar
        // gelirse client `forward_ack` ile silinir, sender tarafı dedup yapar).
        self.flush_forwards_to_all();
        // W1-backstop (Codex HIGH — W1 kesin closure): delivered_live=true sanılıp
        // ack GELMEMİŞ (=aslında teslim olmamış) pending satırları için FCM-wake.
        // W1'in canlılık-ayracı false-pozitif penceresini daraltır ama kapatmaz
        // (ping'ten hemen sonra ölen socket); bu ground-truth backstop kapatır:
        // pending'de duran = ack'lenmemiş = teslim olmamış → grace aşınca push.
        self.backstop_push_stale_pending().await;
        let now_ms_val = (now_secs() * 1000) as i64;
        let last: Option<i64> = self
            .state
            .storage()
            .get::<i64>(LAST_CLEANUP_KEY)
            .await
            .ok()
            .flatten();
        let last_val = last.unwrap_or(0);
        if now_ms_val - last_val >= CLEANUP_INTERVAL_MS {
            // Mesaj bekletme süresi artık admin-ayarlı (D1 server_settings).
            // Eski hard-coded 30 gün yerine her temizlikte tek SELECT ile okunur;
            // hata/satır yoksa helper 30'a fallback yapar. CLEANUP_INTERVAL_MS
            // (24h) sayesinde alarm başına en çok bir kez sorgulanır.
            let days = crate::server::handlers::fetch_message_retention_days(&self.env).await;
            let cutoff = (now_secs() as i64) - days * 24 * 3600;
            let storage = self.state.storage();
            storage.sql().exec_raw(
                "DELETE FROM pending WHERE created_at < ?",
                Some(vec![JsValue::from_f64(cutoff as f64)]),
            )?;
            // Layer-4: receipt_state retention (updated_at ms cinsinden → cutoff*1000).
            // Eski tik zaten gösterilmiş; high-water (`receipt_meta`) purge edilmez →
            // seq monoton kalır, cursor'lar tutarlı.
            let _ = storage.sql().exec_raw(
                "DELETE FROM receipt_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // server-lean audit (2026-07-03): self_read_state RETENTION-PARİTE purge. Eskiden
            // "PURGE EDİLMEZ" (Codex-Q8 full-pull korkusu) → "şişmez" ilkesinin TEK istisnasıydı.
            // Q8-korkusu ASILSIZ çıktı (Fable-devri + Opus-doğrulama): yeni cihaz eski mesajları
            // M4 kardeş-senk'ten alır ve M4 paketi (state_transfer.rs `Vec<MessageRow>`) `viewed_at`'i
            // MESAJLA BİRLİKTE taşır → okundu-state self_read_state'ten BAĞIMSIZ akar. self_read_state
            // = canlı-inkremental yakınsama cursor'u; retention-ötesi satır = ölü-metadata (o mesaj
            // pending'den zaten silindi, M4 read-state'i taşıyor). receipt_state deseni birebir:
            // high-water (self_read_meta) purge EDİLMEZ → seq monoton, cursor tutarlı. updated_at ms.
            let _ = storage.sql().exec_raw(
                "DELETE FROM self_read_state WHERE updated_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            // M1 (Olm-WIPE tekrar-tetikleme): forward_queue retention. Eski orphan
            // makbuz satırları (özellikle delivery_failed — client hiç forward_ack
            // atmadıysa) süresiz birikip TAZE reconnect'te koşulsuz replay ediliyordu
            // → alıcıda `delete_all_olm_blobs` (Olm WIPE) tekrar-tetikleniyordu. Aynı
            // retention penceresiyle temizle. `created_at` MS cinsinden (forward_signal:
            // `now_secs()*1000`) → ms cutoff (receipt_state ile aynı, pending'in
            // saniye-cutoff'undan FARKLI).
            let _ = storage.sql().exec_raw(
                "DELETE FROM forward_queue WHERE created_at < ?",
                Some(vec![JsValue::from_f64((cutoff * 1000) as f64)]),
            );
            let _ = storage.put(LAST_CLEANUP_KEY, now_ms_val).await;
        }
        // W11: alarm zincirini SAĞLAM re-arm et. Eski blind `let _ = set_alarm`
        // tek transient storage-hatasında zinciri BU DO instance ömrü boyunca
        // kırıp offline-flush/forward-replay/cleanup'i sessizce durduruyordu.
        self.ensure_alarm().await;
        Response::empty()
    }
}

impl UserInbox {
    async fn ensure_init(&self) -> Result<()> {
        if self.initialized.get() {
            return Ok(());
        }
        let storage = self.state.storage();
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                envelope_b64 TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_pending_created ON pending(created_at)",
            sql_no_args(),
        )?;
        // Faz 2 (grup fan-out): pending'e group_id kolonu. Grup mesajıysa hangi
        // gruba ait (alıcı Megolm decrypt yolunu seçer); 1:1'de NULL. Eski DO'lar
        // için ALTER (zaten varsa hata IGNORE; forward_queue.pushed_at deseni).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN group_id TEXT",
            sql_no_args(),
        );
        // M2-S2.2 (çoklu-cihaz): pending'e device_id kolonu. Hangi ALICI
        // CİHAZINA ait (per-device kuyruk + ack-izolasyonu). Backfill-öncesi
        // satırlar + S2 öncesi DO'lar için ALTER (zaten varsa hata IGNORE;
        // group_id ALTER deseni). N=1'de tek-primary; daha-eski NULL satırlar
        // ilk-WS backfill ile damgalanır (bkz ws_upgrade NULL-backfill bayrağı).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN device_id TEXT",
            sql_no_args(),
        );
        // M2-S2.2: GÖNDERENİN cihazı. Alıcı frame'inde `sender_device_id`
        // taşınmalı (1:1'de alıcı doğru Olm cihaz-oturumunu seçer; grupta tek
        // Megolm zarfı). Live push notify_inner param'ından gelir; flush replay
        // DB'den okur → ayrı kolon. NULL = sender_device bilinmiyor (eski/uyum).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN sender_device_id TEXT",
            sql_no_args(),
        );
        // W1-backstop: pending'e push_wake_at kolonu (ms). NULL = bu satır için henüz
        // FCM-wake atılmadı (delivered_live=true idi → caller immediate-push atmadı) →
        // alarm-backstop grace aşınca push atar. delivered_live=false satırlarda
        // notify_inner bunu set eder (caller zaten immediate-push atar → backstop
        // atlar). Eski DO'lar için ALTER (zaten varsa hata IGNORE; group_id deseni).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE pending ADD COLUMN push_wake_at INTEGER",
            sql_no_args(),
        );
        // Sprint 8: forward_queue — receipt forward'lari (delivered/read/
        // delivery_failed) WS push fire-and-forget yerine persistent kuyrukta.
        // Bagli WS'lerden 0+ sender'a anlik push + bu tabloya yaz; sender
        // reconnect olunca flush_forwards replay + sender `forward_ack`
        // frame'i ile kuyrugu temizler.
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS forward_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                from_user TEXT NOT NULL,
                ids_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                pushed_at INTEGER
            )",
            sql_no_args(),
        )?;
        // Sprint 8.5a: pushed_at kolonu — Sprint 8'de tablonun ilk oluştuğu
        // DO'lar için ALTER TABLE ADD COLUMN. Hata IGNORE (zaten varsa).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE forward_queue ADD COLUMN pushed_at INTEGER",
            sql_no_args(),
        );
        // M2-S2.2 (çoklu-cihaz): forward_queue'ya recipient_device_id kolonu.
        // Receipt forward'ları (delivered/read/delivery_failed) HANGI ALICI
        // CİHAZINDAN üretildi → replay'de device-doğru taşıma + dedup anahtarına
        // girer (D3-verdict-2: WS-kapalı biriken makbuz replay'de device'sız →
        // N:1 MISS). Eski DO'lar için ALTER (zaten varsa hata IGNORE).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE forward_queue ADD COLUMN recipient_device_id TEXT",
            sql_no_args(),
        );
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_fwd_created ON forward_queue(created_at)",
            sql_no_args(),
        )?;
        // Sprint 8.5a: dedup için (kind, from_user, ids_json) lookup hızlandır.
        // M2-S2.2: dedup anahtarı artık recipient_device_id'yi de içerir →
        // index'i de o kolonla genişlet (eski index zararsız kalır; yeni
        // sorgu bu index'i kullanır).
        let _ = storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_fwd_dedup_dev ON forward_queue(kind, from_user, recipient_device_id, ids_json, created_at)",
            sql_no_args(),
        );
        // Model-B Layer-4: hesap-düzeyi receipt durable log (delivered/read).
        // forward_queue consume-once yerine — her A-cihazı `seq` cursor'undan
        // idempotent senkronlar (kardeş-yarışı/zombie-socket/reconnect-gap fix).
        // PK(peer_id, remote_id) = B'nin per-cihaz receipt id'si; tik aggregation
        // client mdd'de. `seq` monoton hesap-global; `receipt_meta` high-water
        // tablo purge'lense bile geri gitmez → cursor tutarlı. (bkz receipt.rs)
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS receipt_state (
                peer_id TEXT NOT NULL,
                remote_id INTEGER NOT NULL,
                delivered_at INTEGER,
                read_at INTEGER,
                seq INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, remote_id)
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_receipt_seq ON receipt_state(seq)",
            sql_no_args(),
        )?;
        // #11 Layer-4b: msg_uid kolonu (kardeş cihaz oc-satırı `oc-{msg_uid}` ile okundu
        // korelasyonu). Mevcut DO'lara ADD COLUMN (idempotent: zaten varsa hata YUTULUR;
        // `CREATE TABLE IF NOT EXISTS` eski DO'ya kolon eklemez → ayrı ALTER şart).
        let _ = storage.sql().exec_raw(
            "ALTER TABLE receipt_state ADD COLUMN msg_uid TEXT",
            sql_no_args(),
        );
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS receipt_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "INSERT OR IGNORE INTO receipt_meta (k, v) VALUES ('seq', 0)",
            sql_no_args(),
        )?;
        // ── KARDEŞ-OKUNDU durable cursor (2026-06-28, Codex-onaylı tasarım) ──────────────
        // receipt_state'in (gönderen↔alıcı teslim/okundu) AYNADAN-kopyası AMA kardeş-okundu
        // (U'nun KENDİ cihazları arası `viewed_at` yakınsaması) için AYRI eksen. Eski kırılgan
        // ReadSelfSync (anlık Olm self-mesaj; wedge'de ölür, yalnız yeni-okuma, yeni-cihaz backlog
        // yanlış) yerine durable+monoton+cursor. PK=msg_uid (global UUID; peer-agnostik). seq AYRI
        // uzay (`self_read_meta`) → bir self-read gap'i receipt cursor'unu kilitlemez (Codex Q1).
        // Retention: bu tablo PURGE EDİLMEZ (full-pull garantisi; Codex Q8).
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS self_read_state (
                msg_uid TEXT PRIMARY KEY,
                read_at INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_self_read_seq ON self_read_state(seq)",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS self_read_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "INSERT OR IGNORE INTO self_read_meta (k, v) VALUES ('seq', 0)",
            sql_no_args(),
        )?;
        // ── Codex#5: M4/msg_uid-only read receipt (gönderen↔alıcı; remote_id'siz) ────────
        // M4-restore (msg_id=NULL) mesaj okununca core `msg_uids` (ids-boş) gönderir; receipt_state
        // PK=(peer_id,remote_id) bunu taşıyamaz → düşerdi. AYRI uid-keyed tablo (sentetik remote_id
        // DEĞİL — semantik-borç/çakışma riski; Codex Q6). Aynı `receipt_meta` seq-uzayını paylaşır
        // (receipt akışıyla aynı eksen: gönderene tik) → tek cursor'dan senklenir.
        storage.sql().exec_raw(
            "CREATE TABLE IF NOT EXISTS receipt_uid_state (
                peer_id TEXT NOT NULL,
                msg_uid TEXT NOT NULL,
                delivered_at INTEGER,
                read_at INTEGER,
                seq INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, msg_uid)
            )",
            sql_no_args(),
        )?;
        storage.sql().exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_receipt_uid_seq ON receipt_uid_state(seq)",
            sql_no_args(),
        )?;
        // Layer-4 cutover (Codex HIGH-3): delivered/read artık receipt_state'te.
        // forward_queue'daki ESKİ (cutover-öncesi) delivered/read satırları consume-once
        // + global-ack-DELETE kardeş-steal yarışına açık → DRAIN et (temiz kesik;
        // in-flight olanlar StateDigest reconciliation + sonraki receipt ile onarılır).
        // delivery_failed KALIR (hâlâ forward_queue yolunda). Yeni delivered/read
        // forward_queue'ya GİRMEZ (apply_receipt'e gider) → bu DELETE idempotent.
        let _ = storage.sql().exec_raw(
            "DELETE FROM forward_queue WHERE kind IN ('delivered', 'read')",
            sql_no_args(),
        );
        // W11 HARDENING (2026-07-02, Codex-flag): ilk-arm'ı `ensure_alarm`'a yönlendir —
        // eskiden `let _ = set_alarm` (tek deneme, sonuç YUTULUYORDU) → ilk-arm fail + hiç
        // ws-reconnect yoksa backstop HİÇ çalışmazdı. `ensure_alarm` 3x bounded-retry + fail'de
        // görünür log (get_alarm idempotent → zaten kurulu ise no-op).
        self.ensure_alarm().await;
        self.initialized.set(true);
        Ok(())
    }

    async fn ws_upgrade(&self, req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;

        // M2-S2.2: token + device_id parse'ını accept_web_socket + stale-close
        // ÖNCESİNE çek. Attachment{user_id, device_id} hazır olunca accept'lenir;
        // backfill ÖNCE device'ı bilmeli. (Token: Sec-WebSocket-Protocol
        // "sezgi.bearer.v1, <token>" — lib.rs sync_ws zaten doğrulayıp proxy
        // etti; burada attachment için tekrar parse.)
        // Self-host Faz A: DO fetch'i lib.rs `#[event(fetch)]` boot-guard'ından
        // GEÇMEZ (ayrı izolate olabilir) → JWT anahtarını (env-secret yoksa D1
        // self-provision cache'i) bu izolate'te de hazırla. Memoized + env-secret'lı
        // kurulumda D1'e hiç gitmeden döner (bugünkü davranış bit-aynı).
        crate::self_provision::ensure_keys(&self.env).await;

        let mut attach_user: Option<String> = None;
        let mut attach_device: Option<String> = None;
        if let Ok(t) = crate::extract_bearer_subprotocol(&req) {
            if let Ok(uid) = verify_access_token(&self.env, &t) {
                attach_user = Some(uid);
                // device_id claim — S1-öncesi token'da YOK → None (NULL-tolerans).
                attach_device = device_id_from_token(&self.env, &t).ok().flatten();
            }
        }

        // M2-S3.0 (B3): stale-close artık CİHAZ-FARKINDA. Aynı kullanıcının iki
        // cihazı (birincil + bağlı) eşzamanlı WS açar; her biri YALNIZ kendi pending
        // satırlarını flush/ack eder (S2.2 per-device izolasyonu) → eski tek-kuyruk
        // yarışı (ilk ack'leyen satırı siler) artık yapısal olarak yok. Bu yüzden
        // eski soketleri KOŞULSUZ kapatamayız: kapatırsak iki cihaz birbirinin WS'ini
        // sürekli koparır → link akışı + çift-cihaz teslim çalışmaz. Yalnız AYNI
        // device_id'nin eski soketini "superseded" kapat (reconnect/zombie temizliği,
        // çift-push önleme). Option<String> eşitliği tam doğru semantik: None==None
        // (S1-öncesi device'sız aynı-cihaz reconnect → kapat), Some==Some (aynı cihaz
        // reconnect → kapat), None!=Some (cihaz-farkında yeni bağlantı, device'sız
        // eski soketi KORUR — flush/ack "OR device_id IS NULL" toleranslı, o soket
        // kuyruğunu yine alır). N=1: tek cihaz → tüm eski soketler aynı device →
        // "tümünü kapat" davranışı birebir korunur. (Revoke-anında WS-red = S3.5.)
        let stale = self.state.get_websockets();
        self.state.accept_web_socket(&server);
        for old in stale {
            let old_dev = old
                .deserialize_attachment::<Attachment>()
                .ok()
                .flatten()
                .and_then(|a| a.device_id);
            if old_dev == attach_device {
                let _ = old.close(Some(1000), Some("superseded"));
            }
        }

        if let Some(uid) = attach_user {
            let _ = server.serialize_attachment(Attachment {
                user_id: uid,
                device_id: attach_device.clone(),
                // W1: taze accept edilen socket bir `WS_LIVENESS_WINDOW_MS` boyunca
                // "canlı" sayılır (client ilk ping'ini atana kadar spurious-push
                // olmasın). İlk inbound frame'de handle_ws_message tazeler.
                last_seen_ms: Some((now_secs() * 1000) as i64),
            });
        }

        // M2-S2.2 İDEMPOTENT NULL-backfill (red-team HIGH #3, #18): S2-öncesi
        // (device'sız) pending satırları bu ilk device-bilen WS'in cihazıyla
        // damgala. DO-storage tek-seferlik bayrak → reconnect RE-STAMP ETMEZ.
        // Backfill değeri Attachment.device_id'den (claim'den, TÜRETME DEĞİL).
        if let Some(dev) = attach_device.as_deref() {
            self.backfill_null_device_once(dev).await;
        }

        self.flush_pending_to(&server);
        // Sprint 8: WS reconnect replay — birikmiş receipt forward'ları sender bu
        // yeni WS üzerinden alır. force=true: TAZE socket eski (ölü/zombie) socket'e
        // push'lananı almadı → pushed_at'i yok say, kuyruktaki HEPSİNİ ver (saha
        // 2026-06-02 "okundu aşırı gecikti" kök-neden fix; client forward_id dedup'lar).
        self.flush_forwards_to(&server, true);
        // W11: periyodik alarm zinciri (transient set_alarm hatasıyla) kırılmışsa
        // client reconnect'inde SELF-HEAL et → offline-flush/forward-replay/cleanup
        // yeniden canlanır. Armed ise no-op (ucuz get_alarm).
        self.ensure_alarm().await;

        // WS upgrade response: client'ın gönderdiği subprotocol'ü echo et.
        // tokio-tungstenite client tarafı server'ın seçtiği subprotocol'ü doğrular;
        // echolanmazsa "no subprotocol selected" hatası alır.
        let resp = Response::from_websocket(pair.client)?;
        let headers = resp.headers().clone();
        headers.set("Sec-WebSocket-Protocol", "sezgi.bearer.v1")?;
        Ok(resp.with_headers(headers))
    }

    /// M2-S2.2: `pending.device_id IS NULL` satırlarını verilen cihazla TEK
    /// SEFER damgalar (DEVICE_BACKFILL_DONE_KEY bayrağı arkasında). Bayrak set
    /// edildiyse no-op → reconnect re-stamp etmez (red-team HIGH #3).
    /// N=1'de DO tek-cihaza ait → tüm device'sız geçmiş satır o cihaza doğru.
    /// FIX-2(b) NOTU: backfill yalnızca İLK device-bilen bağlantıdaki geçmiş
    /// NULL'ları damgalar; sonradan oluşan NULL pending (grup-fallback FIX-1 →
    /// cihaz yayınlamamış üye) bu bayraktan sonra gelirse backfill ATLANIR ama
    /// flush/ack `OR device_id IS NULL` toleransı (FIX-2(b)) ile yine doğru cihaza
    /// teslim edilir. İki mekanizma tamamlayıcı (NULL yalnız yayınlamamış-tek-cihaz
    /// kullanıcıda → "tek mantıksal cihaz" = bağlanan cihaz). S3-TODO: çok-cihaz
    /// kullanıcısı NULL'a sahip olabilirse hem backfill hem tolerans yeniden gözden
    /// geçirilmeli.
    /// W11: periyodik alarm zincirini sağlam tut. `set_alarm` sonucu eskiden
    /// yutuluyordu (`let _ =`) → tek transient storage-hatası zinciri kırıp
    /// offline-flush/forward-replay/cleanup'i o DO instance ömrü boyunca (evict+
    /// reinit'e kadar) sessizce durduruyordu. Zaten armed ise no-op; değilse
    /// bounded-retry ile kur. alarm() sonu (fire sonrası None → kurar) + her
    /// ws_upgrade (client reconnect = doğal self-heal noktası) çağırır.
    async fn ensure_alarm(&self) {
        let storage = self.state.storage();
        if storage.get_alarm().await.ok().flatten().is_some() {
            return;
        }
        let next = (now_secs() * 1000) as i64 + FLUSH_INTERVAL_MS;
        for _ in 0..3 {
            if storage.set_alarm(next).await.is_ok() {
                return;
            }
        }
        console_log!("UserInbox: set_alarm 3x fail — alarm zinciri risk (sonraki ws_upgrade re-dener)");
    }

    /// W1-backstop (Codex HIGH — W1 kesin closure). Ground-truth: `pending`'de duran
    /// satır = ack'lenmemiş = teslim olmamış. `push_wake_at` NULL (delivered_live=true
    /// sanıldı, immediate-push atılmadı) VE grace aşmış satırlar için FCM-wake at →
    /// W1'in daralttığı ama kapatmadığı false-pozitif pencereyi (ping-sonrası-ölüm)
    /// kapatır. distinct device_id başına tek push (maybe_push_wake None=tüm-cihaz);
    /// sonra push_wake_at damgalanır → sonraki alarm re-push etmez. Idempotent/best-effort.
    async fn backstop_push_stale_pending(&self) {
        let storage = self.state.storage();
        let uid: Option<String> = storage.get(RECIPIENT_UID_KEY).await.ok().flatten();
        let uid = match uid {
            Some(u) => u,
            None => return, // ALICI user_id henüz bilinmiyor (hiç notify gelmedi) → no-op
        };
        let db = match self.env.d1("DB") {
            Ok(d) => d,
            Err(_) => return,
        };
        let now = now_secs() as i64;
        let cutoff = now - PUSH_BACKSTOP_GRACE_SECS; // pending.created_at SANİYE cinsinden
        // Stuck satırların distinct alıcı-cihazları (None = cihaz-blind → tüm cihaz).
        let cursor = match storage.sql().exec_raw(
            "SELECT DISTINCT device_id FROM pending WHERE push_wake_at IS NULL AND created_at < ?",
            Some(vec![JsValue::from_f64(cutoff as f64)]),
        ) {
            Ok(c) => c,
            Err(_) => return,
        };
        #[derive(Deserialize)]
        struct DevRow {
            #[serde(default)]
            device_id: Option<String>,
        }
        let rows: Vec<DevRow> = match cursor.to_array() {
            Ok(r) => r,
            Err(_) => return,
        };
        if rows.is_empty() {
            return;
        }
        // [deliv-telemetry] W1-backstop ateşledi = W1 canlılık-ayracının kaçırdığı
        // (ping-sonrası-ölen / ws.rs-yanıt-kaybı) stuck-pending yakalandı. wrangler
        // tail'de bu satırın SIKLIĞI W1 residual'ının saha-etkisini ölçer (Codex:
        // sayaçsız kanıtlanamaz). Yüksek-sinyal/düşük-frekans → per-olay log OK.
        console_log!(
            "[deliv] W1-backstop wake: {} device stale-unacked (uid={})",
            rows.len(),
            uid
        );
        for r in &rows {
            crate::push::fcm::maybe_push_wake(&self.env, &db, &uid, r.device_id.as_deref()).await;
        }
        // Damgala → sonraki alarm aynı satırları re-push etmesin (best-effort; hata
        // yutulursa en kötü ihtimalle sonraki alarmda tekrar wake = zararsız-fazla-push).
        let _ = storage.sql().exec_raw(
            "UPDATE pending SET push_wake_at = ? WHERE push_wake_at IS NULL AND created_at < ?",
            Some(vec![
                JsValue::from_f64((now * 1000) as f64),
                JsValue::from_f64(cutoff as f64),
            ]),
        );
    }

    async fn backfill_null_device_once(&self, device_id: &str) {
        let storage = self.state.storage();
        let done: Option<bool> = storage
            .get::<bool>(DEVICE_BACKFILL_DONE_KEY)
            .await
            .ok()
            .flatten();
        if done == Some(true) {
            return;
        }
        let _ = storage.sql().exec_raw(
            "UPDATE pending SET device_id = ? WHERE device_id IS NULL",
            Some(vec![JsValue::from_str(device_id)]),
        );
        let _ = storage.put(DEVICE_BACKFILL_DONE_KEY, true).await;
    }
}
