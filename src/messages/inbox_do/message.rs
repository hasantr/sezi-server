use super::*;
use sha2::{Digest, Sha256};

/// W1 (delivered_live yanlış-pozitif fix): bir WS'in "gerçekten canlı" sayılması
/// için son CLIENT→SERVER frame'i (`Attachment.last_seen_ms`) bu pencere içinde
/// olmalı. Client 5sn'de bir text-ping atar (ws_conn.rs) + 14sn frame gelmezse
/// kendi tarafından zombie sayıp reconnect eder → sağlıklı bağlantı her zaman
/// <5sn taze. 20sn = ping-aralığının 4×'i (bir kaçırılan ping + hibernation-wake
/// gecikmesi + saat-kayması payı). Bu pencerenin DIŞINDaki socket'e `send_with_str`
/// Ok dönse bile teslim "canlı" sayılmaz → caller FCM-wake yollar.
const WS_LIVENESS_WINDOW_MS: i64 = 20_000;

/// W2 (per-recipient pending DoS-tavanı, 2026-07-02 Codex-plan): bir alıcının `pending` tablosu
/// (bu DO) sınırsız şişmesin — kötü/gürültücü gönderen kurban DO'sunu SQLite-bloat'la DoS
/// edebilirdi. TTL-retention (alarm `DELETE ... created_at < retention`) ZAMAN'la sınırlar ama
/// retention-penceresi İÇİNDE flood bloat eder → hard row-count tavanı İKİNCİ savunma. Aşıldığında
/// en-eski (en-küçük id) fazlalık evict = bounded FIFO. Değer cömert (meşru offline-backlog nadiren
/// aşar); aşan = çok-uzun-offline/DoS → en-eski undelivered düşer (client M4-senk + redelivery
/// telafi eder; recent korunur).
const PENDING_MAX_ROWS: i64 = 10_000;
/// Tavan-uygulamayı HER insert'te değil ~bu aralıkta bir yap (hot-path COUNT+DELETE maliyetini
/// amortize et; overshoot ≤ PENDING_MAX_ROWS + bu). `row.id` (AUTOINCREMENT monoton) ile gate'lenir.
const PENDING_CAP_ENFORCE_EVERY: i64 = 512;

/// W1: WS attachment'tan `last_seen_ms` (varsa). Yoksa `None` → çağıran taze
/// sayMAZ (muhafazakâr: zombie olabilir → wake tetiklensin; ilk ping'te dolar).
pub(crate) fn ws_last_seen_ms(ws: &WebSocket) -> Option<i64> {
    ws.deserialize_attachment::<Attachment>()
        .ok()
        .flatten()
        .and_then(|a| a.last_seen_ms)
}

/// W1/W9: socket GERÇEKTEN canlı mı — son inbound frame `WS_LIVENESS_WINDOW_MS`
/// içinde mi? Zombie/yarı-açık socket'te `send_with_str` Ok döner ama client
/// almaz; bu ayraç onu "canlı teslim/push" saymaktan alıkoyar. `now_ms` çağırandan
/// (tek `now_secs()` okuması). last_seen yok/bayat → false. notify_inner (W1) +
/// forward_signal (W9) ortak kullanır.
pub(crate) fn ws_is_fresh(ws: &WebSocket, now_ms: i64) -> bool {
    ws_last_seen_ms(ws)
        .map(|ls| now_ms - ls <= WS_LIVENESS_WINDOW_MS)
        .unwrap_or(false)
}

/// M2-S2.2: bu WS bağlantısı verilen hedef-cihazın frame'ini almalı mı?
/// - `recipient_device` None → her WS hedef (N=1 uyum / S2.3-öncesi fan-out).
/// - WS attachment device None (S1-öncesi token) → NULL-tolerans, hedef sayılır.
/// - İkisi de somut → yalnız eşleşen device WS hedeftir.
pub(crate) fn ws_targets_device(ws: &WebSocket, recipient_device: Option<&str>) -> bool {
    let want = match recipient_device {
        Some(d) => d,
        None => return true,
    };
    match ws_attachment_device(ws) {
        Some(have) => have == want,
        None => true, // attachment device bilinmiyor → tolerans
    }
}

/// M2-S2.2: WS attachment'tan device_id (varsa).
pub(crate) fn ws_attachment_device(ws: &WebSocket) -> Option<String> {
    ws.deserialize_attachment::<Attachment>()
        .ok()
        .flatten()
        .and_then(|a| a.device_id)
}

/// M2-S2.2: pending satırından alıcı frame'i (sender_device_id taşır).
pub(crate) fn pending_frame(r: &PendingRow) -> String {
    serde_json::json!({
        "type": "msg",
        "id": r.id,
        "sender_id": r.sender_id,
        "sender_device_id": r.sender_device_id,
        "envelope_b64": r.envelope_b64,
        "group_id": r.group_id,
        "ts": r.created_at,
    })
    .to_string()
}

impl UserInbox {
    pub(crate) async fn notify_inner(
        &self,
        sender_id: &str,
        sender_device_id: Option<&str>,
        recipient_device_id: Option<&str>,
        recipient_id: Option<&str>,
        envelope_b64: &str,
        group_id: Option<&str>,
    ) -> Result<(i64, bool)> {
        // Dönüş: (pending_id, delivered_live). `delivered_live` = en az bir eşleşen
        // AKTİF (gerçekten-canlı, W1) WS'e push gitti mi → false ise alıcı offline →
        // caller FCM-wake yollar.
        let now = now_secs() as i64;

        // W1-backstop: ALICI user_id'yi bir kez persist et (alarm stuck-pending
        // FCM-wake'te kullanır; DO offline'da kendi user'ını başka türlü bilemez).
        // Cell-guard redundant-write önler. recipient_id yoksa (eski gövde) atla.
        if !self.uid_persisted.get() {
            if let Some(rid) = recipient_id {
                let _ = self.state.storage().put(RECIPIENT_UID_KEY, rid.to_string()).await;
                self.uid_persisted.set(true);
            }
        }

        // Idempotency check: aynı (sender, sender_device, recipient_device,
        // envelope) son 60sn içinde işlendiyse cached msg_id'yi döndür,
        // duplicate INSERT yapma. Client retry'si DO storage'ı şişirmesin +
        // recipient'a duplicate WS push gitmesin.
        // M2-S2.2 (BLOCKER #11): hash'e sender_device + recipient_device DAHİL.
        // Grup tek-Megolm-zarfı aynı user'ın İKİ cihazına fan-out edilirse
        // (envelope birebir aynı) recipient_device farkı AYRI hash üretir →
        // ikinci cihaz satırı yutulmaz. Hash16 = SHA256(
        //   sender||"|"||sender_dev||"|"||recipient_dev||"|"||envelope)[0..16].
        let mut envelope_hash = [0u8; 16];
        {
            let mut hasher = Sha256::new();
            hasher.update(sender_id.as_bytes());
            hasher.update(b"|");
            hasher.update(sender_device_id.unwrap_or("").as_bytes());
            hasher.update(b"|");
            hasher.update(recipient_device_id.unwrap_or("").as_bytes());
            hasher.update(b"|");
            hasher.update(envelope_b64.as_bytes());
            envelope_hash.copy_from_slice(&hasher.finalize()[..16]);
        }
        if let Some((cached_id, cached_live)) = self.dedup_lookup(sender_id, &envelope_hash, now) {
            // W4-a (Codex HIGH): dedup-hit'te İLK teslimin GERÇEK delivered_live'ını
            // döndür — sabit `true` DEĞİL. Eski kod "orijinal zaten wake kararını verdi"
            // varsayıyordu; ama W4 in-request retry'da İLK denemenin cross-DO yanıtı
            // düşerse caller o kararı HİÇ görmez; retry dedup'a çarpıp `true` alırsa
            // (alıcı offline olsa bile) FCM-wake SESSİZCE bastırılırdı. Gerçek değeri
            // döndürünce: offline ilk-teslim (live=false) → retry de false → caller wake
            // atar. Online (live=true) → gereksiz wake yok.
            return Ok((cached_id, cached_live));
        }

        let storage = self.state.storage();
        let group_id_val = match group_id {
            Some(g) => JsValue::from_str(g),
            None => JsValue::NULL,
        };
        let sender_device_val = match sender_device_id {
            Some(d) => JsValue::from_str(d),
            None => JsValue::NULL,
        };
        let recipient_device_val = match recipient_device_id {
            Some(d) => JsValue::from_str(d),
            None => JsValue::NULL,
        };
        let cursor = storage.sql().exec_raw(
            "INSERT INTO pending (sender_id, envelope_b64, group_id, device_id, sender_device_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
            Some(vec![
                JsValue::from_str(sender_id),
                JsValue::from_str(envelope_b64),
                group_id_val,
                recipient_device_val,
                sender_device_val,
                JsValue::from_f64(now as f64),
            ]),
        )?;
        #[derive(Deserialize)]
        struct IdRow {
            id: i64,
        }
        let row: IdRow = cursor.one()?;

        // W2 (per-recipient pending DoS-tavanı): amortize edilmiş hard-cap. ~her
        // PENDING_CAP_ENFORCE_EVERY insert'te bir COUNT; tavan aşıldıysa en-eski fazlalığı evict
        // (bounded FIFO — yeni satır en-yeni, korunur). COUNT+DELETE yalnız aralıkta bir → hot-path
        // maliyeti amortize. Log yalnız GERÇEK evict'te (DoS-göstergesi; normalde sessiz).
        if row.id % PENDING_CAP_ENFORCE_EVERY == 0 {
            #[derive(Deserialize)]
            struct CountRow {
                n: i64,
            }
            if let Ok(c) = storage
                .sql()
                .exec_raw("SELECT COUNT(*) AS n FROM pending", sql_no_args())
            {
                if let Some(cnt) = c.to_array::<CountRow>().ok().and_then(|r| r.into_iter().next()) {
                    if cnt.n > PENDING_MAX_ROWS {
                        let evict = cnt.n - PENDING_MAX_ROWS;
                        let _ = storage.sql().exec_raw(
                            "DELETE FROM pending WHERE id IN (SELECT id FROM pending ORDER BY id ASC LIMIT ?)",
                            Some(vec![JsValue::from_f64(evict as f64)]),
                        );
                        worker::console_log!(
                            "[deliv] W2 pending-cap: {evict} en-eski satir evict (recipient bloat guard, count={})",
                            cnt.n
                        );
                    }
                }
            }
        }

        let payload = serde_json::json!({
            "type": "msg",
            "id": row.id,
            "sender_id": sender_id,
            "sender_device_id": sender_device_id,
            "envelope_b64": envelope_b64,
            "group_id": group_id,
            "ts": now,
        })
        .to_string();
        // M2-S2.2: push yalnız HEDEF cihazın WS'ine. recipient_device None ise
        // (S2.3 fan-out henüz doldurmadı / N=1 uyum) HER WS'e (bugünkü davranış).
        // Attachment.device_id None (S1-öncesi token) → o WS de hedef sayılır
        // (NULL-tolerans). Eşleşme: somut-recipient + somut-attachment-device
        // farklıysa o WS'e GİTMEZ.
        // W1 (delivered_live yanlış-pozitif fix): `send_with_str` Ok ≠ client-aldı.
        // MIUI arka-plan kill sonrası TCP yarı-açık kalır → CF edge yazmayı
        // buffered kabul eder (Ok) ama client mesajı ALMAZ. Eski kod bunu
        // `delivered_live=true` sayıp FCM-wake'i BASTIRIYORDU → mesaj `pending`'te
        // 90sn alarm/reconnect'e kadar sessizce bekliyor + bildirim hiç gitmiyordu
        // ("mesaj gelmiyor" kökü). FIX: bir socket ancak (a) send Ok VE (b) son
        // `WS_LIVENESS_WINDOW_MS` içinde client'tan frame gelmişse (last_seen taze)
        // "canlı teslim" sayılır. Bayat/last_seen-yok socket'e yine yazarız
        // (hibernating-ama-canlı ihtimali + pending zaten ack'e kadar durur) ama
        // delivered_live SET ETMEYİZ → caller FCM-wake atar (zombie'de doğru,
        // gerçekten-canlıda zararsız-yedek: client zaten mesajı da alır).
        let now_ms = now * 1000;
        let mut delivered_live = false;
        let mut zombie_seen = false;
        for ws in self.state.get_websockets() {
            if ws_targets_device(&ws, recipient_device_id) {
                let send_ok = ws.send_with_str(payload.as_str()).is_ok();
                let fresh = ws_is_fresh(&ws, now_ms);
                if send_ok && fresh {
                    delivered_live = true;
                } else if send_ok && !fresh {
                    // Yazma Ok ama last_seen bayat = zombie/yarı-açık (send-ok'a
                    // güvenilseydi delivered_live=true olup FCM bastırılırdı — W1 kökü).
                    zombie_seen = true;
                }
            }
        }
        // [deliv-telemetry] W1: zombie yakalandı VE başka canlı socket teslim almadı →
        // delivered_live=false → caller FCM-wake atar. wrangler tail'de bu satırın sıklığı
        // W1'in gerçek etkisini (MIUI-kill zombie yakalama) ölçer (Codex: sayaçsız kanıtlanamaz).
        if zombie_seen && !delivered_live {
            worker::console_log!(
                "[deliv] W1 zombie-socket yakalandı (send-ok+stale) -> FCM-wake yolu (grp={})",
                group_id.unwrap_or("1:1")
            );
        }
        // W1-backstop NOTU: `push_wake_at`'i BURADA set ETMİYORUZ. delivered_live=false
        // (offline) satırlar için caller ANINDA maybe_push_wake atar; AMA burada işaretlersek
        // ws.rs WS-send yanıt-kaybı yolunda (retry yok) satır "pushed" damgalanır ama gerçek
        // push atılmamış olur → backstop atlar → wake HİÇ gitmez (kırılgan-bağ boşluğu).
        // Yerine: `push_wake_at` YALNIZ backstop tarafından (kendi push'undan sonra) set
        // edilir → her satır EN FAZLA bir backstop-wake alır. Offline satır: caller-immediate
        // + (grace sonrası hâlâ unacked ise) bir backstop-wake = bounded, content-less,
        // device-başına deduplike (MIUI için faydalı wake-retry). ws.rs-boşluğu da kapanır.
        // W4-a: dedup entry'yi GERÇEK delivered_live ile SEND-LOOP SONRASI yaz. notify_inner
        // await'siz → DO tek-thread'de send-loop ile bu yazım arası interleave YOK (atomik) →
        // retry aynı envelope'u dedup'ta doğru live değeriyle bulur.
        self.dedup_insert(sender_id.to_string(), envelope_hash, row.id, now, delivered_live);
        Ok((row.id, delivered_live))
    }

    /// Dedup cache'inde (sender, envelope_hash) için existing msg_id var mı?
    /// Aynı zamanda 60sn'den eski kayıtları temizler. Mutex borrow await
    /// sınırını aşmaz — sync-only iş.
    fn dedup_lookup(
        &self,
        sender_id: &str,
        envelope_hash: &[u8; 16],
        now: i64,
    ) -> Option<(i64, bool)> {
        let mut dedup = self.dedup.lock().ok()?;
        dedup.retain(|e| now - e.created_at < DEDUP_TTL_SECS);
        dedup
            .iter()
            .find(|e| e.sender_id == sender_id && &e.envelope_hash == envelope_hash)
            .map(|e| (e.msg_id, e.delivered_live))
    }

    fn dedup_insert(
        &self,
        sender_id: String,
        envelope_hash: [u8; 16],
        msg_id: i64,
        now: i64,
        delivered_live: bool,
    ) {
        if let Ok(mut dedup) = self.dedup.lock() {
            // Bellek tavanı: tavan aşılırsa en eski yarıyı at (FIFO-ish).
            if dedup.len() >= DEDUP_MAX_ENTRIES {
                let half = dedup.len() / 2;
                dedup.drain(0..half);
            }
            dedup.push(DedupEntry {
                sender_id,
                envelope_hash,
                msg_id,
                created_at: now,
                delivered_live,
            });
        }
    }

    pub(crate) fn forward_typing_inner(&self, sender_id: &str) {
        let payload =
            serde_json::json!({ "type": "typing", "from": sender_id }).to_string();
        for ws in self.state.get_websockets() {
            let _ = ws.send_with_str(payload.as_str());
        }
    }

    pub(crate) fn flush_pending_to(&self, ws: &WebSocket) {
        // FIX-2(b) (HIGH — NULL-tolerans GERİ): bu WS'in cihazına ait satırlar
        // VE NULL-device satırlar (`OR device_id IS NULL`, select_pending_for_device).
        // GEREKÇE: NULL pending artık MEŞRU = "cihaz-listesi yayınlamamış kullanıcı"
        // (grup-fallback FIX-1: LEFT JOIN cihazsız üyeye `recipient_device=None`
        // yazar). Böyle bir kullanıcı TEK mantıksal cihazdır → bağlanan cihaza teslim
        // edilir, güvenli (çok-cihaz belirsizliği YOK çünkü NULL yalnız yayınlamamış-
        // tek-cihaz kullanıcıda oluşur; 1:1 yolunda device_id ZORUNLU [FIX-2(a)] →
        // 1:1'den NULL ASLA gelmez). Red-team #18'in "tüm NULL'lar legacy →
        // ws_upgrade backfill damgalar → toleransı kaldır" gerekçesi FIX-1 grup-
        // fallback'i ile GEÇERSİZ (post-cut yeni NULL üretiliyor).
        // S3-TODO: çok-cihaz kullanıcısı NULL satıra sahip olabilirse (linked-device
        // sonrası yayınlamamış üye?) bu tolerans yeniden değerlendirilmeli — o zaman
        // NULL artık "tek mantıksal cihaz" garantisi vermez.
        // Attachment device bilinmeyen (S1-öncesi token) → None-branch (tüm satırlar,
        // device-blind teslim; dokunulmadı).
        let device = ws_attachment_device(ws);
        let rows = self.select_pending_for_device(device.as_deref());
        for r in &rows {
            let _ = ws.send_with_str(pending_frame(r).as_str());
        }
        // FAZ-2 Adım-3: drain-idle sinyali. Tüm `pending` frame'lerinden SONRA gönderilir
        // (CF DO WS-send tek-thread sıralı → `sync_idle` kesinlikle son `msg`'den sonra varır,
        // race YOK). Background-drain bunu "bu turda taşınacak pending bitti" işareti sayar →
        // ack'leri tamamlayıp çıkar. `more=true` (500-cap doldu) → daha var, deadline'a devam.
        // Foreground client bu frame'i YOK SAYAR (yalnız drain modunda anlamlı). Eski client
        // bilinmeyen `type`'ı zaten yutar → geriye-uyumlu.
        let flushed = rows.len();
        let idle = serde_json::json!({
            "type": "sync_idle",
            "flushed": flushed,
            "more": flushed >= 500,
        })
        .to_string();
        let _ = ws.send_with_str(idle.as_str());
    }

    /// FIX-2(b): pending satırlarını verilen cihaza göre seç. Some-branch
    /// `device_id=? OR device_id IS NULL` (NULL pending = cihaz yayınlamamış-tek-cihaz
    /// kullanıcı, grup-fallback FIX-1 → bağlanan cihaza teslim, güvenli). None-branch
    /// (S1-token device-blind) zaten tüm satırları alır, dokunulmadı.
    fn select_pending_for_device(&self, device: Option<&str>) -> Vec<PendingRow> {
        let storage = self.state.storage();
        let cursor = match device {
            Some(d) => storage.sql().exec_raw(
                "SELECT id, sender_id, envelope_b64, group_id, sender_device_id, created_at
                 FROM pending
                 WHERE device_id = ? OR device_id IS NULL
                 ORDER BY id ASC LIMIT 500",
                Some(vec![JsValue::from_str(d)]),
            ),
            // Attachment device bilinmiyor (S1-öncesi token) → tüm satırlar
            // (bugünkü davranış: device-blind teslim; backfill bu yolda koşmaz).
            None => storage.sql().exec_raw(
                "SELECT id, sender_id, envelope_b64, group_id, sender_device_id, created_at
                 FROM pending ORDER BY id ASC LIMIT 500",
                sql_no_args(),
            ),
        };
        match cursor {
            Ok(c) => c.to_array().unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    pub(crate) fn flush_pending_to_all(&self) {
        let ws_list = self.state.get_websockets();
        if ws_list.is_empty() {
            return;
        }
        // M2-S2.2: her WS'i KENDİ device'ıyla filtreli flush'la (artık aynı
        // satırı global HERKESE değil — device-scoped).
        for ws in &ws_list {
            let device = ws_attachment_device(ws);
            let rows = self.select_pending_for_device(device.as_deref());
            for r in &rows {
                let _ = ws.send_with_str(pending_frame(r).as_str());
            }
        }
    }

}
