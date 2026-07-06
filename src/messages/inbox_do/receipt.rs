//! Model-B Layer-4 — hesap-düzeyi receipt (delivered/read) durable log.
//!
//! `forward_queue` consume-once transport'un (push-tüm-WS + global-ack-DELETE)
//! çoklu-cihazda kardeş-yarışı/zombie-socket/reconnect-gap kusurlarını çözer:
//! delivered/read artık A'nın UserInbox DO'sunda **durable state** (`receipt_state`),
//! her A-cihazı **kendi seq-cursor'undan idempotent senkronlar**. WS = yalnız bildirim.
//!
//! - Granülerlik: B'nin per-cihaz `remote_id`'si (receipt'in geldiği id). Logical-mesaja
//!   aggregation CLIENT-tarafı `mdd` ile (mevcut kanıtlı yol; sadece transport değişti).
//! - `seq` = hesap-global monoton high-water (`receipt_meta`). Tablo retention-purge
//!   edilse bile high-water GERİ GİTMEZ → cursor'lar tutarlı kalır (yeni satır asla
//!   eski cursor'un altına düşmez).
//! - delivered/read SET-ONCE monoton (`COALESCE`); read ⇒ delivered. Değişiklik yoksa
//!   seq bump YOK (idempotent, churn yok).
//!
//! delivery_failed BURADA DEĞİL: transient action-signal (retry/OLM-reset tetikler,
//! durable tik değil) → `forward_queue`'da kalır (fresh-device replay'de yan-etki
//! tetiklenmesin diye bilinçli).

use super::*;

#[derive(Deserialize)]
struct ReceiptStateExisting {
    delivered_at: Option<i64>,
    read_at: Option<i64>,
    #[serde(default)]
    msg_uid: Option<String>,
}

#[derive(Deserialize)]
struct ReceiptSeqRow {
    v: i64,
}

#[derive(Deserialize)]
struct ReceiptStateRow {
    peer_id: String,
    remote_id: i64,
    #[serde(default)]
    delivered_at: Option<i64>,
    #[serde(default)]
    read_at: Option<i64>,
    seq: i64,
    /// #11 Layer-4b: gönderenin local_id'si (E2E msg_uid). Kardeş cihaz `oc-{msg_uid}`
    /// ile eşler. Eski satırlar (kolon-öncesi) NULL → None (sibling-yakınsama atlanır).
    #[serde(default)]
    msg_uid: Option<String>,
}

impl UserInbox {
    /// delivered/read receipt'i durable `receipt_state`'e uygula (set-once monoton).
    /// Değişiklik olursa hesap-global seq'i bump eder + tüm WS'lere `receipt_update`
    /// bildirir (best-effort; veri taşımaz → gap-skip yok, client cursor'dan pull'lar).
    /// `kind`: "delivered" | "read". `from_peer` = receipt'i üreten (B). `ids` =
    /// B-cihaz `remote_id`'leri. `ts_ms` = server-alış zamanı (tik gösterimi için yeter).
    pub(crate) fn apply_receipt(
        &self,
        kind: &str,
        from_peer: &str,
        ids: &[i64],
        uids: &[String],
        ts_ms: i64,
    ) {
        if ids.is_empty() {
            return;
        }
        let is_read = kind == "read";
        let storage = self.state.storage();
        let sql = storage.sql();
        // Her DEĞİŞEN row ATOMİK olarak benzersiz, kesin-artan seq alır: high-water'ı
        // row-write'tan ÖNCE `UPDATE ... RETURNING` ile bump+oku (Codex HIGH-2). Böylece
        // meta-update fail/DO-evict ile seq-reuse + (cursor'u geçmiş cihazda) silent-skip
        // YOK; en kötü kullanılmayan seq-gap (zararsız, cursor atlar). Per-row benzersiz
        // seq → `receipt_sync` 500-LIMIT sayfalaması da her zaman ilerler.
        let mut max_seq: i64 = 0;
        let mut changed = false;
        // LATENCY fast-path: bu çağrıda DEĞİŞEN row'ları topla → sonunda canlı `receipt_delta`
        // ile DOĞRUDAN push (gönderici 2.tik'i receipt_sync pull-round-trip'i beklemeden uygular).
        let mut delta_rows: Vec<serde_json::Value> = Vec::new();

        for (i, &rid) in ids.iter().enumerate() {
            // #11 Layer-4b: bu id'ye karşılık gelen msg_uid (gönderenin local_id'si;
            // E2E payload'dan okuyan sağlar — server kör, türetemez). Kardeş cihaz bunu
            // `oc-{msg_uid}` oc-satırıyla eşler (mdd'siz okundu-yakınsama). Boş/eksik → None.
            let uid: Option<&str> = uids.get(i).map(|s| s.as_str()).filter(|s| !s.is_empty());
            // Mevcut state (set-once için). msg_uid de okunur (Codex Q4: uid SONRADAN
            // gelirse değişiklik sayılmalı — yoksa uid'siz oluşmuş read satırı uid'i HİÇ
            // öğrenmez, seq bump olmaz, kardeş cihaz eşleyemez).
            let existing = match sql.exec_raw(
                "SELECT delivered_at, read_at, msg_uid FROM receipt_state WHERE peer_id = ? AND remote_id = ?",
                Some(vec![
                    JsValue::from_str(from_peer),
                    JsValue::from_f64(rid as f64),
                ]),
            ) {
                Ok(c) => c
                    .to_array::<ReceiptStateExisting>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| (r.delivered_at, r.read_at, r.msg_uid)),
                Err(_) => None,
            };
            let (old_d, old_r, old_uid) = existing.unwrap_or((None, None, None));
            // delivered + read İKİSİ de delivered'ı set eder (read ⇒ delivered).
            let new_d = old_d.or(Some(ts_ms));
            let new_r = if is_read { old_r.or(Some(ts_ms)) } else { old_r };
            // #11 Q4: uid YENİ geldi (mevcut NULL, gelen Some) → tik değişmese bile yaz
            // + seq bump → kardeş re-sync'te uid'i görür.
            let uid_newly = uid.is_some() && old_uid.is_none();
            if (new_d, new_r) == (old_d, old_r) && !uid_newly {
                continue; // değişiklik yok (uid de yeni değil) → idempotent skip.
            }
            // Atomik seq rezervasyonu (HIGH-2): bump + yeni-değer tek statement'ta.
            let seq = match sql.exec_raw(
                "UPDATE receipt_meta SET v = v + 1 WHERE k = 'seq' RETURNING v",
                sql_no_args(),
            ) {
                Ok(c) => c
                    .to_array::<ReceiptSeqRow>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| r.v),
                Err(_) => None,
            };
            let Some(seq) = seq else {
                continue; // meta-bump fail (nadir DB-hatası) → row'u atla; seq-reuse YOK.
            };
            changed = true;
            if seq > max_seq {
                max_seq = seq;
            }
            let d_val = match new_d {
                Some(v) => JsValue::from_f64(v as f64),
                None => JsValue::NULL,
            };
            let r_val = match new_r {
                Some(v) => JsValue::from_f64(v as f64),
                None => JsValue::NULL,
            };
            let uid_val = match uid {
                Some(u) => JsValue::from_str(u),
                None => JsValue::NULL,
            };
            let _ = sql.exec_raw(
                "INSERT INTO receipt_state (peer_id, remote_id, delivered_at, read_at, seq, updated_at, msg_uid)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(peer_id, remote_id) DO UPDATE SET
                   delivered_at = excluded.delivered_at,
                   read_at = excluded.read_at,
                   seq = excluded.seq,
                   updated_at = excluded.updated_at,
                   msg_uid = COALESCE(excluded.msg_uid, receipt_state.msg_uid)",
                Some(vec![
                    JsValue::from_str(from_peer),
                    JsValue::from_f64(rid as f64),
                    d_val,
                    r_val,
                    JsValue::from_f64(seq as f64),
                    JsValue::from_f64(ts_ms as f64),
                    uid_val,
                ]),
            );
            // LATENCY fast-path: değişen row'u canlı delta için topla. Şekil = receipt_sync_payload
            // (peer/remote_id/delivered_at/read_at/seq/msg_uid) → client handle_receipt_batch REUSE.
            // msg_uid = COALESCE sonucu (gelen uid.or(eski)).
            delta_rows.push(serde_json::json!({
                "peer": from_peer,
                "remote_id": rid,
                "delivered_at": new_d,
                "read_at": new_r,
                "seq": seq,
                "msg_uid": uid.or(old_uid.as_deref()),
            }));
        }

        if !changed {
            return;
        }
        // High-water zaten her row'da atomik bump'landı (ayrı UPDATE YOK). Tüm A-
        // cihazlarına bildir → her biri kendi cursor'undan pull eder.
        let payload =
            serde_json::json!({ "type": "receipt_update", "max_seq": max_seq }).to_string();
        for ws in self.state.get_websockets() {
            let _ = ws.send_with_str(payload.as_str());
        }
        // LATENCY fast-path: değişen row'ları AYNI WS'lere DOĞRUDAN push (`receipt_delta`).
        // Gönderici 2.tik'i `receipt_sync` pull-round-trip'i BEKLEMEDEN anında uygular →
        // "2.tik asla snappy değil" yapısal kökü kapanır. Durable model KORUNUR: yukarıdaki
        // `receipt_update` yine gidiyor → client cursor'u authoritative-pull ile yakalar (delta
        // NON-ROOTED uygulanır, cursor'u ilerletmez → cross-page gap-skip riski yok). Eski client
        // `receipt_delta`'yı bilmez → yok sayar (forward-compat; receipt_update ile eski-yol sürer).
        if !delta_rows.is_empty() {
            let delta = serde_json::json!({
                "type": "receipt_delta",
                "rows": delta_rows,
                "max_seq": max_seq,
            })
            .to_string();
            for ws in self.state.get_websockets() {
                let _ = ws.send_with_str(delta.as_str());
            }
        }
    }

    // (receipt_seq_current kaldırıldı — seq artık per-row atomik `UPDATE ... RETURNING`
    //  ile rezerve ediliyor; ayrı high-water okuması yok.)

    /// Cursor-sonrası `receipt_state` satırlarını (`seq > since ORDER BY seq ASC LIMIT 500`)
    /// transport-agnostik `{rows, more}` payload'ına serialize eder (type tag YOK — WS
    /// sarmalayıcı ekler). WS frame ve HTTP `GET /messages/receipt-sync` AYNI builder'ı
    /// kullanır → BİT-AYNI rows garantisi. SQL-hatası → `None` (WS: frame gönderme, eski
    /// davranış; HTTP: çağıran boş-batch'e çevirir → cursor ilerlemez, sonraki event re-pull).
    pub(crate) fn receipt_sync_payload(&self, since: i64) -> Option<serde_json::Value> {
        let storage = self.state.storage();
        let rows: Vec<ReceiptStateRow> = match storage.sql().exec_raw(
            "SELECT peer_id, remote_id, delivered_at, read_at, seq, msg_uid FROM receipt_state
             WHERE seq > ? ORDER BY seq ASC LIMIT 500",
            Some(vec![JsValue::from_f64(since as f64)]),
        ) {
            Ok(c) => c.to_array().unwrap_or_default(),
            Err(_) => return None,
        };
        let more = rows.len() == 500;
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "peer": r.peer_id,
                    "remote_id": r.remote_id,
                    "delivered_at": r.delivered_at,
                    "read_at": r.read_at,
                    "seq": r.seq,
                    "msg_uid": r.msg_uid,
                })
            })
            .collect();
        // `since` echo (ortak-kök #1 gap-skip fix): client, sayfanın cursor'dan-köklü
        // (rooted: since≤cursor) mü yoksa pagination-devamı (since=max_seq>cursor) mı
        // olduğunu bundan ayırır → durable cursor'u yalnız köklü sayfada ilerletir
        // (cross-page gap-atlamayı önler).
        Some(serde_json::json!({ "rows": json_rows, "more": more, "since": since }))
    }

    /// WS `receipt_sync{since}` → `receipt_batch` frame. Davranış AYNI (SQL-hatada frame
    /// göndermez). Client `receipt_batch`'i mdd'ye uygular, cursor'u max(seq)'e ilerletir;
    /// `more=true` ise tekrar sync.
    pub(crate) fn receipt_sync(&self, ws: &WebSocket, since: i64) {
        let Some(mut payload) = self.receipt_sync_payload(since) else {
            return; // SQL-hata: eskiden olduğu gibi hiçbir frame gönderme.
        };
        payload["type"] = serde_json::Value::String("receipt_batch".into());
        let _ = ws.send_with_str(payload.to_string().as_str());
    }
}
