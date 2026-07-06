//! Kardeş-okundu durable cursor (2026-06-28, Codex-onaylı) — `receipt.rs` AYNASI, AMA U'nun
//! KENDİ cihazları arası `viewed_at` (okundu) yakınsaması için. PK = `msg_uid` (global UUID;
//! peer-agnostik). seq AYRI uzay (`self_read_meta`) → bir self-read gap'i receipt cursor'unu
//! KİLİTLEMEZ (Codex Q1). Eski kırılgan ReadSelfSync (anlık Olm self-mesaj; wedge'de ölür,
//! yalnız yeni-okuma) latency fast-path olarak KALIR; bu durable yol AUTHORITATIVE backstop:
//! wedge-bağışık (Olm değil, WS/HTTP pull), yeni-cihaz cursor=0'dan full-pull, set-once monoton.
//! Retention (GÜNCELLEME 2026-07-03, server-lean audit — Codex-Q8 TERSİNE ÇEVRİLDİ): bu tablo ARTIK
//! retention-parite PURGE EDİLİR (`mod.rs` alarm-cleanup, receipt_state deseni). Q8-korkusu (full-pull
//! kaybı) asılsız: yeni-cihaz okundu-state'i M4 kardeş-senk ile mesaja BAĞLI gelir (`viewed_at` MessageRow'da).

use super::*;

/// W3 (self-read DoS-hardening, 2026-07-02): per-uid boyut tavanı — meşru msg_uid = UUID (~36 char);
/// bunu aşan = anomali/bloat → atla. Per-REQUEST uid-SAYISI ayrıca sınırlanmaz: handler'daki body-cap
/// (32KB) zaten isteği bounded'lar (~800 uid tavanı) ve `/self-read` DO-route'u YALNIZ o handler'dan
/// erişilir (public değil) → tek giriş = tek sınır. (Eski uid-count truncation KALDIRILDI: Codex-flag
/// — `&uids[..500]` fazlayı SESSİZCE düşürüp 204 dönüyordu; client self-read'i drop-on-error → sessiz
/// okuma-kaybı. Body-cap zaten meşru-üstü isteği 400'le AÇIKÇA reddediyor.)
const MAX_SELF_READ_UID_LEN: usize = 64;

#[derive(Deserialize)]
struct SelfReadExisting {
    read_at: Option<i64>,
}

#[derive(Deserialize)]
struct SelfReadSeqRow {
    v: i64,
}

#[derive(Deserialize)]
struct SelfReadStateRow {
    msg_uid: String,
    read_at: i64,
    seq: i64,
}

impl UserInbox {
    /// U'nun bir cihazı "şu `msg_uid`'leri okudum" dedi → durable `self_read_state`'e SET-ONCE
    /// yaz (zaten read_at varsa idempotent skip), her DEĞİŞEN row ATOMİK benzersiz seq alır
    /// (`UPDATE self_read_meta RETURNING` — receipt.rs deseni), sonra diğer WS'lere
    /// `self_read_update` (cursor-poke) + `self_read_delta` (latency fast-path) push. `ts_ms` =
    /// server-alış (read_at değeri yalnız bookkeeping; client uygularken kendi viewed_at'ini set eder).
    pub(crate) fn apply_self_read(&self, uids: &[String], ts_ms: i64) {
        if uids.is_empty() {
            return;
        }
        let storage = self.state.storage();
        let sql = storage.sql();
        let mut max_seq: i64 = 0;
        let mut changed = false;
        let mut delta_rows: Vec<serde_json::Value> = Vec::new();
        for uid in uids {
            // W3: boş VEYA aşırı-uzun uid'i atla (meşru msg_uid = UUID ~36 char; >MAX = anomali/bloat).
            if uid.is_empty() || uid.len() > MAX_SELF_READ_UID_LEN {
                continue;
            }
            // Set-once: zaten okundu işaretliyse (read_at NOT NULL) → idempotent skip (seq bump yok).
            let existing = match sql.exec_raw(
                "SELECT read_at FROM self_read_state WHERE msg_uid = ?",
                Some(vec![JsValue::from_str(uid)]),
            ) {
                Ok(c) => c
                    .to_array::<SelfReadExisting>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .and_then(|r| r.read_at),
                Err(_) => None,
            };
            if existing.is_some() {
                continue;
            }
            // Atomik seq rezervasyonu (bump + oku tek statement; seq-reuse / silent-skip yok).
            let seq = match sql.exec_raw(
                "UPDATE self_read_meta SET v = v + 1 WHERE k = 'seq' RETURNING v",
                sql_no_args(),
            ) {
                Ok(c) => c
                    .to_array::<SelfReadSeqRow>()
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| r.v),
                Err(_) => None,
            };
            let Some(seq) = seq else {
                continue; // meta-bump fail (nadir) → bu uid'i atla; seq-reuse YOK.
            };
            changed = true;
            if seq > max_seq {
                max_seq = seq;
            }
            let _ = sql.exec_raw(
                "INSERT INTO self_read_state (msg_uid, read_at, seq, updated_at)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT(msg_uid) DO UPDATE SET seq = excluded.seq, updated_at = excluded.updated_at",
                Some(vec![
                    JsValue::from_str(uid),
                    JsValue::from_f64(ts_ms as f64),
                    JsValue::from_f64(seq as f64),
                    JsValue::from_f64(ts_ms as f64),
                ]),
            );
            delta_rows.push(serde_json::json!({ "msg_uid": uid, "read_at": ts_ms, "seq": seq }));
        }
        if !changed {
            return;
        }
        // Tüm U-cihazlarına bildir → her biri kendi cursor'undan pull eder (authoritative).
        let payload =
            serde_json::json!({ "type": "self_read_update", "max_seq": max_seq }).to_string();
        for ws in self.state.get_websockets() {
            let _ = ws.send_with_str(payload.as_str());
        }
        // LATENCY fast-path: değişen row'ları AYNI WS'lere doğrudan push (cursor pull-round-trip
        // beklemeden uygula). Şekil = self_read_sync_payload satırı → client handle_self_read_batch REUSE.
        if !delta_rows.is_empty() {
            let delta = serde_json::json!({
                "type": "self_read_delta",
                "rows": delta_rows,
                "max_seq": max_seq,
            })
            .to_string();
            for ws in self.state.get_websockets() {
                let _ = ws.send_with_str(delta.as_str());
            }
        }
    }

    /// Cursor-sonrası `self_read_state` satırları (`seq > since ORDER BY seq ASC LIMIT 500`) →
    /// transport-agnostik `{rows, more, since}` (receipt_sync_payload deseni; type tag yok).
    /// WS frame ve HTTP `GET /self-read-sync` AYNI builder → bit-aynı rows. SQL-hata → None.
    pub(crate) fn self_read_sync_payload(&self, since: i64) -> Option<serde_json::Value> {
        let storage = self.state.storage();
        let rows: Vec<SelfReadStateRow> = match storage.sql().exec_raw(
            "SELECT msg_uid, read_at, seq FROM self_read_state
             WHERE seq > ? ORDER BY seq ASC LIMIT 500",
            Some(vec![JsValue::from_f64(since as f64)]),
        ) {
            Ok(c) => c.to_array().unwrap_or_default(),
            Err(_) => return None,
        };
        let more = rows.len() == 500;
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| serde_json::json!({ "msg_uid": r.msg_uid, "read_at": r.read_at, "seq": r.seq }))
            .collect();
        Some(serde_json::json!({ "rows": json_rows, "more": more, "since": since }))
    }

    /// WS `self_read_sync{since}` → `self_read_batch` frame (receipt_sync deseni; SQL-hatada sessiz).
    pub(crate) fn self_read_sync(&self, ws: &WebSocket, since: i64) {
        let Some(mut payload) = self.self_read_sync_payload(since) else {
            return;
        };
        payload["type"] = serde_json::Value::String("self_read_batch".into());
        let _ = ws.send_with_str(payload.to_string().as_str());
    }
}
