use super::*;

/// M1 (Olm-WIPE tekrar-tetikleme daraltma): TAZE-reconnect force-replay yalnız
/// son 48 saatlik forward'ları verir. Daha eski orphan satırlar (client hiç
/// `forward_ack` atmamış `delivery_failed` vb.) her reconnect'te koşulsuz replay
/// edilip alıcıda `delete_all_olm_blobs` (Olm WIPE) tekrar-tetikliyordu. 48h =
/// makul teslim penceresi (cleanup retention zaten daha eskileri siler; bu sabit
/// retention beklemeden replay-yüzeyini daraltır). MS cinsinden (created_at ms).
const FORCE_REPLAY_WINDOW_MS: i64 = 48 * 3600 * 1000;

impl UserInbox {
    pub(crate) fn forward_signal(
        &self,
        kind: &str,
        from: &str,
        recipient_device_id: Option<&str>,
        ids: &[i64],
    ) {
        if ids.is_empty() {
            return;
        }
        // Sprint 8.5a: persistent forward_queue + WS push, çift teslimat
        // korumalı.
        // - Sender çift gönderirse (R1 bypass + OpHub race) → 10s dedup
        //   penceresi aynı (kind, from, recipient_device, ids) için INSERT atla.
        // - flush_forwards (replay) push'tan sonra 10sn skip → forward_signal
        //   push + alarm flush_forwards yarışı yok.
        // M2-S2.2 (D3-verdict-2): recipient_device_id artık kalıcı kolon + dedup
        // anahtarının parçası → WS-kapalı biriken makbuz replay'de device taşır
        // (aksi halde N:1 MISS). recipient_device None ise (N=1/S2.3-öncesi)
        // anahtar bugünkü davranışla aynı (NULL).
        let ids_json = match serde_json::to_string(ids) {
            Ok(s) => s,
            Err(_) => return,
        };
        let now = (now_secs() * 1000) as i64;
        let storage = self.state.storage();
        let device_val = match recipient_device_id {
            Some(d) => JsValue::from_str(d),
            None => JsValue::NULL,
        };

        // Dedup: aynı receipt son 10sn'de zaten kuyrukta + henüz silinmemiş
        // mi? (forward_ack DELETE yapıyor → satır kayıpsa client zaten ack
        // atmış demektir, yeni INSERT meşru.) M2-S2.2: recipient_device_id de
        // anahtarda — NULL karşılaştırması için `IS` (=? NULL'da eşleşmez).
        let dedup_window = now - 10_000;
        let recent: Option<i64> = match storage.sql().exec_raw(
            "SELECT id FROM forward_queue
             WHERE kind = ? AND from_user = ?
               AND recipient_device_id IS ? AND ids_json = ?
               AND created_at > ?
             LIMIT 1",
            Some(vec![
                JsValue::from_str(kind),
                JsValue::from_str(from),
                device_val.clone(),
                JsValue::from_str(&ids_json),
                JsValue::from_f64(dedup_window as f64),
            ]),
        ) {
            Ok(c) => match c.to_array::<ForwardIdRow>() {
                Ok(rows) => rows.first().map(|r| r.id),
                Err(_) => None,
            },
            Err(_) => None,
        };
        if recent.is_some() {
            // Sender çift gönderdi → skip; ilk INSERT push'u zaten attı.
            return;
        }

        // INSERT — pushed_at başlangıçta NULL. WS push başarılı olursa aşağıda
        // UPDATE. WS yoksa NULL kalır → alarm() flush_forwards_to_all replay'i
        // hemen push'lar.
        let id_opt: Option<i64> = match storage.sql().exec_raw(
            "INSERT INTO forward_queue (kind, from_user, ids_json, recipient_device_id, created_at, pushed_at)
             VALUES (?, ?, ?, ?, ?, NULL) RETURNING id",
            Some(vec![
                JsValue::from_str(kind),
                JsValue::from_str(from),
                JsValue::from_str(&ids_json),
                device_val,
                JsValue::from_f64(now as f64),
            ]),
        ) {
            Ok(c) => match c.to_array::<ForwardIdRow>() {
                Ok(rows) => rows.first().map(|r| r.id),
                Err(_) => None,
            },
            Err(_) => None,
        };
        let forward_id = match id_opt {
            Some(i) => i,
            None => return, // INSERT fail → push'u atla, fresh replay sonra
        };
        let payload = serde_json::json!({
            "type": kind,
            "from": from,
            "recipient_device_id": recipient_device_id,
            "ids": ids,
            "forward_id": forward_id,
        })
        .to_string();
        let mut any_pushed = false;
        for ws in self.state.get_websockets() {
            // W9 (makbuz "okundu geç" — W1 ile aynı zombie-socket kökü): send_with_str
            // Ok ama yarı-açık socket'te client makbuzu ALMAZ; yine de pushed_at set
            // edilirse flush_forwards 10sn bu satırı atlar → makbuz sonraki 90sn alarma
            // takılır. Yazma HER socket'e yapılır (hibernating-ama-canlı ihtimali) ama
            // "pushed" YALNIZ gerçekten-canlı (last_seen taze) socket için işaretlenir →
            // zombie'de pushed_at NULL kalır → sonraki flush / force-reconnect replay eder.
            if ws.send_with_str(payload.as_str()).is_ok() && super::message::ws_is_fresh(&ws, now) {
                any_pushed = true;
            }
        }
        if any_pushed {
            // Push attı → 10sn boyunca flush_forwards replay'i bu satırı atlar.
            let _ = storage.sql().exec_raw(
                "UPDATE forward_queue SET pushed_at = ? WHERE id = ?",
                Some(vec![
                    JsValue::from_f64(now as f64),
                    JsValue::from_f64(forward_id as f64),
                ]),
            );
        }
    }

    /// Sprint 8.5a: WS reconnect / alarm anında kuyrukta birikmiş forward'ları
    /// replay et. `force=false` (alarm): forward_signal'in az önce push attığı
    /// satırlar (pushed_at son 10sn) SKIP — yoksa "INSERT+push" ile "alarm flush"
    /// yarışı CANLI socket'e çift teslim yapardı.
    ///
    /// `force=true` (TAZE reconnect, `ws_upgrade`): `pushed_at`'i YOK SAY → kuyruktaki
    /// TÜM forward'ları ver. Gerekçe (saha 2026-06-02 "okundu aşırı gecikti"):
    /// forward_signal ÖLÜ/zombie socket'e `send_with_str` Ok dönünce pushed_at
    /// SET ediyordu; client o eski socket'ten ALMADAN reconnect edince 10sn-skip
    /// makbuzu YENİ socket'ten de saklıyor → sonraki alarm'a (90sn!) veya sonraki
    /// receipt'e kadar takılıyordu ("delivered+read birlikte" gözlemi). Yeni socket
    /// tanım gereği eski push'ları almadı → hepsini ver. `forward_id` client'ta
    /// dedup'lanır (tekrar gelse idempotent) → güvenli.
    pub(crate) fn flush_forwards_to(&self, ws: &WebSocket, force: bool) {
        let storage = self.state.storage();
        let now = (now_secs() * 1000) as i64;
        let stale_cutoff = now - 10_000;
        let cursor = if force {
            // M1: force-replay'i son 48 saatle DARALT (eski orphan satırlar
            // koşulsuz replay → alıcıda Olm-WIPE tekrar-tetikleme). pushed_at
            // YOK SAYILIR (force semantiği korunur) ama created_at penceresi var.
            let replay_cutoff = now - FORCE_REPLAY_WINDOW_MS;
            storage.sql().exec_raw(
                "SELECT id, kind, from_user, ids_json, recipient_device_id
                 FROM forward_queue
                 WHERE created_at > ?
                 ORDER BY id ASC LIMIT 500",
                Some(vec![JsValue::from_f64(replay_cutoff as f64)]),
            )
        } else {
            // M1/FIX-4 (CONCERN M1 — steady-replay Olm-WIPE penceresi): 48h force-yoluna
            // eklenen created_at penceresi steady ~90sn alarm yolunda YOKTU → forward_ack'-
            // lenmemiş eski orphan `delivery_failed` satırı her 90sn yeniden push → alıcıda
            // KOŞULSUZ Olm-WIPE → 30 güne dek ~90sn'de bir re-WIPE. AYNI created_at penceresini
            // (FORCE_REPLAY_WINDOW_MS) bu yola da uygula → eski orphan'lar re-push edilmez
            // (M1 forward_queue retention DELETE'i ile birlikte temizlenir). pushed_at-skip
            // (taze-INSERT/alarm yarışı koruması) KORUNUR. NOT: bu yalnız worker-yüzey
            // daraltması; gerçek kök (alıcı WIPE'ını idempotent yapmak) CORE tarafı = scope-dışı.
            let replay_cutoff = now - FORCE_REPLAY_WINDOW_MS;
            storage.sql().exec_raw(
                "SELECT id, kind, from_user, ids_json, recipient_device_id
                 FROM forward_queue
                 WHERE (pushed_at IS NULL OR pushed_at < ?)
                   AND created_at > ?
                 ORDER BY id ASC LIMIT 500",
                Some(vec![
                    JsValue::from_f64(stale_cutoff as f64),
                    JsValue::from_f64(replay_cutoff as f64),
                ]),
            )
        };
        let cursor = match cursor {
            Ok(c) => c,
            Err(_) => return,
        };
        let rows: Vec<ForwardQueueRow> = match cursor.to_array() {
            Ok(r) => r,
            Err(_) => return,
        };
        if rows.is_empty() {
            return;
        }
        let mut pushed_ids: Vec<i64> = Vec::with_capacity(rows.len());
        for row in &rows {
            let ids: Vec<i64> = serde_json::from_str(&row.ids_json).unwrap_or_default();
            let payload = serde_json::json!({
                "type": row.kind,
                "from": row.from_user,
                "recipient_device_id": row.recipient_device_id,
                "ids": ids,
                "forward_id": row.id,
            })
            .to_string();
            // W9-b (Codex MED): replay yolu da forward_signal ile aynı zombie-socket
            // ayracına tabi. Yalnız gerçekten-canlı socket'e teslim "pushed" sayılır →
            // zombie'de pushed_at NULL kalır → sonraki flush/force replay eder. force=true
            // (taze reconnect) socket'i accept-anında damgalı → daima taze → regresyon yok.
            if ws.send_with_str(payload.as_str()).is_ok() && super::message::ws_is_fresh(ws, now) {
                pushed_ids.push(row.id);
            }
        }
        if !pushed_ids.is_empty() {
            let placeholders = (0..pushed_ids.len()).map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!(
                "UPDATE forward_queue SET pushed_at = ? WHERE id IN ({})",
                placeholders
            );
            let mut args: Vec<JsValue> = Vec::with_capacity(pushed_ids.len() + 1);
            args.push(JsValue::from_f64(now as f64));
            for id in &pushed_ids {
                args.push(JsValue::from_f64(*id as f64));
            }
            let _ = storage.sql().exec_raw(&sql, Some(args));
        }
    }

    /// Sprint 8: sender `forward_ack` frame'i gönderince çağrılır;
    /// kuyruktan ilgili forward_id'leri siler.
    pub(crate) fn forward_ack(&self, ids: &[i64]) {
        if ids.is_empty() {
            return;
        }
        let storage = self.state.storage();
        // SQLite IN clause manuel bind yerine BATCH delete (max 500 OK).
        let placeholders = (0..ids.len()).map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "DELETE FROM forward_queue WHERE id IN ({})",
            placeholders
        );
        let args: Vec<JsValue> = ids.iter().map(|i| JsValue::from_f64(*i as f64)).collect();
        let _ = storage.sql().exec_raw(&sql, Some(args));
    }

    pub(crate) fn flush_forwards_to_all(&self) {
        let websockets = self.state.get_websockets();
        if websockets.is_empty() {
            return;
        }
        // Hepsi aynı kullanıcının WS'leri (multi-device) — kuyrukta birikmiş
        // forward'ları her birine push. Client tarafında forward_id dedup.
        // force=false: canlı socket'lere periyodik flush → 10sn-skip ile
        // forward_signal-push vs alarm-flush yarışında çift teslimi önler.
        for ws in websockets {
            self.flush_forwards_to(&ws, false);
        }
    }
}
