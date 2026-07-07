use super::*;

impl UserInbox {
    /// WS frame handler — `DurableObject::websocket_message` buraya delege eder.
    /// Frame türleri: ack / typing / ping / forward_ack / send / read.
    pub(crate) async fn handle_ws_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let text = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(_) => return Ok(()),
        };
        // W1 (delivered_live yanlış-pozitif fix): HERHANGİ bir inbound frame =
        // client→server yolunun GERÇEKTEN canlı olduğunun kanıtı. Socket
        // attachment'ında `last_seen_ms`'i tazele → notify_inner bu damgayı
        // zombie-socket ayracı olarak kullanır (client 5sn'de bir ping atar →
        // canlı socket her zaman taze; MIUI-kill sonrası yarı-açık socket
        // bayatlar → o socket'e teslim "canlı" sayılmaz → FCM-wake tetiklenir).
        // Hata yut: attachment yoksa/parse-fail → atla (ör. S1-öncesi bağlantı).
        if let Ok(Some(mut att)) = ws.deserialize_attachment::<Attachment>() {
            att.last_seen_ms = Some((now_secs() * 1000) as i64);
            let _ = ws.serialize_attachment(att);
        }
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let kind = value.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match kind {
            "ack" => {
                let ids: Vec<i64> = value
                    .get("ids")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
                    .unwrap_or_default();
                if ids.is_empty() {
                    return Ok(());
                }
                // A1-tamamla: `ids`'e PARALEL msg_uid'ler (görünür 1:1 mesajda dolu).
                // delivered makbuzu artık (read gibi) uid taşır → gönderenin KARDEŞİ
                // `oc-{msg_uid}` satırını Sent→Delivered ilerletir. id→uid eşlemesi:
                // `/forward-delivered` payload'ı `ids` sırasında uid dizisi taşısın.
                let ack_uids: Vec<String> = value
                    .get("uids")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|x| x.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let id_to_uid: std::collections::HashMap<i64, String> = ids
                    .iter()
                    .copied()
                    .zip(ack_uids.iter().cloned())
                    .filter(|(_, u)| !u.is_empty())
                    .collect();
                // `success` opsiyonel — default true (geriye uyumluluk).
                // false ise: queue temizlenir ama sender'a `delivered` forward
                // edilmez. Receiver decrypt fail (MAC mismatch vb) durumunda
                // queue temizliği için gönderilir; yanlış 2-tik göstermek
                // istemediğimiz durum. Bkz. project_olm_2tik_fix.
                let success = value
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                // M2-S2.3 ack-izolasyonu: yalnız BU cihaza ait satırlar SELECT+DELETE.
                // FIX-2(b) (HIGH — NULL-tolerans GERİ): somut device varsa
                // `AND (device_id=? OR device_id IS NULL)`. GEREKÇE: NULL pending
                // artık MEŞRU = cihaz-listesi yayınlamamış-tek-cihaz kullanıcı
                // (grup-fallback FIX-1 LEFT JOIN). Böyle kullanıcı TEK mantıksal cihaz
                // → onun bağlanan cihazı kendi NULL satırını ack'leyebilmeli (aksi
                // halde teslim edilen mesaj kuyruktan silinmez → redeliver-loop).
                // Güvenli: NULL yalnız yayınlamamış-tek-cihazda oluşur (1:1 yolunda
                // device_id ZORUNLU [FIX-2(a)] → 1:1'den NULL gelmez), çok-cihaz
                // belirsizliği yok. Red-team #18'in kaldırma gerekçesi FIX-1 ile
                // geçersiz.
                // S3-TODO: çok-cihaz kullanıcısı NULL satıra sahip olabilirse
                // yeniden değerlendir (NULL artık "tek cihaz" garantisi vermez →
                // yanlış-cihaz silme riski geri gelir).
                let ack_device: Option<String> = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten()
                    .and_then(|a| a.device_id);
                let placeholders: String =
                    (0..ids.len()).map(|_| "?").collect::<Vec<_>>().join(",");
                // device filtresi: somut device varsa (device_id=? OR NULL), yoksa
                // (S1-öncesi token) filtre yok = bugünkü device-blind davranış.
                let (dev_clause, mut extra_arg): (&str, Option<JsValue>) = match &ack_device {
                    Some(d) => (
                        " AND (device_id = ? OR device_id IS NULL)",
                        Some(JsValue::from_str(d)),
                    ),
                    None => ("", None),
                };
                let select_sql = format!(
                    "SELECT id, sender_id, device_id FROM pending WHERE id IN ({}){}",
                    placeholders, dev_clause
                );
                let del_sql = format!(
                    "DELETE FROM pending WHERE id IN ({}){}",
                    placeholders, dev_clause
                );
                let base_vals: Vec<JsValue> =
                    ids.iter().map(|i| JsValue::from_f64(*i as f64)).collect();
                let mut select_vals = base_vals.clone();
                if let Some(a) = extra_arg.take() {
                    select_vals.push(a);
                }
                let mut del_vals = base_vals;
                if let Some(d) = &ack_device {
                    del_vals.push(JsValue::from_str(d));
                }
                let storage = self.state.storage();
                let sql = storage.sql();
                let cursor = sql.exec_raw(&select_sql, Some(select_vals))?;
                #[derive(Deserialize)]
                struct AckRow {
                    id: i64,
                    sender_id: String,
                    /// M2-S2.2: bu satırın alıcı-cihazı (delivered forward'a taşınır).
                    #[serde(default)]
                    device_id: Option<String>,
                }
                let rows: Vec<AckRow> = cursor.to_array()?;
                sql.exec_raw(&del_sql, Some(del_vals))?;
                let _ = ws.send_with_str(
                    serde_json::json!({"type": "ack_ok", "ids": ids})
                        .to_string()
                        .as_str(),
                );

                // recipient userId attachment'tan
                let recipient_id: Option<String> = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten()
                    .map(|a| a.user_id);
                if let Some(rid) = recipient_id {
                    use std::collections::HashMap;
                    // M2-S2.2: makbuzu (sender, recipient_device) çiftine grupla.
                    // delivery-failed self-heal cihaz-çiftini doğru hedeflesin
                    // (D1-BLOCKER). N=1'de tek device → tek grup; satır device'ı
                    // NULL ise (backfill penceresi) ack_device'a düş.
                    let mut by_key: HashMap<(String, Option<String>), Vec<i64>> = HashMap::new();
                    for r in rows {
                        let dev = r.device_id.or_else(|| ack_device.clone());
                        by_key.entry((r.sender_id, dev)).or_default().push(r.id);
                    }
                    let namespace = self.env.durable_object("USER_INBOX")?;
                    // `success=true` → /forward-delivered (sender 2-tik).
                    // `success=false` → /forward-delivery-failed (sender
                    //  failedDelivery status → UI 1.5-tik + auto-retry).
                    let forward_path = if success {
                        "https://do.sezgi/forward-delivered"
                    } else {
                        "https://do.sezgi/forward-delivery-failed"
                    };
                    for ((sender_id, recipient_device), acked) in by_key {
                        let stub = namespace.id_from_name(&sender_id)?.get_stub()?;
                        // A1-tamamla: `acked` sırasına PARALEL uid dizisi (yoksa boş string).
                        // `/forward-delivered` → apply_receipt("delivered", .., uids) →
                        // receipt_state.msg_uid → kardeş cursor-senk'te oc-satırını ilerletir.
                        let uids: Vec<String> = acked
                            .iter()
                            .map(|id| id_to_uid.get(id).cloned().unwrap_or_default())
                            .collect();
                        let payload = serde_json::json!({
                            "from": rid,
                            "recipient_device_id": recipient_device,
                            "ids": acked,
                            "uids": uids,
                        })
                        .to_string();
                        let mut init = RequestInit::new();
                        init.with_method(Method::Post);
                        init.with_body(Some(payload.into()));
                        let headers = Headers::new();
                        headers.set("content-type", "application/json")?;
                        init.with_headers(headers);
                        let do_req = Request::new_with_init(forward_path, &init)?;
                        let _ = stub.fetch_with_request(do_req).await;
                    }
                }
            }
            "typing" => {
                let to = value.get("to").and_then(|v| v.as_str()).unwrap_or("");
                if to.is_empty() {
                    return Ok(());
                }
                let sender_id: Option<String> = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten()
                    .map(|a| a.user_id);
                let sid = match sender_id {
                    Some(s) if s != to => s,
                    _ => return Ok(()),
                };
                let namespace = self.env.durable_object("USER_INBOX")?;
                let stub = namespace.id_from_name(to)?.get_stub()?;
                let payload = serde_json::json!({ "sender_id": sid }).to_string();
                let mut init = RequestInit::new();
                init.with_method(Method::Post);
                init.with_body(Some(payload.into()));
                let headers = Headers::new();
                headers.set("content-type", "application/json")?;
                init.with_headers(headers);
                let do_req = Request::new_with_init("https://do.sezgi/forward-typing", &init)?;
                let _ = stub.fetch_with_request(do_req).await;
            }
            "ping" => {
                // Application-level keepalive — client zombie detection için
                // pong döndürmek şart. Yoksa client TCP hala açık görür ama
                // server-side hibernation/migration sonrası recv akışı kopuk.
                let _ = ws.send_with_str(r#"{"type":"pong"}"#);
            }
            // Sprint 8: client receipt forward'ları aldığını onaylar →
            // kuyruktan sil. Frame: { type: "forward_ack", ids: [...] }
            "forward_ack" => {
                if let Some(ids_val) = value.get("ids") {
                    if let Ok(ids) = serde_json::from_value::<Vec<i64>>(ids_val.clone()) {
                        self.forward_ack(&ids);
                    }
                }
            }
            // Layer-4: client cursor'dan sonraki durable receipt_state'i ister →
            // `receipt_batch` (delivered/read state) döner. Client connect'te +
            // `receipt_update` bildiriminde + periyodik tetikler. (bkz receipt.rs)
            "receipt_sync" => {
                let since = value.get("since").and_then(|v| v.as_i64()).unwrap_or(0);
                self.receipt_sync(&ws, since);
            }
            // Kardeş-okundu durable cursor (2026-06-28): U'nun cihazı okuduğu msg_uid'leri SICAK
            // WS'ten bildirir → self_read_state set-once + diğer U-cihazlarına self_read_update/delta.
            "self_read" => {
                if let Some(uids_val) = value.get("uids") {
                    if let Ok(uids) = serde_json::from_value::<Vec<String>>(uids_val.clone()) {
                        self.apply_self_read(&uids, (now_secs() * 1000) as i64);
                    }
                }
            }
            // Client cursor'dan sonraki self_read_state'i ister → `self_read_batch`. Connect'te +
            // `self_read_update` bildiriminde + yeni-cihaz cursor=0 full-pull'da tetikler.
            "self_read_sync" => {
                let since = value.get("since").and_then(|v| v.as_i64()).unwrap_or(0);
                self.self_read_sync(&ws, since);
            }
            // WS-send (saha 2026-06-02 + M2-S2.3 WIRE-CUT batch): mesaji HTTP-POST
            // yerine SICAK WS'ten gonder → per-mesaj TLS/ECH handshake YOK (~85-150ms;
            // HTTP soguk ~470ms). Bu kol GONDERENIN DO'sunda calisir; aliciya cross-DO
            // POST /notify (handlers::send ile AYNI mantik → notify_inner store+id+push).
            //
            // M2-S2.3: frame `envelopes[]` batch (HTTP ≡ WS-send, bit-ayni). 1:1'de
            // cihaz-basina ayri zarf ({device_id, envelope_b64}); grupta tek-eleman
            // device_id'siz. envelopes[] dongusu → per-device /notify → TEK
            // `send_ack_batch{ref, acks:[{device_id,id}], ts}`. KISMI-FAIL: bir cihaz
            // /notify 500 → ack listesinden DUSER, batch yine send_ack_batch. send_err
            // YALNIZ hicbir cihaz basarisizsa. N=1'de tek-eleman → tek ack = bugunku
            // tek-zarf akisi. ref HER ZAMAN yanitlanir.
            "send" => {
                let reff = value.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let recipient_id =
                    value.get("recipient_id").and_then(|v| v.as_str()).unwrap_or("");
                let group_id = value.get("group_id").and_then(|v| v.as_str());
                // GÜVENLİK (checkpoint 3 — Codex "biggest miss"): WS-send YALNIZ 1:1 taşır.
                // Grup HTTP `/messages/send` fan-out'unda yapılır (orada `group_role` ÜYELİK
                // kontrolü var). group_id'li WS-send üyelik-kontrolsüz grup-enjeksiyon yolu
                // açıyordu → REDDET (grup HTTP'ye yönlendir). `ref` her zaman yanıtlanır.
                if group_id.is_some() {
                    let _ = ws.send_with_str(
                        serde_json::json!({"type":"send_err","ref":reff,"code":"group_via_http"})
                            .to_string()
                            .as_str(),
                    );
                    return Ok(());
                }
                // Gonderen kimligi + cihazi WS attachment'tan (ws_upgrade JWT).
                let attach = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten();
                let sender_id = attach.as_ref().map(|a| a.user_id.clone());
                let sender_device_id = attach.as_ref().and_then(|a| a.device_id.clone());
                // M2-S2.3: envelopes[] parse. EnvItem{device_id?, envelope_b64}.
                let env_items: Vec<(Option<String>, String)> = value
                    .get("envelopes")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|e| {
                                let dev = e
                                    .get("device_id")
                                    .and_then(|d| d.as_str())
                                    .map(|s| s.to_string());
                                let env = e
                                    .get("envelope_b64")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                (dev, env)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                // 1:1 yolu icin recipient gerekli; grup yolu group_id ile (recipient
                // bos). WS-send su an 1:1'i tasir (grup HTTP fan-out'ta — handlers).
                // Yine de group_id varsa recipient-len kontrolunu atla.
                let is_group = group_id.is_some();
                // Validasyon (handlers::send paritesi): auth + ref + batch boyut +
                // her zarf boyut + (1:1) uuid len + self-degil-veya-farkli-cihaz.
                let envelopes_ok = !env_items.is_empty()
                    && env_items.len() <= 100
                    && env_items
                        .iter()
                        .all(|(_, e)| e.len() >= 20 && e.len() <= 64 * 1024);
                // FIX-2(a) (HIGH — orphan NULL, handlers::send paritesi): 1:1 yolunda
                // (is_group=false) her EnvItem.device_id ZORUNLU SOMUT. Gönderen
                // bundle'dan alıcı cihazlarını bilir → her zarf somut cihaz hedefler;
                // device_id=None taşıyan 1:1 = buggy/eski client → orphan-NULL pending.
                // (Self-send dalı zaten device_id-Some + farklı-cihaz şartını kapsıyor.)
                let recipient_ok = is_group
                    || (recipient_id.len() == 36
                        && env_items.iter().all(|(d, _)| d.is_some())
                        && (Some(recipient_id) != sender_id.as_deref()
                            || env_items.iter().all(|(d, _)| {
                                d.as_deref() != sender_device_id.as_deref()
                            })));
                let valid = sender_id.is_some()
                    && sender_device_id.is_some()
                    && !reff.is_empty()
                    && envelopes_ok
                    && recipient_ok;
                if !valid {
                    let _ = ws.send_with_str(
                        serde_json::json!({"type":"send_err","ref":reff,"code":"bad_request"})
                            .to_string()
                            .as_str(),
                    );
                    return Ok(());
                }
                let sender_id = sender_id.unwrap();
                let sender_device_id = sender_device_id.unwrap();
                // R1 (güvenlik, device-lifecycle denetimi): WS-send revoke-asimetrisini kapat.
                // HTTP `/messages/send` (handlers.rs:125) device_revoked çağırıyor ama WS-send
                // çağırmıyordu → revoke edilmiş cihaz SICAK WS'ten 1:1 mesaj ENJEKTE edebiliyordu
                // (outbound-injection asimetrisi). Fail-closed pariteyle kapat (`ref` yanıtlanır).
                match crate::auth::middleware::device_revoked(&self.env, &sender_id, &sender_device_id).await {
                    Ok(true) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"device_revoked"})
                                .to_string()
                                .as_str(),
                        );
                        return Ok(());
                    }
                    Ok(false) => {}
                    Err(_) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"revoke_check_unavailable"})
                                .to_string()
                                .as_str(),
                        );
                        return Ok(());
                    }
                }
                // H2 (DoS — WS sıcak-yol rate-limit paritesi): HTTP `/messages/send`
                // (handlers.rs:94) per-user `msg:send:{sender_id}` 300/60s KV sliding-window
                // uyguluyor; SICAK WS-send bunu ATLIYORDU → WS'ten sınırsız mesaj enjekte
                // edilip alıcı DO (SQLite) şişirilebiliyordu. AYNI KV-kovası/parametre →
                // ortak limit (HTTP+WS toplamı 300/60s). revoke-check'ten SONRA, alıcı DO'ya
                // /notify'dan ÖNCE. KV binding self.env'den (HTTP yoluyla aynı).
                // ŞABLON-DİYETİ: self-host şablonunda RATE_LIMIT KV binding'i YOK
                // (deploy-ekranı sadeliği + isim-çakışması) → binding-yok/KV-hata
                // fail-open, limitsiz devam (kurulu-KV'li prod bit-aynı).
                if !crate::ratelimit::check_rate_limit_env(
                    &self.env, &format!("msg:send:{sender_id}"), 300, 60,
                )
                .await
                {
                    let _ = ws.send_with_str(
                        serde_json::json!({"type":"send_err","ref":reff,"code":"rate_limited"})
                            .to_string()
                            .as_str(),
                    );
                    return Ok(());
                }
                // Alicinin DO'suna per-device /notify (handlers::send paritesi).
                let namespace = self.env.durable_object("USER_INBOX")?;
                let stub = namespace.id_from_name(recipient_id)?.get_stub()?;
                #[derive(Deserialize)]
                struct Idr {
                    id: i64,
                    #[serde(default)]
                    delivered_live: bool,
                }
                // FCM-wake için D1 handle (1:1 WS-send yolu — alıcı offline'da içeriksiz uyandırma).
                let push_db = self.env.d1("DB").ok();
                let mut acks: Vec<serde_json::Value> = Vec::with_capacity(env_items.len());
                for (dev, env_b64) in &env_items {
                    let payload = serde_json::json!({
                        "sender_id": sender_id,
                        "sender_device_id": sender_device_id,
                        "recipient_device_id": dev,
                        // W1-backstop: ALICI user_id → notify_inner persist → alarm
                        // stuck-pending FCM-wake (DO offline'da user'ını bilemez).
                        "recipient_id": recipient_id,
                        "envelope_b64": env_b64,
                        "group_id": group_id,
                    })
                    .to_string();
                    let mut init = RequestInit::new();
                    init.with_method(Method::Post);
                    init.with_body(Some(payload.into()));
                    let headers = Headers::new();
                    headers.set("content-type", "application/json")?;
                    init.with_headers(headers);
                    let do_req = Request::new_with_init("https://do.sezgi/notify", &init)?;
                    // (id, delivered_live). Hata/şüphe → live=true (boşuna wake yollama).
                    let (resp_id, live) = match stub.fetch_with_request(do_req).await {
                        Ok(mut resp) if resp.status_code() == 200 => match resp.json::<Idr>().await {
                            Ok(r) => (Some(r.id), r.delivered_live),
                            Err(_) => (None, true),
                        },
                        _ => (None, true),
                    };
                    // KISMI-FAIL: basarili cihaz acks'e; basarisiz cihaz DUSER.
                    if let Some(id) = resp_id {
                        acks.push(serde_json::json!({ "device_id": dev, "id": id }));
                        // Alıcı o cihazda OFFLINE (canlı WS yok) → içeriksiz FCM-wake.
                        if !live {
                            if let Some(db) = &push_db {
                                crate::push::fcm::maybe_push_wake(
                                    &self.env, db, recipient_id, dev.as_deref(),
                                )
                                .await;
                            }
                        }
                    }
                }
                if acks.is_empty() {
                    // Hicbir cihaz basaramadi → send_err (eski do_notify_failed paritesi).
                    let _ = ws.send_with_str(
                        serde_json::json!({
                            "type": "send_err", "ref": reff, "code": "do_notify_failed"
                        })
                        .to_string()
                        .as_str(),
                    );
                } else {
                    let _ = ws.send_with_str(
                        serde_json::json!({
                            "type": "send_ack_batch", "ref": reff, "acks": acks, "ts": now_secs()
                        })
                        .to_string()
                        .as_str(),
                    );
                }
            }
            // WS-read (saha 2026-06-02): okundu (3-tik) receipt'ini SICAK WS'ten al →
            // per-receipt TLS/ECH handshake YOK (HTTP /messages/read soguk ~470ms; WS-send
            // mesajlari WS'e alinca HTTP bagi soguyor). Bu kol OKUYANIN DO'sunda calisir;
            // gonderenin (peer_id) DO'suna cross-DO /forward-read (handlers::read 104-118
            // paritesi → forward_signal("read") + persistent forward_queue). Fire-and-forget:
            // ack YOK (okundu idempotent/kozmetik; client beklemez, kayipta viewport tetikler).
            "read" => {
                let peer_id = value.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
                let ids: Vec<i64> = value
                    .get("ids")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
                    .unwrap_or_default();
                // #11 Layer-4b: `ids`'e PARALEL msg_uid'ler (okuyan sağlar) — gönderen DO'ya
                // taşı → kardeş cihaz oc-satırını eşlesin. Eksikse boş (geriye-uyum).
                let uids: Vec<String> = value
                    .get("uids")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|x| x.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let reader_id = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten()
                    .map(|a| a.user_id);
                // Validasyon (handlers::read paritesi): auth + ids (1..=500) + uuid + self-degil.
                let valid = reader_id.is_some()
                    && !ids.is_empty()
                    && ids.len() <= 500
                    && peer_id.len() == 36
                    && Some(peer_id) != reader_id.as_deref();
                if !valid {
                    return Ok(()); // fire-and-forget: gecersiz → sessizce yut (ack yok)
                }
                let reader_id = reader_id.unwrap();
                // H2 (DoS — WS sıcak-yol rate-limit paritesi): WS-read de revoke/limit-siz
                // peer DO'ya forward enjekte edebiliyordu. send ile AYNI KV-kovası
                // (`msg:send:{reader_id}`) 300/60s → ortak limit (HTTP+WS+send+read toplamı).
                // Fire-and-forget: aşılırsa/KV-hata → sessizce yut (read kozmetik/idempotent;
                // client viewport tetikler, ack beklemez). peer DO'ya forward'dan ÖNCE.
                // ŞABLON-DİYETİ: KV binding OPSİYONEL — yoksa limitsiz devam (fail-open;
                // eski davranış binding-yokta fail-closed'du ama binding artık şablonda yok).
                if !crate::ratelimit::check_rate_limit_env(
                    &self.env, &format!("msg:send:{reader_id}"), 300, 60,
                )
                .await
                {
                    return Ok(()); // limit aşıldı → sessizce yut
                }
                let namespace = self.env.durable_object("USER_INBOX")?;
                let stub = namespace.id_from_name(peer_id)?.get_stub()?;
                let payload =
                    serde_json::json!({ "from": reader_id, "ids": ids, "uids": uids }).to_string();
                let mut init = RequestInit::new();
                init.with_method(Method::Post);
                init.with_body(Some(payload.into()));
                let headers = Headers::new();
                headers.set("content-type", "application/json")?;
                init.with_headers(headers);
                let do_req = Request::new_with_init("https://do.sezgi/forward-read", &init)?;
                let _ = stub.fetch_with_request(do_req).await; // fire-and-forget
            }
            _ => {}
        }
        Ok(())
    }
}
