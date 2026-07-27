use super::*;

impl UserInbox {
    /// WS frame handler — `DurableObject::websocket_message` delegates here.
    /// Frame kinds: ack / typing / ping / forward_ack / receipt_sync / self_read /
    /// self_read_sync / send / read. Anything else is ignored.
    pub(crate) async fn handle_ws_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let text = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(_) => return Ok(()),
        };
        // W1 (delivered_live false-positive fix): ANY inbound frame proves the
        // client→server direction is GENUINELY alive. Refresh `last_seen_ms` in the socket
        // attachment; notify_inner uses that stamp as its zombie-socket test (the client
        // pings every 5s, so a live socket is always fresh, while a half-open socket left
        // behind by a MIUI background kill goes stale → delivery to it does not count as
        // "live" → an FCM wake is triggered instead). Errors are swallowed: no attachment
        // or a parse failure (e.g. a pre-S1 connection) simply skips the refresh.
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
                // A1 completion: msg_uids PARALLEL to `ids` (populated for a visible 1:1
                // message). The delivered receipt now carries uids just like read does, so the
                // sender's SIBLING can advance its `oc-{msg_uid}` row from Sent to Delivered.
                // The id→uid mapping travels as a uid array in `ids` order on the
                // `/forward-delivered` payload.
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
                // `success` is optional and defaults to true (backwards compatibility).
                // When false the queue is still drained but no `delivered` is forwarded to
                // the sender (a `delivery_failed` goes out instead, see below). The client
                // sends it to clear the queue after a decrypt failure (MAC mismatch and
                // friends), which is exactly when we must not paint a second tick.
                // See project_olm_2tik_fix.
                let success = value
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                // M2-S2.3 ack isolation: SELECT+DELETE only rows belonging to THIS device.
                // FIX-2(b) (HIGH — NULL tolerance RESTORED): with a concrete device, filter
                // on `AND (device_id = ? OR device_id IS NULL)`. RATIONALE: a NULL pending row
                // is now LEGITIMATE — it means a user who never published a device list
                // (group fallback FIX-1, the LEFT JOIN). Such a user is a SINGLE logical
                // device, so the device that connects must be able to ack its own NULL rows;
                // otherwise a delivered message is never removed from the queue and we get a
                // redelivery loop. This is safe because NULL only arises for an
                // unpublished-single-device user (the 1:1 path REQUIRES device_id [FIX-2(a)],
                // so NULL never comes from 1:1) → no multi-device ambiguity. Red-team #18's
                // argument for dropping the tolerance is void since FIX-1.
                // S3-TODO: revisit if a multi-device user can ever own a NULL row (NULL would
                // no longer imply "one device" → the risk of deleting another device's row
                // comes back).
                let ack_device: Option<String> = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten()
                    .and_then(|a| a.device_id);
                let placeholders: String =
                    (0..ids.len()).map(|_| "?").collect::<Vec<_>>().join(",");
                // Device filter: with a concrete device, (device_id = ? OR NULL); without one
                // (pre-S1 token) no filter at all, i.e. the existing device-blind behaviour.
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
                    /// M2-S2.2: this row's recipient device (carried into the delivered forward).
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

                // Recipient userId comes from the socket attachment.
                let recipient_id: Option<String> = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten()
                    .map(|a| a.user_id);
                if let Some(rid) = recipient_id {
                    use std::collections::HashMap;
                    // M2-S2.2: group the receipts by (sender, recipient_device) so a
                    // delivery-failed self-heal targets the right device pair (D1 BLOCKER).
                    // With N=1 there is a single device → a single group; when the row's
                    // device is NULL (the backfill window) fall back to ack_device.
                    let mut by_key: HashMap<(String, Option<String>), Vec<i64>> = HashMap::new();
                    for r in rows {
                        let dev = r.device_id.or_else(|| ack_device.clone());
                        by_key.entry((r.sender_id, dev)).or_default().push(r.id);
                    }
                    let namespace = self.env.durable_object("USER_INBOX")?;
                    // `success=true` → /forward-delivered (second tick for the sender).
                    // `success=false` → /forward-delivery-failed (sender moves to
                    //  failedDelivery → the UI shows a 1.5 tick and auto-retries).
                    let forward_path = if success {
                        "https://do.sezgi/forward-delivered"
                    } else {
                        "https://do.sezgi/forward-delivery-failed"
                    };
                    for ((sender_id, recipient_device), acked) in by_key {
                        let stub = namespace.id_from_name(&sender_id)?.get_stub()?;
                        // A1 completion: a uid array PARALLEL to `acked` (empty string when
                        // unknown). `/forward-delivered` → apply_receipt("delivered", .., uids)
                        // → receipt_state.msg_uid → the sibling advances its oc- row on the
                        // next cursor sync.
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
                // Application-level keepalive: returning a pong is mandatory for the
                // client's zombie detection. Without it the client still sees an open TCP
                // connection while, after a server-side hibernation/migration, the receive
                // path is actually broken.
                let _ = ws.send_with_str(r#"{"type":"pong"}"#);
            }
            // Sprint 8: the client confirms it received the forwarded receipts → drop them
            // from the queue. Frame: { type: "forward_ack", ids: [...] }
            "forward_ack" => {
                if let Some(ids_val) = value.get("ids") {
                    if let Ok(ids) = serde_json::from_value::<Vec<i64>>(ids_val.clone()) {
                        self.forward_ack(&ids);
                    }
                }
            }
            // Layer-4: the client asks for durable receipt_state past its cursor and gets a
            // `receipt_batch` (delivered/read state) back. Clients trigger this on connect,
            // on a `receipt_update` notification and periodically. (See receipt.rs.)
            "receipt_sync" => {
                let since = value.get("since").and_then(|v| v.as_i64()).unwrap_or(0);
                self.receipt_sync(&ws, since);
            }
            // Sibling-read durable cursor (2026-06-28): a device of U reports the msg_uids it
            // read over the HOT socket → self_read_state set-once + self_read_update/delta to
            // U's other devices.
            "self_read" => {
                if let Some(uids_val) = value.get("uids") {
                    if let Ok(uids) = serde_json::from_value::<Vec<String>>(uids_val.clone()) {
                        self.apply_self_read(&uids, (now_secs() * 1000) as i64);
                    }
                }
            }
            // The client asks for self_read_state past its cursor → `self_read_batch`.
            // Triggered on connect, on a `self_read_update` notification, and by a new
            // device's cursor=0 full pull.
            "self_read_sync" => {
                let since = value.get("since").and_then(|v| v.as_i64()).unwrap_or(0);
                self.self_read_sync(&ws, since);
            }
            // WS-send (field report 2026-06-02 + the M2-S2.3 WIRE-CUT batch): send the message
            // over the HOT socket instead of an HTTP POST → no per-message TLS/ECH handshake
            // (~85-150ms, versus ~470ms for a cold HTTP request). This arm runs in the SENDER's
            // DO and does a cross-DO POST /notify to the recipient (SAME logic as
            // handlers::send → notify_inner stores, assigns an id and pushes).
            //
            // M2-S2.3: the frame carries an `envelopes[]` batch (HTTP and WS-send are
            // bit-identical). For 1:1 there is one envelope per device
            // ({device_id, envelope_b64}); for a group a single element without a device_id.
            // The envelopes[] loop does a per-device /notify and answers with ONE
            // `send_ack_batch{ref, acks:[{device_id,id}], ts}`. PARTIAL FAILURE: a device whose
            // /notify 500s DROPS OUT of the ack list, and the batch is still a send_ack_batch;
            // send_err is sent ONLY when no device succeeded. With N=1 the single element
            // yields a single ack, i.e. today's single-envelope flow. `ref` is ALWAYS answered.
            "send" => {
                let reff = value.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let recipient_id =
                    value.get("recipient_id").and_then(|v| v.as_str()).unwrap_or("");
                let group_id = value.get("group_id").and_then(|v| v.as_str());
                // SECURITY (checkpoint 3 — Codex's "biggest miss"): WS-send carries 1:1 ONLY.
                // Groups go through the HTTP `/messages/send` fan-out, which checks MEMBERSHIP
                // via `group_role`. A WS-send with a group_id opened a group-injection path
                // with no membership check → REJECT it and push groups to HTTP. `ref` is
                // always answered.
                if group_id.is_some() {
                    let _ = ws.send_with_str(
                        serde_json::json!({"type":"send_err","ref":reff,"code":"group_via_http"})
                            .to_string()
                            .as_str(),
                    );
                    return Ok(());
                }
                // Sender identity + device come from the WS attachment (the ws_upgrade JWT).
                let attach = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten();
                let sender_id = attach.as_ref().map(|a| a.user_id.clone());
                let sender_device_id = attach.as_ref().and_then(|a| a.device_id.clone());
                // M2-S2.3: parse envelopes[] as EnvItem{device_id?, envelope_b64}.
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
                // The 1:1 path needs a recipient; the group path is keyed by group_id with an
                // empty recipient. WS-send currently carries only 1:1 (groups fan out over
                // HTTP in handlers), but the recipient-length check is still skipped when a
                // group_id is present.
                let is_group = group_id.is_some();
                // Validation (parity with handlers::send): auth + ref + batch size + per-
                // envelope size + (1:1) uuid length + not-self-or-a-different-device.
                let envelopes_ok = !env_items.is_empty()
                    && env_items.len() <= 100
                    && env_items
                        .iter()
                        .all(|(_, e)| e.len() >= 20 && e.len() <= 64 * 1024);
                // FIX-2(a) (HIGH — orphan NULLs, parity with handlers::send): on the 1:1 path
                // (is_group=false) every EnvItem.device_id MUST be concrete. The sender knows
                // the recipient's devices from the bundle, so each envelope targets a concrete
                // device; a 1:1 body with device_id=None is a buggy/old client and would create
                // orphan NULL pending rows. (The self-send branch already implies device_id is
                // Some and must differ from the sender's device.)
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
                // R1 (security, device-lifecycle audit): close the WS-send revoke asymmetry.
                // HTTP `/messages/send` (`messages::handlers::send`) calls device_revoked but WS-send did
                // not, so a revoked device could still INJECT 1:1 messages over the HOT socket
                // (outbound-injection asymmetry). Closed with fail-closed parity (`ref` is
                // still answered).
                match crate::auth::middleware::account_device_active(&self.env, &sender_id, &sender_device_id).await {
                    Ok(false) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"inactive_session"})
                                .to_string()
                                .as_str(),
                        );
                        return Ok(());
                    }
                    Ok(true) => {}
                    Err(_) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"authorization_unavailable"})
                                .to_string()
                                .as_str(),
                        );
                        return Ok(());
                    }
                }
                let authz_db = match self.env.d1("DB") {
                    Ok(db) => db,
                    Err(_) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"authorization_unavailable"})
                                .to_string().as_str(),
                        );
                        return Ok(());
                    }
                };
                match crate::contacts::direct_decision(&authz_db, &sender_id, recipient_id).await {
                    Ok(crate::contacts::DirectDecision::Allowed) => {}
                    Ok(crate::contacts::DirectDecision::NotFound) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"recipient_not_found"})
                                .to_string().as_str(),
                        );
                        return Ok(());
                    }
                    Ok(crate::contacts::DirectDecision::Denied) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"contact_not_authorized"})
                                .to_string().as_str(),
                        );
                        return Ok(());
                    }
                    Err(_) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"authorization_unavailable"})
                                .to_string().as_str(),
                        );
                        return Ok(());
                    }
                }
                // H2 (DoS — rate-limit parity for the hot WS path): HTTP `/messages/send`
                // (`messages::handlers::send`) enforces a per-user `msg:send:{sender_id}` 300/60s KV
                // sliding window; hot WS-send BYPASSED it, so a client could inject unlimited
                // messages over the socket and bloat the recipient DO's SQLite. Uses the SAME
                // KV bucket and parameters → one shared limit (HTTP + WS together 300/60s).
                // Placed AFTER the revoke check and BEFORE the /notify to the recipient DO.
                // The KV binding comes from self.env (same as the HTTP path).
                // TEMPLATE DIET: the self-host template ships NO RATE_LIMIT KV binding (deploy
                // screen simplicity + name clashes), so a missing binding or a KV error is
                // fail-open and traffic continues unlimited (bit-identical on a prod install
                // that does have the KV).
                if !crate::ratelimit::check_rate_limit_env(
                    &self.env,
                    &crate::messages::handlers::send_rate_limit_key(&sender_id),
                    300,
                    60,
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
                // Per-device /notify to the recipient's DO (parity with handlers::send).
                let namespace = self.env.durable_object("USER_INBOX")?;
                let stub = namespace.id_from_name(recipient_id)?.get_stub()?;
                #[derive(Deserialize)]
                struct Idr {
                    id: i64,
                    #[serde(default)]
                    delivered_live: bool,
                }
                // D1 handle for the FCM wake (1:1 WS-send path — a content-less wake when the
                // recipient is offline).
                let push_db = self.env.d1("DB").ok();
                let mut acks: Vec<serde_json::Value> = Vec::with_capacity(env_items.len());
                for (dev, env_b64) in &env_items {
                    // D-M12: do not deliver to a revoked RECIPIENT device over the hot WS path
                    // either. This loop does NOT go through handlers.rs (it is its own
                    // per-device delivery path), so without the gate here the hot path would
                    // stay open to revoked devices. Revoked → skip that device (no pending row,
                    // no ack; active devices are delivered to normally); a D1 error is
                    // fail-closed send_err (the `account_device_active` idiom used by the send arm
                    // above). Matches
                    // the behaviour of the group JOIN.
                    if let Some(d) = dev.as_deref() {
                        match crate::auth::middleware::device_revoked(&self.env, recipient_id, d)
                            .await
                        {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(_) => {
                                let _ = ws.send_with_str(
                                    serde_json::json!({"type":"send_err","ref":reff,"code":"authorization_unavailable"})
                                        .to_string()
                                        .as_str(),
                                );
                                return Ok(());
                            }
                        }
                    }
                    let payload = serde_json::json!({
                        "sender_id": sender_id,
                        "sender_device_id": sender_device_id,
                        "recipient_device_id": dev,
                        // W1 backstop: the RECIPIENT user_id, which notify_inner persists so the
                        // alarm can FCM-wake stuck pending rows (an offline DO cannot otherwise
                        // know its own user).
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
                    // (id, delivered_live). On error or doubt assume live=true (don't send a
                    // pointless wake).
                    let (resp_id, live) = match stub.fetch_with_request(do_req).await {
                        Ok(mut resp) if resp.status_code() == 200 => match resp.json::<Idr>().await {
                            Ok(r) => (Some(r.id), r.delivered_live),
                            Err(_) => (None, true),
                        },
                        _ => (None, true),
                    };
                    // PARTIAL FAILURE: a successful device joins acks, a failed one DROPS OUT.
                    if let Some(id) = resp_id {
                        acks.push(serde_json::json!({ "device_id": dev, "id": id }));
                        // Recipient is OFFLINE on that device (no live socket) → content-less
                        // FCM wake.
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
                    // No device succeeded → send_err (parity with the old do_notify_failed).
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
            // WS-read (field report 2026-06-02): take the read (third tick) receipt over the HOT
            // socket → no per-receipt TLS/ECH handshake (cold HTTP /messages/read is ~470ms, and
            // once WS-send moved messages onto the socket the HTTP connection goes cold). This
            // arm runs in the READER's DO and does a cross-DO /forward-read to the sender's
            // (peer_id) DO (parity with handlers::read 104-118 → forward_signal("read") + the
            // persistent forward_queue). Fire-and-forget, NO ack: read state is idempotent and
            // cosmetic, the client does not wait for it, and a loss is retriggered by the
            // viewport.
            "read" => {
                let peer_id = value.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
                let ids: Vec<i64> = value
                    .get("ids")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
                    .unwrap_or_default();
                // #11 Layer-4b: msg_uids PARALLEL to `ids` (supplied by the reader) — carried to
                // the sender's DO so a sibling device can match its oc- row. Missing → empty
                // (backwards compatible).
                let uids: Vec<String> = value
                    .get("uids")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|x| x.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let reader_attachment = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten();
                let reader_id = reader_attachment.as_ref().map(|a| a.user_id.clone());
                let reader_device_id = reader_attachment.as_ref().and_then(|a| a.device_id.clone());
                // Validation (parity with handlers::read): auth + ids (1..=500) + uuid + not-self.
                let valid = reader_id.is_some()
                    && reader_device_id.is_some()
                    && !ids.is_empty()
                    && ids.len() <= 500
                    && peer_id.len() == 36
                    && Some(peer_id) != reader_id.as_deref();
                if !valid {
                    return Ok(()); // fire-and-forget: invalid → swallow silently (no ack)
                }
                let reader_id = reader_id.unwrap();
                let reader_device_id = reader_device_id.unwrap();
                if !matches!(
                    crate::auth::middleware::account_device_active(
                        &self.env,
                        &reader_id,
                        &reader_device_id,
                    )
                    .await,
                    Ok(true)
                ) {
                    return Ok(());
                }
                let authz_db = match self.env.d1("DB") {
                    Ok(db) => db,
                    Err(_) => return Ok(()),
                };
                if !matches!(
                    crate::contacts::direct_decision(&authz_db, &reader_id, peer_id).await,
                    Ok(crate::contacts::DirectDecision::Allowed)
                ) {
                    return Ok(());
                }
                // H2 (DoS — rate-limit parity for the hot WS path): WS-read could likewise
                // inject forwards into the peer DO without any limit. Uses the SAME separate
                // bucket as HTTP read (`msg:read:{reader_id}`, 300/60s) → HTTP + WS reads are
                // bounded together, and legitimate read traffic does not eat the send quota.
                // Fire-and-forget: over the limit → swallow silently (read is cosmetic and
                // idempotent; the client retriggers from the viewport and expects no ack).
                // Placed BEFORE the forward to the peer DO. TEMPLATE DIET: the KV binding is
                // OPTIONAL — with no binding (or a KV error) the limiter is fail-open and
                // traffic continues unlimited; the older behaviour was fail-closed when the
                // binding was absent, but the template no longer ships it.
                if !crate::ratelimit::check_rate_limit_env(
                    &self.env,
                    &crate::messages::handlers::read_rate_limit_key(&reader_id),
                    300,
                    60,
                )
                .await
                {
                    return Ok(()); // over the limit → swallow silently
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
