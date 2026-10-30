use super::*;
use crate::push::coalesce::WakeIntent;

impl UserInbox {
    /// WS frame handler — `DurableObject::websocket_message` delegates here.
    /// Frame kinds: ack / ping / forward_ack / receipt_sync / self_read / self_read_sync /
    /// send / read. Anything else is ignored. There is deliberately no `typing` kind — see the
    /// note where its arm used to be.
    pub(crate) async fn handle_ws_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let text = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(_) => return Ok(()),
        };
        // ANY inbound frame proves the client→server direction is genuinely alive, so the stamp
        // refreshes here. `notify_inner` uses it as its zombie-socket test: the client pings every
        // 5s, so a live socket stays fresh while a half-open one left by a background kill goes
        // stale, and delivery to it stops counting as "live" (an FCM wake goes out instead).
        // Errors are swallowed — a missing attachment just skips the refresh.
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
                // msg_uids PARALLEL to `ids`. The delivered receipt carries uids like read does,
                // so the sender's SIBLING can advance its `oc-{msg_uid}` row to Delivered; the
                // mapping travels as a uid array in `ids` order on `/forward-delivered`.
                let ack_uids: Vec<String> = value
                    .get("uids")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|x| x.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                // `success` is optional, defaulting to true. False still drains the queue but
                // sends `delivery_failed` instead of `delivered`: the client uses it to clear the
                // queue after a decrypt failure, which is exactly when a second tick would lie.
                let success = value
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                // The socket's own device scopes the delete (ack isolation, see `ack.rs`).
                let ack_device: Option<String> = ws
                    .deserialize_attachment::<Attachment>()
                    .ok()
                    .flatten()
                    .map(|a| a.device_id);
                let rows = self.delete_acked_rows(&ids, ack_device.as_deref())?;
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
                self.forward_acked_rows(
                    rows,
                    &ids,
                    &ack_uids,
                    success,
                    ack_device.as_deref(),
                    recipient_id.as_deref(),
                )
                .await?;
            }
            // NO `typing` ARM, deliberately. The indicator is an E2E-encrypted
            // `InnerMessage::Typing` inside an ordinary `send`, so the server never sees it as
            // typing — a frame arm here would be the one path in this file authorizing nothing.
            "ping" => {
                // Application-level keepalive; the pong is mandatory for the client's zombie
                // detection. Without it the client sees an open TCP connection while, after a
                // hibernation or migration, the receive path is broken.
                let _ = ws.send_with_str(r#"{"type":"pong"}"#);
            }
            // The client confirms it received the forwarded receipts → drop them from the queue.
            // Frame: `{ type: "forward_ack", ids: [...] }`
            "forward_ack" => {
                if let Some(ids_val) = value.get("ids") {
                    if let Ok(ids) = serde_json::from_value::<Vec<i64>>(ids_val.clone()) {
                        self.forward_ack(&ids);
                    }
                }
            }
            // The client asks for durable receipt_state past its cursor and gets a `receipt_batch`
            // back — on connect, on a `receipt_update` notification, and periodically.
            "receipt_sync" => {
                let since = value.get("since").and_then(|v| v.as_i64()).unwrap_or(0);
                self.receipt_sync(&ws, since);
            }
            // A device reports over the hot socket the msg_uids it read → self_read_state
            // set-once, plus a self_read_update delta to that user's other devices.
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
            // WS-send: the message goes over the HOT socket instead of an HTTP POST, so it costs
            // no per-message TLS/ECH handshake (~85-150ms against ~470ms for a cold request).
            // This arm runs in the SENDER's DO and cross-DO POSTs /notify to the recipient, the
            // same logic as `handlers::send`.
            //
            // Wire: an `envelopes[]` batch, bit-identical to HTTP — one envelope per device for
            // 1:1 ({device_id, envelope_b64}), a single element without a device_id for a group.
            // The loop /notifies per device and answers ONE
            // `send_ack_batch{ref, acks:[{device_id,id}], ts}`. PARTIAL FAILURE: a device whose
            // /notify 500s drops out of the ack list and it is still a send_ack_batch; send_err
            // goes out only when NO device succeeded. `ref` is ALWAYS answered.
            "send" => {
                let reff = value.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let recipient_id =
                    value.get("recipient_id").and_then(|v| v.as_str()).unwrap_or("");
                let group_id = value.get("group_id").and_then(|v| v.as_str());
                // SECURITY: WS-send carries 1:1 ONLY. Groups go through the HTTP
                // `/messages/send` fan-out, which checks MEMBERSHIP via `group_role`; accepting a
                // group_id here would be group injection with no membership check.
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
                let sender_device_id = attach.as_ref().map(|a| a.device_id.clone());
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
                // The 1:1 path needs a recipient; a group is keyed by group_id with an empty one,
                // so the recipient-length check is skipped when a group_id is present.
                let is_group = group_id.is_some();
                // Validation at parity with `handlers::send`: auth + ref + batch size + envelope
                // size + (1:1) uuid length + not-self-or-a-different-device.
                let envelopes_ok = !env_items.is_empty()
                    && env_items.len() <= 100
                    && env_items
                        .iter()
                        .all(|(_, e)| e.len() >= 20 && e.len() <= 64 * 1024);
                // On the 1:1 path every device_id MUST be concrete — the sender knows the
                // recipient's devices from the bundle, and a `None` would create orphan NULL
                // pending rows nothing acks.
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
                // Revoke parity with HTTP `/messages/send`, fail-closed: without it a revoked
                // device can still INJECT 1:1 messages over the hot socket.
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
                // Rate-limit parity for the hot path: the SAME KV bucket and parameters as HTTP
                // `/messages/send`, so the two share one 300/60s per-user limit rather than
                // leaving the socket an unlimited way to bloat the recipient DO's SQLite. It runs
                // after the revoke check and before the /notify. A missing RATE_LIMIT KV binding
                // (the self-host template ships none) is fail-open.
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
                // The recipient's published devices, resolved ONCE for the batch, at parity with
                // `handlers::send`. `device_revoked` answers false for a device that DOES NOT
                // EXIST, so checking only that accepts envelopes aimed at invented device ids:
                // each becomes a `pending` row nobody can ack, and `pending` evicts oldest-first
                // at 10 000 rows — enough of them push the victim's real backlog out of their own
                // inbox.
                let recipient_devices = match crate::messages::recipient_devices::
                    load_recipient_devices(&authz_db, recipient_id)
                    .await
                {
                    Ok(d) => d,
                    Err(_) => {
                        let _ = ws.send_with_str(
                            serde_json::json!({"type":"send_err","ref":reff,"code":"authorization_unavailable"})
                                .to_string()
                                .as_str(),
                        );
                        return Ok(());
                    }
                };
                // ALL-OR-NOTHING, as on the HTTP path: one fabricated target refuses the whole
                // batch, so the sender learns its device list is wrong instead of half-succeeding.
                if env_items.iter().any(|(dev, _)| {
                    dev.as_deref().map(|d| {
                        recipient_devices.verdict(d)
                            == crate::messages::recipient_devices::DeviceVerdict::Unknown
                    }) == Some(true)
                }) {
                    let _ = ws.send_with_str(
                        serde_json::json!({
                            "type": "send_err",
                            "ref": reff,
                            "code": crate::messages::recipient_devices::UNKNOWN_DEVICE_CODE,
                        })
                        .to_string()
                        .as_str(),
                    );
                    return Ok(());
                }
                // Every target revoked → the typed `devices_stale`, at parity with
                // `handlers::send` (not the "no device took it" `do_notify_failed` below).
                if let Some(refusal) =
                    recipient_devices.stale_refusal(env_items.iter().map(|(d, _)| d.as_deref()))
                {
                    let _ = ws.send_with_str(refusal.ws_frame(&reff).to_string().as_str());
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
                let wake = ws_send_wake(&value);
                let mut acks: Vec<serde_json::Value> = Vec::with_capacity(env_items.len());
                for (dev, env_b64) in &env_items {
                    // This loop is its own per-device delivery path and does NOT go through
                    // handlers.rs, so the revoked-RECIPIENT gate has to be repeated here or the
                    // hot path stays open to revoked devices. Revoked → skip the device (no
                    // pending row, no ack), matching the group JOIN; an UNKNOWN device or a D1
                    // error already refused the whole batch above.
                    if let Some(d) = dev.as_deref() {
                        if recipient_devices.verdict(d)
                            != crate::messages::recipient_devices::DeviceVerdict::Active
                        {
                            continue;
                        }
                    }
                    let payload = ws_notify_payload(
                        &sender_id,
                        &sender_device_id,
                        recipient_id,
                        dev.as_deref(),
                        env_b64,
                        wake,
                    );
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
                        // Recipient is OFFLINE on that device (no live socket): the recipient's
                        // inbox sends the content-less wake itself, through its coalescing gate
                        // (`wake_gate.rs`) — or none, for silent control traffic. These lines
                        // only say that the WS path asked, apart from the HTTP one.
                        if !live {
                            match wake {
                                WakeIntent::Silent => console_log!(
                                    "[push] skipped (silent ws) 1:1 user={recipient_id} dev={dev:?}"
                                ),
                                WakeIntent::Ordinary => console_log!(
                                    "[push] waking ws 1:1 user={recipient_id} dev={dev:?}"
                                ),
                                WakeIntent::Urgent => console_log!(
                                    "[push] waking ws (urgent) 1:1 user={recipient_id} dev={dev:?}"
                                ),
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
            // WS-read: the third-tick receipt over the HOT socket, avoiding a per-receipt TLS/ECH
            // handshake (cold HTTP is ~470ms, and once WS-send moved messages onto the socket the
            // HTTP connection is always cold). Runs in the READER's DO and cross-DO /forward-reads
            // to the sender's. NOT via forward_signal + the consume-once forward_queue:
            // delivered/read are durable `receipt_state` now, and the DO drains those kinds OUT of
            // that queue — `forward_signal`'s one remaining caller is delivery_failed.
            // Fire-and-forget, NO ack: read state is idempotent and cosmetic, and a loss is
            // retriggered by the viewport.
            "read" => {
                let peer_id = value.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
                let ids: Vec<i64> = value
                    .get("ids")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
                    .unwrap_or_default();
                // msg_uids PARALLEL to `ids`, carried to the sender's DO so a sibling device can
                // match its oc- row. Missing → empty.
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
                let reader_device_id = reader_attachment.as_ref().map(|a| a.device_id.clone());
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
                // Rate-limit parity again, before the forward to the peer DO: the same SEPARATE
                // bucket as HTTP read (`msg:read:{reader_id}`, 300/60s), so reads are bounded
                // together and legitimate read traffic does not eat the send quota. Over the
                // limit is swallowed silently, as this arm is fire-and-forget. A missing KV
                // binding is fail-open.
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

/// What the sender asked of the wake. The core sends 1:1 control traffic — state digests,
/// receipts, typing, reactions, edits, caps, pair-ack fan-outs — over the warm socket first, so
/// the WS `send` frame carries `"silent": true` for it; and `"urgent": true` for a call signal
/// that starts or stops a ring (both emitted only when true). Absent, or anything but a JSON
/// `true` (an older client), is an ordinary wake, which is what every WS send was before the
/// fields: until 2026-10-30 this path ignored `silent`, and every silent kind woke the
/// recipient whenever the sender's socket happened to be warm.
pub(super) fn ws_send_wake(frame: &serde_json::Value) -> WakeIntent {
    let flag = |k: &str| frame.get(k).and_then(serde_json::Value::as_bool).unwrap_or(false);
    WakeIntent::from_flags(flag("silent"), flag("urgent"))
}

/// The recipient inbox's `/notify` body for one device of a WS `send` — the HTTP path's twin
/// (`handlers::build_notify_payload`). 1:1 only: a group never comes this way (`group_via_http`).
/// `silent` is persisted on the pending row, so the backstop alarm stays quiet about it too, and
/// the recipient's inbox sends no wake for it; `urgent` takes its wake past the coalescing gate.
pub(super) fn ws_notify_payload(
    sender_id: &str,
    sender_device_id: &str,
    recipient_id: &str,
    recipient_device_id: Option<&str>,
    envelope_b64: &str,
    wake: WakeIntent,
) -> String {
    serde_json::json!({
        "sender_id": sender_id,
        "sender_device_id": sender_device_id,
        "recipient_device_id": recipient_device_id,
        // notify_inner persists this so the alarm can FCM-wake stuck pending rows; an offline DO
        // has no other way to know its own user.
        "recipient_id": recipient_id,
        "envelope_b64": envelope_b64,
        "silent": wake.silent(),
        "urgent": wake.urgent(),
    })
    .to_string()
}

#[cfg(test)]
#[path = "ws_send_tests.rs"]
mod send_tests;
