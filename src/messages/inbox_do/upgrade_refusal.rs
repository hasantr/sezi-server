//! The answer to a `/sync` upgrade whose token the inbox could not verify (audit 2026-11-03
//! finding #7).
//!
//! The worker checked the token before proxying, so this happens only when it expired in between
//! or the JWT key failed to load in the inbox's isolate. Such an upgrade is never accepted as a
//! socket of the inbox: a socket with no device would be a target for every device's frames,
//! would be flushed every device's rows, and its ack would delete them.

use worker::*;

/// Why a socket is closed right after the new pair, or for carrying no device: `1013` ("try again
/// later"). The client reconnects on any close.
pub(super) const REFUSED_CLOSE_CODE: u16 = 1013;

/// A plain upgrade gets the `401 invalid_token` the worker's own check gives: the client reads a
/// 401 on connect as "refresh the token" and reconnects (`ws_connect_fail_should_refresh`).
///
/// An upgrade that was also the token refresh (`auth::sync_refresh`) has already rotated the pair,
/// so a bare refusal would strand the client with a revoked refresh token. That socket is accepted
/// OUTSIDE the inbox — `accept()`, not `accept_web_socket`, so it is never one of
/// `get_websockets()` and no flush, live frame or ack can reach it — only to hand over the new
/// pair, and closed in the same turn.
pub(super) fn refuse_unverified_upgrade(req: &Request) -> Result<Response> {
    let (tokens_frame, protocol) = crate::auth::sync_refresh::forwarded(req);
    let Some(frame) = tokens_frame else {
        return crate::respond::json_err(401, "invalid_token");
    };
    let pair = WebSocketPair::new()?;
    let refused = pair.server;
    refused.accept()?;
    let _ = refused.send_with_str(frame.as_str());
    let _ = refused.close(Some(REFUSED_CLOSE_CODE), Some("try_again"));
    let resp = Response::from_websocket(pair.client)?;
    let headers = resp.headers().clone();
    headers.set("Sec-WebSocket-Protocol", protocol)?;
    Ok(resp.with_headers(headers))
}

/// Close every socket of the inbox that carries no device. None is accepted since 2026-11-03; one
/// accepted before (a hibernated socket that outlived the update) is closed here rather than
/// flushed every device's rows, and reconnects through the verified upgrade.
pub(super) fn close_unverified_sockets(state: &State) {
    for ws in state.get_websockets() {
        if super::message::ws_attachment_device(&ws).is_none() {
            let _ = ws.close(Some(REFUSED_CLOSE_CODE), Some("try_again"));
        }
    }
}

// Source guards: none of these paths runs outside a Durable Object.
#[cfg(test)]
mod tests {
    fn code_of(src: &str) -> &str {
        src.split("#[cfg(test)]").next().unwrap()
    }

    #[test]
    fn the_upgrade_is_refused_before_anything_is_accepted() {
        let src = include_str!("mod.rs");
        let refuse = src.find("return refuse_unverified_upgrade(&req)").expect("the refusal");
        let accept = src.find("accept_web_socket(&server)").expect("the accept");
        assert!(refuse < accept, "a socket is accepted before its token was verified");
    }

    #[test]
    fn a_refused_socket_never_joins_the_inbox() {
        assert!(!code_of(include_str!("upgrade_refusal.rs")).contains(".accept_web_socket("));
    }

    #[test]
    fn a_socket_without_a_device_acks_nothing_and_is_no_target() {
        let ack = code_of(include_str!("ack.rs"));
        let body = &ack[ack.find("fn delete_acked_rows").unwrap()..];
        let guard = body.find("let Some(device) = ack_device else").expect("the device guard");
        assert!(guard < body.find("exec_raw").unwrap(), "SQL runs before the device is known");
        let msg = include_str!("message.rs");
        let targets = &msg[msg.find("fn ws_targets_device").unwrap()..];
        let targets = &targets[..targets.find("\n}\n").unwrap()];
        assert!(!targets.contains("None => true, //"), "a device-less socket is a target");
    }
}
