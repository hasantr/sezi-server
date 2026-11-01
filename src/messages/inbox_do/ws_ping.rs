//! The keepalive, answered by the runtime without waking the inbox.
//!
//! An app on screen sends `{"type":"ping"}` every 5 s (the core's `PING_PAYLOAD`), and each one
//! used to reach `websocket_message`, so a user's Durable Object never hibernated while an app
//! was open. The runtime can answer one exact request string with one exact response on its own
//! (`setWebSocketAutoResponse`), the object staying asleep; installed in the constructor, the
//! ping is answered with the same `{"type":"pong"}` the `ping` arm sends (that arm stays, for a
//! runtime without the feature).
//!
//! What the ping also did was prove the socket alive: `ws_is_fresh` reads the last frame a socket
//! sent, and a ping the object never sees stamps nothing. The runtime records when it last
//! auto-answered on a socket (`getWebSocketAutoResponseTimestamp`), so a socket is heard at the
//! later of that and its attachment's stamp. Both halves exist or neither is used: with the
//! answer installed and the timestamp missing, every live socket would look stale after 20 s and
//! every message would wake a phone that is on screen.

use worker::wasm_bindgen::prelude::*;
use worker::worker_sys::{DurableObjectState, WebSocketRequestResponsePair};
use worker::{js_sys, web_sys};

/// The ping the core sends, byte for byte (`core/src/client/sync_wire.rs` `PING_PAYLOAD`): the
/// runtime matches the whole string, so any other spelling reaches the `ping` arm instead.
pub(crate) const PING: &str = r#"{"type":"ping"}"#;
/// The answer the `ping` arm gives too.
pub(crate) const PONG: &str = r#"{"type":"pong"}"#;

#[wasm_bindgen]
extern "C" {
    /// The object state, seen through the one method `worker-sys` does not bind.
    #[wasm_bindgen(extends = js_sys::Object)]
    type AutoResponseState;

    #[wasm_bindgen(method, catch, js_name = getWebSocketAutoResponseTimestamp)]
    fn auto_response_timestamp(
        this: &AutoResponseState,
        ws: &web_sys::WebSocket,
    ) -> Result<Option<js_sys::Date>, JsValue>;
}

/// The runtime's auto-answered ping, when it offers both halves (module note).
pub(crate) struct AutoPong {
    state: Option<AutoResponseState>,
}

impl AutoPong {
    /// Install the answer, in the object's constructor. Without both halves, nothing is installed
    /// and every ping wakes the object as before.
    pub(crate) fn install(raw: &DurableObjectState) -> Self {
        let has = |name: &str| js_sys::Reflect::has(raw, &JsValue::from_str(name)).unwrap_or(false);
        if !(has("setWebSocketAutoResponse") && has("getWebSocketAutoResponseTimestamp")) {
            return Self { state: None };
        }
        let installed = match WebSocketRequestResponsePair::new(PING, PONG) {
            Ok(pair) => raw.set_websocket_auto_response(&pair).is_ok(),
            Err(_) => false,
        };
        let handle = || AsRef::<JsValue>::as_ref(raw).clone().unchecked_into::<AutoResponseState>();
        Self { state: installed.then(handle) }
    }

    /// When the runtime last answered a ping on `ws`, in ms; `None` when it never did, or the
    /// answer is not installed.
    pub(crate) fn last_ping_ms(&self, ws: &worker::WebSocket) -> Option<i64> {
        let state = self.state.as_ref()?;
        let at = state.auto_response_timestamp(ws.as_ref()).ok().flatten()?;
        Some(at.get_time() as i64)
    }
}

/// The later of the two signs a socket is alive: its last frame the object saw, its last ping the
/// runtime answered.
pub(crate) fn last_heard(frame_ms: Option<i64>, ping_ms: Option<i64>) -> Option<i64> {
    frame_ms.max(ping_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_is_heard_at_its_latest_sign() {
        assert_eq!(last_heard(None, None), None, "never heard: not fresh, so a wake goes out");
        assert_eq!(last_heard(Some(5), None), Some(5));
        assert_eq!(last_heard(None, Some(7)), Some(7), "pings alone keep it fresh");
        assert_eq!(last_heard(Some(9), Some(7)), Some(9));
    }

    /// The pair is the `ping` arm's own exchange, so a runtime with and one without the feature
    /// answer alike.
    #[test]
    fn the_auto_answer_is_the_ping_arms_answer() {
        assert_eq!(PING, r#"{"type":"ping"}"#);
        assert_eq!(PONG, r#"{"type":"pong"}"#);
        let ws = include_str!("ws.rs");
        assert!(ws.contains(concat!("ws.send_with_str(super::ws_ping::", "PONG)")));
    }
}
