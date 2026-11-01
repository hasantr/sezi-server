//! The `/sync` upgrade that is also the token refresh.
//!
//! An access token lives 15 minutes (`jwt.rs`), so nearly every push wake of an idle phone found
//! it expired and paid a separate `POST /auth/refresh` — its own TCP + TLS, ~350 ms and ~6 KB on
//! a POCO (2026-11-01) — before it could open the socket. A client that holds a valid refresh
//! token may instead open `/sync` presenting it:
//!
//! ```text
//! Sec-WebSocket-Protocol: sezgi.refresh.v1, <refresh_token>
//! ```
//!
//! The worker spends it exactly as `/auth/refresh` does — the same [`refresh::rotate`], so
//! rotation, replay (a spent token is `invalid_refresh`), the device binding and the revocation
//! check cannot differ — then checks the account and device as the bearer upgrade does, and hands
//! the upgrade to the user's inbox with the NEW access token in the bearer form and the new pair
//! in [`TOKENS_HEADER`]. The inbox sends that pair as the socket's FIRST frame,
//! `{"type":"tokens", …}` with `/auth/refresh`'s fields, and selects `sezgi.refresh.v1` back. A
//! refused refresh is the same status and code `/auth/refresh` answers, before any upgrade.
//!
//! Announced as `protocol.sync_refresh: 1` on `/capabilities`; a client uses it only when the
//! relay said so. An older relay refuses the scheme with a 400 and the client falls back to
//! `/auth/refresh`; an older client never offers it.
//!
//! [`refresh::rotate`]: crate::auth::refresh::rotate

use crate::auth::refresh::Rotated;
use crate::respond::json_err;
use worker::*;

/// The subprotocol scheme a bearer upgrade names first.
pub(crate) const BEARER_SCHEME: &str = "sezgi.bearer.v1";
/// The subprotocol scheme an upgrade that is also a refresh names first.
pub(crate) const REFRESH_SCHEME: &str = "sezgi.refresh.v1";
/// Worker → inbox only: the `tokens` frame the inbox sends first. Never accepted from a client
/// (`refuse_planted`), so nobody can make an inbox send a frame of their choosing.
pub(crate) const TOKENS_HEADER: &str = "x-sezi-sync-tokens";

/// What a `/sync` upgrade presented.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SyncCredential {
    Bearer(String),
    Refresh(String),
}

/// Parse `Sec-WebSocket-Protocol`: two entries, the scheme then the credential.
pub(crate) fn parse_credential(raw: Option<&str>) -> std::result::Result<SyncCredential, &'static str> {
    let raw = raw.ok_or("subprotocol_required")?;
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.len() != 2 || (parts[0] != BEARER_SCHEME && parts[0] != REFRESH_SCHEME) {
        return Err("expected_subprotocol_sezgi_bearer_v1");
    }
    if parts[1].is_empty() {
        return Err("token_empty");
    }
    Ok(if parts[0] == REFRESH_SCHEME {
        SyncCredential::Refresh(parts[1].to_string())
    } else {
        SyncCredential::Bearer(parts[1].to_string())
    })
}

/// The first frame of a socket whose upgrade was the refresh: `/auth/refresh`'s answer, typed.
pub(crate) fn tokens_frame(rotated: &Rotated) -> String {
    let mut frame = rotated.answer();
    frame["type"] = serde_json::Value::String("tokens".into());
    frame.to_string()
}

/// A bearer upgrade carrying [`TOKENS_HEADER`] came from a client, not from this worker: refused.
pub(crate) fn refuse_planted(req: &Request) -> Option<Result<Response>> {
    req.headers()
        .get(TOKENS_HEADER)
        .ok()
        .flatten()
        .map(|_| json_err(400, "bad_request"))
}

/// The upgrade that spends `refresh_token` (module note). Answers the inbox's upgrade response,
/// or `/auth/refresh`'s refusal.
pub(crate) async fn upgrade(req: Request, env: &Env, refresh_token: &str) -> Result<Response> {
    // Not a WebSocket: refused before anything is spent.
    let upgrade = req.headers().get("upgrade").ok().flatten();
    if upgrade.as_deref().map(|s| s.to_lowercase()) != Some("websocket".into()) {
        return json_err(426, "expected_websocket");
    }
    let rotated = match crate::auth::refresh::rotate(env, refresh_token, None).await? {
        Ok(r) => r,
        Err((status, code)) => return json_err(status, code),
    };
    // The bearer upgrade's own gate (`validate_active_token`): a removed account or an inactive
    // device gets no socket. Asked after the rotation because only the stored row names whom the
    // token belongs to — `/auth/refresh` followed by a bearer upgrade ends the same way.
    if let Err(resp) =
        crate::auth::middleware::validate_active_token(env, &rotated.access_token).await
    {
        return Ok(resp);
    }
    let mut forwarded = req.clone_mut()?;
    let headers = forwarded.headers_mut()?;
    headers.set(
        "Sec-WebSocket-Protocol",
        &format!("{BEARER_SCHEME}, {}", rotated.access_token),
    )?;
    headers.set(TOKENS_HEADER, &tokens_frame(&rotated))?;
    let stub = env
        .durable_object("USER_INBOX")?
        .id_from_name(&rotated.user_id)?
        .get_stub()?;
    stub.fetch_with_request(forwarded).await
}

/// In the inbox: the frame to send first and the subprotocol to select, for an upgrade the worker
/// forwarded — the `tokens` frame and [`REFRESH_SCHEME`] when the upgrade was the refresh, else
/// nothing and [`BEARER_SCHEME`].
pub(crate) fn forwarded(req: &Request) -> (Option<String>, &'static str) {
    match req.headers().get(TOKENS_HEADER).ok().flatten() {
        Some(frame) => (Some(frame), REFRESH_SCHEME),
        None => (None, BEARER_SCHEME),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_schemes_parse_and_nothing_else_does() {
        assert_eq!(
            parse_credential(Some("sezgi.bearer.v1, eyJ.a.b")),
            Ok(SyncCredential::Bearer("eyJ.a.b".into()))
        );
        assert_eq!(
            parse_credential(Some("sezgi.refresh.v1,  rt-abc ")),
            Ok(SyncCredential::Refresh("rt-abc".into()))
        );
        assert_eq!(parse_credential(None), Err("subprotocol_required"));
        assert_eq!(parse_credential(Some("sezgi.refresh.v1, ")), Err("token_empty"));
        assert_eq!(
            parse_credential(Some("sezgi.refresh.v2, rt")),
            Err("expected_subprotocol_sezgi_bearer_v1")
        );
        assert_eq!(
            parse_credential(Some("sezgi.refresh.v1, a, b")),
            Err("expected_subprotocol_sezgi_bearer_v1"),
            "exactly two entries"
        );
    }

    /// The first frame is `/auth/refresh`'s answer with a type: a client stores it exactly as it
    /// stores that answer.
    #[test]
    fn the_tokens_frame_is_the_refresh_answer_typed() {
        let rotated = Rotated {
            user_id: "u".into(),
            access_token: "eyJ.new".into(),
            refresh_token: "rt-new".into(),
        };
        let frame: serde_json::Value = serde_json::from_str(&tokens_frame(&rotated)).unwrap();
        assert_eq!(frame["type"], "tokens");
        assert_eq!(frame["access_token"], "eyJ.new");
        assert_eq!(frame["refresh_token"], "rt-new");
        assert_eq!(frame["user_id"], "u");
        let mut answer = rotated.answer();
        answer["type"] = "tokens".into();
        assert_eq!(frame, answer);
    }

    /// Source guard: the upgrade spends the token through the one rotation `/auth/refresh` uses,
    /// refuses a non-WebSocket request before spending it, and the bearer upgrade refuses a
    /// planted tokens header. Needles split with `concat!`.
    #[test]
    fn the_upgrade_rotates_through_the_refresh_path_and_only_for_a_websocket() {
        let src = include_str!("sync_refresh.rs");
        let body = &src[src.find(concat!("pub(crate) async fn ", "upgrade(")).unwrap()..];
        let ws = body.find(concat!("return json_err(426, ", "\"expected_websocket\")")).unwrap();
        let spend = body.find(concat!("crate::auth::refresh::", "rotate(env")).unwrap();
        let gate = body.find(concat!("validate_active_", "token(env")).unwrap();
        assert!(ws < spend && spend < gate);
        let lib = include_str!("../lib.rs");
        assert!(lib.contains(concat!("sync_refresh::refuse_", "planted(&req)")));
    }
}
