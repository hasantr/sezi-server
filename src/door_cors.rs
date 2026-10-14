//! CORS for the door — the routes that tell a live invite from a dead one: `POST /auth/redeem`,
//! `POST /invites/describe` and `GET /<CODE>`.
//!
//! Everywhere else the relay answers `Access-Control-Allow-Origin: *` (`lib.rs`, `apply_cors`), and
//! rightly: the API is authorized by a bearer token a page holds only if the user put it there.
//! The door is different. It needs no token, and what it answers IS the secret's test — so with
//! `*`, any website could make its visitors' browsers guess codes for it and READ the answers,
//! spending each visitor's own per-address miss budget, a botnet for free. (`Accept:
//! application/json` is a CORS-safelisted header, so `GET /<CODE>` does not even need a preflight.)
//!
//! The native app is not a browser and is untouched by CORS. The web client is: it is served from
//! `https://sezi-web.pages.dev` and talks to every relay cross-origin, so it needs the door. The
//! door therefore answers only an ALLOWED origin — that one, its preview deployments, a page on
//! this machine (the dev harness), and whatever the operator lists in `SEZI_WEB_ORIGINS` (comma
//! separated, e.g. a custom domain the web client is served from). Any other origin gets no
//! `Access-Control-Allow-Origin`, so its page can send a simple GET but cannot read the answer, and
//! a preflight for redeem's JSON POST is refused, so that request is never sent at all.

/// The web client's production origin.
pub(crate) const WEB_CLIENT_ORIGIN: &str = "https://sezi-web.pages.dev";

/// Is `path` one of the door's routes?
pub(crate) fn is_door_path(path: &str) -> bool {
    if path == "/auth/redeem" || path == "/invites/describe" {
        return true;
    }
    // `GET /<CODE>`: one segment that is a code (`invite_page`'s own grammar).
    path.strip_prefix('/')
        .filter(|seg| !seg.is_empty() && !seg.contains('/'))
        .is_some_and(|seg| crate::auth::invite_code::normalize(seg).is_some())
}

/// May a page from `origin` read the door's answers? `extra` is `SEZI_WEB_ORIGINS`.
pub(crate) fn origin_allowed(origin: &str, extra: &str) -> bool {
    let origin = origin.trim().trim_end_matches('/');
    if origin.eq_ignore_ascii_case(WEB_CLIENT_ORIGIN) {
        return true;
    }
    // A Pages preview deployment: `https://<hash>.sezi-web.pages.dev`.
    if let Some(sub) = origin
        .strip_prefix("https://")
        .and_then(|h| h.strip_suffix(".sezi-web.pages.dev"))
    {
        if !sub.is_empty() && sub.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return true;
        }
    }
    // A page on this machine: the dev harness, or a web client the operator runs locally.
    if let Some(rest) = origin.strip_prefix("http://") {
        // `host[:port]`, the host possibly a bracketed IPv6 literal.
        let split = if rest.starts_with('[') {
            rest.split_once("]:")
                .map(|(h, p)| (format!("{h}]"), Some(p)))
        } else {
            rest.split_once(':').map(|(h, p)| (h.to_string(), Some(p)))
        };
        let (host, port) = split.unwrap_or((rest.to_string(), None));
        let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if port_ok && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
            return true;
        }
    }
    extra
        .split(',')
        .map(|o| o.trim().trim_end_matches('/'))
        .any(|o| !o.is_empty() && o != "*" && o.eq_ignore_ascii_case(origin))
}

/// The door's CORS headers for a request from `origin`: the origin echoed when allowed, nothing
/// otherwise. `Vary: Origin` either way, so no cache serves one origin's answer to another.
pub(crate) fn apply(
    headers: &mut worker::Headers,
    origin: Option<&str>,
    extra: &str,
) -> worker::Result<()> {
    headers.append("Vary", "Origin")?;
    if let Some(origin) = origin.filter(|o| origin_allowed(o, extra)) {
        headers.set("Access-Control-Allow-Origin", origin)?;
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
        headers.set("Access-Control-Allow-Headers", "Content-Type, Accept")?;
        headers.set("Access-Control-Expose-Headers", "Retry-After")?;
        headers.set("Access-Control-Max-Age", "86400")?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "door_cors_tests.rs"]
mod tests;
