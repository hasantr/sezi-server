use serde::Serialize;
use worker::{Headers, Response, Result};

/// Hand a Durable Object's answer back through the Router.
///
/// A `Response` that came out of `fetch` is IMMUTABLE in workerd, and every routed answer passes
/// through `apply_cors(resp.headers_mut())` on its way out (`lib.rs`). So a handler that returns
/// the DO's response verbatim throws `TypeError: Can't modify immutable headers` AFTER doing its
/// work correctly, and the router turns that into a 500. Copying the body and the status into a
/// fresh `Response` gives the caller headers it is allowed to write.
///
/// This was not found by a test and could not have been: the failure is in the router's
/// after-handler, on a real request, so anything that merely compiles the worker sees nothing. It
/// showed up as `GET /messages/self-read-sync 500` on the first sync of a freshly registered
/// device — and both halves of durable sibling-read, plus the plugin log, sit on the same shape.
/// It arrived with CORS in 7d8662b4 (2026-08-03).
///
/// `/sync` is not affected and must never come through here: a WebSocket upgrade is returned
/// before the Router (`lib.rs`), and reading its body would destroy it.
pub async fn passthrough(mut resp: Response) -> Result<Response> {
    let status = resp.status_code();

    let headers = Headers::new();
    for (name, value) in resp.headers() {
        // Everything except the two that describe the body as it was ON THE WIRE. `bytes()` hands
        // back the decoded body, so carrying `content-encoding` over would label plain bytes as
        // compressed; `content-length` is the runtime's to recompute.
        let n = name.to_ascii_lowercase();
        if n == "content-encoding" || n == "content-length" {
            continue;
        }
        headers.set(&name, &value)?;
    }

    let body = resp.bytes().await?;

    // A NULL-BODY STATUS MUST STAY BODYLESS. `Response::from_bytes(vec![])` produces a response
    // that HAS a body — an empty one — and workerd rejects a body on 101/204/205/304, which
    // workers-rs surfaces as a panic and the router as a 500. Seven of the inbox DO's arms answer
    // `Response::empty().with_status(204)` (`messages/inbox_do/mod.rs:241` onward), so the first
    // version of this function turned the fix for one 500 into a new 500 on `POST
    // /messages/self-read` — the durable write half of sibling-read, hit on every mark-read.
    if body.is_empty() || matches!(status, 101 | 204 | 205 | 304) {
        return Ok(Response::empty()?.with_status(status).with_headers(headers));
    }

    Ok(Response::from_bytes(body)?.with_status(status).with_headers(headers))
}

pub fn json_err(status: u16, code: &str) -> Result<Response> {
    let resp = Response::from_json(&serde_json::json!({"error": code}))?;
    Ok(resp.with_status(status))
}

pub fn json_err_msg(status: u16, code: &str, message: &str) -> Result<Response> {
    let resp =
        Response::from_json(&serde_json::json!({"error": code, "message": message}))?;
    Ok(resp.with_status(status))
}

#[allow(dead_code)] // util-belt: json_err/no_content kardeşi, ileride kullanılabilir
pub fn json_status<T: Serialize>(status: u16, body: &T) -> Result<Response> {
    let resp = Response::from_json(body)?;
    Ok(resp.with_status(status))
}

pub fn no_content() -> Result<Response> {
    Ok(Response::empty()?.with_status(204))
}

#[cfg(test)]
#[path = "respond_tests.rs"]
mod tests;
