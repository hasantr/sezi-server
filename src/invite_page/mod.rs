//! `GET /<CODE>` — the invite page (campus gap K6). ONE route answers a browser and the app.
//!
//! The projector URL is `<base>/<CODE>` (`auth::invite_code`): until this route it led nowhere —
//! a browser got `Not Found`, and the app learned nothing about an invite before it was redeemed,
//! so the door could not say who had invited you. Now the same URL answers:
//!
//! - a browser with a small static page (English or Turkish, as `welcome.rs` picks), saying what
//!   the invite is and how to open it in Sezi;
//! - the app — `Accept: application/json` — with the same facts as JSON ([`lookup::InviteView`]).
//!
//! **Why one path with content negotiation rather than a sibling `/invites/<code>/describe`:** the
//! URL the app holds IS this one (it parses `<base>/<CODE>` out of the projector QR), so asking it
//! needs no second grammar; and a single handler means one lookup, one rate limit and one view
//! struct for both answers — the page can never show more than the JSON does, because it is
//! rendered from the same value. `Vary: Accept` keeps any cache from mixing the two.
//!
//! **What it never says.** Not the token, not the code's hash, no account id, no member list, no
//! personal invite's admin note — [`lookup::InviteView`] is the whole answer and has no field for
//! any of them. A token is accepted as INPUT, in the body of the app's `POST /invites/describe` only
//! (a personal envelope carries no code; a token never goes in a URL), and it
//! is the caller's own and is never echoed.
//!
//! **Guessing.** A usable invite has to be distinguishable — that is the page's purpose — so the
//! defence is the same one redeem has (`ratelimit`, "The door"): misses are counted per address in
//! the SAME bucket as redeem's (`ratelimit::door_miss_key`, asked in `gate.rs`), so this door adds
//! no guesses to the ones redeem already allows. The miss is RESERVED before the lookup in one
//! atomic D1 statement and given back on a hit (`door_bucket`), so requests in flight at once
//! cannot outrun the budget, and a caller over it is turned away before the lookup. Every way of
//! being unusable — unknown, spent, expired, withdrawn, full, the founding invite — is ONE answer, from
//! one statement that returns one row whatever the code ([`lookup`]). A per-address ceiling sized
//! for a lecture hall behind one NAT bounds plain reloading.
//!
//! **Path collisions.** `/:invite` is one segment deep, and matchit prefers a static segment, so
//! `/healthz`, `/groups`, `/capabilities` and every other one-segment route keep winning (a test
//! inserts the whole routing table to prove it). A segment that is not a code (and, for JSON, not
//! a token) is answered exactly like an unrouted path — `404 Not Found` — and costs nothing. One
//! side effect: a one-segment path with a method no route has (`POST /foo`) now answers 405 rather
//! than 404, because the router sees a GET route there.

mod gate;
mod html;
mod lookup;

#[cfg(test)]
#[path = "html_tests.rs"]
mod html_tests;
#[cfg(test)]
#[path = "lookup_tests.rs"]
mod lookup_tests;
#[cfg(test)]
#[path = "route_tests.rs"]
mod route_tests;

use worker::*;

use crate::door_bucket::{Reservation, Reserved};
use crate::ratelimit::{admit_env, client_ip, Admission};
use crate::utils::now_secs;
use gate::{answer_with, Answer, DoorPort};
use lookup::{DescribeRow, LookupKey};

/// Does the caller want the JSON answer? Only when it asks for JSON and not for HTML: a browser's
/// `Accept` lists `text/html` (and often `*/*`), the app's lists `application/json` alone. No
/// header at all is a browser-ish caller (curl) and gets the page.
pub(crate) fn wants_json(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    let accept = accept.to_ascii_lowercase();
    accept.contains("application/json") && !accept.contains("text/html")
}

/// The live port: the KV limiter and D1.
struct LivePort<'a> {
    env: &'a Env,
}

impl DoorPort for LivePort<'_> {
    async fn reserve_miss(&self, bucket: &str, limit: usize, now: i64) -> Reserved {
        match self.env.d1("DB") {
            Ok(db) => crate::door_bucket::reserve(&db, bucket, limit, now).await,
            // Fails closed, as the counter does.
            Err(_) => Reserved::Refused { retry_after_s: 60 },
        }
    }
    async fn refund_miss(&self, reservation: &Reservation) {
        if let Ok(db) = self.env.d1("DB") {
            crate::door_bucket::refund(&db, reservation).await;
        }
    }
    async fn admit(&self, key: &str, max_hits: usize, window_s: u64) -> Admission {
        admit_env(self.env, key, max_hits, window_s).await
    }
    async fn lookup(&self, key: &LookupKey, now: i64) -> Result<DescribeRow> {
        lookup::lookup(&self.env.d1("DB")?, key, now).await
    }
}

/// `GET /:invite`.
pub async fn invite_page(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let json = wants_json(req.headers().get("accept").ok().flatten().as_deref());
    let segment = ctx.param("invite").cloned().unwrap_or_default();
    // A path carries a code or nothing — never a token (`LookupKey::parse`).
    let Some(key) = LookupKey::parse(&segment, false) else {
        // The router's own answer for a path it has no route for.
        return Response::error("Not Found", 404);
    };
    let lang = crate::welcome::negotiate_lang(&req);
    // As redeem: the KV binding is optional, and a non-prod ENV runs unlimited (fail-secure
    // default "prod").
    let limited = crate::utils::var_or(&ctx.env, "ENV", "prod") == "prod";
    let ip = client_ip(&req, &ctx.env);
    let now = now_secs() as i64;
    let answer = answer_with(&LivePort { env: &ctx.env }, &ip, &key, limited, now).await?;

    let status = page_status(&answer);
    let resp = match (answer, json) {
        (Answer::Refused { retry_after_s }, true) => crate::respond::rate_limited(retry_after_s)?,
        (Answer::Refused { retry_after_s }, false) => {
            let mut r = Response::from_html(html::render_rate_limited(lang, retry_after_s))?
                .with_status(status);
            r.headers_mut()
                .set("Retry-After", &retry_after_s.to_string())?;
            r
        }
        (Answer::Unavailable, true) => crate::respond::json_err(404, "invite_unavailable")?,
        (Answer::Unavailable, false) => {
            Response::from_html(html::render_unavailable(lang))?.with_status(status)
        }
        (Answer::Usable(view), true) => Response::from_json(&view)?,
        (Answer::Usable(view), false) => {
            // What the visitor opened, rebuilt in its canonical display form: the link the app
            // reads. A path never yields a token, so this is always a code.
            let LookupKey::Code(code) = &key else {
                return Response::error("Not Found", 404);
            };
            let display = crate::auth::invite_code::display(code);
            let origin = req
                .url()
                .map(|u| u.origin().ascii_serialization())
                .unwrap_or_default();
            let link = format!("{origin}/{display}");
            Response::from_html(html::render_invite(lang, &view, &link, &display, now))?
        }
    };
    private(resp, json)
}

/// The HTML page's status. A usable invite and an unusable one are BOTH 200 — only the body
/// differs — because a page any site can embed (`<script src>`, `<object data>`) without reading
/// it still learns its status from the element's load and error events, and 200 against 404 was
/// a free oracle for guessing codes through visitors' browsers (adversarial review 2026-10-14,
/// F5). A refusal stays 429: it says something about the visitor's budget, nothing about the
/// code. The JSON answer keeps its 404: CORS decides who may read that one.
pub(crate) fn page_status(answer: &Answer) -> u16 {
    match answer {
        Answer::Refused { .. } => 429,
        Answer::Unavailable | Answer::Usable(_) => 200,
    }
}

/// The app's question, `POST /invites/describe` with `{"invite": "<code or token>"}`: the same
/// gate, lookup and JSON as `GET /<CODE>`, for an invite the app holds as a bearer token (a
/// personal envelope carries no code), which must not be put in a URL. Text that is neither a
/// code nor a token is a `400` and costs nothing; it names no invite.
pub async fn describe_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    #[derive(serde::Deserialize)]
    struct Body {
        invite: String,
    }
    // As redeem: not JSON, or cross-site from a page not allowed, costs nothing and looks nothing
    // up (`door_cors::post_refusal`).
    if let Some(refused) = crate::door_cors::refuse_post(&req, &ctx.env)? {
        return private(refused, true);
    }
    let key = match req.json::<Body>().await {
        Ok(b) if b.invite.len() <= 128 => LookupKey::parse(b.invite.trim(), true),
        _ => None,
    };
    let Some(key) = key else {
        return private(crate::respond::json_err(400, "bad_request")?, true);
    };
    let limited = crate::utils::var_or(&ctx.env, "ENV", "prod") == "prod";
    let ip = client_ip(&req, &ctx.env);
    let now = now_secs() as i64;
    let resp = match answer_with(&LivePort { env: &ctx.env }, &ip, &key, limited, now).await? {
        Answer::Refused { retry_after_s } => crate::respond::rate_limited(retry_after_s)?,
        Answer::Unavailable => crate::respond::json_err(404, "invite_unavailable")?,
        Answer::Usable(view) => Response::from_json(&view)?,
    };
    private(resp, true)
}

/// Headers every answer of this route carries: never cached (an invite changes as seats go), never
/// indexed, one answer per `Accept`, and — for the page — a policy that allows nothing but its own
/// inline style and the copy button.
fn private(mut resp: Response, json: bool) -> Result<Response> {
    let h = resp.headers_mut();
    h.set("Cache-Control", "no-store")?;
    h.set("Vary", "Accept, Accept-Language")?;
    h.set("X-Robots-Tag", "noindex")?;
    h.set("Referrer-Policy", "no-referrer")?;
    if !json {
        h.set(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )?;
    }
    Ok(resp)
}
