use crate::auth::jwt::public_jwk;
use crate::respond::json_err;
use worker::*;

mod admin;
mod auth;
mod cf_analytics;
mod contact_grant;
mod contact_qr;
mod contacts;
mod d1util;
mod devices;
mod email;
mod groups;
mod instrument_pack;
mod keys;
mod maintenance;
mod media;
mod membership;
mod messages;
mod page_cursor;
mod plugin_blob;
mod plugin_log;
mod plugin_media;
mod push;
mod quota;
mod ratelimit;
mod realtime;
mod respond;
mod room_library;
mod self_provision;
mod server;
mod sigv4;
mod storage;
#[cfg(test)]
mod test_schema;
mod turn;
mod usage;
mod utils;
mod welcome;

pub use messages::inbox_do::UserInbox;
pub use plugin_log::PluginRoomLog;

#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// Daily cleanup cron — driven by `[triggers] crons` in wrangler.toml. The daily body is
/// `maintenance::run_daily`, SHARED with the lazy path. Every cron run refreshes its own timestamp,
/// so on a cron-enabled deployment the lazy path stays asleep (see the maintenance.rs header); on a
/// cron-less template deployment all maintenance runs off the lazy path instead.
#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Boot guard: the cron can cold-start an isolate BEFORE any fetch does, and the drain touches
    // tables a fresh fork has not created, so migrations and key provisioning must be guaranteed
    // here too. Memoized → a no-op on a warm isolate, and on an already-provisioned deployment.
    self_provision::ensure_ready(&env).await;
    // Drain the durable retry queue on EVERY scheduled invocation: matching on the cron string is
    // brittle, so both the frequent trigger and the daily one drain.
    crate::messages::handlers::drain_fanout_retry(&env).await;
    membership::drain_purge_outbox(&env).await;
    // With a live cron the drain stamp is always fresh, so the fetch-path lazy drain never wakes.
    maintenance::stamp_drain(&env).await;
    // Draining-backend move tick (≤4 blobs per run; exits after one cheap SELECT when no backend
    // is draining). Like the fanout drain it runs on EVERY invocation, and its stamp likewise keeps
    // the lazy storage-move asleep.
    if let Err(e) = storage::drain::run_storage_move(&env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("storage move error: {}", truncated);
    }
    maintenance::stamp_move(&env).await;
    // Bail out early on the frequent cron (no cleanup/GC). The test is written this way round so
    // that the daily trigger AND any unexpected cron string FALL THROUGH to cleanup: cleanup is
    // idempotent, so an extra run is harmless, while the opposite direction would silently stall
    // media-GC and TTL-GC on a surprise. The drain above already ran unconditionally.
    if event.cron() == "*/2 * * * *" {
        return;
    }
    // Daily set (cleanup + fanout TTL-GC + quota reconcile) — the same body the lazy path runs,
    // plus the daily stamp that puts lazy daily-GC to sleep.
    maintenance::run_daily(&env).await;
    maintenance::stamp_daily(&env).await;
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    // Boot guard: D1 self-migration + key self-provisioning. Memoized per isolate, so it runs on
    // the first request and adds no D1 round-trip to the hot path afterwards. Must run BEFORE
    // /sync: sync_ws validates a token, so the signing key has to be ready.
    self_provision::ensure_ready(&env).await;

    // Lazy maintenance, for cron-less deployments: the cost on the critical path is a thread_local
    // time comparison (no D1, no await), and the stamp check plus any resulting work happen in the
    // background via `ctx.wait_until`.
    maintenance::maybe_run_lazy(&env, &ctx);

    // /sync WS upgrades are handed straight to the DO — handled before the Router
    // because a WS upgrade requires header passthrough.
    let url = req.url()?;
    let path = url.path().to_string();
    if path == "/sync" {
        return sync_ws(req, env).await;
    }

    // CORS preflight. A browser sends this before any request that carries `Authorization`, and
    // it never reaches the router — there is no `OPTIONS` route and adding sixty of them would
    // be the wrong shape. See `cors_headers` for why the policy is what it is.
    if req.method() == Method::Options {
        let mut resp = Response::empty()?.with_status(204);
        apply_cors(resp.headers_mut())?;
        return Ok(resp);
    }

    let mut resp = Router::new()
        // Root = welcome page (human-readable; a fresh install shows "your server is
        // ready" plus copy-the-address instructions instead of an alarming 404).
        // The API surface is untouched.
        .get_async("/", welcome::welcome)
        .get("/healthz", |_, _| {
            Response::from_json(&serde_json::json!({"ok": true}))
        })
        .get_async("/.well-known/jwks.json", jwks)
        .get_async("/server/info", server::handlers::info)
        .get_async("/capabilities", server::handlers::capabilities)
        .get_async("/bootstrap", auth::bootstrap::bootstrap)
        .post_async("/auth/redeem", auth::invite::redeem)
        .post_async("/auth/verify", auth::verify::verify)
        .post_async("/auth/refresh", auth::refresh::refresh)
        .post_async("/auth/relogin", auth::relogin::relogin)
        .get_async("/auth/me", auth::me::me)
        .patch_async("/auth/profile", auth::profile::update)
        .post_async("/auth/leave", membership::leave)
        .post_async("/admin/invites", admin::invites::create_invite)
        .get_async("/admin/invites", admin::invite_list::list_invites)
        .post_async("/admin/revoke-invite", admin::invites::revoke_invite)
        .get_async("/admin/users", admin::handlers::list_users)
        .post_async("/admin/set-role", admin::handlers::set_role)
        .post_async("/admin/remove-member", admin::handlers::remove_member)
        .post_async(
            "/admin/transfer-ownership",
            admin::handlers::transfer_ownership,
        )
        .patch_async("/admin/server-settings", admin::handlers::update_settings)
        // Owner-only DATA wipe, gated a second time by the `RESET_PASSWORD` secret — a server that
        // never set one cannot be wiped over the network at all. See admin/reset.rs.
        .post_async("/admin/reset", admin::reset::reset)
        // The destruction kit itself: the owner sets it from the app, so a server deployed with the
        // dashboard button is not left unable to reset itself for want of shell access.
        .post_async("/admin/reset-key", admin::reset::set_reset_key)
        // Virtual server directory + account-level contacts (V2). Directory pages never expose
        // email, last-seen, devices or raw key material.
        .get_async("/directory", contacts::directory)
        .get_async("/directory/changes", contacts::directory_changes)
        .get_async("/directory/visibility", contacts::get_visibility)
        .patch_async("/directory/visibility", contacts::set_visibility)
        .get_async("/contacts/state/:user_id", contacts::contact_state)
        .get_async("/contacts/requests", contacts::list_requests)
        .post_async("/contacts/requests", contacts::create_request)
        .post_async("/contacts/requests/:id/respond", contacts::respond_request)
        .post_async("/contacts/requests/:id/revoke", contacts::revoke_request)
        .get_async("/contacts/grants", contacts::list_grants)
        .post_async("/contacts/grants/:id/revoke", contacts::revoke_grant)
        .get_async("/contacts/blocks", contacts::list_blocks)
        .post_async("/contacts/blocks", contacts::block)
        .delete_async("/contacts/blocks/:user_id", contacts::unblock)
        .get_async("/contacts/changes", contacts::contact_changes)
        // Short-lived, single-use mutual contact QR. The raw capability secret is
        // never stored on the server; a claim atomically wins exactly once.
        .post_async("/contacts/qr/offers", contact_qr::create_offer)
        .post_async("/contacts/qr/claims", contact_qr::claim_offer)
        .get_async("/contacts/qr/offers/:id/status", contact_qr::offer_status)
        // CF Analytics config — owner ONLY and WRITE-ONLY: the token can be written here, and no
        // endpoint ever hands it back.
        .patch_async("/admin/cf-config", admin::cf_config::set_cf_config)
        // FCM push config — owner ONLY and WRITE-ONLY, same contract as cf-config.
        .patch_async("/admin/fcm-config", admin::fcm_config::set_fcm_config)
        .patch_async("/admin/turn-config", admin::turn_config::set_turn_config)
        // Self-reported usage statistics, admin/owner-gated. SHADOW MODE: reporting only, no
        // limit is enforced.
        .get_async("/admin/stats", admin::stats::stats)
        // Per-group library usage (admin/owner): sizes, counts and dates — never content, which
        // the server does not have. Paged, largest first.
        .get_async("/admin/library", admin::library::usage)
        // Shorten the library retention: preview (admin), then apply on an explicit confirm
        // (owner). Deletion itself happens at the nightly sweep. See admin/library_retention.rs.
        .get_async(
            "/admin/library/retention-preview",
            admin::library_retention::preview,
        )
        .post_async("/admin/library/retention", admin::library_retention::apply)
        // Server-wide plugin policy. GET = require_active_auth, i.e. any caller whose account
        // still exists and whose token-bound device is not revoked (their plugin picker filters
        // on the result); POST = require_admin (admin|owner). Not `require_auth`: that one gates
        // on the stateless JWT alone, and a revoked device's access token stays valid for ~15
        // minutes — `admin/mod.rs` has a test that fails the build if an admin module uses it.
        // DISABLED-only storage: a row means the plugin is disabled.
        .get_async("/plugin-policy", admin::plugin_policy::get_plugin_policy)
        .post_async(
            "/admin/plugin-policy",
            admin::plugin_policy::set_plugin_policy,
        )
        // Pluggable storage — the owner attaches and manages external blob backends. GET/probe =
        // require_admin; POST/PATCH/DELETE/drain = require_owner, because backend credentials are
        // powerful. `config_json` is a secret returned by NO response — WRITE-ONLY, same contract
        // as cf/fcm-config. drain marks a backend for evacuation; the move engine is storage/drain.rs.
        .get_async("/admin/storage", admin::storage::list)
        .post_async("/admin/storage", admin::storage::add)
        .patch_async("/admin/storage/:id", admin::storage::update)
        .delete_async("/admin/storage/:id", admin::storage::remove)
        .post_async("/admin/storage/:id/probe", admin::storage::probe)
        .post_async("/admin/storage/:id/drain", admin::storage::drain)
        // Groups — membership, member-level rather than server-admin.
        .post_async("/groups", groups::create_group)
        .get_async("/groups", groups::list_my_groups)
        .get_async("/groups/:id/members", groups::group_members)
        .post_async("/groups/:id/add-member", groups::add_member)
        .post_async("/groups/:id/remove-member", groups::remove_member)
        .post_async("/groups/:id/set-role", groups::set_role)
        .post_async("/groups/:id/settings", groups::update_settings)
        .post_async("/groups/:id/accept", groups::accept_invite)
        .post_async("/groups/:id/decline", groups::decline_invite)
        // Join requests a class invite left in its landing group (`groups_requests.rs`): the
        // group's admins decide; the requester reads only their own.
        .get_async("/groups/:id/join-requests", groups::list_join_requests)
        .post_async(
            "/groups/:id/join-requests/approve-all",
            groups::approve_all_join_requests,
        )
        .post_async(
            "/groups/:id/join-requests/:user/approve",
            groups::approve_join_request,
        )
        .post_async("/groups/:id/join-requests/:user/deny", groups::deny_join_request)
        .get_async("/join-requests/mine", groups::my_join_requests)
        .delete_async("/groups/:id", groups::delete_group)
        // Multi-device: store and serve the signed device list.
        .put_async("/devices/list", devices::handlers::put_list)
        .get_async("/devices/list/:user_id", devices::handlers::get_list)
        // What the server OBSERVED about my own devices, beside the signed list rather than
        // inside it — the primary signs that document and cannot know when another device last
        // connected. Self only.
        .get_async("/devices/activity", devices::handlers::get_activity)
        // QR device-link flow; all POST, see devices/link.rs.
        .post_async("/devices/link-start", devices::link::link_start)
        .post_async("/devices/link-approve", devices::link::link_approve)
        .post_async("/devices/link-status", devices::link::link_status)
        .get_async("/keys/:user_id/bundle", keys::handlers::bundle)
        .post_async("/keys/otks/replenish", keys::handlers::replenish)
        // Diagnostic: the caller's OWN unconsumed pool depth. `bundle` claims an OTK
        // per active device on every fetch while the core counts only the PreKeys it decrypts,
        // so the local number is not a proxy for this one — the core logs both together.
        .get_async("/keys/otks/count", keys::handlers::otk_count)
        .post_async("/keys/signed-prekey", keys::handlers::rotate_signed_prekey)
        .post_async("/messages/send", messages::handlers::send)
        .post_async("/messages/read", messages::handlers::read)
        // The HTTP twin of receipt-sync: a device without a live WS pulls its own ticks by cursor,
        // returning {rows,more} identical to the WS `receipt_sync` frame.
        .get_async("/messages/receipt-sync", messages::handlers::receipt_sync)
        // Durable sibling-read cursor: a device reports the msg_uids it has read to its own inbox
        // DO (self_read_state), plus a cursor pull. The read-your-own-messages twin of the above.
        .post_async("/messages/self-read", messages::handlers::self_read)
        .get_async(
            "/messages/self-read-sync",
            messages::handlers::self_read_sync,
        )
        // Plugin/feed server log: a per-(room, plugin) append-only encrypted log. append = JWT +
        // active member + author binding → DO; sync = cursor pull. The server stays BLIND to the
        // contents.
        .post_async("/plugin-log/:room/:plugin/append", plugin_log::append)
        .get_async("/plugin-log/:room/:plugin/sync", plugin_log::sync)
        .post_async("/plugin-blob/:room/:id", plugin_blob::put_code)
        .get_async("/plugin-blob/:room/:id", plugin_blob::get_code)
        // Member-uploadable PERSISTENT plugin media — plugin_blob's member-PUT, 50 MiB sibling:
        // active-member PUT/GET, room-scoped R2, quota/usage counters SHARED with regular media.
        .post_async("/plugin-media/:room/:id", plugin_media::put_media)
        .get_async("/plugin-media/:room/:id", plugin_media::get_media)
        // The group LIBRARY (campus plan R1): durable encrypted parts charged to the room, with
        // their own retention and per-group cap. Active-member PUT/GET/list; DELETE by the
        // uploader or a group admin. GET streams. See room_library.rs for the full contract.
        .put_async("/room-library/:room/:id", room_library::put_object)
        .get_async("/room-library/:room/:id", room_library::get_object)
        .delete_async("/room-library/:room/:id", room_library::delete_object)
        .get_async("/room-library/:room", room_library::list_objects)
        // The operator-hosted instrument pack (music studio): one SoundFont per server. PUT and
        // DELETE are owner-only; both GETs take any active member token. This is the ONE object
        // the relay stores and serves in PLAINTEXT — see instrument_pack.rs for why. The static
        // `meta` segment sits above the bare path, which matchit resolves without ambiguity.
        .put_async("/admin/instrument-pack", instrument_pack::put_pack)
        .delete_async("/admin/instrument-pack", instrument_pack::delete_pack)
        .get_async("/instrument-pack/meta", instrument_pack::meta)
        .get_async("/instrument-pack", instrument_pack::download)
        .post_async("/media/upload", media::handlers::upload)
        // Avatar blob: E2E-encrypted, single-slot, exempt from retention. The static `avatar`
        // segment sits at the same level as the `:id` param — matchit prefers static segments,
        // like the /media/upload + /media/:id/ack mix already here, so there is no conflict.
        .post_async("/media/avatar", media::avatar::upload)
        .get_async("/media/avatar/:id", media::avatar::download)
        .get_async("/media/:id", media::handlers::download)
        .post_async("/media/:id/ack", media::handlers::ack)
        .post_async("/push/register", push::handlers::register)
        .post_async("/push/unregister", push::handlers::unregister)
        // TURN credentials for calls — relaying over the internet, budget-gated.
        .post_async("/turn/credentials", turn::credentials)
        .run(req, env)
        .await?;
    apply_cors(resp.headers_mut())?;
    Ok(resp)
}

/// Let a browser talk to this server.
///
/// A native app makes the request it means to make; a page cannot. The browser will not hand back
/// a cross-origin response unless the server says it may, and with an `Authorization` header it
/// will not send the request at all until a preflight `OPTIONS` allows the header.
///
/// **`*`, and it is not a weakening.** CORS is not an authorization boundary: it governs what one
/// ORIGIN may read from another in a browser, and this API is authorized by a bearer token a page
/// only holds if the user put it there. The wildcard also makes credentialed requests illegal, so
/// no cookie or client certificate can ride along. An echoed allow-list buys nothing — a
/// self-hosted server cannot know which page its owner runs the web client from.
///
/// `/sync` is not covered and need not be: a WebSocket handshake is exempt from the same-origin
/// policy, which is also why its token travels as a subprotocol.
fn apply_cors(headers: &mut Headers) -> Result<()> {
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    )?;
    // `x-sezi-scope-*` is the media upload's group gate (`media/handlers.rs`). A header the client
    // sends but this list omits fails the preflight, and the browser reports it as a generic CORS
    // failure — so the two have to be kept in step by hand. `x-pack-name` is the instrument
    // pack's display name, and `If-None-Match` its conditional GET: neither is CORS-safelisted,
    // so a browser that sent one without this line would be refused before the request left.
    // `x-sezi-library-kind` is the group library's part label (`room_library.rs`).
    headers.set(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, If-None-Match, Range, x-sezi-scope-kind, x-sezi-scope-id, x-pack-name, x-sezi-library-kind",
    )?;
    // Without this a page can read only the six CORS-safelisted response headers, so
    // `content-length` — which the media download path checks before allocating — comes back
    // absent rather than wrong. `ETag`/`Content-Range`/`Accept-Ranges` are the instrument pack's
    // resume machinery: unexposed, a page cannot tell a resumed download from a fresh one.
    // `Retry-After` is the auth door's wait (`respond::rate_limited`); unexposed, the browser's
    // door could only say "a few minutes" where the app counts down.
    headers.set(
        "Access-Control-Expose-Headers",
        "Content-Length, Content-Type, ETag, Content-Range, Accept-Ranges, Retry-After",
    )?;
    // One preflight per day per (origin, method, header set) instead of one per request.
    headers.set("Access-Control-Max-Age", "86400")?;
    Ok(())
}

async fn jwks(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let jwk = public_jwk(&ctx.env)?;
    let mut resp = Response::from_json(&serde_json::json!({ "keys": [jwk] }))?;
    let headers = resp.headers_mut();
    headers.set("cache-control", "public, max-age=300")?;
    Ok(resp)
}

/// WS /sync upgrade: validate the token, then proxy the original request to the
/// user's DO stub (the WS pair is established inside the DO via header passthrough).
///
/// Auth: `Sec-WebSocket-Protocol: sezgi.bearer.v1, <access_token>` — the first subprotocol names
/// the scheme, the second carries the credential. The token stays out of the URL query, so it
/// never surfaces in Workers tail logs (URLs are logged, headers are not).
async fn sync_ws(req: Request, env: Env) -> Result<Response> {
    let token = match extract_bearer_subprotocol(&req) {
        Ok(t) => t,
        Err(e) => return json_err(400, e),
    };
    let auth = match crate::auth::middleware::validate_active_token(&env, &token).await {
        Ok(auth) => auth,
        Err(resp) => return Ok(resp),
    };
    // "This device connected" — the truest form of the question the devices screen asks, and once
    // per socket rather than once per request. Best-effort: failing to record it is not a reason
    // to refuse the connection. See `touch_device_seen`.
    if let Err(e) =
        crate::auth::middleware::touch_device_seen(&env, &auth.user_id, &auth.device_id).await
    {
        console_log!("last_seen touch failed on sync for {}: {e}", auth.device_id);
    }
    let user_id = auth.user_id;
    let upgrade = req.headers().get("upgrade").ok().flatten();
    if upgrade.as_deref().map(|s| s.to_lowercase()) != Some("websocket".into()) {
        return json_err(426, "expected_websocket");
    }

    let namespace = env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?;
    stub.fetch_with_request(req).await
}

/// Parse `Sec-WebSocket-Protocol: sezgi.bearer.v1, <token>` and return the token. A `?token=`
/// query param is not accepted.
pub(crate) fn extract_bearer_subprotocol(
    req: &Request,
) -> std::result::Result<String, &'static str> {
    let raw = req
        .headers()
        .get("Sec-WebSocket-Protocol")
        .ok()
        .flatten()
        .ok_or("subprotocol_required")?;
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.len() != 2 || parts[0] != "sezgi.bearer.v1" {
        return Err("expected_subprotocol_sezgi_bearer_v1");
    }
    if parts[1].is_empty() {
        return Err("token_empty");
    }
    Ok(parts[1].to_string())
}
