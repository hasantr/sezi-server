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
mod keys;
mod maintenance;
mod media;
mod membership;
mod messages;
mod plugin_blob;
mod plugin_log;
mod plugin_media;
mod push;
mod quota;
mod ratelimit;
mod realtime;
mod respond;
mod self_provision;
mod server;
mod sigv4;
mod storage;
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

/// Daily cleanup cron — driven by `[triggers] crons` in wrangler.toml. The daily
/// body lives in `maintenance::run_daily`, the function SHARED by the cron and the
/// lazy path (it was moved there verbatim). Every cron run refreshes its own
/// timestamp, so on a cron-enabled deployment the lazy path stays asleep (see the
/// maintenance.rs module header); on a cron-less template deployment all
/// maintenance runs off the lazy path instead.
#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Self-host phase-A boot guard: the cron can cold-start an isolate BEFORE any
    // fetch does (on a fresh fork the drain touches the 0021 fanout_retry table), so
    // migrations and key provisioning must be guaranteed here as well. Memoized →
    // no-op on a warm isolate, and a complete no-op on env-secret + wrangler-migrated
    // prod.
    self_provision::ensure_ready(&env).await;
    // W4-b: drain the durable retry queue on EVERY scheduled invocation (Fable #4:
    // matching on the cron string is BRITTLE → run the drain UNCONDITIONALLY, so both
    // the frequent "*/2 * * * *" trigger and the daily "0 4 * * *" one drain).
    crate::messages::handlers::drain_fanout_retry(&env).await;
    membership::drain_purge_outbox(&env).await;
    // Lazy-maintenance stamp: with a live cron the drain stamp is always fresh, so
    // the fetch-path lazy drain NEVER wakes up (prod stays bit-identical).
    maintenance::stamp_drain(&env).await;
    // Pluggable storage phase 4: draining-backend move tick (≤4 blobs per run; exits
    // quietly after one cheap SELECT when no backend is draining). Like the fanout
    // drain it runs on EVERY invocation; the stamp keeps the lazy storage-move asleep
    // on cron-enabled deployments.
    if let Err(e) = storage::drain::run_storage_move(&env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("storage move error: {}", truncated);
    }
    maintenance::stamp_move(&env).await;
    // MINOR-2 (Fable+Codex): bail out early on the frequent cron (no cleanup/GC). The
    // daily "0 4 * * *" AND any unexpected normalization surprise FALL THROUGH to
    // cleanup (fail-toward-running: noisy but SAFE; the old `!= "0 4"` direction would
    // have SILENTLY skipped cleanup+GC on a surprise = media-GC and TTL-GC stall).
    // cleanup is idempotent → an extra run is harmless. The drain already ran
    // unconditionally above → it is never skipped.
    if event.cron() == "*/2 * * * *" {
        return;
    }
    // Daily set (cleanup + fanout TTL-GC + quota reconcile) — the same body the lazy
    // path runs, bit for bit, plus the daily stamp that puts lazy daily-GC to sleep.
    maintenance::run_daily(&env).await;
    maintenance::stamp_daily(&env).await;
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    // Self-host phase-A boot guard: D1 self-migration (A2) + key self-provisioning
    // (A1). Memoized per isolate → runs on the first request, no-op afterwards (NO D1
    // round-trip is added to the hot path). On an env-secret + wrangler-migrated
    // deployment (our prod) it degenerates to a complete no-op. Must run BEFORE
    // /sync: sync_ws validates a token, so the signing key has to be ready.
    self_provision::ensure_ready(&env).await;

    // Lazy-maintenance (cron-less deployments): the request-piggybacked maintenance
    // trigger. Cost on the request critical path is a thread_local time comparison
    // (no D1, no await); the stamp check and any resulting work happen in the
    // background via `ctx.wait_until`.
    maintenance::maybe_run_lazy(&env, &ctx);

    // /sync WS upgrades are handed straight to the DO — handled before the Router
    // because a WS upgrade requires header passthrough.
    let url = req.url()?;
    let path = url.path().to_string();
    if path == "/sync" {
        return sync_ws(req, env).await;
    }

    Router::new()
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
        .post_async("/admin/invites", admin::handlers::create_invite)
        .get_async("/admin/invites", admin::handlers::list_invites)
        .post_async("/admin/revoke-invite", admin::handlers::revoke_invite)
        .get_async("/admin/users", admin::handlers::list_users)
        .post_async("/admin/set-role", admin::handlers::set_role)
        .post_async("/admin/remove-member", admin::handlers::remove_member)
        .post_async(
            "/admin/transfer-ownership",
            admin::handlers::transfer_ownership,
        )
        .patch_async("/admin/server-settings", admin::handlers::update_settings)
        // Virtual server directory + account-level contacts (V2). Directory
        // pages never expose email, last-seen, devices or raw key material.
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
        // CF Analytics config — owner self-service (owner ONLY; WRITE-ONLY: the token
        // can only be written here, no endpoint ever hands it back).
        .patch_async("/admin/cf-config", admin::cf_config::set_cf_config)
        // FCM push config — owner self-service (owner ONLY; WRITE-ONLY: the service
        // account can only be written here, no endpoint ever hands it back).
        .patch_async("/admin/fcm-config", admin::fcm_config::set_fcm_config)
        // Quota epic phase 0: self-reported usage statistics (admin/owner-gated;
        // SHADOW MODE — reporting only, no limit is enforced).
        .get_async("/admin/stats", admin::stats::stats)
        // Server-wide plugin policy. GET = require_auth, i.e. any authenticated caller
        // (their plugin picker filters on the result); POST = require_admin (admin|owner).
        // DISABLED-only storage: a row means the plugin is disabled.
        .get_async("/plugin-policy", admin::plugin_policy::get_plugin_policy)
        .post_async(
            "/admin/plugin-policy",
            admin::plugin_policy::set_plugin_policy,
        )
        // Pluggable storage (phases 2+4) — the owner attaches and manages external blob
        // backends. GET/probe = require_admin; POST/PATCH/DELETE/drain = require_owner
        // (backend credentials are powerful). config_json (a secret) is returned by NO
        // response — WRITE-ONLY, same contract as cf/fcm-config. drain (phase 4) marks
        // a backend for evacuation; the move engine itself lives in storage/drain.rs.
        .get_async("/admin/storage", admin::storage::list)
        .post_async("/admin/storage", admin::storage::add)
        .patch_async("/admin/storage/:id", admin::storage::update)
        .delete_async("/admin/storage/:id", admin::storage::remove)
        .post_async("/admin/storage/:id/probe", admin::storage::probe)
        .post_async("/admin/storage/:id/drain", admin::storage::drain)
        // Groups (phase 1 — membership; member-level, not server-admin). Fan-out is
        // phase 2.
        .post_async("/groups", groups::create_group)
        .get_async("/groups", groups::list_my_groups)
        .get_async("/groups/:id/members", groups::group_members)
        .post_async("/groups/:id/add-member", groups::add_member)
        .post_async("/groups/:id/remove-member", groups::remove_member)
        .post_async("/groups/:id/set-role", groups::set_role)
        .post_async("/groups/:id/settings", groups::update_settings)
        .post_async("/groups/:id/accept", groups::accept_invite)
        .post_async("/groups/:id/decline", groups::decline_invite)
        .delete_async("/groups/:id", groups::delete_group)
        // Multi-device (M1 — store and serve the signed device list; additive).
        .put_async("/devices/list", devices::handlers::put_list)
        .get_async("/devices/list/:user_id", devices::handlers::get_list)
        // Multi-device (M2-S3.2 — QR link flow; all POST, see devices/link.rs).
        .post_async("/devices/link-start", devices::link::link_start)
        .post_async("/devices/link-approve", devices::link::link_approve)
        .post_async("/devices/link-status", devices::link::link_status)
        .get_async("/keys/:user_id/bundle", keys::handlers::bundle)
        .post_async("/keys/otks/replenish", keys::handlers::replenish)
        .post_async("/keys/signed-prekey", keys::handlers::rotate_signed_prekey)
        .post_async("/messages/send", messages::handlers::send)
        .post_async("/messages/read", messages::handlers::read)
        // Shared-root #1: the HTTP twin of receipt-sync — a device without a live WS
        // pulls its own ticks by cursor, returning {rows,more} bit-identical to the WS
        // `receipt_sync` frame.
        .get_async("/messages/receipt-sync", messages::handlers::receipt_sync)
        // Durable sibling-read cursor (2026-06-28): a user's device reports the msg_uids
        // it has read to its own inbox DO (self_read_state), plus a cursor pull. The
        // read-your-own-messages twin of receipt-sync.
        .post_async("/messages/self-read", messages::handlers::self_read)
        .get_async(
            "/messages/self-read-sync",
            messages::handlers::self_read_sync,
        )
        // Plugin/feed server log (phase 2): per-(room, plugin) append-only encrypted
        // log. append = JWT + active member + author binding → DO; sync = cursor pull.
        // The server stays BLIND to the contents.
        .post_async("/plugin-log/:room/:plugin/append", plugin_log::append)
        .get_async("/plugin-log/:room/:plugin/sync", plugin_log::sync)
        .post_async("/plugin-blob/:room/:id", plugin_blob::put_code)
        .get_async("/plugin-blob/:room/:id", plugin_blob::get_code)
        // Member-uploadable PERSISTENT plugin media — plugin_blob's member-PUT, 50 MiB
        // sibling: active-member PUT/GET, room-scoped R2, and quota/usage counters
        // SHARED with the regular media channel.
        .post_async("/plugin-media/:room/:id", plugin_media::put_media)
        .get_async("/plugin-media/:room/:id", plugin_media::get_media)
        .post_async("/media/upload", media::handlers::upload)
        // Avatar blob (Profile Photo epic §2.3): E2E-encrypted, single-slot, exempt from
        // retention. The static `avatar` segment sits at the same level as the `:id`
        // param — matchit prefers static segments, exactly like the /media/upload +
        // /media/:id/ack mix already in the POST tree, so there is no conflict.
        .post_async("/media/avatar", media::avatar::upload)
        .get_async("/media/avatar/:id", media::avatar::download)
        .get_async("/media/:id", media::handlers::download)
        .post_async("/media/:id/ack", media::handlers::ack)
        .post_async("/push/register", push::handlers::register)
        .post_async("/push/unregister", push::handlers::unregister)
        // TURN credentials for calls (calls phase 1.5 — relaying over the internet;
        // budget-gated).
        .post_async("/turn/credentials", turn::credentials)
        .run(req, env)
        .await
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
/// Auth pattern: `Sec-WebSocket-Protocol: sezgi.bearer.v1, <access_token>`.
/// The first subprotocol is the scheme name, the second is the credential. This is
/// the standard "token via subprotocol" technique — the token is not in the URL
/// query, so it never surfaces in CF Workers tail debug logs (URLs are logged,
/// headers are not).
async fn sync_ws(req: Request, env: Env) -> Result<Response> {
    let token = match extract_bearer_subprotocol(&req) {
        Ok(t) => t,
        Err(e) => return json_err(400, e),
    };
    let auth = match crate::auth::middleware::validate_active_token(&env, &token).await {
        Ok(auth) => auth,
        Err(resp) => return Ok(resp),
    };
    let user_id = auth.user_id;
    let upgrade = req.headers().get("upgrade").ok().flatten();
    if upgrade.as_deref().map(|s| s.to_lowercase()) != Some("websocket".into()) {
        return json_err(426, "expected_websocket");
    }

    let namespace = env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?;
    stub.fetch_with_request(req).await
}

/// Parse `Sec-WebSocket-Protocol: sezgi.bearer.v1, <token>` and return the token.
/// The legacy `?token=` query param is no longer supported (hard cutover).
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
