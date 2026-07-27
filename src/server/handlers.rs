use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct ServerSettingsRow {
    name: String,
    join_mode: String,
    directory_mode: String,
    dm_policy: String,
}

/// Stable instance binding for signed contact-request transcripts. The public
/// JWT signing key is already the server's durable identity; hash its canonical
/// base64url JWK `x` value so no secret or raw key is persisted in contact rows.
pub(crate) fn server_instance_fingerprint(env: &Env) -> Result<String> {
    let jwk = crate::auth::jwt::public_jwk(env)?;
    Ok(crate::auth::hashing::sha256_hex(&jwk.x))
}

pub async fn info(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = ctx.env.d1("DB")?;
    let row: Option<ServerSettingsRow> = db
        .prepare(
            "SELECT name, join_mode, directory_mode, dm_policy
               FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first(None)
        .await?;
    let (name, join_mode, directory_mode, dm_policy) = row
        .map(|r| (r.name, r.join_mode, r.directory_mode, r.dm_policy))
        .unwrap_or_else(|| {
            (
                "Sezi".into(),
                "invite_only".into(),
                "off".into(),
                "members".into(),
            )
        });
    // owner_exists answers onboarding's very first question — is this server owned or
    // unowned — with ONE side-effect-free field. Without it the app has to probe
    // /bootstrap for 200-vs-410, and that gate runs the ghost-owner audit SELECTs plus a
    // possible self-heal batch. The definition of "owner" has a SINGLE authority in
    // welcome.rs (bit-identical SELECT); there is no copy of it here. FAIL-SECURE: if the
    // query fails (None) we answer `true`, i.e. "assume owned", so an unowned server is
    // never mistakenly advertised as claimable — the app still confirms definitively via
    // /bootstrap. The field is additive, so existing /server/info consumers parsing
    // name/join_mode keep working.
    let owner_exists = crate::welcome::owner_exists(&ctx.env).await.unwrap_or(true);
    Response::from_json(&serde_json::json!({
        "name": name,
        "join_mode": join_mode,
        "directory_mode": directory_mode,
        "dm_policy": dm_policy,
        "server_fingerprint": server_instance_fingerprint(&ctx.env)?,
        // Transitional alias for early P1 clients; canonical field is
        // `server_fingerprint`.
        "server_instance_fingerprint": server_instance_fingerprint(&ctx.env)?,
        "owner_exists": owner_exists,
    }))
}

/// The capabilities this server supports. The client calls `/capabilities` and enables or
/// greys out its UI toggles according to the returned `p2p.kinds` list.
///
/// Current state (P2P scaffolding mode):
///   - `p2p.supported = true` — the client enables its UI toggles so the user's preference
///     can be stored.
///   - `p2p.kinds = ["message", "image", "attachment", "file"]` — every kind is permitted.
///   - `transport = "iroh-pending"` — the server advertises the iroh signaling scaffold,
///     but no real transport bridging is active yet.
///   - **Behaviour**: the client still sends all traffic over CF, because the mobile
///     `shouldUseP2P()` helper sees `transportAvailable=false` and falls back to CF. When
///     the P3 integration lands the transport switches on by itself, with user preferences
///     already saved.
///
/// Versioning: the `version` field increases on a protocol change, and the client uses it
/// to cope with incompatible versions.
pub async fn capabilities(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Server name, from server_settings — the same source as /server/info.
    let db = ctx.env.d1("DB")?;
    let row: Option<ServerSettingsRow> = db
        .prepare(
            "SELECT name, join_mode, directory_mode, dm_policy
               FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first(None)
        .await?;
    let (name, directory_mode, dm_policy) = row
        .map(|r| (r.name, r.directory_mode, r.dm_policy))
        .unwrap_or_else(|| ("Sezi".into(), "off".into(), "members".into()));
    let retention_days = fetch_retention_days(&ctx.env).await;
    let message_retention_days = fetch_message_retention_days(&ctx.env).await;
    let delete_window_hours = fetch_delete_window_hours(&ctx.env).await;
    // Lite install (R2 is OPTIONAL): features that depend on the MEDIA binding are announced
    // DYNAMICALLY. If the owner adds the binding from the dashboard later — no redeploy
    // needed — the next /capabilities call returns true and the client card updates itself.
    // Faz 1: any_available is simply "is the MEDIA binding present", bit-identical to the old
    // MediaStore::available. Faz 3: the router will also see external stores from D1, so a
    // Lite+B2 install reports true.
    let media_ok = crate::storage::StorageRouter::from_env(&ctx.env)
        .await
        .map(|r| r.any_available())
        .unwrap_or(false);
    Response::from_json(&serde_json::json!({
        "version": 1,
        // Self-host update detection (2026-07-12): a BUILD-TIME stamp, a monotonic
        // yyyyMMddHHmm integer. `sync-template.ps1` sets the `SEZI_BUILD` env var BEFORE the
        // worker build and writes the same value into a `VERSION` file at the template root,
        // so the stamp and the prebuilt WASM always come out of the SAME run (no drift). The
        // client compares its current build against the upstream VERSION to decide whether an
        // update exists. With no env var — monorepo prod, or a manual deploy — 0 means
        // "unknown" and the client shows no badge. Keep this separate from `version`, which is
        // the protocol version.
        "build": option_env!("SEZI_BUILD").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
        "name": name,
        "server_fingerprint": server_instance_fingerprint(&ctx.env)?,
        "server_instance_fingerprint": server_instance_fingerprint(&ctx.env)?,
        "policy": {
            "directory_mode": directory_mode,
            "dm_policy": dm_policy,
            "directory_v2": true,
            "contacts_v2": true,
            "contact_trust": "server_asserted",
            "contact_request_signature": "ed25519-active-device-v1",
            "common_group_exception": true,
            "qr_v2": true,
            "account_leave_v1": true,
            "profile_name_v1": true,
            "contact_nudge_v1": true,
            "avatar_v1": true
        },
        // M2-S2.3 (WIRE-CUT): the protocol capability announcement. device_addressing=1 means
        // the server supports the batch wire format (envelopes[]) and per-device OTK/bundle v2;
        // the old single envelope_b64 form now gets a 400. The client sends the batch form
        // accordingly and the legacy single form is removed.
        "protocol": {
            "device_addressing": 1
        },
        // Data retention announcement. The model is "relay": a message is deleted by the DO
        // fan-out on delivery (`on_delivery`), and an undelivered one is kept for at most
        // `message_days`.
        // ⚠️ MEDIA HONESTY (2026-07-10 audit #3): the media ACK-delete chain is NOT wired up
        // on the client, so media is NOT deleted on delivery — in every case it is kept until
        // the `media_days` TTL. Hence `media: "ttl"` rather than on_delivery: the announcement
        // matches actual behaviour exactly. Genuine delete-after-delivery would require
        // recipient/room bookkeeping (the audit #2 + #3 epic).
        "retention": {
            "model": "relay",
            "messages": "on_delivery",
            "media": "ttl",
            "media_days": retention_days,
            "message_days": message_retention_days,
        },
        // The "delete for everyone" window (2026-07-12): how many HOURS after a message was
        // SENT it may still be deleted for everyone. Owner-configurable, DEFAULT 48. The
        // recipient side will ENFORCE this in future (message age > window → reject); the
        // server only announces the VALUE. Twin of the retention pattern, also from D1
        // server_settings. Deliberately top-level rather than inside the retention block,
        // because the client expects a flat `delete_window_hours` field.
        "delete_window_hours": delete_window_hours,
        // Server feature announcement (C3). true = supported, false = not configured or not
        // implemented yet.
        // R2 dependency map (Lite install, verified against the code on 2026-07-06):
        //   - media/files → media/handlers.rs upload/download are R2 blobs → media_ok.
        //   - apps → plugin code distribution goes through plugin_blob.rs put/get_code, i.e.
        //     R2: anything over 8KB, and ALL bundles unconditionally (see core
        //     plugin_install.rs CODE_INLINE_THRESHOLD). The plugin log is DO-based and works
        //     without R2, and a single ≤8KB html goes inline, but the platform's main
        //     distribution path is R2, so an honest announcement is media_ok.
        //   - backup → there is NO server endpoint at all: backup is local-file export/import
        //     in core and the worker has no backup route, so it is INDEPENDENT of R2 and
        //     stays true.
        //   - calls → signaling relay (DO/WS) plus TURN (CF Calls API), fully functional
        //     without R2, hence true.
        "features": {
            "messaging": true,
            "media": media_ok,
            "files": media_ok,
            "calls": true,
            "backup": true,
            "apps": media_ok
        },
        // ⚠️ P2P HONESTY (2026-07-10 audit #5): `supported:true` means the capability EXISTS
        // and client toggles can be persisted, while `available:false` means the transport is
        // NOT ACTIVE YET (iroh-pending). Both are stated so that anyone reading the raw JSON —
        // an auditor, a third-party client — cannot conclude that P2P is working. The client
        // already falls back to CF unless `transport=='iroh'` (p2p_router.shouldUseP2P).
        // `available` and `status` are additive, so existing parsers of `supported`/`transport`
        // keep working.
        "p2p": {
            "supported": true,
            "available": false,
            "status": "experimental",
            "kinds": ["message", "image", "attachment", "file"],
            "transport": "iroh-pending",
            "note": "scaffolding mode; client preferences saved, transport activates with P3"
        }
    }))
}

/// `server_settings.retention_days` — how many days undelivered media is kept (the cron
/// fallback window). Missing table or row, or any error, yields the default of 30. Both the
/// `/capabilities` announcement and `media/upload`'s `expires_at` computation read this.
pub async fn fetch_retention_days(env: &Env) -> i64 {
    let Ok(db) = env.d1("DB") else {
        return 30;
    };
    #[derive(Deserialize)]
    struct R {
        retention_days: i64,
    }
    let row: Option<R> = db
        .prepare("SELECT retention_days FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
        .ok()
        .flatten();
    row.map(|r| r.retention_days).unwrap_or(30)
}

/// `server_settings.message_retention_days` — how many days an undelivered message stays in
/// the DO `pending` queue (the DO alarm cleanup window). Missing table, row or column, or any
/// error, yields the default of 30. Both the `/capabilities` announcement and the inbox_do
/// alarm cleanup read this.
pub async fn fetch_message_retention_days(env: &Env) -> i64 {
    let Ok(db) = env.d1("DB") else {
        return 30;
    };
    #[derive(Deserialize)]
    struct R {
        message_retention_days: i64,
    }
    let row: Option<R> = db
        .prepare("SELECT message_retention_days FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
        .ok()
        .flatten();
    row.map(|r| r.message_retention_days).unwrap_or(30)
}

/// `server_settings.delete_window_hours` — the owner-configurable "delete for everyone"
/// window: how many HOURS after a message was SENT it may still be deleted for everyone. The
/// recipient side will ENFORCE this in future; `/capabilities` only announces the VALUE.
/// Missing table, row or column, or any error, yields the default of 48 — twin of the
/// message_retention_days pattern.
pub async fn fetch_delete_window_hours(env: &Env) -> i64 {
    let Ok(db) = env.d1("DB") else {
        return 48;
    };
    #[derive(Deserialize)]
    struct R {
        delete_window_hours: i64,
    }
    let row: Option<R> = db
        .prepare("SELECT delete_window_hours FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
        .ok()
        .flatten();
    row.map(|r| r.delete_window_hours).unwrap_or(48)
}
