//! `GET /admin/stats` — server usage statistics. An admin/owner-gated at-a-glance
//! summary: member and invite counts, media storage (the server_stats counter), the
//! advertised retention, monthly video call (TURN) usage and daily media volume.
//! REPORTING ONLY — this endpoint enforces no limit.
//!
//! Dual logic: with CF_API_TOKEN installed, request counts come from CF GraphQL
//! Analytics (billing-accurate, `authoritative:true`); without it, or on error, the
//! self-report counters are used (`authoritative:false`, the standalone path).
//! cf_analytics.rs fails open at every layer.
//!
//! If the counter tables have not been migrated yet, the reads fail open with 0 (the
//! turn.rs counter-read pattern), so a minimal install still answers.

use crate::auth::middleware::{require_admin, require_active_auth};
use crate::d1util::{d1_int, d1_text};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct CountRow {
    n: i64,
}

#[derive(Deserialize)]
struct TurnUsageRow {
    issued: i64,
}

#[derive(Deserialize)]
struct MediaStatsRow {
    media_bytes: i64,
    media_count: i64,
}

#[derive(Deserialize)]
struct CapsRow {
    max_storage_bytes: Option<i64>,
    max_user_storage_bytes: Option<i64>,
    // The group library's pair (0040). Both NULLABLE: NULL = unlimited / keep until deleted.
    max_room_library_bytes: Option<i64>,
    library_retention_days: Option<i64>,
}

/// Compact store badge for `/admin/stats`.
#[derive(Deserialize)]
struct StorageSummaryRow {
    total: i64,
    unhealthy: i64,
    draining: i64,
}

pub async fn stats(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }
    let db = ctx.env.d1("DB")?;
    let now = now_secs();

    // Member counts, from the same table list_users uses. `admins` counts every
    // elevated role INCLUDING owner (an owner can do every admin action —
    // consistent with the middleware).
    let members: i64 = db
        .prepare("SELECT COUNT(*) AS n FROM users")
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);
    let admins: i64 = db
        .prepare("SELECT COUNT(*) AS n FROM users WHERE role IN ('admin','owner')")
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);
    // Pending invites: unused, unexpired and not yet claimed in the attribution
    // ledger (same table list_invites reads). Used/expired rows are not actionable
    // anyway and cron eventually prunes them; the ledger check keeps an invite
    // whose `used` flip lost a race from being counted as still pending. A class invite counts
    // while it has a free seat and has not been revoked.
    let invites: i64 = db
        .prepare(
            "SELECT COUNT(*) AS n FROM invite_tokens it
              WHERE it.used = 0 AND it.expires_at > ?
                AND it.revoked_at IS NULL AND it.uses < it.max_uses
                AND NOT EXISTS (
                  SELECT 1 FROM invite_attributions ia
                   WHERE ia.invite_token_hash = it.token_hash
                )",
        )
        .bind(&[d1_int(now as i64)])?
        .first::<CountRow>(None)
        .await?
        .map(|r| r.n)
        .unwrap_or(0);

    // Media storage — the server_stats counter, fed by the upload/ack/cron hooks plus
    // the daily reconcile. Missing table/row or an error → 0 (fail-open).
    let media = db
        .prepare("SELECT media_bytes, media_count FROM server_stats WHERE id = 1 LIMIT 1")
        .first::<MediaStatsRow>(None)
        .await
        .ok()
        .flatten();
    let (media_bytes, media_count) = media
        .map(|m| (m.media_bytes, m.media_count))
        .unwrap_or((0, 0));

    // Retention — the SAME source /capabilities advertises (what we advertise is
    // what we do).
    let media_days = crate::server::handlers::fetch_retention_days(&ctx.env).await;
    let message_days = crate::server::handlers::fetch_message_retention_days(&ctx.env).await;

    // CF Analytics dual logic. `fetch` fails open: with no token/account in either env
    // or D1 it returns None FAST without touching the CF network; a CF error or parse
    // failure logs a console_warn and returns None. None means "use the self-report
    // branch"; stats NEVER 500s.
    let cf = crate::cf_analytics::fetch(&ctx.env).await;

    // cf_configured lets the owner UI know whether a token was entered (env secret OR
    // the D1 value the owner typed in the app). WRITE-ONLY CONTRACT: the token VALUE is
    // returned nowhere, this endpoint included — only this bool. `is_configured` is cheap
    // (no CF network call; fails open to false). How it differs from `authoritative`: a
    // token that is present but failing yields configured=true + authoritative=false, so
    // the UI can say "connected but no data".
    let cf_configured = crate::cf_analytics::is_configured(&ctx.env).await;

    // fcm_configured tells the owner UI whether push can be delivered at all. CAREFUL —
    // it is true when project-id AND service-account are both present (env, or the D1
    // values the owner typed in the app) OR when a push relay URL resolves, and the relay
    // falls back to a built-in default unless explicitly `off`. So this is NOT proof that
    // the owner installed their own FCM credentials. WRITE-ONLY, as with cf_configured:
    // the values are returned nowhere, only this bool. Presence check only, no call to
    // Google; fails open to false.
    let fcm_mode = crate::push::fcm::mode(&ctx.env).await;
    // Whether a TURN credential can be issued at all — the owner screen needs it to say
    // whether calls between DIFFERENT networks will connect. Write-only: the bool only.
    let turn_configured = crate::turn::is_configured(&ctx.env).await;
    let fcm_configured = fcm_mode.can_push();
    // Does the server carry the means to wipe itself? The owner checklist needs this:
    // without a reset key the one irreversible action an owner may legitimately want is
    // unavailable. Presence only — the key is returned nowhere.
    let reset_key_configured = crate::admin::reset::reset_key_configured(&ctx.env).await;

    // requests_today — CF's billing-accurate number when available, otherwise the
    // self-report usage_counters 'requests' row. Counting every request in D1 is
    // too expensive, so nothing writes that row and it is effectively a 0 stub. The
    // wire type is ALWAYS a number, never null, so an older client's i64 parse
    // cannot break; even "CF present but today's field parsed as None" falls back to
    // self-report (per-field fail-open).
    let requests_today_self = crate::usage::read_today(&db, "requests").await;
    let requests_today = cf
        .as_ref()
        .and_then(|c| c.requests_today)
        .unwrap_or(requests_today_self);
    // requests_month — only CF can supply it (there is no monthly self-report counter),
    // so it is null without CF (the client treats it as an Option and renders '—').
    let requests_month = cf.as_ref().and_then(|c| c.requests_month);
    // R2 storage as measured by CF, reported ALONGSIDE the self-report
    // `media.bytes` (it never replaces it) so the two can be reconciled. Null
    // without CF.
    let storage_cf_bytes = cf.as_ref().and_then(|c| c.r2_storage_bytes);

    // Video calls (TURN) — this month's credential-issue counter (the `turn_usage` table
    // that turn.rs's budget guard maintains) plus the advertised cap, read from the SAME
    // source as the guard (turn::monthly_cap). Fail-open: missing table or D1 error → 0,
    // so stats never 500s.
    let turn_issued: i64 = match db
        .prepare("SELECT issued FROM turn_usage WHERE month = ? LIMIT 1")
        .bind(&[d1_text(&crate::turn::current_month_utc())])
    {
        Ok(stmt) => stmt
            .first::<TurnUsageRow>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.issued)
            .unwrap_or(0),
        Err(_) => 0,
    };
    let turn_cap = crate::turn::monthly_cap(&ctx.env);

    // Daily media volume — fed by the count_bump hooks in media/handlers.rs; read_today
    // fails open (missing table/row → 0).
    let upload_bytes_today = crate::usage::read_today(&db, "upload_bytes").await;
    let upload_count_today = crate::usage::read_today(&db, "upload_count").await;
    let download_count_today = crate::usage::read_today(&db, "download_count").await;
    let download_bytes_today = crate::usage::read_today(&db, "download_bytes").await;

    // Monthly media volume — the SUM of this month's usage_counters day rows (read_month
    // uses a month-prefix LIKE, the same month window as the TURN budget). Fails open
    // (missing table or D1 error → 0).
    let upload_bytes_month = crate::usage::read_month(&db, "upload_bytes").await;
    let upload_count_month = crate::usage::read_month(&db, "upload_count").await;
    let download_count_month = crate::usage::read_month(&db, "download_count").await;
    let download_bytes_month = crate::usage::read_month(&db, "download_bytes").await;

    // Quota caps — NULLABLE columns of server_settings. NULL means unlimited; an error, a
    // missing row or a missing migration also yields null (fail-open, so stats never 500s).
    let caps = db
        .prepare(
            "SELECT max_storage_bytes, max_user_storage_bytes, \
             max_room_library_bytes, library_retention_days \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first::<CapsRow>(None)
        .await
        .ok()
        .flatten();
    let (max_storage, max_user_storage) = caps
        .as_ref()
        .map(|c| (c.max_storage_bytes, c.max_user_storage_bytes))
        .unwrap_or((None, None));
    let (max_room_library, library_days) = caps
        .map(|c| (c.max_room_library_bytes, c.library_retention_days))
        .unwrap_or((None, None));

    // The BADGE on the panel's main card: store count, unhealthy count (last_health_ok=0
    // only; NULL = never probed is NOT counted) and whether anything is draining. The
    // detail view (per-store list with secret-free identity/health) comes from
    // `GET /admin/storage`. Fail-open: missing table or D1 error → 0/false.
    let storage = db
        .prepare(
            "SELECT COUNT(*) AS total, \
             COALESCE(SUM(CASE WHEN last_health_ok = 0 THEN 1 ELSE 0 END), 0) AS unhealthy, \
             COALESCE(SUM(CASE WHEN state = 'draining' THEN 1 ELSE 0 END), 0) AS draining \
             FROM storage_backends",
        )
        .first::<StorageSummaryRow>(None)
        .await
        .ok()
        .flatten();
    let (stores_total, stores_unhealthy, draining_count) = storage
        .map(|s| (s.total, s.unhealthy, s.draining))
        .unwrap_or((0, 0, 0));

    Response::from_json(&serde_json::json!({
        "members": members,
        "admins": admins,
        "invites": invites,
        "media": { "bytes": media_bytes, "count": media_count },
        // `library_days` null = the group library is kept until deleted (the default).
        "retention": {
            "media_days": media_days,
            "message_days": message_days,
            "library_days": library_days,
        },
        "requests_today": requests_today,
        "caps": {
            "max_storage_bytes": max_storage,
            "max_user_storage_bytes": max_user_storage,
            "max_room_library_bytes": max_room_library,
        },
        // Monthly video-call (TURN) usage + daily media volume.
        "turn": { "issued_month": turn_issued, "cap": turn_cap },
        "today": {
            "upload_bytes": upload_bytes_today,
            "upload_count": upload_count_today,
            "download_count": download_count_today,
            "download_bytes": download_bytes_today,
        },
        // This month's media volume for the "THIS MONTH" card (a usage_counters SUM).
        // requests_month (CF-only) already lives at top level and TURN issued_month
        // inside the turn block, so neither is repeated here.
        "month": {
            "upload_bytes": upload_bytes_month,
            "upload_count": upload_count_month,
            "download_count": download_count_month,
            "download_bytes": download_bytes_month,
        },
        // The dual-logic contract fields. `backend` is where this binary runs (a future
        // standalone port will send "standalone"); `authoritative` true means the numbers
        // match the CF bill exactly (GraphQL Analytics), false means self-report (no
        // token, or a CF error). `storage_cf_bytes` is CF's measurement and never replaces
        // the self-report media.bytes.
        "backend": "cf",
        "authoritative": cf.is_some(),
        "requests_month": requests_month,
        "storage_cf_bytes": storage_cf_bytes,
        // "Is a token present" bool — NEVER the value (write-only contract).
        "cf_configured": cf_configured,
        // "Can push be delivered" bool — NEVER the values (write-only).
        "fcm_configured": fcm_configured,
        // Which of the two ways, so the owner screen does not imply the shared relay was
        // something they set up: a server with zero FCM keys still reports
        // fcm_configured=true, because the relay default is on.
        "fcm_mode": fcm_mode.as_str(),
        "turn_configured": turn_configured,
        // Shipped under the SAME `version` as the storage badge — a client cannot gate on
        // the version number for it, only on the key's presence. Absent on an older server
        // → the client reads it as false and shows the gap, which is the safe direction:
        // claiming a server can be reset when it cannot wastes the owner's time at the
        // worst moment.
        "reset_key_configured": reset_key_configured,
        // The compact store badge; detail lives at GET /admin/storage. draining = is any
        // store being emptied.
        "storage": {
            "stores_total": stores_total,
            "stores_unhealthy": stores_unhealthy,
            "draining": draining_count > 0,
        },
        "version": 8,
    }))
}
