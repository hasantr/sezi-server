//! `GET /admin/stats` — server usage statistics (quota epic **Faz 0**
//! SHADOW-MODE, **Faz 1c** widening, **Faz 3** CF Analytics dual logic).
//! An admin/owner-gated at-a-glance summary: member and invite counts, media
//! storage (the server_stats counter), the advertised retention, monthly video
//! call (TURN) usage and daily media volume. REPORTING ONLY — this endpoint
//! enforces no limit.
//!
//! Faz 3 dual logic: with CF_API_TOKEN installed, request counts come from CF
//! GraphQL Analytics (billing-accurate, `authoritative:true`); without it, or on
//! error, the self-report counters are used unchanged (`authoritative:false`, the
//! VPS/standalone path). cf_analytics.rs fails open at every layer.
//!
//! If the newer counter tables (0022/0009) have not been migrated yet, the reads
//! fail open with 0 (the turn.rs counter-read pattern), so stats-lite always
//! works.

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
}

/// Pluggable storage Faz 3 (v8) — compact store badge for `/admin/stats`.
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
    // whose `used` flip lost a race from being counted as still pending.
    let invites: i64 = db
        .prepare(
            "SELECT COUNT(*) AS n FROM invite_tokens it
              WHERE it.used = 0 AND it.expires_at > ?
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

    // Media storage — the server_stats SHADOW counter (0022), fed by the
    // upload/ack/cron hooks plus the daily reconcile. Missing table/row or an
    // error → 0 (fail-open).
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

    // Faz 3 — CF Analytics dual logic. `fetch` fails open: with no token/account
    // (neither env nor D1 — VPS/standalone, or simply never entered) it returns
    // None FAST without touching the CF network (today's behaviour, bit for bit);
    // a CF error or parse failure logs a console_warn and returns None. None means
    // "use the self-report branch"; stats NEVER 500s.
    let cf = crate::cf_analytics::fetch(&ctx.env).await;

    // v6: cf_configured lets the owner UI know whether a token was entered (env
    // secret OR the D1 value the owner typed in the app). WRITE-ONLY CONTRACT: the
    // token VALUE is returned nowhere, this endpoint included — only this bool.
    // `is_configured` is cheap (no CF network call; fails open to false). How it
    // differs from `authoritative`: a token that is present but failing yields
    // configured=true + authoritative=false, so the UI can say "connected but no
    // data".
    let cf_configured = crate::cf_analytics::is_configured(&ctx.env).await;

    // v7: fcm_configured tells the owner UI whether push can be delivered at all.
    // CAREFUL — it is true when project-id AND service-account are both present
    // (env, or the D1 values the owner typed in the app) OR when a push relay URL
    // resolves, and the relay falls back to a built-in default unless explicitly
    // `off`. So this is NOT proof that the owner installed their own FCM
    // credentials. WRITE-ONLY CONTRACT (as with cf_configured): the values are
    // returned nowhere, this endpoint included — only this bool. `is_configured`
    // is cheap (no call to Google, presence check only; fails open to false).
    let fcm_configured = crate::push::fcm::is_configured(&ctx.env).await;

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
    // requests_month — new in v4: only CF can supply it (there is no monthly
    // self-report counter), so it is null without CF (the client treats it as an
    // Option and renders '—').
    let requests_month = cf.as_ref().and_then(|c| c.requests_month);
    // R2 storage as measured by CF, reported ALONGSIDE the self-report
    // `media.bytes` (it never replaces it) so the two can be reconciled. Null
    // without CF.
    let storage_cf_bytes = cf.as_ref().and_then(|c| c.r2_storage_bytes);

    // Video calls (TURN) — this month's credential-issue counter (the `turn_usage`
    // table from 0009 that turn.rs's budget guard maintains) plus the advertised
    // cap, read from the SAME source as the guard (turn::monthly_cap). Fail-open:
    // missing table or D1 error → 0, so stats never 500s.
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

    // Daily media volume (Faz 1c) — fed by the count_bump hooks in
    // media/handlers.rs; read_today fails open (missing table/row → 0).
    let upload_bytes_today = crate::usage::read_today(&db, "upload_bytes").await;
    let upload_count_today = crate::usage::read_today(&db, "upload_count").await;
    let download_count_today = crate::usage::read_today(&db, "download_count").await;
    let download_bytes_today = crate::usage::read_today(&db, "download_bytes").await;

    // Monthly media volume (v5, month detail) — the SUM of this month's
    // usage_counters day rows (read_month uses a month-prefix LIKE, the same month
    // window as the TURN budget). read_month fails open (missing table or D1 error
    // → 0).
    let upload_bytes_month = crate::usage::read_month(&db, "upload_bytes").await;
    let upload_count_month = crate::usage::read_month(&db, "upload_count").await;
    let download_count_month = crate::usage::read_month(&db, "download_count").await;
    let download_bytes_month = crate::usage::read_month(&db, "download_bytes").await;

    // Quota caps (Faz 1a) — NULLABLE columns of server_settings. NULL means
    // unlimited; an error, a missing row or a missing migration also yields null
    // (fail-open, so stats never 500s).
    let caps = db
        .prepare(
            "SELECT max_storage_bytes, max_user_storage_bytes \
             FROM server_settings WHERE id = 1 LIMIT 1",
        )
        .first::<CapsRow>(None)
        .await
        .ok()
        .flatten();
    let (max_storage, max_user_storage) = caps
        .map(|c| (c.max_storage_bytes, c.max_user_storage_bytes))
        .unwrap_or((None, None));

    // Pluggable storage Faz 3 (plan e) — the BADGE on the panel's main card: store
    // count, unhealthy count (last_health_ok=0 only; NULL = never probed is NOT
    // counted) and whether anything is draining. The detail view (per-store list
    // with secret-free identity/health) comes from `GET /admin/storage`. Fail-open:
    // missing table (migration not applied) or D1 error → 0/false, so stats never
    // 500s.
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
        "retention": { "media_days": media_days, "message_days": message_days },
        "requests_today": requests_today,
        "caps": {
            "max_storage_bytes": max_storage,
            "max_user_storage_bytes": max_user_storage,
        },
        // Faz 1c: monthly video-call (TURN) usage + daily media volume. The
        // existing fields are untouched (an older client keeps reading the v2
        // fields; the new blocks are additive).
        "turn": { "issued_month": turn_issued, "cap": turn_cap },
        "today": {
            "upload_bytes": upload_bytes_today,
            "upload_count": upload_count_today,
            "download_count": download_count_today,
            "download_bytes": download_bytes_today,
        },
        // Month detail (v5, additive): this month's media volume for the "THIS
        // MONTH" card (a usage_counters SUM). requests_month (CF-only) already
        // lives at top level and TURN issued_month inside the turn block, so
        // neither is repeated here.
        "month": {
            "upload_bytes": upload_bytes_month,
            "upload_count": upload_count_month,
            "download_count": download_count_month,
            "download_bytes": download_bytes_month,
        },
        // Faz 3 (v4, additive): the dual-logic contract fields. `backend` is where
        // this binary runs (a future VPS/standalone port will send "standalone");
        // `authoritative` true means the numbers match the CF bill exactly (GraphQL
        // Analytics), false means self-report (no token, or a CF error).
        // `storage_cf_bytes` is CF's measurement and never replaces the self-report
        // media.bytes.
        "backend": "cf",
        "authoritative": cf.is_some(),
        "requests_month": requests_month,
        "storage_cf_bytes": storage_cf_bytes,
        // v6 (additive): "is a token present" bool — NEVER the value (write-only
        // contract).
        "cf_configured": cf_configured,
        // v7 (additive): "can push be delivered" bool — NEVER the values
        // (write-only).
        "fcm_configured": fcm_configured,
        // v8 (additive, pluggable storage Faz 3): the compact store badge. Detail
        // lives at GET /admin/storage. draining = is any store being emptied
        // (Faz 4 drain).
        "storage": {
            "stores_total": stores_total,
            "stores_unhealthy": stores_unhealthy,
            "draining": draining_count > 0,
        },
        "version": 8,
    }))
}
