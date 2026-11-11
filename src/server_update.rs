//! The owner's one-tap update of a self-hosted (bare workerd) relay — the relay's half
//! (`docs/SERVER_UPDATE_PLAN.md` §4.2–4.3, rollout step 8).
//!
//! **Why the box asks, not the relay.** The relay runs inside workerd's sandbox: it writes only its
//! own stores and can start nothing. So the box's update timer (`deploy/sezi-update-poll.sh`, as
//! root, every 2 min) calls `GET /internal/update-request` on loopback with the updater token, and
//! when the owner asked for a build it runs `deploy/update.sh --to <build>`, which installs only a
//! build the SIGNED release channel names, then reports with `POST /internal/update-result`. What a
//! taken relay can do through this is ask the box for a build Hasan's release key signed — an older
//! kept one included. It cannot name code, a URL or a command: root reads nothing from here but a
//! build number and the nightly switch.
//!
//! **The token** (`SEZI_UPDATER_TOKEN`, put into `.dev.vars` and the root-only
//! `/etc/sezi/updater-token` by `deploy/install-updater.sh`). Loopback alone is not enough — a
//! cloudflared tunnel also connects from 127.0.0.1. With no token configured (every Cloudflare
//! relay, a box without the updater) both `/internal/*` routes answer 404, `/capabilities` says
//! `updater: false`, and the owner's request is refused `server-update/no-updater`.
//!
//! **Stored**: the requests and results in `server_update_requests` (migration 0058); when the box
//! last called in and the nightly switch as two `server_config` keys. `updater` on `/capabilities`
//! is true while the box called in within [`ALIVE_MS`] — what makes the app offer the button.
//!
//! The owner's routes are `admin/server_update.rs`.

use crate::auth::hashing::secret_eq;
use crate::d1util::{d1_int, d1_opt_int, d1_text};
use crate::respond::{json_err, no_content};
use serde::Deserialize;
use serde_json::{json, Value};
use worker::*;

/// The relay's environment variable holding the updater token.
pub(crate) const TOKEN_VAR: &str = "SEZI_UPDATER_TOKEN";
/// The header the box's updater presents it in.
pub(crate) const TOKEN_HEADER: &str = "x-sezi-updater";
/// The shortest token believed to be one `install-updater.sh` made (it writes 64 hex digits).
pub(crate) const TOKEN_MIN_LEN: usize = 32;
/// `/capabilities` says `updater: true` while the box called in this recently (it calls every
/// 2 min).
pub(crate) const ALIVE_MS: i64 = 15 * 60_000;
/// A request the box has not taken by then is closed `expired`: a box that comes back after a day
/// off must not act on a tap nobody is watching any more. The app waits as long.
pub(crate) const REQUEST_TTL_MS: i64 = 15 * 60_000;
/// The `server_config` key of the nightly switch: `off`, `all` or `security`.
pub(crate) const AUTO_KEY: &str = "server_update_auto";
/// The `server_config` key of when the box last called in (ms, as text).
pub(crate) const SEEN_KEY: &str = "updater_seen_at";
/// The largest result body the box sends.
pub(crate) const RESULT_MAX_BYTES: usize = 4096;

/// The owner's nightly switch (plan §4.3, decision D6: off by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Auto {
    Off,
    /// Install every newer build the channel offers, once a night.
    All,
    /// Only a release the channel marks as a security fix.
    Security,
}

impl Auto {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "off" => Some(Self::Off),
            "all" => Some(Self::All),
            "security" => Some(Self::Security),
            _ => None,
        }
    }

    /// A stored value; anything unreadable is off.
    pub(crate) fn stored(s: Option<&str>) -> Self {
        s.and_then(Self::parse).unwrap_or(Self::Off)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::All => "all",
            Self::Security => "security",
        }
    }
}

/// What a presented updater token is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenCheck {
    /// No usable token is configured: this relay has no updater.
    NotConfigured,
    Wrong,
    Ok,
}

/// The configured token, when it is one (long enough, after trimming).
pub(crate) fn configured(token: Option<&str>) -> Option<&str> {
    token.map(str::trim).filter(|t| t.len() >= TOKEN_MIN_LEN)
}

/// Compare a presented token with the configured one, in constant time.
pub(crate) fn check_token(configured_token: Option<&str>, presented: Option<&str>) -> TokenCheck {
    match configured(configured_token) {
        None => TokenCheck::NotConfigured,
        Some(want) if presented.is_some_and(|p| secret_eq(p.trim(), want)) => TokenCheck::Ok,
        Some(_) => TokenCheck::Wrong,
    }
}

/// Has the box called in recently enough to be believed running?
pub(crate) fn alive(seen_at: Option<i64>, now: i64) -> bool {
    seen_at.is_some_and(|s| now - s <= ALIVE_MS && s <= now + 60_000)
}

/// A build stamp (yyyyMMddHHmm, twelve digits).
pub(crate) fn valid_build(b: i64) -> bool {
    (100_000_000_000..1_000_000_000_000).contains(&b)
}

/// update.sh's result code, kept only when it looks like one (`ok`, `unhealthy-rolled-back`).
pub(crate) fn clean_code(code: &str) -> String {
    let c = code.trim();
    if !c.is_empty() && c.len() <= 48 && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        c.to_string()
    } else {
        "unknown".into()
    }
}

// ── SQL (bound in order; the tests run each against the real schema) ─────────────────────────────

pub(crate) const CONFIG_READ_SQL: &str = "SELECT value FROM server_config WHERE key = ?1 LIMIT 1";
pub(crate) const CONFIG_WRITE_SQL: &str = "INSERT INTO server_config (key, value, created_at) VALUES (?1, ?2, ?3) \
     ON CONFLICT(key) DO UPDATE SET value = excluded.value";
/// Close every request still open from before `?1` that the box never took (`?2` = now).
pub(crate) const EXPIRE_SQL: &str = "UPDATE server_update_requests SET done_at = ?2, ok = 0, code = 'expired' \
     WHERE done_at IS NULL AND picked_at IS NULL AND requested_at < ?1";
/// A new request replaces any open one that was not taken yet (`?1` = now).
pub(crate) const SUPERSEDE_SQL: &str = "UPDATE server_update_requests SET done_at = ?1, ok = 0, code = 'superseded' \
     WHERE done_at IS NULL AND picked_at IS NULL";
pub(crate) const INSERT_REQUEST_SQL: &str = "INSERT INTO server_update_requests (to_build, requested_by, requested_at) \
     VALUES (?1, ?2, ?3)";
pub(crate) const LATEST_SQL: &str = "SELECT id, to_build, requested_by, requested_at, picked_at, done_at, ok, code, \
     from_build, automatic FROM server_update_requests ORDER BY id DESC LIMIT 1";
/// The newest open request.
pub(crate) const OPEN_SQL: &str = "SELECT id, to_build, requested_by, requested_at, picked_at, done_at, ok, code, \
     from_build, automatic FROM server_update_requests WHERE done_at IS NULL ORDER BY id DESC LIMIT 1";
pub(crate) const PICK_SQL: &str = "UPDATE server_update_requests SET picked_at = ?2 WHERE id = ?1 AND picked_at IS NULL";
/// The box's result for request `?1`.
pub(crate) const FINISH_SQL: &str = "UPDATE server_update_requests SET done_at = ?2, ok = ?3, code = ?4, from_build = ?5, \
     picked_at = COALESCE(picked_at, ?2) WHERE id = ?1";
/// A result nobody asked for: the nightly run.
pub(crate) const INSERT_RESULT_SQL: &str = "INSERT INTO server_update_requests \
     (to_build, requested_by, requested_at, picked_at, done_at, ok, code, from_build, automatic) \
     VALUES (?1, 'updater', ?2, ?2, ?2, ?3, ?4, ?5, 1)";

/// One row of `server_update_requests`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct RequestRow {
    pub id: i64,
    pub to_build: i64,
    pub requested_by: String,
    pub requested_at: i64,
    pub picked_at: Option<i64>,
    pub done_at: Option<i64>,
    pub ok: Option<i64>,
    pub code: Option<String>,
    pub from_build: Option<i64>,
    pub automatic: i64,
}

/// A request as the owner's app reads it.
pub(crate) fn request_json(r: &RequestRow) -> Value {
    json!({
        "id": r.id,
        "to_build": r.to_build,
        "requested_at": r.requested_at,
        "picked_at": r.picked_at,
        "done_at": r.done_at,
        "ok": r.ok.map(|o| o != 0),
        "code": r.code,
        "from_build": r.from_build,
        "automatic": r.automatic != 0,
    })
}

/// `GET /admin/server-update`'s body.
pub(crate) fn status_body(configured: bool, seen_at: Option<i64>, auto: Auto, latest: Option<&RequestRow>, now: i64) -> Value {
    json!({
        "updater": {
            "configured": configured,
            "seen_at": seen_at,
            "alive": configured && alive(seen_at, now),
        },
        "auto": auto.as_str(),
        "request": latest.map(request_json),
        "request_ttl_ms": REQUEST_TTL_MS,
    })
}

/// `GET /internal/update-request`'s body: the build asked for (if any) and the nightly switch.
/// Nothing else crosses to root.
pub(crate) fn poll_body(open: Option<&RequestRow>, auto: Auto) -> Value {
    json!({
        "request": open.map(|r| json!({ "id": r.id, "to_build": r.to_build })),
        "auto": auto.as_str(),
    })
}

/// What the box reports (`deploy/sezi-update-poll.sh`, from update.sh's result file).
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct ResultBody {
    /// The request it ran for; absent for a nightly run.
    #[serde(default)]
    pub request_id: Option<i64>,
    /// The build it went for (absent when update.sh refused before choosing one).
    #[serde(default)]
    pub to: Option<i64>,
    #[serde(default)]
    pub from: Option<i64>,
    pub ok: bool,
    #[serde(default)]
    pub code: String,
}

pub(crate) fn parse_result(body: &[u8]) -> Option<ResultBody> {
    if body.len() > RESULT_MAX_BYTES {
        return None;
    }
    serde_json::from_slice(body).ok()
}

// ── D1 ──────────────────────────────────────────────────────────────────────────────────────────

pub(crate) async fn config_value(db: &D1Database, key: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Row {
        value: String,
    }
    let stmt = db.prepare(CONFIG_READ_SQL).bind(&[d1_text(key)]).ok()?;
    stmt.first::<Row>(None).await.ok().flatten().map(|r| r.value)
}

pub(crate) async fn set_config(db: &D1Database, key: &str, value: &str) -> Result<()> {
    db.prepare(CONFIG_WRITE_SQL)
        .bind(&[d1_text(key), d1_text(value), d1_int(crate::utils::now_secs() as i64)])?
        .run()
        .await?;
    Ok(())
}

pub(crate) async fn read_auto(db: &D1Database) -> Auto {
    Auto::stored(config_value(db, AUTO_KEY).await.as_deref())
}

pub(crate) async fn read_seen(db: &D1Database) -> Option<i64> {
    config_value(db, SEEN_KEY).await.and_then(|v| v.trim().parse().ok())
}

pub(crate) async fn expire_stale(db: &D1Database, now: i64) -> Result<()> {
    db.prepare(EXPIRE_SQL).bind(&[d1_int(now - REQUEST_TTL_MS), d1_int(now)])?.run().await?;
    Ok(())
}

pub(crate) async fn row(db: &D1Database, sql: &str) -> Result<Option<RequestRow>> {
    db.prepare(sql).first::<RequestRow>(None).await
}

pub(crate) fn token_of(env: &Env) -> Option<String> {
    crate::utils::env_text(env, TOKEN_VAR)
}

/// `/capabilities`' `updater`: a token is configured and the box called in within [`ALIVE_MS`].
/// No D1 read on a relay without a token — every Cloudflare one.
pub(crate) async fn updater_alive(env: &Env, db: &D1Database) -> bool {
    if configured(token_of(env).as_deref()).is_none() {
        return false;
    }
    alive(read_seen(db).await, crate::utils::now_ms() as i64)
}

/// The updater's token gate: `Ok(())`, or the answer to give (404 when there is no updater at all,
/// so a relay without one looks like any other).
fn gate(req: &Request, env: &Env) -> std::result::Result<(), Result<Response>> {
    let presented = req.headers().get(TOKEN_HEADER).ok().flatten();
    match check_token(token_of(env).as_deref(), presented.as_deref()) {
        TokenCheck::Ok => Ok(()),
        TokenCheck::NotConfigured => Err(json_err(404, "not_found")),
        TokenCheck::Wrong => Err(json_err(401, "server-update/bad-token")),
    }
}

/// `GET /internal/update-request` — the box's poll. Stamps "updater seen", closes requests nobody
/// took in time, and answers the newest open request and the nightly switch.
pub async fn internal_request(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = gate(&req, &ctx.env) {
        return resp;
    }
    let db = ctx.env.d1("DB")?;
    let now = crate::utils::now_ms() as i64;
    set_config(&db, SEEN_KEY, &now.to_string()).await?;
    expire_stale(&db, now).await?;
    let open = row(&db, OPEN_SQL).await?;
    if let Some(r) = &open {
        db.prepare(PICK_SQL).bind(&[d1_int(r.id), d1_int(now)])?.run().await?;
    }
    Response::from_json(&poll_body(open.as_ref(), read_auto(&db).await))
}

/// `POST /internal/update-result` — how a run ended. After a restart the relay answering is the new
/// build or the restored one; either stores it.
pub async fn internal_result(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if let Err(resp) = gate(&req, &ctx.env) {
        return resp;
    }
    let Some(body) = parse_result(&req.bytes().await.unwrap_or_default()) else {
        return json_err(400, "server-update/bad-result");
    };
    let db = ctx.env.d1("DB")?;
    let now = crate::utils::now_ms() as i64;
    set_config(&db, SEEN_KEY, &now.to_string()).await?;
    let code = clean_code(&body.code);
    let ok = d1_int(i64::from(body.ok));
    match body.request_id {
        Some(id) => {
            db.prepare(FINISH_SQL)
                .bind(&[d1_int(id), d1_int(now), ok, d1_text(&code), d1_opt_int(body.from)])?
                .run()
                .await?;
        }
        None => {
            // 0 = no build was chosen (the channel did not verify): still worth telling the owner.
            let to = body.to.filter(|b| valid_build(*b)).unwrap_or(0);
            db.prepare(INSERT_RESULT_SQL)
                .bind(&[d1_int(to), d1_int(now), ok, d1_text(&code), d1_opt_int(body.from)])?
                .run()
                .await?;
        }
    }
    no_content()
}

#[cfg(test)]
#[path = "server_update_tests.rs"]
mod tests;
