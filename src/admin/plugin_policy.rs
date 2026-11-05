//! `GET /plugin-policy` (member) + `POST /admin/plugin-policy` (admin/owner) —
//! server-wide plugin availability policy.
//!
//! MODEL: everything is ENABLED by default. The `server_plugin_policy` table
//! (0027) holds rows ONLY for DISABLED plugins (row present = disabled), so an
//! empty table means every plugin is available.
//!
//! - **GET /plugin-policy** — auth: `require_active_auth` (ANY authenticated member, NOT
//!   admin). Every client reads it to filter its plugin picker. Returns
//!   `{"disabled":[...]}`.
//! - **POST /admin/plugin-policy** — auth: `require_admin` (admin|owner). Body:
//!   `{"plugin_id":"...","disabled":true|false}`. true → INSERT OR REPLACE
//!   (disable); false → DELETE (enable). Returns `{"ok":true,"disabled":[...]}`
//!   with the up-to-date list.
//!
//! - **The plugin log's append** (`plugin_log::append`) asks [`append_refused`]: an entry for a
//!   disabled plugin is refused with `400 {"error":"plugin_disabled"}`. It is the one place the
//!   relay sees a plugin id in the clear; everything else a plugin sends is end-to-end encrypted
//!   and gated by the app's core (`core/src/kernel/plugin_policy.rs`).
//!
//! Precedent: the cf_config/fcm_config admin self-service pattern plus the
//! require_admin GET in stats.rs, and plugin_epoch_floor's "table missing →
//! fail-open" read discipline.

use crate::auth::middleware::{require_admin, require_active_auth};
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// Read the current DISABLED plugin_id list. Deterministic alphabetical order
/// keeps the wire format and the tests stable. Missing table (migration not
/// applied yet) or a D1 error → empty list (fail-open, the
/// plugin_log::epoch_floor pattern), so the picker sees "everything enabled".
async fn read_disabled(db: &D1Database) -> Vec<String> {
    #[derive(Deserialize)]
    struct Row {
        plugin_id: String,
    }
    let rows = db
        .prepare("SELECT plugin_id FROM server_plugin_policy ORDER BY plugin_id ASC")
        .all()
        .await
        .and_then(|r| r.results::<Row>());
    match rows {
        Ok(rows) => rows.into_iter().map(|r| r.plugin_id).collect(),
        Err(_) => Vec::new(),
    }
}

/// `GET /plugin-policy` — read by any authenticated member so the client can
/// filter its picker. Deliberately NOT admin-gated: every member needs the list
/// to hide entries. Rate limit 600 per 5 min (same as media download).
pub async fn get_plugin_policy(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // The KV binding is OPTIONAL (slim template): without it we continue
    // unlimited — see ratelimit.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("plugpol:get:{user_id}"), 600, 5 * 60).await {
        return json_err(429, "rate_limited");
    }
    let db = ctx.env.d1("DB")?;
    let disabled = read_disabled(&db).await;
    Response::from_json(&serde_json::json!({ "disabled": disabled }))
}

/// Plugin ids no policy row can switch off — the core's `NEVER_DISABLED`
/// (`core/src/kernel/plugin_policy.rs`), kept in step by a test. `library` is the group library's
/// record layer (course sessions, attendance, recordings), not a plugin anyone picks; a server
/// turns its library off with `/capabilities` `features.library`, never with this table.
pub(crate) const NEVER_DISABLED: &[&str] = &["library"];

/// One plugin's row: present = disabled.
pub(crate) const IS_DISABLED_SQL: &str =
    "SELECT 1 AS disabled FROM server_plugin_policy WHERE plugin_id = ?1 LIMIT 1";

/// How a plugin-log append for a disabled plugin is answered (`plugin_log::append`).
///
/// A `400`, not a `403`, for the apps already out there: every app since 2046 ends an op at the
/// first `400` (`core/src/kernel/op_error.rs` `is_request_refused`, terminal, its own lane — never
/// held behind it), while a `403` is no code it knows and walks the eight-attempt retry ladder,
/// once per record the plugin writes. The body's code is what an app reads to tell why.
pub(crate) const APPEND_REFUSED_STATUS: u16 = 400;
pub(crate) const APPEND_REFUSED_CODE: &str = "plugin_disabled";

/// The decision, given whether the table holds a row for `plugin_id`.
pub(crate) fn refuses_append(plugin_id: &str, row_present: bool) -> bool {
    row_present && !NEVER_DISABLED.contains(&plugin_id)
}

/// Must an append to `plugin_id`'s log be refused? Reads the one row; a missing table or a D1
/// error refuses nothing (fail-open, as `read_disabled` and `plugin_log::epoch_floor` read).
/// Only appends ask: reads stay open, since nothing is deleted on a disable and re-enabling
/// brings every entry back.
pub(crate) async fn append_refused(db: &D1Database, plugin_id: &str) -> bool {
    if NEVER_DISABLED.contains(&plugin_id) {
        return false;
    }
    let row_present = match db.prepare(IS_DISABLED_SQL).bind(&[d1_text(plugin_id)]) {
        Ok(stmt) => matches!(stmt.first::<serde_json::Value>(None).await, Ok(Some(_))),
        Err(_) => false,
    };
    refuses_append(plugin_id, row_present)
}

#[derive(Deserialize, Default)]
struct PolicyBody {
    plugin_id: Option<String>,
    disabled: Option<bool>,
}

/// plugin_id validation: non-empty, ≤128 chars, [A-Za-z0-9._-] (slug or
/// reverse-DNS id). The tight charset guards against SQL/log injection and
/// control-character DoS (same class as cf_config's field_ok, but stricter
/// because this is a PRIMARY KEY).
fn plugin_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// `POST /admin/plugin-policy` — admin|owner disables/enables one plugin
/// server-wide.
pub async fn set_plugin_policy(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // require_admin includes owner (an owner can do every admin action;
    // consistent with the middleware).
    if let Err(resp) = require_admin(&user_id, &ctx.env).await {
        return Ok(resp);
    }

    let body: PolicyBody = req.json().await.unwrap_or_default();
    let plugin_id = match body.plugin_id.as_deref().map(str::trim) {
        Some(p) if plugin_id_ok(p) => p.to_string(),
        _ => return json_err(400, "bad_request"),
    };
    let Some(disabled) = body.disabled else {
        return json_err(400, "bad_request");
    };

    let db = ctx.env.d1("DB")?;
    if disabled {
        // Row present = disabled. INSERT OR REPLACE keeps it idempotent:
        // re-disabling only refreshes the disabled_at stamp.
        db.prepare(
            "INSERT OR REPLACE INTO server_plugin_policy (plugin_id, disabled_at) VALUES (?, ?)",
        )
        .bind(&[d1_text(&plugin_id), d1_int(now_secs() as i64)])?
        .run()
        .await?;
    } else {
        // enable = REMOVE the row (back to the default). Deleting a missing row
        // is a no-op, so this is idempotent too.
        db.prepare("DELETE FROM server_plugin_policy WHERE plugin_id = ?")
            .bind(&[d1_text(&plugin_id)])?
            .run()
            .await?;
    }

    // Answer with the fresh list so the client refreshes its state in one
    // round-trip.
    let disabled_list = read_disabled(&db).await;
    Response::from_json(&serde_json::json!({ "ok": true, "disabled": disabled_list }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped lookup, run against the real schema: a row = disabled, no row = enabled.
    fn row_present(db: &rusqlite::Connection, plugin_id: &str) -> bool {
        db.query_row(IS_DISABLED_SQL, [plugin_id], |_| Ok(()))
            .map(|_| true)
            .unwrap_or(false)
    }

    fn schema_with_disabled(ids: &[&str]) -> rusqlite::Connection {
        let db = crate::test_schema::full_schema();
        for id in ids {
            db.execute(
                "INSERT INTO server_plugin_policy (plugin_id, disabled_at) VALUES (?1, 1)",
                [id],
            )
            .unwrap();
        }
        db
    }

    #[test]
    fn an_append_for_a_disabled_plugin_is_refused() {
        let db = schema_with_disabled(&["draw"]);
        assert!(refuses_append("draw", row_present(&db, "draw")));
    }

    #[test]
    fn an_append_for_an_enabled_plugin_goes_through() {
        let db = schema_with_disabled(&["draw"]);
        assert!(!refuses_append("todo", row_present(&db, "todo")));
        // An empty table — every server that never touched the policy — refuses nothing.
        let empty = schema_with_disabled(&[]);
        assert!(!refuses_append("draw", row_present(&empty, "draw")));
    }

    /// `library` is the group library's record layer, not a plugin anyone picks; the core never
    /// obeys a policy row for it (`core/src/kernel/plugin_policy.rs` `NEVER_DISABLED`) and
    /// neither does the relay, or course sessions and attendance would stop here while the app
    /// still offered them.
    #[test]
    fn the_library_is_never_refused_whatever_the_table_says() {
        let db = schema_with_disabled(&["library"]);
        assert!(row_present(&db, "library"), "the premise: a hand-made row exists");
        assert!(!refuses_append("library", row_present(&db, "library")));
        assert_eq!(NEVER_DISABLED, &["library"], "keep in step with the core's NEVER_DISABLED");
    }

    /// The status is part of the contract with apps already out there: every app since 2046
    /// ends an op at the first `400` (`core/src/kernel/op_error.rs` `is_request_refused`), while
    /// a `403` walks the eight-attempt retry ladder once per record. The code is the reason.
    #[test]
    fn the_refusal_is_a_400_plugin_disabled() {
        assert_eq!(APPEND_REFUSED_STATUS, 400);
        assert_eq!(APPEND_REFUSED_CODE, "plugin_disabled");
    }

    #[test]
    fn plugin_id_validation() {
        // Valid: slug, reverse-DNS, dash/underscore/dot, exactly 128 chars.
        assert!(plugin_id_ok("echo"));
        assert!(plugin_id_ok("com.sezi.arena"));
        assert!(plugin_id_ok("my-plugin_2"));
        assert!(plugin_id_ok(&"a".repeat(128)));
        // Empty → reject.
        assert!(!plugin_id_ok(""));
        // Over 128 → reject (DoS / PRIMARY KEY bloat guard).
        assert!(!plugin_id_ok(&"a".repeat(129)));
        // Forbidden characters (space/injection/control/unicode/path) → reject.
        assert!(!plugin_id_ok("bad id"));
        assert!(!plugin_id_ok("drop;table"));
        assert!(!plugin_id_ok("a\nb"));
        assert!(!plugin_id_ok("emoji😀"));
        assert!(!plugin_id_ok("path/traversal"));
    }
}
