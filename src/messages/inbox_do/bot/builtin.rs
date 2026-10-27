//! A built-in bot (docs/BOTS_HELPER_PLAN.md): the relay is the bot's program. Its configuration
//! and secrets, the owner's measured test, and what the owner's page reads; the runner itself is
//! `builtin_run.rs`.
//!
//! A built-in runner is the third consumer of the update queue, beside the poll and the webhook,
//! and the only one while it is set: setting a kind clears the webhook, and `getUpdates` /
//! `setWebhook` answer `bot/builtin-active` (409).
//!
//! **Secrets** (`bot_kv`, this inbox only — never D1, never logged): the provider key
//! (`builtin_api_key`), kept only while the bot is an AI or a hearings bot and only for the
//! service it was given for (`builtin_rules::service_follows`), and the sheet's shared secret
//! (`sheet_secret`), made the first time the bot is meant to write a sheet — before its address
//! exists, since the helper hands the script over first — and kept for the life of the bot, so a
//! script already pasted keeps working through a change of kind. No route ever returns the key;
//! the sheet secret is returned by the owner's set, so the helper can rebuild the script.
//!
//! Internal routes: `/bot/builtin` (POST set, GET read), `/bot/builtin-test`, `/bot/wake`.

use super::builtin_ai::{self, Turn};
use super::builtin_copy::{line, Line};
use super::builtin_sheet;
use super::builtin_store as bs;
use super::store::Exec;
use super::*;
use super::builtin_policy;
use crate::bots::builtin_rules::{allow_lan, service_follows, Config, Kind};

const KV_CONFIG: &str = "builtin";
/// A sheet bot (or a row-writing AI bot) whose `/exec` address is not set yet.
pub(super) const NOT_CONNECTED: &str = "bot/sheet-not-connected";
const KV_API_KEY: &str = "builtin_api_key";
const KV_SHEET_SECRET: &str = "sheet_secret";
const KV_LAST_OK: &str = "builtin_last_ok_at";
const KV_LAST_ERROR: &str = "builtin_last_error";
/// While the bot is off, the runner looks again at this time (ms).
pub(super) const KV_HOLD_UNTIL: &str = "builtin_hold_until";

/// The owner's set, as the Worker forwards it after `builtin_rules::validate`.
#[derive(Deserialize)]
pub(super) struct SetBody {
    #[serde(default)]
    config: Option<Config>,
    #[serde(default)]
    api_key: Option<String>,
}

impl UserInbox {
    /// The configuration in force, if this is a built-in bot.
    pub(super) fn builtin_config(&self) -> Option<Config> {
        let raw = self.bot_store().kv_get(KV_CONFIG)?;
        serde_json::from_str(&raw).ok()
    }

    pub(super) fn builtin_api_key(&self) -> Option<String> {
        self.bot_store().kv_get(KV_API_KEY)
    }

    pub(super) fn builtin_sheet_secret(&self) -> Option<String> {
        self.bot_store().kv_get(KV_SHEET_SECRET)
    }

    /// A measured outcome, for the owner's page: success stamps the time and clears the error.
    pub(super) fn builtin_note(&self, outcome: std::result::Result<(), &str>, now: i64) {
        let store = self.bot_store();
        match outcome {
            Ok(()) => {
                store.kv_put(KV_LAST_OK, &now.to_string());
                store.db.run("DELETE FROM bot_kv WHERE k = ?", &[super::store::Arg::T(KV_LAST_ERROR)]);
            }
            Err(code) => {
                console_log!("[bot] built-in failure {code}");
                store.kv_put(KV_LAST_ERROR, code);
            }
        }
    }

    /// `/bot/builtin` POST: set (or, with no config, clear) the built-in runner.
    ///
    /// Every set bumps the configuration's generation, so a round in flight drops what it was
    /// doing on the old one (`builtin_run.rs`). What was owed to a sheet — waiting proposals and
    /// rows — goes when the bot stops writing to that sheet; a stored key goes with the service
    /// it was given for (`builtin_rules::service_follows`).
    pub(super) async fn bot_builtin_set(&self, body: SetBody) -> Result<Response> {
        let store = self.bot_store();
        let old = self.builtin_config();
        let new = body.config;
        // Refused before anything changes: a key may not travel to another provider or address.
        // The AI bot's and the hearings bot's key share one slot, kept only for the service
        // (provider, address) it was given for (`service_follows`).
        let keep_key = match (&new, &body.api_key) {
            (Some(c), None) if c.key_service().is_some() => {
                let follows = service_follows(old.as_ref(), c) && store.kv_get(KV_API_KEY).is_some();
                if c.needs_key() && !follows {
                    let refusal = serde_json::json!({ "ok": false, "error": "ai/no-key" });
                    return Ok(Response::from_json(&refusal)?.with_status(400));
                }
                follows
            }
            _ => false,
        };
        store.db.run(bs::GEN_BUMP, &[]);
        // A different bot is an untested one: nothing measured on the old settings carries over.
        if builtin_policy::changes_behaviour(old.as_ref(), new.as_ref(), body.api_key.is_some()) {
            for k in [KV_LAST_OK, KV_LAST_ERROR] {
                store.db.run("DELETE FROM bot_kv WHERE k = ?", &[super::store::Arg::T(k)]);
            }
        }
        if builtin_policy::sheet_target_changed(old.as_ref(), new.as_ref()) {
            store.db.run(bs::PROPOSALS_FORGET, &[]);
            store.db.run(bs::JOBS_FORGET, &[]);
        }
        if builtin_policy::drops_hearings_queue(old.as_ref(), new.as_ref()) {
            for q in bs::HEARINGS_QUEUE_FORGET {
                store.db.run(q, &[]);
            }
        }
        let Some(config) = new else {
            // Back to "program" mode: the key and what the AI remembered go; the sheet secret
            // stays (it is the script's, not a key to anything).
            for k in [KV_CONFIG, KV_API_KEY, KV_HOLD_UNTIL, KV_LAST_ERROR] {
                store.db.run("DELETE FROM bot_kv WHERE k = ?", &[super::store::Arg::T(k)]);
            }
            for q in bs::AI_FORGET {
                store.db.run(q, &[]);
            }
            if old.as_ref().is_some_and(|o| o.kind == Kind::Hearings) {
                store.db.run(super::builtin_hearings::SENT_EXPIRE, &[super::store::Arg::I(i64::MAX)]);
            }
            return Response::from_json(&serde_json::json!({ "ok": true }));
        };
        let has_key = match (config.key_service(), body.api_key) {
            (Some(_), Some(key)) => {
                store.kv_put(KV_API_KEY, &key);
                true
            }
            (Some(_), None) if keep_key => true,
            _ => {
                store.db.run("DELETE FROM bot_kv WHERE k = ?", &[super::store::Arg::T(KV_API_KEY)]);
                false
            }
        };
        // What an AI bot remembered goes with the kind. A hearings bot keeps its own proposals
        // and day counts (the same tables) across a re-set of the same kind: a set must not hand
        // a member a fresh day of calls.
        let old_kind = old.as_ref().map(|o| o.kind);
        let keeps_own = config.kind == Kind::Ai || (config.kind == Kind::Hearings && old_kind == Some(Kind::Hearings));
        if !keeps_own {
            for q in bs::AI_FORGET {
                store.db.run(q, &[]);
            }
        }
        // A hearings bot's sent answers carry names (§8.2): they do not outlive its kind.
        if old_kind == Some(Kind::Hearings) && config.kind != Kind::Hearings {
            store.db.run(super::builtin_hearings::SENT_EXPIRE, &[super::store::Arg::I(i64::MAX)]);
        }
        // Made when the bot is MEANT to write a sheet, before its address exists: the helper
        // hands the script (with this secret) over first.
        let secret = config.wants_sheet().then(|| {
            store.kv_get(KV_SHEET_SECRET).unwrap_or_else(|| {
                let s = crate::utils::random_b64u(24);
                store.kv_put(KV_SHEET_SECRET, &s);
                s
            })
        });
        // The owner's page says "not connected" from the set on, until the address arrives.
        if config.sheet_not_connected() {
            store.kv_put(KV_LAST_ERROR, NOT_CONNECTED);
        } else if store.kv_get(KV_LAST_ERROR).as_deref() == Some(NOT_CONNECTED) {
            store.db.run("DELETE FROM bot_kv WHERE k = ?", &[super::store::Arg::T(KV_LAST_ERROR)]);
        }
        // One queue, one reader: the webhook goes.
        store.db.run("DELETE FROM bot_kv WHERE k IN ('webhook_url', 'webhook_secret')", &[]);
        let json = serde_json::to_string(&config).map_err(|e| Error::RustError(e.to_string()))?;
        store.kv_put(KV_CONFIG, &json);
        // Whatever was waiting is the runner's now.
        self.arm_alarm_within(0).await;
        let mut answer = serde_json::json!({ "ok": true, "has_api_key": has_key });
        if let Some(s) = secret {
            answer["sheet_secret"] = s.into();
        }
        Response::from_json(&answer)
    }

    /// The configuration's generation (`bs::GEN_BUMP`): read again after every `await` of a round.
    pub(super) fn builtin_gen(&self) -> i64 {
        self.bot_store().db.int(bs::GEN_GET, &[]).unwrap_or(0)
    }

    /// When the alarm must come back to forget a turn or a proposal on time (24 h), even with no
    /// other work: `None` when the bot remembers nothing.
    pub(super) fn bot_builtin_expiry_next(&self) -> Option<i64> {
        let keep = [super::store::Arg::I(bs::TURN_TTL_MS), super::store::Arg::I(bs::PROPOSAL_KEEP_MS)];
        self.bot_store().db.int(bs::EXPIRY_NEXT, &keep)
    }

    /// `/bot/builtin` GET: the configuration without its key.
    pub(super) fn bot_builtin_get(&self) -> Result<Response> {
        let has_key = self.builtin_api_key().is_some();
        match self.builtin_config() {
            Some(c) => Response::from_json(&c.to_owner_json(has_key)),
            None => Response::from_json(&serde_json::json!({ "kind": null, "has_api_key": false })),
        }
    }

    /// What `/bot/state` adds for the owner's list. No secret, no instructions.
    pub(super) fn builtin_state(&self) -> serde_json::Value {
        let store = self.bot_store();
        let c = self.builtin_config();
        let mut v = serde_json::json!({
            "builtin": c.as_ref().map(|c| c.kind),
            "ai_provider": c.as_ref().and_then(Config::model_provider),
            "ai_model": c.as_ref().and_then(Config::model_name),
            "last_ok_at": store.kv_get(KV_LAST_OK).and_then(|v| v.parse::<i64>().ok()),
            "last_error": store.kv_get(KV_LAST_ERROR),
        });
        // A hearings bot's audit, as counts (`hearings_audit.rs`): never a row of it.
        if c.as_ref().is_some_and(|c| c.kind == Kind::Hearings) {
            v["hearings"] = self.hearings_state((now_secs() * 1000) as i64);
        }
        v
    }

    /// `/bot/wake`: the bot was turned back on; whatever waits runs now.
    pub(super) async fn bot_wake(&self) -> Result<Response> {
        for k in [KV_HOLD_UNTIL, super::deliver::KV_WEBHOOK_HOLD] {
            self.bot_store().db.run("DELETE FROM bot_kv WHERE k = ?", &[super::store::Arg::T(k)]);
        }
        // Its room work too: posts, key requests and chunks held while it was off.
        self.bot_room_wake((now_secs() * 1000) as i64);
        self.arm_alarm_within(0).await;
        Response::empty().map(|r| r.with_status(204))
    }

    /// `/bot/builtin-test`: the owner's "Dene", run NOW, answered with the measured outcome.
    /// Sheet: a `test: true` POST the script must answer `{"ok":true}`; AI: one model call.
    pub(super) async fn bot_builtin_test(&self, who: serde_json::Value) -> Result<Response> {
        let Some(cfg) = self.builtin_config() else {
            return crate::bots::api::bot_err(409, "not-builtin");
        };
        let now = (now_secs() * 1000) as i64;
        let user_id = who.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
        let name = who.get("display_name").and_then(|v| v.as_str()).unwrap_or("");
        let text = line(cfg.lang, Line::TestMessage);
        let (outcome, answer) = match (cfg.kind, cfg.ai.as_ref()) {
            (Kind::Sheet, _) => (self.builtin_sheet_test(&cfg, now, user_id, name, text).await, None),
            (Kind::Ai, Some(ai)) => {
                let (model, answer) = match self.builtin_api_key() {
                    None => (Err("ai/no-key"), None),
                    Some(key) => {
                        let bot_name = self.builtin_bot_name().await.unwrap_or_default();
                        let system = builtin_ai::system_prompt(ai, &bot_name, name, None, cfg.writes_sheet(), now);
                        let body = builtin_ai::request_body(ai, &system, &[] as &[Turn], text);
                        match builtin_ai::call(ai, &key, &body, allow_lan(&self.env)).await {
                            Ok(t) => (Ok(()), Some(builtin_ai::split_row(&t).0)),
                            Err(code) => (Err(code), None),
                        }
                    }
                };
                // A row-writing AI bot with its sheet connected tests the sheet too.
                let sheet = match (model, cfg.writes_sheet()) {
                    (Ok(()), true) => Some(self.builtin_sheet_test(&cfg, now, user_id, name, text).await),
                    _ => None,
                };
                (builtin_policy::test_outcome(model, sheet), answer)
            }
            (Kind::Ai, None) => (Err("builtin/ai"), None),
            (Kind::Hearings, _) => match cfg.hearings.as_ref() {
                None => (Err("builtin/hearings"), None),
                Some(h) => {
                    let (model, answer) = self.hearings_test(cfg.lang, h, now, name).await;
                    let sheet = match (model, cfg.writes_sheet()) {
                        (Ok(()), true) => Some(self.builtin_sheet_test(&cfg, now, user_id, name, text).await),
                        _ => None,
                    };
                    (builtin_policy::test_outcome(model, sheet), answer)
                }
            },
        };
        self.builtin_note(outcome, now);
        let mut v = serde_json::json!({
            "ok": outcome.is_ok(),
            "kind": cfg.kind,
            "outcome": outcome.err().unwrap_or("ok"),
        });
        if let Some(a) = answer {
            v["answer"] = a.into();
        }
        Response::from_json(&v)
    }

    /// The sheet's part of a test: a `test: true` POST the script must answer `{"ok":true}`.
    async fn builtin_sheet_test(
        &self,
        cfg: &Config,
        now: i64,
        user_id: &str,
        name: &str,
        text: &str,
    ) -> std::result::Result<(), &'static str> {
        match (cfg.sheet_url.as_deref(), self.builtin_sheet_secret()) {
            (None, _) => Err(NOT_CONNECTED),
            // The hearings bot's script is tested in its own version (v2): a test upsert, nothing written.
            (Some(url), Some(s)) if cfg.kind == Kind::Hearings => {
                let empty = builtin_sheet::Upsert::default();
                let body = builtin_sheet::body_v2_json(&s, true, None, now, user_id, name, None, &empty);
                builtin_sheet::post_upsert(url, &body, allow_lan(&self.env)).await.0.map(|_| ())
            }
            (Some(url), Some(s)) => {
                let body = builtin_sheet::body_json(&s, true, None, now, user_id, name, None, text, None);
                builtin_sheet::post(url, &body, allow_lan(&self.env)).await.0
            }
            (Some(_), None) => Err("bot/sheet-secret"),
        }
    }

    /// The bot's name as members see it, from D1.
    pub(super) async fn builtin_bot_name(&self) -> Option<String> {
        Some(self.builtin_bot_row().await.ok()??.0)
    }

    /// (name, enabled) of this bot, from D1: `Ok(None)` when it is deleted, `Err` when D1 did
    /// not answer.
    pub(super) async fn builtin_bot_row(&self) -> std::result::Result<Option<(String, bool)>, ()> {
        #[derive(Deserialize)]
        struct R {
            name: String,
            #[serde(default)]
            disabled_at: Option<i64>,
        }
        let bot_id = self.bot_store().kv_get("bot_id").ok_or(())?;
        let db = self.env.d1("DB").map_err(|_| ())?;
        let row: Option<R> = db
            .prepare("SELECT name, disabled_at FROM bots WHERE bot_id = ?1 AND deleted_at IS NULL")
            .bind(&[crate::d1util::d1_text(&bot_id)])
            .map_err(|_| ())?
            .first(None)
            .await
            .map_err(|_| ())?;
        Ok(row.map(|r| (r.name, r.disabled_at.is_none())))
    }

    /// When the runner next needs the alarm: the head of the update queue or of the sheet's,
    /// pushed back while the bot is off. `None` for a program bot, or when nothing waits.
    pub(super) fn bot_builtin_next(&self) -> Option<i64> {
        let cfg = self.builtin_config()?;
        let store = self.bot_store();
        // Rows count only for a bot that writes them: the round would not send them, and an
        // alarm armed for them would fire at once, forever.
        let jobs = cfg.writes_sheet().then(|| store.db.int(bs::JOB_NEXT, &[])).flatten();
        let next = [store.db.int(super::deliver::HOOK_NEXT, &[]), jobs].into_iter().flatten().min()?;
        let hold = store.kv_get(KV_HOLD_UNTIL).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
        Some(next.max(hold))
    }
}
