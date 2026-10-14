//! One member's wake: read the send mode and the tokens, send to each, act on each verdict.
//!
//! The orchestration is `wake_with`, written against `WakePort` so the host tests run the REAL
//! loop (`wake_tests.rs`, and the subrequest count in `messages/spend_tests.rs`); `D1Wake` is the
//! production port.

use serde::Deserialize;
use worker::*;

use super::config::{self, ProjectVerdict, PushConfig, SendMode, KEY_OWN_REACHED};
use super::fcm::{send_wake, send_wake_relay, DirectSend};
use crate::d1util::d1_text;
use crate::utils::now_secs;

/// Recipient is OFFLINE → a contentless wake to their registered push tokens.
/// `recipient_device_id` Some → that device only; None → ALL of the user's devices.
/// Best-effort: own config → direct FCM, else the shared relay, and with the relay `off` a silent
/// no-op. A stale token is deleted from `push_tokens`.
pub async fn maybe_push_wake(
    env: &Env,
    db: &D1Database,
    recipient_id: &str,
    recipient_device_id: Option<&str>,
) {
    match recipient_device_id {
        Some(d) => push_wake_devices(env, db, recipient_id, Some(&[d.to_string()])).await,
        None => push_wake_devices(env, db, recipient_id, None).await,
    }
}

/// One device's push token.
const DEVICE_TOKEN_SQL: &str = "SELECT device_id, fcm_token, relay_project FROM push_tokens
     WHERE user_id = ? AND device_id = ?";

/// The push tokens of a user — what a device-blind wake, and a member with several asleep devices,
/// read. Never a REVOKED device's (its token used to outlive it: the D8 review's F6), and at most
/// `MAX_DEVICES`, newest first, so a pile of tokens from before device addressing cannot turn one
/// wake into a dozen fetches. Rows with no device row at all are such pre-addressing tokens.
const USER_TOKENS_SQL: &str = "SELECT pt.device_id, pt.fcm_token, pt.relay_project FROM push_tokens pt
     WHERE pt.user_id = ?
       AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.user_id = pt.user_id
                         AND d.device_id = pt.device_id AND d.revoked_at IS NOT NULL)
     ORDER BY pt.last_seen_at DESC
     LIMIT 5";

/// Mark one token as the published app's: Google refused `?1`, the owner's project, for it, so
/// its wakes go through the shared relay. Bound to the token itself, so a token the device
/// re-registered in the meantime is not marked for what was measured about the old one.
pub(crate) const ROUTE_VIA_RELAY_SQL: &str = "UPDATE push_tokens SET relay_project = ?1
     WHERE user_id = ?2 AND device_id = ?3 AND fcm_token = ?4";

/// One registered device's token.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct TokenRow {
    pub(crate) device_id: String,
    pub(crate) fcm_token: String,
    /// The own project Google refused this token for (K8): its wakes go through the shared relay
    /// while that project is the server's. None = direct.
    #[serde(default)]
    pub(crate) relay_project: Option<String>,
}

/// Every subrequest a wake makes, behind one seam.
pub(crate) trait WakePort {
    /// The push config (one D1 query). None = D1 unreadable → no wake.
    async fn config(&self) -> Option<PushConfig>;
    /// One device's token (`devices` of one), or the user's newest tokens (one D1 query).
    async fn tokens(&self, devices: Option<&[String]>) -> Result<Vec<TokenRow>>;
    /// A send through the owner's own project (the OAuth mint, when due, rides on the first).
    async fn direct(&self, project_id: &str, service_account: &str, token: &str) -> DirectSend;
    /// A send through the shared relay: Ok(true) sent, Ok(false) stale, Err failed.
    async fn relay(&self, url: &str, token: &str) -> Result<bool>;
    async fn delete_token(&self, device_id: &str);
    /// Record that the owner's own project has reached a device (`config::KEY_OWN_REACHED`).
    async fn record_reached(&self, verdict: ProjectVerdict);
    /// Mark one token as relayed from now on ([`ROUTE_VIA_RELAY_SQL`]).
    async fn route_via_relay(&self, row: &TokenRow, project_id: &str);
    fn now(&self) -> i64;
    /// A log line (the console is a JS import, absent from the host tests).
    fn log(&self, line: String);
}

/// What one wake came to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WakeTally {
    pub(crate) tokens: usize,
    pub(crate) ok: usize,
    pub(crate) stale: usize,
    pub(crate) failed: usize,
    /// Wakes of an own-project server that went through the shared relay (a token marked
    /// before, or refused in this wake) — or tried to.
    pub(crate) relayed: usize,
    /// Tokens this wake found refused for the own project and marked for the relay.
    pub(crate) routed: usize,
}

/// One member's offline devices → a contentless wake to each. The send mode is resolved ONCE and
/// the tokens are read in ONE query however many devices are named, which is what lets a group
/// member's whole wake cost a few D1 reads plus one fetch per token (D8: the recipient's inbox DO
/// calls this for the devices of one `/notify-member`).
/// `devices` Some → those devices only (an empty list wakes nobody); None → every device.
pub async fn push_wake_devices(
    env: &Env,
    db: &D1Database,
    recipient_id: &str,
    devices: Option<&[String]>,
) {
    let port = D1Wake { env, db, user: recipient_id };
    wake_with(&port, recipient_id, devices).await;
}

/// The wake itself. Every exit logs one verdict line: silence would make "push is switched off",
/// "the device has no token", "the token was stale and was just deleted" and "it went out fine"
/// indistinguishable from outside — which is why "notifications do not arrive when the app is
/// closed" once had no answer. The mode is named because a server with no FCM configuration falls
/// back to the shared relay, and its operator should not push through someone else's
/// infrastructure unknowingly.
pub(crate) async fn wake_with<P: WakePort>(
    p: &P,
    user: &str,
    devices: Option<&[String]>,
) -> WakeTally {
    let mut t = WakeTally::default();
    if devices.is_some_and(|d| d.is_empty()) {
        return t;
    }
    let Some(mode) = p.config().await.and_then(|c| c.send_mode()) else {
        p.log(format!("[push] user={user} mode=off -> skipped (FCM not configured, or 'off')"));
        return t;
    };
    let mode_name = match &mode {
        SendMode::Direct { .. } => "direct",
        SendMode::Relay { .. } => "relay",
    };
    let rows = match p.tokens(devices).await {
        Ok(r) => r,
        Err(e) => {
            p.log(format!("[push] user={user} mode={mode_name} token query FAIL: {e:?}"));
            return t;
        }
    };
    // One device: the narrow query. Several: the user's tokens, filtered here — still one query.
    let rows: Vec<TokenRow> = match devices {
        Some(list) if list.len() > 1 => rows
            .into_iter()
            .filter(|r| list.iter().any(|d| d == &r.device_id))
            .collect(),
        _ => rows,
    };
    if rows.is_empty() {
        // Not an error, and the single most useful thing to know: this device never registered, or
        // its token was deleted as stale.
        p.log(format!("[push] user={user} mode={mode_name} token=0 -> not sent (no registered device)"));
        return t;
    }
    t.tokens = rows.len();

    // NO wake debounce. A 20s per-recipient+device debounce suppressed legitimate follow-up
    // messages arriving just after a drain finished — no wake, no delivery, a single tick and no
    // notification. `delivered_live` (message.rs) already prevents wakes during a drain over an
    // active WS, so a debounce is redundant as well as harmful. Every undelivered message gets its
    // wake.
    //
    // `reached`: the own project has woken a device — recorded before, or earlier in this wake.
    let mut reached = matches!(mode, SendMode::Direct { reached: true, .. });
    for row in &rows {
        let (project_id, service_account, fallback) = match &mode {
            SendMode::Relay { url } => {
                via_relay(p, user, url, row, &mut t).await;
                continue;
            }
            SendMode::Direct { project_id, service_account, fallback, .. } => {
                (project_id, service_account, fallback.as_deref())
            }
        };
        // A token Google refused for THIS project before: the published app's. Straight to the
        // relay, never direct again until the device registers another token (`handlers.rs`).
        // Every decision here is about one token: no wake moves any other device's route.
        if row.relay_project.as_deref() == Some(project_id.as_str()) {
            relay_refused(p, user, fallback, row, &mut t).await;
            continue;
        }
        match p.direct(project_id, service_account, &row.fcm_token).await {
            DirectSend::Sent => {
                t.ok += 1;
                if !reached {
                    reached = true;
                    let v = ProjectVerdict { at: p.now(), project: project_id.clone() };
                    p.record_reached(v).await;
                }
            }
            DirectSend::Stale => stale(p, user, row, &mut t).await,
            // K8: this token was minted by another Firebase project — the published app's, which
            // the shared relay serves. This wake is resent there so it is not lost, and the token
            // is marked so the next one goes there first. Marked after the relay's answer: a token
            // the relay calls stale is deleted, and a mark on it would be a write for nothing.
            DirectSend::SenderMismatch => {
                p.log(format!(
                    "[push] user={user} device={} project={project_id} REFUSED by FCM \
                     (SENDER_ID_MISMATCH): the published app's token -> the shared relay from now on",
                    row.device_id
                ));
                t.routed += 1;
                if relay_refused(p, user, fallback, row, &mut t).await {
                    p.route_via_relay(row, project_id).await;
                }
            }
            DirectSend::Failed(e) => {
                t.failed += 1;
                p.log(format!("[push] user={user} device={} send FAILED: {e}", row.device_id));
            }
        }
    }
    p.log(format!(
        "[push] user={user} mode={mode_name} token={} ok={} stale={} failed={} relayed={} routed={}",
        t.tokens, t.ok, t.stale, t.failed, t.relayed, t.routed
    ));
    t
}

/// A token the own project cannot reach, through the shared relay — or nowhere with the relay off.
/// Answers whether the token is still registered (the relay did not call it stale).
async fn relay_refused<P: WakePort>(
    p: &P,
    user: &str,
    fallback: Option<&str>,
    row: &TokenRow,
    t: &mut WakeTally,
) -> bool {
    let Some(url) = fallback else {
        t.failed += 1;
        p.log(format!(
            "[push] user={user} device={} send FAILED: the published app's token and the relay is off",
            row.device_id
        ));
        return true;
    };
    t.relayed += 1;
    via_relay(p, user, url, row, t).await
}

/// One token through the shared relay. Answers whether the token is still registered.
async fn via_relay<P: WakePort>(p: &P, user: &str, url: &str, row: &TokenRow, t: &mut WakeTally) -> bool {
    match p.relay(url, &row.fcm_token).await {
        Ok(true) => t.ok += 1,
        Ok(false) => {
            stale(p, user, row, t).await;
            return false;
        }
        Err(e) => {
            t.failed += 1;
            p.log(format!("[push] user={user} device={} send FAILED: {e:?}", row.device_id));
        }
    }
    true
}

/// Stale token → drop it, so later messages do not retry it for nothing. Logged per device on
/// purpose: the deletion is correct but invisible, and it permanently ends push for that device.
/// "Notifications just stopped" needs a trace to follow, and a bulk deletion after an FCM 400 has
/// bitten this project before.
async fn stale<P: WakePort>(p: &P, user: &str, row: &TokenRow, t: &mut WakeTally) {
    t.stale += 1;
    p.log(format!(
        "[push] user={user} device={} token STALE -> deleted (this device can no longer be woken)",
        row.device_id
    ));
    p.delete_token(&row.device_id).await;
}

/// The production port: D1, KV, Google and the relay.
struct D1Wake<'a> {
    env: &'a Env,
    db: &'a D1Database,
    user: &'a str,
}

impl WakePort for D1Wake<'_> {
    async fn config(&self) -> Option<PushConfig> {
        config::read(self.env, self.db).await
    }

    async fn tokens(&self, devices: Option<&[String]>) -> Result<Vec<TokenRow>> {
        let stmt = match devices {
            Some([d]) => self.db.prepare(DEVICE_TOKEN_SQL).bind(&[d1_text(self.user), d1_text(d)])?,
            _ => self.db.prepare(USER_TOKENS_SQL).bind(&[d1_text(self.user)])?,
        };
        stmt.all().await?.results()
    }

    async fn direct(&self, project_id: &str, service_account: &str, token: &str) -> DirectSend {
        send_wake(self.env, service_account, token, project_id).await
    }

    async fn relay(&self, url: &str, token: &str) -> Result<bool> {
        send_wake_relay(url, token).await
    }

    async fn delete_token(&self, device_id: &str) {
        if let Ok(stmt) = self
            .db
            .prepare("DELETE FROM push_tokens WHERE user_id = ? AND device_id = ?")
            .bind(&[d1_text(self.user), d1_text(device_id)])
        {
            let _ = stmt.run().await;
        }
    }

    async fn record_reached(&self, verdict: ProjectVerdict) {
        config::record(self.db, KEY_OWN_REACHED, &verdict).await;
    }

    async fn route_via_relay(&self, row: &TokenRow, project_id: &str) {
        // Best effort: a lost mark only means the next wake asks Google once more.
        if let Ok(stmt) = self.db.prepare(ROUTE_VIA_RELAY_SQL).bind(&[
            d1_text(project_id),
            d1_text(self.user),
            d1_text(&row.device_id),
            d1_text(&row.fcm_token),
        ]) {
            let _ = stmt.run().await;
        }
    }

    fn now(&self) -> i64 {
        now_secs() as i64
    }

    fn log(&self, line: String) {
        // A refusal or a failure is a warning, everything else a plain line, as before.
        if line.contains("FAIL") || line.contains("STALE") {
            console_warn!("{line}");
        } else {
            console_log!("{line}");
        }
    }
}

#[cfg(test)]
#[path = "wake_tests.rs"]
pub(crate) mod tests;
