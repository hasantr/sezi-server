//! How a wake shows itself on the device it reaches — the one place its FCM message is built.
//!
//! **`data`** (every device, the default): `data:{type:"wake"}` and nothing else. The app's own
//! process wakes, decrypts what is waiting and draws the real notification itself.
//!
//! **`visible`** (a device that told us it cannot be woken that way): the same data, plus an
//! `android.notification` block the OS draws WITHOUT starting the app. It exists for Xiaomi's
//! MIUI/HyperOS with "Autostart" off — there the system will not start Sezi's process for a data
//! wake, so a data-only push shows nothing at all, while WhatsApp and Telegram are on Xiaomi's own
//! whitelist (Hasan's phone, 2026-10-24). The client measures that switch and registers its token
//! with `wake: "visible"`; when the switch is turned on it registers `data` again.
//!
//! What a visible wake may say is fixed text: the product's name and "new message", in the
//! token's language. The server has no message content, and nothing it does hold goes in either —
//! no server id, room, sender or count. Google already learns "a push happened, now" from a data
//! wake; a visible one adds only that the device shows a notification. One `tag` for every wake,
//! so ten messages are one notification, not ten.

use serde_json::{json, Value};

/// The notification channel the app creates (`fcm_service.dart`'s `_kMsgChannel`).
pub(crate) const CHANNEL: &str = "sezgi_messages_v2";
/// The app's monochrome status-bar icon (`ic_stat_sezgi` drawable).
pub(crate) const ICON: &str = "ic_stat_sezgi";
/// One tag for every visible wake: the next one replaces the last one. The app takes it down
/// when it shows the real notifications (`fcm_service.dart`, `kVisibleWakeTag`).
pub(crate) const TAG: &str = "sezi-wake";

/// The language of a visible wake's two lines. Turkish when the token said nothing usable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Lang {
    #[default]
    Tr,
    En,
}

impl Lang {
    /// What the client sent, or what the row holds. Anything but `en`/`tr` is Turkish.
    pub(crate) fn parse(s: Option<&str>) -> Self {
        match s {
            Some("en") => Lang::En,
            _ => Lang::Tr,
        }
    }

    /// The stored and relayed spelling.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Lang::Tr => "tr",
            Lang::En => "en",
        }
    }

    /// The notification's body. The title is the product's name in every language.
    fn new_message(self) -> &'static str {
        match self {
            Lang::Tr => "Yeni mesaj",
            Lang::En => "New message",
        }
    }
}

/// How one token is woken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum WakeStyle {
    #[default]
    Data,
    Visible(Lang),
}

impl WakeStyle {
    /// From a register body or a `push_tokens` row (`wake`, `wake_lang`). Anything but
    /// `visible` is `data`: an old row (the column's default), an old client (no field), and a
    /// value a newer client might send that this server does not know — the behaviour every
    /// token had before visible wakes existed.
    pub(crate) fn parse(wake: Option<&str>, lang: Option<&str>) -> Self {
        match wake {
            Some("visible") => WakeStyle::Visible(Lang::parse(lang)),
            _ => WakeStyle::Data,
        }
    }

    /// The `push_tokens.wake` column.
    pub(crate) fn column(self) -> &'static str {
        match self {
            WakeStyle::Data => "data",
            WakeStyle::Visible(_) => "visible",
        }
    }

    /// The `push_tokens.wake_lang` column: only a visible token has a language to keep.
    pub(crate) fn lang_column(self) -> Option<&'static str> {
        match self {
            WakeStyle::Data => None,
            WakeStyle::Visible(l) => Some(l.code()),
        }
    }
}

/// The FCM HTTP v1 `messages:send` body for one wake.
///
/// A data wake is the message every device got before visible wakes existed, byte for byte
/// (`style_tests.rs` holds it to that). data-ONLY is what makes Android hand a terminated app its
/// `onBackgroundMessage`; `priority: high` takes it out of doze.
///
/// **No `android.collapse_key`, deliberately** (weighed 2026-10-30, after the ZH wake storm). It
/// would let FCM keep only the latest undelivered wake for an offline device, but it makes the
/// data wake COLLAPSIBLE, and Google throttles collapsible messages to "a burst of 20 messages per
/// app per device, with a refill of 1 message every 3 minutes" — delayed, not dropped
/// (firebase.google.com/docs/cloud-messaging/throttling-and-quotas). A chat recipient who connects
/// and leaves between messages legitimately gets more than 20 wakes, and past that each one would
/// wait minutes. Google's own guidance keeps chat non-collapsible. Repeated wakes are cut where
/// they start instead: one per unseen device per window (`coalesce.rs`). A visible wake is a
/// notification message, which FCM always treats as collapsible and whose `collapse_key` it
/// ignores; its `tag` already collapses what the user sees.
pub(crate) fn fcm_message(token: &str, style: WakeStyle) -> Value {
    match style {
        WakeStyle::Data => json!({
            "message": {
                "token": token,
                "data": { "type": "wake" },
                "android": { "priority": "high" }
            }
        }),
        WakeStyle::Visible(lang) => json!({
            "message": {
                "token": token,
                // Kept, so a tap opens the app and an app that IS started still drains.
                "data": { "type": "wake" },
                "android": {
                    "priority": "high",
                    "notification": {
                        // The product's name, not a sentence: the same in every language.
                        "title": "Sezi",
                        "body": lang.new_message(),
                        "channel_id": CHANNEL,
                        "icon": ICON,
                        "tag": TAG,
                        "notification_priority": "PRIORITY_HIGH",
                        "default_sound": true
                    }
                }
            }
        }),
    }
}

/// The shared push relay's `/wake` body (`push-relay/src/index.js`). A data wake sends what it
/// always sent, `{token}`; a relay that predates visible wakes ignores the two extra fields and
/// sends a data wake, which is what that device got before.
pub(crate) fn relay_body(token: &str, style: WakeStyle) -> Value {
    match style {
        WakeStyle::Data => json!({ "token": token }),
        WakeStyle::Visible(lang) => json!({ "token": token, "wake": "visible", "lang": lang.code() }),
    }
}

#[cfg(test)]
#[path = "style_tests.rs"]
mod tests;
