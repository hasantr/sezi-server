//! Owner/admin surface.
//!
//! Every endpoint here must gate on `require_active_auth`, never on `require_auth`. See the guard
//! test at the bottom of this file for why — it encodes a real hole that existed until 2026-07-25.

pub mod cf_config;
pub mod fcm_config;
pub mod turn_config;
pub mod handlers;
pub mod plugin_policy;
pub mod reset;
pub mod stats;
pub mod storage;

/// Guards the admin surface against re-opening the device-revocation hole.
///
/// `require_auth` verifies a stateless JWT's signature and expiry and nothing else.
/// `require_active_auth` additionally proves the account still exists AND the token-bound device is
/// still present and not revoked.
///
/// The difference is not academic. Revoking a device deletes its refresh token, but its ~15-minute
/// ACCESS token keeps verifying — it is stateless. Until 2026-07-25 five of the six admin modules
/// gated on `require_auth`, so for that window a revoked device belonging to a still-valid
/// owner/admin (it passes the role lookup too) could still read the server stats, read and WRITE the
/// storage configuration, and write the CF and FCM configuration — the last of which redirects push.
/// `handlers.rs` had it right the whole time, which is exactly why the inconsistency went unnoticed:
/// revocation demonstrably worked when you tested it on invites or members.
///
/// A source-level assertion is the right shape for this. The bug was never in a function's logic; it
/// was in which middleware a handler happened to call, and no behavioural test over one endpoint can
/// see that the endpoint NEXT to it chose differently.
#[cfg(test)]
mod auth_gate_guard {
    /// `include_str!` rather than reading from disk: it binds at compile time, so renaming or
    /// deleting a module breaks the build instead of silently emptying the guard.
    const ADMIN_MODULES: [(&str, &str); 6] = [
        ("cf_config.rs", include_str!("cf_config.rs")),
        ("fcm_config.rs", include_str!("fcm_config.rs")),
        ("handlers.rs", include_str!("handlers.rs")),
        ("plugin_policy.rs", include_str!("plugin_policy.rs")),
        ("stats.rs", include_str!("stats.rs")),
        ("storage.rs", include_str!("storage.rs")),
    ];

    #[test]
    fn no_admin_module_gates_on_the_stateless_jwt_alone() {
        let mut offenders = Vec::new();
        for (name, src) in ADMIN_MODULES {
            // `require_active_auth` does not contain `require_auth` as a substring, and the `(`
            // keeps a mention inside a comment from tripping the guard.
            if src.contains("require_auth(") {
                offenders.push(name);
            }
        }
        assert!(
            offenders.is_empty(),
            "these admin modules gate on require_auth, which does NOT check whether the calling \
             device was revoked: {offenders:?}. Use require_active_auth — a revoked device's access \
             token stays valid for ~15 minutes and would keep full admin access, including writing \
             the FCM config."
        );
    }

    /// `PATCH /admin/server-settings` must stay OWNER-only.
    ///
    /// It was `require_admin` until 2026-07-25, which accepts admin OR owner — so any admin could
    /// change `join_mode` (turning an invite-only server open), `directory_mode`/`dm_policy`, both
    /// retention windows, both storage caps and `delete_window_hours`, while the app's own editors
    /// described those as owner-only. This pins the gate so the next edit cannot quietly widen it back.
    ///
    /// Scoped to the function body rather than the file, because `handlers.rs` legitimately uses
    /// `require_admin` elsewhere — invites, the member list, removing a member. Only CONFIGURATION
    /// mutations are owner-only, matching `admin/storage.rs`.
    #[test]
    fn server_settings_stays_owner_only() {
        let src = include_str!("handlers.rs");
        let at = src
            .find("pub async fn update_settings")
            .expect("update_settings must exist — if it was renamed, re-point this guard");
        // The gate is decided in the first few statements; 40 lines is generous and keeps a later
        // `require_admin` call for some other purpose from satisfying the check by accident.
        let head: String = src[at..].lines().take(40).collect::<Vec<_>>().join("\n");
        assert!(
            head.contains("require_owner("),
            "update_settings must gate on require_owner — every field it writes is server-wide policy"
        );
        assert!(
            !head.contains("require_admin("),
            "update_settings must NOT gate on require_admin: that accepts any admin, and `join_mode` \
             alone lets one change who may join the server"
        );
    }

    /// The positive half: every module must actually reach for the strict gate. Without this, the
    /// test above passes for a module that has no authentication at all.
    #[test]
    fn every_admin_module_reaches_for_the_active_gate() {
        let mut missing = Vec::new();
        for (name, src) in ADMIN_MODULES {
            if !src.contains("require_active_auth(") {
                missing.push(name);
            }
        }
        assert!(
            missing.is_empty(),
            "these admin modules never call require_active_auth: {missing:?}. An admin endpoint \
             without an active-device proof is the hole this guard exists for."
        );
    }
}
