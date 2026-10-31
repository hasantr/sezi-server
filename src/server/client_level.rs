//! The oldest app this relay still works with (Hasan, 2026-10-31).
//!
//! Announced on the public `GET /capabilities` as `min_client_level` (`handlers.rs`). An app whose
//! own level (`sezi_protocol::client_level::CLIENT_LEVEL`) is below it tells its person to update,
//! on this server, with a banner and one notification (`core/src/kernel/app_update.rs`). An app
//! older than that mechanism cannot be told anything; that is accepted.
//!
//! **Never raise this casually.** Relays and apps update independently — a self-hosted relay when
//! its owner updates it, an app when the store does — so every change here must keep working with
//! the apps already out there. Only a change that cannot raises this, together with the core's
//! `CLIENT_LEVEL`, in the same commit (`AGENTS.md`, "Server ↔ app compatibility"). The guard in
//! `client_level_tests.rs` refuses a minimum above the level of the app built from this tree.

/// The lowest app level this relay serves. 1 = every app that knows the field: nobody is asked to
/// update.
pub const MIN_CLIENT_LEVEL: u32 = 1;

#[cfg(test)]
#[path = "client_level_tests.rs"]
mod tests;
