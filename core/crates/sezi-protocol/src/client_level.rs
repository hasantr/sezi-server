//! How new this app is, in the one number a server can ask for (Hasan, 2026-10-31).
//!
//! Servers and apps update independently: a self-hosted relay is updated by its owner, an app by
//! the store, and either can be months ahead of the other. Every relay change is meant to keep
//! working with the apps already out there. When one cannot, the relay raises the minimum it
//! announces on the public `GET /capabilities` (`min_client_level`, worker-rs
//! `server/client_level.rs` `MIN_CLIENT_LEVEL`) and the app built in the same commit raises
//! [`CLIENT_LEVEL`] to match. Every app older than that then reads the relay's minimum at attach
//! and tells its person to update (`core/src/kernel/app_update.rs`).
//!
//! **A protocol level, not the store's build number.** Neither the core nor Dart knows the build
//! number (`mobile/pubspec.yaml`'s `+2025` is a packaging detail), and a browser build has none at
//! all; this constant is compiled into every build of the core, the web one included.
//!
//! It lives here rather than in the client crate because the relay names it too: worker-rs checks
//! that its minimum never exceeds the level of the app built from the same tree, which would ask
//! every person to install an update that does not exist.

/// This app's level. Raise it ONLY together with worker-rs `MIN_CLIENT_LEVEL`, in the same commit,
/// for a relay change that apps below the new level cannot survive (`AGENTS.md`, "Server ↔ app
/// compatibility").
pub const CLIENT_LEVEL: u32 = 1;

// A relay that never raised its minimum announces 1, and the first app with this code is already
// there. A level below 1 would make every such relay ask every app to update.
const _: () = assert!(CLIENT_LEVEL >= 1);

/// The typed code the UI turns into "update the app" — never a sentence from the core.
pub const UPDATE_REQUIRED_CODE: &str = "app/update-required";

/// Does a server that announces `min_client_level` need a newer app than this one? An absent
/// announcement reads as 0: no requirement, which is what every relay older than this field means.
pub fn update_required(min_client_level: u32) -> bool {
    min_client_level > CLIENT_LEVEL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_minimum_above_mine_requires_an_update() {
        assert!(!update_required(0), "an old relay announces nothing");
        assert!(!update_required(CLIENT_LEVEL), "exactly my level is enough");
        assert!(!update_required(CLIENT_LEVEL - 1));
        assert!(update_required(CLIENT_LEVEL + 1));
        assert!(update_required(u32::MAX));
    }

    #[test]
    fn the_code_is_the_one_the_ui_reads() {
        assert_eq!(UPDATE_REQUIRED_CODE, "app/update-required");
    }
}
