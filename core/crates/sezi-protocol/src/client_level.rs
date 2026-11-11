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

/// The oldest relay build (`/capabilities` `build`, yyyyMMddHHmm) this app works with — the other
/// side's half of the bargain (`docs/SERVER_UPDATE_PLAN.md` §2.3, decision D10). The release
/// channel's `app.min_server_build` says it too, and the higher of the two wins; this constant is
/// what a device that has no manifest at hand goes by (a member's phone never reads the channel).
///
/// 0 = no relay build is known to be too old for this app. Raise it in the commit of an app change
/// that a relay older than some build cannot serve; a server below it then shows its members a
/// quiet "older than your app" line and its owner a red one. A build of 0 or none (a hand-built
/// relay) is never judged.
pub const MIN_SERVER_BUILD: i64 = 0;

/// The typed code of "this server is older than this app", never a sentence from the core.
pub const SERVER_TOO_OLD_CODE: &str = "server/too-old";

/// Is a relay announcing `build` older than `wanted`? Unknown (0 or negative) on either side is
/// no claim either way.
pub fn server_too_old(build: i64, wanted: i64) -> bool {
    build > 0 && wanted > 0 && build < wanted
}

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
        assert_eq!(SERVER_TOO_OLD_CODE, "server/too-old");
    }

    #[test]
    fn only_a_known_build_below_a_known_floor_is_too_old() {
        assert!(server_too_old(202_610_010_000, 202_611_010_000));
        assert!(!server_too_old(202_611_010_000, 202_611_010_000));
        assert!(!server_too_old(0, 202_611_010_000), "unknown build: no claim");
        assert!(!server_too_old(202_610_010_000, 0), "no floor: no claim");
    }
}
