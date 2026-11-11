//! Plugin bundle packing/unpacking, the signed app manifest and the egress scanner.
//!
//! Split out of `messaging-core` in D5; see the crate manifest for why these modules and
//! not others.

pub mod allowlist;
pub mod app_manifest;
pub mod plugin_bundle;
pub mod plugin_bundle_v2;
pub mod plugin_scan;
pub mod semver;
