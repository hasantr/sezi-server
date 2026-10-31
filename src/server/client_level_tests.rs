//! The relay's minimum app level: what it may be, and that `/capabilities` says it.

use super::MIN_CLIENT_LEVEL;

/// A minimum above the app built from the same tree asks every person for an update that does not
/// exist yet. The two constants move together, in one commit.
#[test]
fn the_minimum_never_exceeds_the_app_built_beside_it() {
    assert!(
        !sezi_protocol::client_level::update_required(MIN_CLIENT_LEVEL),
        "MIN_CLIENT_LEVEL {MIN_CLIENT_LEVEL} is above the core's CLIENT_LEVEL {}: raise both \
         together, or an app from this tree is told to update by a relay from this tree",
        sezi_protocol::client_level::CLIENT_LEVEL
    );
}

/// The handler needs D1 and a live worker environment, so the announcement is guarded at source
/// level: the `capabilities` handler itself — not merely the file — must put the constant under
/// the name the core reads (`ServerCaps::min_client_level`).
#[test]
fn capabilities_announces_the_minimum() {
    const SRC: &str = include_str!("handlers.rs");
    let start = SRC
        .find("\npub async fn capabilities(")
        .expect("the capabilities handler is in handlers.rs");
    let rest = &SRC[start + 1..];
    let end = rest.find("\npub ").unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(
        body.contains("\"min_client_level\": crate::server::client_level::MIN_CLIENT_LEVEL"),
        "/capabilities must announce `min_client_level` from MIN_CLIENT_LEVEL"
    );
}
