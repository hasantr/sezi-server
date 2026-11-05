//! Guards the plugin log's two handlers against the server's plugin policy drifting out of them.
//!
//! Source-level, for the reason `groups_tests.rs` gives: both handlers need D1, a Durable Object
//! and a live worker environment, so no behavioural test reaches them. The decision itself
//! (`admin/plugin_policy.rs` `refuses_append`, its SQL against the real schema) is tested there.

/// `include_str!` resolves relative to THIS file, so moving `plugin_log.rs` breaks the build
/// instead of silently emptying the guard.
const SRC: &str = include_str!("plugin_log.rs");

/// One handler's source, from its `pub async fn` line to the next one.
fn handler_body(name: &str) -> &'static str {
    let needle = format!("\npub async fn {name}(");
    let start = SRC
        .find(&needle)
        .unwrap_or_else(|| panic!("no handler named {name} in plugin_log.rs — re-point this guard"));
    let rest = &SRC[start + 1..];
    let end = rest.find("\npub async fn ").unwrap_or(rest.len());
    &rest[..end]
}

/// An append for a plugin the server's admins switched off is refused before it reaches the
/// room's log — and before the epoch-floor gate, whose `409 epoch_stale` makes the app refresh
/// its groups and re-append under a new epoch, a round trip that would only be refused again.
#[test]
fn append_refuses_a_disabled_plugin_before_the_epoch_floor() {
    let body = handler_body("append");
    let policy = body
        .find("plugin_policy::append_refused(")
        .expect("append must consult the plugin policy");
    let floor = body.find("epoch_floor(").expect("append still has its epoch-floor gate");
    let forward = body.find("PLUGIN_ROOM_LOG").expect("append still forwards to the DO");
    assert!(policy < floor, "the policy is read before the epoch floor");
    assert!(policy < forward, "and before anything reaches the log");
}

/// Reads are unchanged: the relay deletes nothing on a disable, so re-enabling brings every entry
/// back, and the entries written before the switch stay readable meanwhile.
#[test]
fn sync_does_not_read_the_plugin_policy() {
    assert!(!handler_body("sync").contains("plugin_policy"));
}
