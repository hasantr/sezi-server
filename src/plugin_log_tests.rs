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
    assert!(!handler_body("sync").contains("append_refused"));
}

/// The room DO's append, from its `async fn do_append` to the next fn.
fn do_append_body() -> &'static str {
    let start = SRC.find("async fn do_append(").expect("the DO still has do_append");
    let rest = &SRC[start..];
    let end = rest[1..].find("\n    async fn ").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

/// Review 2026-11 H10: the member budget (`plugin_log_budget.rs`) is asked before the entry is
/// sequenced — a refused entry takes no seq — and charged only after the row is written.
#[test]
fn do_append_asks_the_member_budget_before_the_seq_and_charges_after_the_row() {
    let body = do_append_body();
    let admit = body.find("budget::admit(").expect("do_append must ask the member budget");
    let seq = body.find("INSERT OR IGNORE INTO plugin_log_meta").expect("the seq bump");
    let row = body.find("INSERT INTO plugin_log_entries").expect("the row insert");
    let charge = body.find("budget::charge(").expect("do_append must charge the author");
    assert!(admit < seq, "the budget is asked before a seq is taken");
    assert!(row < charge, "and charged once the row is written");
    assert!(body.contains("budget::LOG_FULL_CODE"), "a refusal says plugin/log-full");
}

/// Review 2026-11 H9/H10: both handlers take only a well-formed plugin id
/// (`admin::plugin_policy::plugin_id_ok`, the policy's own rule) before the DO sees it.
#[test]
fn both_handlers_check_the_plugin_id_shape() {
    for name in ["append", "sync"] {
        let body = handler_body(name);
        let check = body
            .find("plugin_policy::plugin_id_ok(")
            .unwrap_or_else(|| panic!("{name} must check the plugin id"));
        let forward = body.find("PLUGIN_ROOM_LOG").expect("still forwards to the DO");
        assert!(check < forward, "{name}: the id is checked before the DO sees it");
    }
}

/// Review 2026-11 H1: a refused append below the room's epoch floor names the floor, so an
/// admin's app can mint its next epoch at or past it in one step. The code and the status stay
/// what every app already reads — an older app sees the `409 {"error":"epoch_stale"}` it always did.
#[test]
fn the_epoch_stale_refusal_names_the_floor_beside_the_old_code() {
    let body = super::epoch_stale_body(3);
    assert_eq!(body["error"], "epoch_stale", "the code an older app reads is unchanged");
    assert_eq!(body["floor"], 3);
    assert_eq!(super::EPOCH_STALE_STATUS, 409, "the status an older app reads is unchanged");
}

/// …and the append handler answers with that body, not the bare code.
#[test]
fn append_answers_epoch_stale_with_the_floor() {
    let body = handler_body("append");
    assert!(body.contains("epoch_stale_body(floor)"), "the 409 carries the floor");
    assert!(!body.contains("json_err(409, \"epoch_stale\")"), "no bare 409 is left");
}
