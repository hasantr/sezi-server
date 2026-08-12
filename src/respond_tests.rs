//! A source-level guard for the one thing about `passthrough` that a runtime test cannot reach.
//!
//! `include_str!` binds at compile time and resolves relative to THIS file, so the handlers must
//! stay where they are for these to compile at all — which is the same trick `groups_tests.rs`
//! uses, and for the same reason: the invariant is about the SHAPE of the code, and by the time
//! the shape is wrong the only symptom is a 500 on a live request.

// No `use super::*`: these tests read the handlers as TEXT rather than calling them, which is the
// only way to check the invariant — a `Response` from a Durable Object cannot be constructed off
// a real workerd request, so there is nothing to call.

/// Every Durable Object answer that leaves a handler has to go through `respond::passthrough`.
///
/// The failure this prevents: a `Response` that came out of `fetch` is immutable in workerd, and
/// `apply_cors(resp.headers_mut())` runs on every routed answer, so returning the DO's response
/// verbatim throws `TypeError: Can't modify immutable headers` and the router answers 500 — after
/// the handler already did its work. It cost five endpoints for five days, including both halves
/// of durable sibling-read, and nothing caught it: the worker compiled, its unit tests passed, and
/// the only place the fault exists is the router's after-handler on a real request.
///
/// So the check is on the text. A `fetch_with_request` whose result is RETURNED must name
/// `passthrough` on the same line; one that is bound (`let …`) or discarded (`…?;`) is a caller
/// that reads the response itself and never hands it to the router.
#[test]
fn durable_object_responses_are_never_returned_verbatim() {
    const SOURCES: [(&str, &str); 2] = [
        ("messages/handlers.rs", include_str!("messages/handlers.rs")),
        ("plugin_log.rs", include_str!("plugin_log.rs")),
    ];

    let mut bare = Vec::new();
    for (name, src) in SOURCES {
        for (i, line) in src.lines().enumerate() {
            if !line.contains("fetch_with_request(") {
                continue;
            }
            let t = line.trim();
            let returned = !t.starts_with("let ") && !t.ends_with("?;");
            if returned && !t.contains("passthrough(") {
                bare.push(format!("{name}:{}: {t}", i + 1));
            }
        }
    }

    assert!(
        bare.is_empty(),
        "a Durable Object response is returned straight to the Router, which will 500 on it \
         once `apply_cors` touches its immutable headers — wrap it in `respond::passthrough`:\n{}",
        bare.join("\n"),
    );
}

/// The wrapper is actually used, so the test above cannot pass by the handlers having been
/// rewritten to never talk to a Durable Object at all.
#[test]
fn the_five_known_passthrough_sites_are_still_wrapped() {
    let handlers = include_str!("messages/handlers.rs").matches("passthrough(").count();
    let plugin_log = include_str!("plugin_log.rs").matches("passthrough(").count();
    assert_eq!(
        (handlers, plugin_log),
        (3, 2),
        "expected `receipt_sync`, `self_read` and `self_read_sync` in messages/handlers.rs and \
         `append`/`sync` in plugin_log.rs to be wrapped. If a route was added or removed, change \
         this count deliberately — drifting silently to zero is what it guards.",
    );
}
