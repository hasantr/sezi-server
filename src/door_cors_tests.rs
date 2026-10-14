//! Which routes are the door, which pages may read it, and that `lib.rs` answers the door with
//! these rules rather than with `*`.

use super::*;

#[test]
fn the_door_is_redeem_describe_and_a_code_path_only() {
    for door in [
        "/auth/redeem",
        "/invites/describe",
        "/K7QM-4827",
        "/k7qm4827",
    ] {
        assert!(is_door_path(door), "{door}");
    }
    for not in [
        "/",
        "/healthz",
        "/server/info",
        "/groups",
        "/auth/verify",
        "/K7QM-4827/x",
        "/favicon.ico",
        "/media/K7QM-4827",
    ] {
        assert!(!is_door_path(not), "{not}");
    }
}

#[test]
fn the_web_client_its_previews_and_this_machine_may_read_the_door() {
    for ok in [
        "https://sezi-web.pages.dev",
        "https://SEZI-WEB.pages.dev/",
        "https://0a09eefb.sezi-web.pages.dev",
        "http://localhost:8099",
        "http://127.0.0.1:8099",
        "http://localhost",
        "http://[::1]:8099",
    ] {
        assert!(origin_allowed(ok, ""), "{ok}");
    }
}

#[test]
fn any_other_page_may_not() {
    for no in [
        "https://evil.example",
        "https://sezi-web.pages.dev.evil.example",
        "https://evil.example/https://sezi-web.pages.dev",
        "https://x.y.sezi-web.pages.dev",
        "http://sezi-web.pages.dev",
        "https://localhost:8099",
        "http://localhost.evil.example",
        "http://localhost:80x",
        "null",
        "",
    ] {
        assert!(!origin_allowed(no, ""), "{no}");
    }
}

#[test]
fn the_operator_can_add_an_origin_but_not_a_wildcard() {
    let extra = " https://chat.okul.edu.tr/ , https://other.example";
    assert!(origin_allowed("https://chat.okul.edu.tr", extra));
    assert!(origin_allowed("https://other.example", extra));
    assert!(!origin_allowed("https://evil.example", extra));
    assert!(!origin_allowed("https://evil.example", "*"));
}

/// The routing half: the preflight and every routed answer go through the door rules for a door
/// path. Source-level, because the fetch handler needs a live `Env`.
#[test]
fn lib_answers_the_door_with_these_rules() {
    let lib = include_str!("lib.rs");
    assert!(lib.contains(concat!("door_cors::is_door_", "path(&path)")));
    let preflight = lib
        .find(concat!("if req.method() == Method::", "Options {"))
        .expect("the preflight branch moved");
    let refused = lib[preflight..]
        .find(concat!("door_cors::origin_", "allowed(o, extra)"))
        .expect("the preflight checks the origin for a door path");
    assert!(refused < 600, "inside the preflight branch");
    assert_eq!(
        lib.matches(concat!("door_cors::apply(resp.headers_", "mut()"))
            .count(),
        2,
        "the preflight and every routed answer"
    );
}
