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

// ---- The door's POSTs (adversarial review 2026-10-14, F5) ----

/// A body not declared JSON is refused, whatever the page: the cross-origin "simple" POST
/// (`text/plain`, no preflight) no longer reaches the miss budget or the lookup.
#[test]
fn a_door_post_must_be_declared_json() {
    for ct in [None, Some("text/plain"), Some("text/plain;charset=UTF-8"), Some("multipart/form-data"), Some("application/x-www-form-urlencoded"), Some("application/jsonx")] {
        assert_eq!(post_refusal(ct, None, None, ""), Some(PostRefusal::NotJson), "{ct:?}");
    }
    for ct in ["application/json", "application/json; charset=utf-8", "Application/JSON"] {
        assert_eq!(post_refusal(Some(ct), None, None, ""), None, "{ct}");
    }
    assert_eq!(PostRefusal::NotJson.status(), 415);
}

/// A browser that says the request is cross-site is refused unless its page may read the door;
/// the native app (no `Sec-Fetch-Site`) and a same-site page are not asked.
#[test]
fn a_cross_site_door_post_needs_an_allowed_origin() {
    let json = Some("application/json");
    assert_eq!(
        post_refusal(json, Some("cross-site"), Some("https://evil.example"), ""),
        Some(PostRefusal::CrossSite)
    );
    assert_eq!(post_refusal(json, Some("cross-site"), None, ""), Some(PostRefusal::CrossSite));
    assert_eq!(post_refusal(json, Some("cross-site"), Some(WEB_CLIENT_ORIGIN), ""), None);
    assert_eq!(
        post_refusal(json, Some("cross-site"), Some("https://chat.okul.edu.tr"), "https://chat.okul.edu.tr"),
        None
    );
    assert_eq!(post_refusal(json, Some("same-origin"), None, ""), None);
    assert_eq!(post_refusal(json, None, None, ""), None, "the native app");
    assert_eq!(PostRefusal::CrossSite.status(), 403);
}

/// Both POSTs ask first — before the miss budget is reserved and before anything is looked up.
#[test]
fn both_door_posts_refuse_before_they_cost_anything() {
    let redeem = include_str!("auth/invite.rs");
    let body = redeem.split("pub async fn redeem").nth(1).unwrap();
    let guard = body.find("door_cors::refuse_post(&req").expect("redeem asks");
    assert!(guard < body.find("door_bucket::reserve").unwrap());
    assert!(guard < body.find("req.json()").unwrap());
    let page = include_str!("invite_page/mod.rs");
    let body = page.split("pub async fn describe_post").nth(1).unwrap();
    let guard = body.find("door_cors::refuse_post(&req").expect("describe asks");
    assert!(guard < body.find("answer_with(").unwrap());
    assert!(guard < body.find("req.json::<Body>()").unwrap());
}
