use super::*;

// The vector `tools/bots/README.md`'s Apps Script snippet reproduces. Change one, change both.
const TOKEN: &str = "sezibot_00000000-0000-4000-8000-000000000001_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SECRET: &str = "ec0fb4201fe5b16ce5064f37b5aace9646c2167fe52b2a02aaef1523b1020c06";
const UPDATE_JSON: &str = r#"{"update_id":1,"kind":"ping","at":1761200000000}"#;
const TS: i64 = 1_761_200_000_000;
const SIG: &str = "31143c155f630ee1d333444201a3f261673fffef95eb5122668538dac6a4fbb8";

#[test]
fn the_fixed_vector_holds() {
    assert!(crate::bots::token::parse(TOKEN).is_some(), "the vector's token is well formed");
    assert_eq!(derive_secret(TOKEN), SECRET);
    assert_eq!(sign(SECRET, TS, UPDATE_JSON), SIG);
}

#[test]
fn the_envelope_carries_the_exact_update_string_and_its_signature() {
    let body: serde_json::Value = serde_json::from_str(&envelope(SECRET, TS, UPDATE_JSON)).unwrap();
    assert_eq!(body["v"], 1);
    assert_eq!(body["ts"], TS);
    assert_eq!(body["update_json"], UPDATE_JSON);
    assert_eq!(body["sig"], SIG);
}

#[test]
fn a_new_key_or_a_new_attempt_signs_differently() {
    let other = TOKEN.replace("AAAA", "AAAB");
    assert_ne!(derive_secret(&other), SECRET);
    assert_ne!(sign(SECRET, TS + 1, UPDATE_JSON), SIG);
}

const HOOK: &str = "https://script.google.com/macros/s/X/exec";

#[test]
fn a_2xx_is_taken_and_an_error_is_not() {
    for s in [200, 201, 204] {
        assert!(taken(s, None, HOOK), "{s}");
    }
    for s in [100, 400, 401, 404, 429, 500, 502] {
        assert!(!taken(s, None, HOOK), "{s}");
    }
}

#[test]
fn a_redirect_is_taken_only_to_where_a_program_that_ran_sends_its_caller() {
    // An Apps Script web app that RAN answers 302 to its result page.
    let ran = "https://script.googleusercontent.com/macros/echo?user_content_key=abc&lib=X";
    for s in [302, 303] {
        assert!(taken(s, Some(ran), HOOK), "{s}");
    }
    assert!(taken(302, Some("https://SCRIPT.googleusercontent.com/x"), HOOK), "a host has no case");
    // The webhook's own host, absolute or relative.
    assert!(taken(302, Some("https://script.google.com/done"), HOOK));
    assert!(taken(303, Some("/thanks"), HOOK));
    assert!(taken(307, Some("https://hook.example.com/v2"), "https://hook.example.com/v1"));
    // A deployment not shared with "Anyone" sends the POST to sign in, WITHOUT running.
    let sign_in = "https://accounts.google.com/ServiceLogin?service=wise&continue=https://script.google.com/x";
    assert!(!taken(302, Some(sign_in), HOOK), "a sign-in page is a failure");
    for elsewhere in ["https://evil.example/", "https://script.googleusercontent.com.evil.example/", "//accounts.google.com/x"] {
        assert!(!taken(302, Some(elsewhere), HOOK), "{elsewhere}");
    }
    assert!(!taken(302, None, HOOK), "a 3xx with no Location");
    assert!(!taken(302, Some("http://[bad"), HOOK), "a Location that does not parse");
}

#[test]
fn the_owner_sees_a_webhooks_host_and_nothing_after_it() {
    assert_eq!(host_of("https://Script.Google.com/macros/s/SECRET/exec?k=v").as_deref(), Some("script.google.com"));
    assert_eq!(host_of("not a url"), None);
}

#[test]
fn only_plain_https_urls_are_accepted() {
    assert_eq!(
        clean_url(" https://script.google.com/macros/s/X/exec ", false).as_deref(),
        Some("https://script.google.com/macros/s/X/exec")
    );
    for bad in [
        "http://example.com/hook",
        "https://user:pw@example.com/",
        "https://example.com/#frag",
        "ftp://example.com",
        "not a url",
        "",
    ] {
        assert_eq!(clean_url(bad, false), None, "{bad}");
    }
    let long = format!("https://example.com/{}", "a".repeat(600));
    assert_eq!(clean_url(&long, false), None);
}

#[test]
fn a_webhook_may_not_point_into_the_relays_own_network() {
    // A self-hosted relay's fetch reaches private addresses (bare workerd keeps miniflare's
    // `internet` service, `allow = ["public", "private"]`), so a bot key must not be a way in.
    for bad in [
        "https://192.168.1.1/hook",
        "https://10.0.0.5/hook",
        "https://127.0.0.1:8787/admin/users",
        "https://2130706433/hook",
        "https://0x7f.1/hook",
        "https://[::1]/hook",
        "https://[::ffff:127.0.0.1]/hook",
        "https://localhost/hook",
        "https://relay.localhost/hook",
        "https://nas.local/hook",
        "https://router.lan/hook",
        "https://fritz.box/hook",
        "https://printer/hook",
    ] {
        assert_eq!(clean_url(bad, false), None, "{bad}");
    }
    // The lab's escape (`BOT_BUILTIN_ALLOW_LAN=1`) lifts it, as it does for the built-in bots.
    assert!(clean_url("https://10.0.0.5/hook", true).is_some());
}
