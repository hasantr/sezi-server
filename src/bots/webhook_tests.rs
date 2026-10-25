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

#[test]
fn a_redirect_counts_as_taken_and_an_error_does_not() {
    for s in [200, 204, 302, 303] {
        assert!(taken(s), "{s}");
    }
    for s in [100, 400, 404, 429, 500, 502] {
        assert!(!taken(s), "{s}");
    }
}

#[test]
fn only_plain_https_urls_are_accepted() {
    assert_eq!(
        clean_url(" https://script.google.com/macros/s/X/exec ").as_deref(),
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
        assert_eq!(clean_url(bad), None, "{bad}");
    }
    let long = format!("https://example.com/{}", "a".repeat(600));
    assert_eq!(clean_url(&long), None);
}
