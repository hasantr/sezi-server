//! Static network/egress scan of plugin CODE (O-L2 — moved out of Dart into the core).
//!
//! HARDENING (2026-06-25): an install-time NETWORK/EGRESS static scan. A data plugin is
//! NOT EXPECTED to make network calls (the bridge plus network-off is enough); if its
//! code contains one of these tokens the admin is warned ("if you grant internet
//! permission, this could ship your data out").
//! **NOT A SECURITY BOUNDARY** — a transparency/warning layer (the real boundary is
//! network-off-by-default + the sandbox). Obfuscation (`window['fet'+'ch']`, eval,
//! dynamic property access) defeats it → it catches honest code; against a cheat,
//! network-off still protects.
//!
//! The logic lives in the CORE so a frontend swap cannot lose it (ported verbatim from
//! the old `k7_plugin_picker.dart` `scanPluginEgress` — token set, lowercasing and
//! dedup preserved).

/// The network/egress tokens searched for (VERBATIM from the Dart `scanPluginEgress`;
/// all lowercase — `code` is lowercased and matched with `contains`). The order matters:
/// the returned list follows it → deterministic UI/telemetry.
pub const EGRESS_TOKENS: &[&str] = &[
    "fetch(",
    "xmlhttprequest",
    "websocket",
    "eventsource",
    "sendbeacon",
    "importscripts",
    "import(",
    "http://",
    "https://",
    "ws://",
    "wss://",
];

/// Return the (human-readable) egress tokens found in `code`; empty = clean.
/// Parity with the Dart `scanPluginEgress`: `code` is lowercased, every token is matched
/// with `contains`, and the hits are collected in list order and deduplicated.
pub fn scan_plugin_egress(code: &str) -> Vec<String> {
    let lower = code.to_lowercase();
    let mut found: Vec<String> = Vec::new();
    for t in EGRESS_TOKENS {
        if lower.contains(t) && !found.iter().any(|f| f == t) {
            found.push((*t).to_string());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_network_tokens_in_order() {
        let code = "const x = fetch('https://evil.example'); new WebSocket('wss://y');";
        let found = scan_plugin_egress(code);
        // List order is preserved: fetch( < websocket < https:// < wss://
        assert_eq!(found, vec!["fetch(", "websocket", "https://", "wss://"]);
    }

    #[test]
    fn clean_code_yields_empty() {
        let code = "function add(a,b){ return a+b; } // saf hesap";
        assert!(scan_plugin_egress(code).is_empty());
    }

    #[test]
    fn case_insensitive_match() {
        // Uppercase is matched too (lowercase parity).
        let found = scan_plugin_egress("const R = new XMLHttpRequest();");
        assert_eq!(found, vec!["xmlhttprequest"]);
    }

    #[test]
    fn token_set_matches_dart_list() {
        // The token set is locked to the original Dart list (regression lock).
        assert_eq!(
            EGRESS_TOKENS,
            &[
                "fetch(",
                "xmlhttprequest",
                "websocket",
                "eventsource",
                "sendbeacon",
                "importscripts",
                "import(",
                "http://",
                "https://",
                "ws://",
                "wss://",
            ]
        );
    }

    #[test]
    fn each_token_deduped_once() {
        // A token that appears many times is still reported once.
        let found = scan_plugin_egress("fetch( ... fetch( ... fetch(");
        assert_eq!(found, vec!["fetch("]);
    }
}
