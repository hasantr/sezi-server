//! `sezi-app.json`'s reader: the documented example, each refusal, the lenient half, and a
//! seeded property run (no dependency: a fixed xorshift, so a failing seed replays).

use super::*;
use serde_json::json;

/// The documented example (`docs/platform/sezi-app.example.json`), read from the file itself so
/// the reader and the documentation cannot drift.
const EXAMPLE: &str = include_str!("../../../../docs/platform/sezi-app.example.json");

fn base() -> Value {
    json!({
        "sezi_app": 1,
        "id": "ext:acme/standup",
        "name": "Standup",
        "version": "1.2.0",
        "contract": { "min": 2 },
        "publisher": {
            "key_id": "ed25519:2Kq0m3c9pY8bWQwUu2h7oD5r1sXvN4fA6tLzJgEiHkM",
            "name": "Acme Tools"
        }
    })
}

fn parse(v: &Value) -> Result<AppManifest, &'static str> {
    parse_app_manifest(&serde_json::to_vec(v).unwrap())
}

fn with(f: impl FnOnce(&mut Map<String, Value>)) -> Result<AppManifest, &'static str> {
    let mut v = base();
    f(v.as_object_mut().unwrap());
    parse(&v)
}

#[test]
fn the_documented_example_reads_whole() {
    let m = parse_app_manifest(EXAMPLE.as_bytes()).expect("the example parses");
    assert_eq!(m.id, "ext:acme/standup");
    assert_eq!(m.names.get("tr").map(String::as_str), Some("Günlük toplantı"));
    assert_eq!(m.version.to_string(), "1.2.0");
    assert_eq!(m.contract, ContractRange { min: 2, max: None });
    assert_eq!(m.requires, vec!["records.pending".to_string(), "ui.confirm".to_string()]);
    assert_eq!(m.mode, AppMode::Persistent);
    assert_eq!(m.entry, "index.html");
    assert_eq!(m.icon.as_deref(), Some("assets/icon.svg"));
    assert_eq!(m.publisher.key_id, "ed25519:2Kq0m3c9pY8bWQwUu2h7oD5r1sXvN4fA6tLzJgEiHkM");
    let c = &m.capabilities;
    assert!(c.roster && c.media && c.link_meta && !c.video && !c.video_thumb);
    assert_eq!(c.origins, vec!["https://api.acme.example".to_string()]);
    assert!(c.unknown.is_empty());
    assert_eq!(m.collections.get("entry"), Some(&CollectionRule::Owned));
    assert_eq!(
        m.collections.get("ack"),
        Some(&CollectionRule::PerMember { needs_parent: true })
    );
    assert_eq!(
        c.granted().into_iter().collect::<Vec<_>>(),
        vec!["external.linkMeta", "media", "network", "network:https://api.acme.example", "roster"]
    );
}

#[test]
fn the_smallest_manifest_takes_the_defaults() {
    let m = parse(&base()).unwrap();
    assert_eq!(m.mode, AppMode::Persistent);
    assert_eq!(m.entry, "index.html");
    assert!(m.capabilities.granted().is_empty());
    assert!(m.collections.is_empty());
    assert_eq!(m.budgets, Budgets::default());
}

#[test]
fn each_rule_refuses_with_its_code() {
    let cases: Vec<(&str, Box<dyn FnOnce(&mut Map<String, Value>)>, &str)> = vec![
        ("no format", Box::new(|m| { m.remove("sezi_app"); }), BAD_FORMAT),
        ("a later format", Box::new(|m| { m.insert("sezi_app".into(), json!(2)); }), BAD_FORMAT),
        ("an html id", Box::new(|m| { m.insert("id".into(), json!("html:u-1")); }), BAD_ID),
        ("a built-in id", Box::new(|m| { m.insert("id".into(), json!("library")); }), BAD_ID),
        ("a host id", Box::new(|m| { m.insert("id".into(), json!("site:deste")); }), BAD_ID),
        ("an id with no name", Box::new(|m| { m.insert("id".into(), json!("ext:acme/")); }), BAD_ID),
        ("an upper-case id", Box::new(|m| { m.insert("id".into(), json!("ext:Acme/x")); }), BAD_ID),
        ("a nested id", Box::new(|m| { m.insert("id".into(), json!("ext:a/b/c")); }), BAD_ID),
        ("no name", Box::new(|m| { m.remove("name"); }), BAD_FIELD),
        ("a long name", Box::new(|m| { m.insert("name".into(), json!("x".repeat(49))); }), BAD_FIELD),
        ("not a version", Box::new(|m| { m.insert("version".into(), json!("1.2")); }), BAD_VERSION),
        ("contract 1", Box::new(|m| { m.insert("contract".into(), json!({"min": 1})); }), BAD_CONTRACT),
        ("max below min", Box::new(|m| { m.insert("contract".into(), json!({"min": 3, "max": 2})); }), BAD_CONTRACT),
        ("no publisher", Box::new(|m| { m.remove("publisher"); }), BAD_PUBLISHER),
        ("a short key", Box::new(|m| { m.insert("publisher".into(), json!({"key_id": "ed25519:abc", "name": "A"})); }), BAD_PUBLISHER),
        ("an rsa key", Box::new(|m| { m.insert("publisher".into(), json!({"key_id": "rsa:2Kq0m3c9pY8bWQwUu2h7oD5r1sXvN4fA6tLzJgEiHkM", "name": "A"})); }), BAD_PUBLISHER),
        ("an http contact", Box::new(|m| { m.insert("publisher".into(), json!({"key_id": "ed25519:2Kq0m3c9pY8bWQwUu2h7oD5r1sXvN4fA6tLzJgEiHkM", "name": "A", "contact": "http://a.example"})); }), BAD_PUBLISHER),
        ("a bad mode", Box::new(|m| { m.insert("mode".into(), json!("forever")); }), BAD_FIELD),
        ("an entry going up", Box::new(|m| { m.insert("entry".into(), json!("../index.html")); }), BAD_FIELD),
        ("an absolute entry", Box::new(|m| { m.insert("entry".into(), json!("/index.html")); }), BAD_FIELD),
        ("a wildcard origin", Box::new(|m| { m.insert("capabilities".into(), json!({"network": {"origins": ["https://*.acme.example"]}})); }), BAD_ORIGIN),
        ("an http origin", Box::new(|m| { m.insert("capabilities".into(), json!({"network": {"origins": ["http://acme.example"]}})); }), BAD_ORIGIN),
        ("an origin with a path", Box::new(|m| { m.insert("capabilities".into(), json!({"network": {"origins": ["https://acme.example/api"]}})); }), BAD_ORIGIN),
        ("a bare scheme", Box::new(|m| { m.insert("capabilities".into(), json!({"network": {"origins": ["https:"]}})); }), BAD_ORIGIN),
        ("a port out of range", Box::new(|m| { m.insert("capabilities".into(), json!({"network": {"origins": ["https://acme.example:70000"]}})); }), BAD_ORIGIN),
        ("no origins", Box::new(|m| { m.insert("capabilities".into(), json!({"network": {"origins": []}})); }), BAD_CAPABILITY),
        ("link meta with no network", Box::new(|m| { m.insert("capabilities".into(), json!({"external": {"linkMeta": true}})); }), BAD_CAPABILITY),
        ("a roster that is not a flag", Box::new(|m| { m.insert("capabilities".into(), json!({"roster": "all"})); }), BAD_CAPABILITY),
        ("a capability with no name shape", Box::new(|m| { m.insert("capabilities".into(), json!({"Camera!": true})); }), BAD_CAPABILITY),
        ("an unknown shape", Box::new(|m| { m.insert("collections".into(), json!({"a": {"shape": "shared"}})); }), BAD_COLLECTION),
        ("an owned record with a parent", Box::new(|m| { m.insert("collections".into(), json!({"a": {"needs_parent": true}})); }), BAD_COLLECTION),
        ("a collection name with a slash", Box::new(|m| { m.insert("collections".into(), json!({"a/b": {}})); }), BAD_COLLECTION),
        ("a zero budget", Box::new(|m| { m.insert("budgets".into(), json!({"records": 0})); }), BAD_FIELD),
        ("a duplicate requirement", Box::new(|m| { m.insert("requires".into(), json!(["ui.confirm", "ui.confirm"])); }), BAD_FIELD),
    ];
    for (what, edit, code) in cases {
        assert_eq!(with(edit).err(), Some(code), "{what}");
    }
    assert_eq!(parse_app_manifest(b"[]").err(), Some(BAD_JSON));
    assert_eq!(parse_app_manifest(b"{").err(), Some(BAD_JSON));
    let huge = vec![b' '; MAX_APP_MANIFEST_BYTES + 1];
    assert_eq!(parse_app_manifest(&huge).err(), Some(BAD_JSON));
}

/// The lenient half: what a later format-1 manifest may add opens here without a grant.
#[test]
fn an_unknown_capability_is_kept_and_never_granted() {
    let m = with(|m| {
        m.insert(
            "capabilities".into(),
            json!({
                "camera": true,
                "geo": { "precision": "city" },
                "clipboard": false,
                "roster": true,
                "network": { "origins": ["wss://live.acme.example"], "keepalive": 30 },
                "external": { "linkMeta": true, "maps": true }
            }),
        );
        m.insert("x-acme".into(), json!({"anything": 1}));
        m.insert("a_field_from_later".into(), json!(true));
    });
    let m = m.expect("unknown capabilities and fields parse");
    let unknown: Vec<_> = m.capabilities.unknown.iter().map(String::as_str).collect();
    assert_eq!(unknown, vec!["camera", "external.maps", "geo", "network.keepalive"]);
    let granted = m.capabilities.granted();
    for u in &m.capabilities.unknown {
        assert!(!granted.contains(u), "{u} is never granted");
    }
    assert!(granted.contains("roster") && granted.contains("network:wss://live.acme.example"));
}

#[test]
fn widening_is_measured_against_what_was_consented() {
    let before = with(|m| {
        m.insert("capabilities".into(), json!({"media": true, "network": {"origins": ["https://a.example"]}}));
    })
    .unwrap();
    let consented = before.capabilities.granted();
    let same = with(|m| {
        m.insert("capabilities".into(), json!({"network": {"origins": ["https://a.example"]}, "media": true, "nfc": true}));
    })
    .unwrap();
    assert!(same.capabilities.widened_from(&consented).is_empty(), "an unknown capability widens nothing");
    let narrower = with(|m| { m.insert("capabilities".into(), json!({"media": true})); }).unwrap();
    assert!(narrower.capabilities.widened_from(&consented).is_empty(), "taking away is no widening");
    let wider = with(|m| {
        m.insert("capabilities".into(), json!({"media": true, "roster": true, "network": {"origins": ["https://a.example", "https://b.example"]}}));
    })
    .unwrap();
    assert_eq!(
        wider.capabilities.widened_from(&consented),
        vec!["network:https://b.example".to_string(), "roster".to_string()]
    );
}

#[test]
fn budgets_are_asks_held_to_the_servers() {
    let m = with(|m| { m.insert("budgets".into(), json!({"records": 50, "record_bytes": 1u64 << 40})); }).unwrap();
    assert_eq!(m.budgets.records_within(2000), 50);
    assert_eq!(m.budgets.bytes_within(16 << 20), 16 << 20, "never above the server's");
    assert_eq!(Budgets::default().records_within(2000), 2000);
}

#[test]
fn key_ids_round_trip() {
    let key = [9u8; 32];
    let id = key_id_of(&key);
    assert_eq!(id.len(), "ed25519:".len() + 43);
    assert_eq!(parse_key_id(&id), Some(key));
    assert_eq!(parse_key_id(&id.replace("ed25519:", "ed448:")), None);
    assert_eq!(parse_key_id(&format!("{id}=")), None, "padding is not unpadded base64url");
}

#[test]
fn contract_ranges_admit_their_majors() {
    let open = ContractRange { min: 2, max: None };
    let closed = ContractRange { min: 2, max: Some(3) };
    assert!(open.admits(2) && open.admits(9) && !open.admits(1));
    assert!(closed.admits(3) && !closed.admits(4));
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

const ORIGINS: [&str; 5] = [
    "https://a.example",
    "https://api.b.example:8443",
    "wss://c.example",
    "https://d-e.example",
    "wss://f9.example",
];

/// A random VALID manifest and what it declares, so the property is "parses to exactly that".
fn random_manifest(r: &mut Rng) -> (Value, BTreeSet<String>) {
    let mut v = base();
    let mut caps = Map::new();
    let mut want = BTreeSet::new();
    for (name, key) in [("roster", "roster"), ("media", "media"), ("video", "video")] {
        if r.coin() {
            caps.insert(key.into(), json!(true));
            want.insert(name.to_string());
        }
    }
    let n = r.below(4) as usize;
    if n > 0 {
        let origins: BTreeSet<&str> = (0..n).map(|_| ORIGINS[r.below(5) as usize]).collect();
        caps.insert("network".into(), json!({"origins": origins.iter().collect::<Vec<_>>()}));
        want.insert("network".into());
        want.extend(origins.iter().map(|o| format!("network:{o}")));
        if r.coin() {
            caps.insert("external".into(), json!({"linkMeta": true}));
            want.insert("external.linkMeta".into());
        }
    }
    if r.coin() {
        caps.insert(format!("later{}", r.below(9)), json!({"x": 1}));
    }
    v["capabilities"] = Value::Object(caps);
    v["version"] = json!(format!("{}.{}.{}", r.below(20), r.below(20), r.below(20)));
    (v, want)
}

#[test]
fn property_random_valid_manifests_grant_exactly_what_they_declare() {
    for seed in 1..=400u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (v, want) = random_manifest(&mut r);
        let m = parse(&v).unwrap_or_else(|e| panic!("seed {seed}: {e} for {v}"));
        assert_eq!(m.capabilities.granted(), want, "seed {seed}");
        assert!(m.capabilities.widened_from(&want).is_empty(), "seed {seed}: own grant is no widening");
    }
}

/// Damaged bytes never panic the reader, and whatever it accepts is internally sound.
#[test]
fn property_mutated_bytes_never_panic() {
    let seedbytes = EXAMPLE.as_bytes();
    for seed in 1..=3000u64 {
        let mut r = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
        let mut b = seedbytes.to_vec();
        for _ in 0..=r.below(6) {
            let i = r.below(b.len() as u64) as usize;
            match r.below(3) {
                0 => b[i] = (r.next() & 0xff) as u8,
                1 => {
                    b.remove(i);
                }
                _ => b.insert(i, b"\"{}[],:0aZ-./*"[r.below(14) as usize]),
            }
            if b.is_empty() {
                break;
            }
        }
        if let Ok(m) = parse_app_manifest(&b) {
            assert!(is_app_id(&m.id), "seed {seed}");
            assert!(m.capabilities.origins.iter().all(|o| is_origin(o)), "seed {seed}");
            assert!(!m.capabilities.granted().iter().any(|g| m.capabilities.unknown.contains(g)));
        }
    }
}

/// `library` (2026-11-22): the room's library, read only — a known name, granted and consented
/// under that name; declared false it is nothing at all.
#[test]
fn the_library_capability_is_read_and_granted_by_name() {
    let m = with(|o| {
        o.insert("capabilities".into(), serde_json::json!({ "library": true }));
    })
    .unwrap();
    assert!(m.capabilities.library && m.capabilities.has(Capability::Library));
    assert!(m.capabilities.unknown.is_empty());
    assert_eq!(m.capabilities.granted().into_iter().collect::<Vec<_>>(), vec!["library"]);
    let off = with(|o| {
        o.insert("capabilities".into(), serde_json::json!({ "library": false }));
    })
    .unwrap();
    assert!(off.capabilities.granted().is_empty());
    assert!(with(|o| {
        o.insert("capabilities".into(), serde_json::json!({ "library": "yes" }));
    })
    .is_err());
}
