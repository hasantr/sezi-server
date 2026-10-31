//! What a wake carries: the `/sync` frame plus the device, sealed to that device — or nothing.

use super::*;
use serde_json::json;

fn key(id: &str, fill: u8) -> PushKey {
    PushKey { id: id.into(), key: [fill; 32] }
}

fn frame(envelope: &str) -> Value {
    json!({
        "type": "msg",
        "id": 42,
        "sender_id": "alice",
        "sender_device_id": "a1b2c3d4e5f60718",
        "envelope_b64": envelope,
        "group_id": null,
        "ts": 1_700_000_000,
    })
}

/// What the phone does (`kernel/carried.rs` `open_frame`), here only to prove the seal.
fn open(sealed: &str, key: &PushKey, device: &str) -> Option<Value> {
    let mut parts = sealed.splitn(3, '.');
    assert_eq!(parts.next(), Some("v1"));
    assert_eq!(parts.next(), Some(key.id.as_str()));
    let blob = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
    let (nonce, ct) = blob.split_at(24);
    let pt = XChaCha20Poly1305::new((&key.key).into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: device.as_bytes() })
        .ok()?;
    serde_json::from_slice(&pt).ok()
}

/// The one sealed form, byte for byte: the core's `carried_tests.rs` opens this same string, so
/// the two halves cannot drift apart unseen.
pub(crate) const VECTOR: &str =
    "v1.k1.BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH5g78kc2vak4ohAN-jj7LzTiOq1xuXPV1Ztp5no09xmsM1uPDEQ";

#[test]
fn the_sealed_form_is_the_shared_test_vector() {
    let sealed = seal(&key("k1", 1), "dev-b", &[7; 24], br#"{"type":"msg","id":7}"#).unwrap();
    assert_eq!(sealed, VECTOR);
}

/// Sealed, the carried copy is the `/sync` frame with its nulls left out and the device added —
/// and it opens only under that key, for that device.
#[test]
fn the_carried_frame_opens_only_under_its_key_for_its_device() {
    let k = key("k1", 1);
    let sealed = frame_for(&frame("ZW52"), "d9", &k, &[3; 24]).unwrap();
    assert!(sealed.starts_with("v1.k1."), "{sealed}");
    assert!(!sealed.contains("alice") && !sealed.contains("a1b2c3"), "Google sees no ids: {sealed}");
    let v = open(&sealed, &k, "d9").expect("opens");
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["envelope_b64", "id", "rd", "sender_device_id", "sender_id", "ts", "type"]);
    assert_eq!((v["rd"].clone(), v["id"].clone()), (json!("d9"), json!(42)));
    assert!(open(&sealed, &k, "another-device").is_none(), "the device is bound in");
    assert!(open(&sealed, &key("k1", 2), "d9").is_none(), "another key opens nothing");
}

/// A device that never fetched a key (an older client) is woken content-free.
#[test]
fn no_key_carries_nothing() {
    let mut c = Carried::none();
    assert!(!c.add("d9", &frame("ZW52"), None));
    assert_eq!(c.for_device("d9"), None);
}

/// A frame whose sealed form does not fit is not carried: that wake goes out content-free.
#[test]
fn a_frame_that_does_not_fit_is_not_carried() {
    let k = key("k1", 1);
    let fits = |n: usize| frame_for(&frame(&"A".repeat(n)), "d9", &k, &[0; 24]).is_some();
    let mut n = 0;
    while fits(n + 1) {
        n += 1;
    }
    assert!(n > 2_000, "a frame of {n} bytes of envelope is the most that fits");
    let sealed = frame_for(&frame(&"A".repeat(n)), "d9", &k, &[0; 24]).unwrap();
    assert!(sealed.len() <= MAX_CARRIED_FRAME_BYTES);
    let mut c = Carried::none();
    assert!(!c.add("d9", &frame(&"A".repeat(n + 4)), Some(&k)));
}

/// Each device gets its own row's frame under its own key, and nobody else's.
#[test]
fn each_device_carries_its_own_frame() {
    let (k1, k2) = (key("k1", 1), key("k2", 2));
    let mut c = Carried::none();
    let mut f1 = frame("b25l");
    f1["id"] = json!(1);
    let mut f2 = frame("dHdv");
    f2["id"] = json!(2);
    assert!(c.add("d1", &f1, Some(&k1)));
    assert!(c.add("d2", &f2, Some(&k2)));
    assert_eq!(open(c.for_device("d1").unwrap(), &k1, "d1").unwrap()["id"], json!(1));
    assert_eq!(open(c.for_device("d2").unwrap(), &k2, "d2").unwrap()["id"], json!(2));
    assert_eq!(c.for_device("d3"), None);
}

/// FCM's own ceiling, with our keys counted: the largest carried payload stays under it.
#[test]
fn the_largest_carried_payload_fits_fcms_ceiling() {
    let data_bytes = "type".len() + "wake".len() + DATA_KEY.len() + MAX_CARRIED_FRAME_BYTES;
    assert!(data_bytes <= 4096 - 256, "{data_bytes} leaves no margin under FCM's 4096");
}
