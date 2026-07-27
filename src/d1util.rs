use js_sys::Uint8Array;
use wasm_bindgen::JsValue;

/// Vec<u8> / &[u8] → D1 BLOB binding value (Uint8Array).
pub fn d1_blob(bytes: &[u8]) -> JsValue {
    Uint8Array::from(bytes).into()
}

pub fn d1_text(s: &str) -> JsValue {
    JsValue::from_str(s)
}

pub fn d1_int(n: i64) -> JsValue {
    // F9 footgun guard (2026-06-28): once |n| >= 2^53, a workerd D1 READ (which goes
    // through a JS Number) rounds to f64 = SILENT corruption — this was the root of the
    // prekey_id wedge. Catch it in debug/test builds (compiled out in release). Any
    // column that can exceed 2^53 (msg_id/seq/lamport/epoch) must either be TEXT/BLOB
    // or mask like d1_prekey_id does; writing a BigInt is NOT enough on its own,
    // because the read path is f64 too.
    debug_assert!(
        n.unsigned_abs() < (1u64 << 53),
        "d1_int: |{n}| >= 2^53 → workerd f64-okuma sessiz-bozulma riski"
    );
    JsValue::from_f64(n as f64)
}

/// prekey_id (a u64 derived from the pubkey; `otk_prekey_id` on the client) → a
/// D1/workerd-SAFE binding. Masking to 53 bits (positive and < 2^53) means the D1
/// write (i64), the workerd D1 READ (a JS Number, i.e. f64) and serde's i64/u64
/// decoding all round-trip EXACTLY. Unmasked, two things break: a u64 above 2^63
/// becomes a NEGATIVE i64 (signedness), and anything above 2^53 gets f64-rounded on
/// read → serde reports "float, expected i64" → /keys/bundle 500 → the peer bundle
/// cannot be fetched → no session → NO MESSAGES AT ALL (the ROOT of the 2026-06-27
/// field wedge). prekey_id is only used for worker-side dedup and diagnostics; client
/// encryption keys off `prekey_pub_b64`, so a masked id is harmless. EVERY prekey_id
/// write path (registration SPK/OTK, OTK replenish, SPK rotation) goes through this
/// helper → one consistent id space, and no copy-pasted 53-bit masks scattered around.
pub fn d1_prekey_id(raw: u64) -> JsValue {
    JsValue::from_f64((raw & 0x1F_FFFF_FFFF_FFFF) as f64)
}

pub fn d1_null() -> JsValue {
    JsValue::null()
}

/// `Option<i64>` → D1 binding: `Some` → a number (including d1_int's 2^53 guard),
/// `None` → NULL. For NULLABLE int columns, e.g. quota caps where NULL = unlimited.
pub fn d1_opt_int(n: Option<i64>) -> JsValue {
    match n {
        Some(v) => d1_int(v),
        None => JsValue::null(),
    }
}

pub fn d1_opt_text(s: Option<&str>) -> JsValue {
    match s {
        Some(v) => JsValue::from_str(v),
        None => JsValue::null(),
    }
}
