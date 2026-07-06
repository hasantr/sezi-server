use js_sys::Uint8Array;
use wasm_bindgen::JsValue;

/// Vec<u8> / &[u8] → D1 BLOB binding değeri (Uint8Array).
pub fn d1_blob(bytes: &[u8]) -> JsValue {
    Uint8Array::from(bytes).into()
}

pub fn d1_text(s: &str) -> JsValue {
    JsValue::from_str(s)
}

pub fn d1_int(n: i64) -> JsValue {
    // F9-footgun guard (2026-06-28): |n| >= 2^53 → workerd D1-OKUMA (JS-Number) f64'e yuvarlar
    // = SESSİZ bozulma (prekey_id wedge'inin kökü). debug/test'te yakala (release'de derlenmez).
    // >2^53 olabilecek kolon (msg_id/seq/lamport/epoch) ya TEXT/BLOB olmalı ya d1_prekey_id-benzeri
    // mask kullanmalı; BigInt yazma TEK BAŞINA yetmez (okuma da f64).
    debug_assert!(
        n.unsigned_abs() < (1u64 << 53),
        "d1_int: |{n}| >= 2^53 → workerd f64-okuma sessiz-bozulma riski"
    );
    JsValue::from_f64(n as f64)
}

/// prekey_id (pubkey-türevli u64; client `otk_prekey_id`) → D1/workerd-GÜVENLİ binding.
/// 53-bit maskele (pozitif + < 2^53) → D1 yazımı (i64) + workerd D1-OKUMA (JS-Number f64) +
/// serde i64/u64 hepsi TAM okur. Maskesiz: 2^63 üstü u64 → NEGATİF i64 (signedness),
/// 2^53 üstü → workerd-okumada f64-yuvarlama → serde "float, expected i64" → /keys/bundle 500
/// → peer bundle çekilemez → session yok → HİÇ MESAJ (2026-06-27 saha-wedge KÖKÜ). prekey_id
/// yalnız worker-dedup + bilgi; client encrypt'te `prekey_pub_b64` kullanır → maskeli id zararsız.
/// TÜM prekey_id yazım yolları (registration SPK/OTK, replenish OTK, SPK rotate) bunu kullanır
/// → tutarlı id-uzayı (tek nokta; 53-bit mask kopyala-yapıştır dağınıklığı biter).
pub fn d1_prekey_id(raw: u64) -> JsValue {
    JsValue::from_f64((raw & 0x1F_FFFF_FFFF_FFFF) as f64)
}

pub fn d1_null() -> JsValue {
    JsValue::null()
}

/// `Option<i64>` → D1 binding: `Some` → sayı (d1_int 2^53 guard'ı dahil),
/// `None` → NULL. NULLABLE int kolonlar için (örn. kota cap'leri: NULL = sınırsız).
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
