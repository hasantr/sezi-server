//! `PUT /devices/list` + `GET /devices/list/:user_id` — M1 cihaz-listesi.
//!
//! ## JWS bayt-imza modeli (KRİTİK)
//! `doc_json`, dış gövdede bir JSON STRING alanıdır; değeri client'ın imzaladığı
//! iç JSON metnin AYNEN kendisidir. serde dış gövdeyi parse edince `body.doc_json`
//! o metnin verbatim UTF-8 baytlarını taşır → imza `body.doc_json.as_bytes()`
//! üzerinde doğrulanır. İç dokümanı ASLA yeniden serileştirmeyiz (kanonikleştirme
//! gerekmez; serileştirme-farkı bug sınıfı baştan yok). İç parse YALNIZ doğrulama
//! için alanları (user_id, rev, primary ed_pub/x_pub) okumak amacıyladır.
//!
//! ## Kimlik doğrulama zinciri (relogin.rs deseni — KRİTİK)
//! Liste, primary cihazın **Ed25519** anahtarıyla imzalanır. Ama bu Ed-key'i
//! `users.identity_pubkey` ile DOĞRUDAN doğrulayamayız: o BLOB bir Curve25519/DH
//! anahtarıdır (register `id.diffie_pubkey()` gönderir), Ed25519 imza anahtarı
//! DEĞİL. Bunun yerine relogin.rs'teki bağlama desenini uygularız:
//!   1) Doc'taki primary `ed_pub_b64`'ten `VerifyingKey` kur (bozuksa 400).
//!   2) **Bağlama:** kullanıcının `signed_prekeys` EN YENİ satırını çek; SPK
//!      pub'ı kayıt anında `account.sign(spk_pub)` ile gerçek kimlik tarafından
//!      imzalandığı için, iddia edilen Ed-key bu imzayı doğrulayabiliyorsa
//!      kayıtlı kimliğe KRİPTOGRAFİK bağlanmış olur (yoksa/başarısızsa 403).
//!   3) **Liste imzası:** aynı Ed-key, doc_json'un verbatim baytlarını doğrular.
//!   4) **Tutarlılık:** primary `x_pub_b64` decode'u == `users.identity_pubkey`.
//!
//! ## Ortak doğrulama-sakla yolu (M2-S3.2 B6)
//! `put_list` + `link-approve` (bkz `link.rs`) AYNI `validate_and_store_signed_list`
//! yolundan geçer → tek doğrulama kaynağı. `device_lists` yazımı **atomik
//! rev-koşullu** (`WHERE excluded.rev > device_lists.rev` + RETURNING): eşzamanlı
//! iki yazar (link-approve + put_list) read-then-write yarışına düşmez; kaybeden
//! 409 alır.

use crate::auth::middleware::require_auth;
use crate::d1util::{d1_blob, d1_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{b64_decode, now_ms, now_secs};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::Deserialize;
use worker::*;

const MAX_DEVICES: usize = 5; // 1 primary + ≤4 linked
const MAX_DOC_BYTES: usize = 16 * 1024; // imzalı doküman üst sınırı (DoS bekçisi)

/// device_id türetimi — core `devices::device_id_from_ed25519_b64` PARİTESİ:
/// `hex(blake3(ed_pub_bytes)[..8])` → 16 küçük-hex. `ed_pub_32` 32 bayt olmalı
/// (çağıran kontrol eder). Item 2: worker liste-yazımında her cihaz için bunu
/// doğrular → sahte device_id'li entry route-state'e sızamaz (self-certifying).
fn derive_device_id(ed_pub_32: &[u8]) -> String {
    let hash = blake3::hash(ed_pub_32);
    hex::encode(&hash.as_bytes()[..8])
}

#[derive(Deserialize)]
struct PutBody {
    doc_json: String,
    sig_b64: String,
}

/// İç doküman — YALNIZ doğrulama-sonrası alan okuma için parse edilir.
#[derive(Deserialize)]
pub(crate) struct DeviceListDoc {
    pub(crate) v: u32,
    pub(crate) user_id: String,
    pub(crate) rev: i64,
    pub(crate) devices: Vec<DeviceEntry>,
    /// Model-B Layer-1: imzalı tombstone'lar (çıkarılan cihazlar). Eski doc'larda
    /// yok → serde default (boş). İmza tüm doc'u kapsadığından server ekleyemez.
    #[serde(default)]
    pub(crate) removed_devices: Vec<DeviceEntry>,
}

#[derive(Deserialize)]
pub(crate) struct DeviceEntry {
    pub(crate) device_id: String,
    pub(crate) role: String,
    pub(crate) ed_pub_b64: String,
    pub(crate) x_pub_b64: String,
    #[serde(default)]
    pub(crate) label: Option<String>,
    pub(crate) added_at_ms: i64,
}

#[derive(Deserialize)]
struct UserRow {
    identity_pubkey: Vec<u8>,
    /// Model-B Layer-1 BLOCKER fix: cihaz-listesi rev HIGH-WATER. `device_lists`
    /// satırı D1-churn'de kaybolsa bile burada (users) KALIR → bayat re-PUT
    /// (rev < high_water) reddedilir → revoked cihaz diriltilemez (resurrection-fix).
    #[serde(default)]
    device_list_rev: i64,
}

#[derive(Deserialize)]
struct ListRow {
    doc_json: String,
    sig_b64: String,
    rev: i64,
}

/// `PUT /devices/list` — birincil-imzalı cihaz-listesini yükle.
/// İnce sarıcı: auth + rate-limit + gövde → `validate_and_store_signed_list`.
pub async fn put_list(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth_user = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };

    // Rate-limit (nadir çağrı; ucuz koruma — mevcut KV sliding-window altyapısı).
    let kv = ctx.env.kv("RATE_LIMIT")?;
    if !crate::ratelimit::check_rate_limit(&kv, &format!("devices:list:{auth_user}"), 20, 60).await? {
        return json_err(429, "rate_limited");
    }

    let body: PutBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    let db = ctx.env.d1("DB")?;
    let rev =
        match validate_and_store_signed_list(&db, &auth_user, &body.doc_json, &body.sig_b64).await? {
            Ok(rev) => rev,
            Err(resp) => return Ok(resp),
        };
    Response::from_json(&serde_json::json!({ "rev": rev }))
}

/// İmzalı cihaz-listesini doğrula + ATOMİK sakla. `put_list` + `link-approve` ortak
/// yolu (tek doğrulama kaynağı). Tüm kontroller fail-closed. Başarı → `Ok(rev)`;
/// red → `Err(Response)` (çağıran `return Ok(resp)` eder).
///
/// Hata kodları (makine-okunur): 400 bad_doc / doc_too_large / unsupported_version /
///   user_mismatch / no_primary / multiple_primary / primary_key_mismatch /
///   bad_pubkey / too_many_devices / bad_signature · 401 user_not_found ·
///   403 identity_mismatch / sig_invalid · 409 rev_conflict · 500 bad_spk_sig.
///
/// **B6 atomiklik:** `device_lists` yazımı `ON CONFLICT DO UPDATE ... WHERE
/// excluded.rev > device_lists.rev RETURNING rev` → eşzamanlı yazarda yalnız
/// rev-ilerleten kazanır, kaybeden RETURNING-boş → 409 (read-then-write yarışı yok).
pub(crate) async fn validate_and_store_signed_list(
    db: &D1Database,
    auth_user: &str,
    doc_json: &str,
    sig_b64: &str,
) -> Result<std::result::Result<i64, Response>> {
    macro_rules! reject {
        ($code:expr, $msg:expr) => {
            return Ok(Err(json_err($code, $msg)?))
        };
    }

    if doc_json.len() > MAX_DOC_BYTES {
        reject!(400, "doc_too_large");
    }

    // (a) doc_json parse — alanları OKUMAK için (imza yine ham baytlar üzerinde).
    let doc: DeviceListDoc = match serde_json::from_str(doc_json) {
        Ok(d) => d,
        Err(_) => reject!(400, "bad_doc"),
    };
    if doc.v != 1 {
        reject!(400, "unsupported_version");
    }

    // (b) doc.user_id == auth'lu user_id.
    if doc.user_id != auth_user {
        reject!(400, "user_mismatch");
    }

    // (e) cihaz sayısı ≤ 5 (1 primary + ≤4 linked).
    if doc.devices.is_empty() || doc.devices.len() > MAX_DEVICES {
        reject!(400, "too_many_devices");
    }

    // (c) TAM BİR adet role=="primary".
    let primaries: Vec<&DeviceEntry> = doc.devices.iter().filter(|d| d.role == "primary").collect();
    let primary = match primaries.as_slice() {
        [] => reject!(400, "no_primary"),
        [p] => *p,
        _ => reject!(400, "multiple_primary"),
    };

    let user: Option<UserRow> = db
        .prepare("SELECT identity_pubkey, device_list_rev FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(auth_user)])?
        .first(None)
        .await?;
    let user = match user {
        Some(u) => u,
        None => reject!(401, "user_not_found"),
    };

    // (1) Primary entry'nin Ed25519 imza anahtarından VerifyingKey kur.
    let primary_ed = match b64_decode(&primary.ed_pub_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => reject!(400, "bad_pubkey"),
    };
    let ed_arr: [u8; 32] = primary_ed.as_slice().try_into().unwrap();
    let verifying = match VerifyingKey::from_bytes(&ed_arr) {
        Ok(v) => v,
        Err(_) => reject!(400, "bad_pubkey"),
    };

    // (2) Bağlama: iddia edilen Ed-key, kullanıcının kayıtlı SPK'sını imzalamış
    //     kimliğin anahtarı mı? (relogin.rs deseni). SPK yoksa fail-closed → 403.
    #[derive(Deserialize)]
    struct SpkRow {
        prekey_pub: Vec<u8>,
        signature: Vec<u8>,
    }
    // M2-S3.2 (review HIGH): SPK seçimini PRIMARY cihazın device_id'siyle scope'la.
    // Bağlı cihaz onboard olunca KENDİ SPK'sını yayınlar (append); device-id'siz "EN
    // YENİ" seçim → birincilin liste-imza binding'i BAĞLI cihazın SPK'sına karşı
    // doğrulanır → identity_mismatch → birincil ARTIK liste yayınlayamaz/cihaz-çıkaramaz
    // (S3.5 revoke kırılır). Primary entry'nin device_id'siyle eşleşeni tercih et.
    let primary_dev = primary.device_id.as_str();
    let spk: Option<SpkRow> = db
        .prepare(
            "SELECT prekey_pub, signature FROM signed_prekeys
             WHERE user_id = ? AND (device_id = ? OR device_id IS NULL OR device_id = '')
             ORDER BY CASE WHEN device_id = ? THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
        )
        .bind(&[d1_text(auth_user), d1_text(primary_dev), d1_text(primary_dev)])?
        .first(None)
        .await?;
    let spk = match spk {
        Some(s) => s,
        None => reject!(403, "identity_mismatch"),
    };
    if spk.signature.len() != 64 {
        reject!(500, "bad_spk_sig");
    }
    let spk_sig_arr: [u8; 64] = spk.signature.as_slice().try_into().unwrap();
    let spk_sig = ed25519_dalek::Signature::from_bytes(&spk_sig_arr);
    if verifying.verify(&spk.prekey_pub, &spk_sig).is_err() {
        reject!(403, "identity_mismatch");
    }

    // (3) Liste imzası: aynı Ed-key, doc_json'un AYNEN GELEN UTF-8 baytlarını
    //     doğrular. Yeniden serileştirme YASAK.
    let sig_bytes = match b64_decode(sig_b64) {
        Ok(b) if b.len() == 64 => b,
        _ => reject!(400, "bad_signature"),
    };
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    if verifying.verify(doc_json.as_bytes(), &sig).is_err() {
        reject!(403, "sig_invalid");
    }

    // (4) Tutarlılık: primary.x_pub_b64 (decode) == users.identity_pubkey (DH kökü).
    let primary_x = match b64_decode(&primary.x_pub_b64) {
        Ok(b) => b,
        Err(_) => reject!(400, "bad_pubkey"),
    };
    if primary_x != user.identity_pubkey {
        reject!(400, "primary_key_mismatch");
    }

    // (f) rev fresh-insert guard (>= 1). Conflict durumunu atomik WHERE ele alır.
    if doc.rev < 1 {
        reject!(409, "rev_conflict");
    }

    // Model-B Layer-1 BLOCKER fix (revoke-resurrection): rev HIGH-WATER kapısı.
    // `device_lists` satırı D1-churn'de kaybolsa, eski (silme-öncesi, tombstone'suz)
    // bir doc fresh-insert olarak kabul edilip aktif-cihaz upsert'i revoked_at=NULL ile
    // çıkarılmış cihazı DİRİLTİYORDU. `users.device_list_rev` device_lists'ten BAĞIMSIZ
    // (satır kaybına dayanıklı) → rev < high_water = bayat → reddet. EŞİT-rev (== high_water)
    // RESTORE için izinli (imza zaten doğrulandı = gerçek primary doc, en-güncel). Kazanan
    // yazar batch'te high_water'ı MAX ile ilerletir.
    if doc.rev < user.device_list_rev {
        reject!(409, "rev_conflict");
    }

    // Tüm cihaz pubkey'lerini önceden decode et (her ihlal → reddet, atomiklik).
    struct DecodedEntry<'a> {
        device_id: &'a str,
        role: &'a str,
        ed_pub: Vec<u8>,
        x_pub: Vec<u8>,
        label: Option<&'a str>,
        added_at_ms: i64,
    }
    let mut decoded: Vec<DecodedEntry> = Vec::with_capacity(doc.devices.len());
    for d in &doc.devices {
        let ed = match b64_decode(&d.ed_pub_b64) {
            Ok(b) if b.len() == 32 => b,
            _ => reject!(400, "bad_pubkey"),
        };
        let xk = match b64_decode(&d.x_pub_b64) {
            Ok(b) => b,
            Err(_) => reject!(400, "bad_pubkey"),
        };
        // Item 2 (Codex): HER cihazın device_id'si ed_pub'tan TÜRETİMLE eşleşmeli
        // (core verify §5 paritesi). Worker eskiden yalnız primary-binding'i kontrol
        // ediyordu → sahte device_id'li linked entry `devices` route-state'e sızabiliyordu
        // (core reddeder ama worker kabul → asimetri). Self-certifying kapı.
        if derive_device_id(&ed) != d.device_id {
            reject!(400, "device_id_mismatch");
        }
        decoded.push(DecodedEntry {
            device_id: &d.device_id,
            role: &d.role,
            ed_pub: ed,
            x_pub: xk,
            label: d.label.as_deref(),
            added_at_ms: d.added_at_ms,
        });
    }

    // Item 1w (Model-B tombstone): removed_devices'ı doğrula — her tombstone self-
    // consistent (device_id ← ed_pub) + AKTİF cihazlarla DISJOINT (bir cihaz aynı anda
    // hem aktif hem tombstone OLAMAZ; core verify §6/§7 paritesi). Remove-wins ENFORCE:
    // tombstone'lu cihaz `devices` (aktif) listesinde olmadığından aşağıdaki omission-
    // revoke onu zaten `revoked_at=now` yapar → bayat re-PUT onu diriltemez.
    for r in &doc.removed_devices {
        let red = match b64_decode(&r.ed_pub_b64) {
            Ok(b) if b.len() == 32 => b,
            _ => reject!(400, "bad_pubkey"),
        };
        if derive_device_id(&red) != r.device_id {
            reject!(400, "tombstone_device_id_mismatch");
        }
        if decoded.iter().any(|a| a.device_id == r.device_id) {
            reject!(400, "device_active_and_removed");
        }
    }

    // ---- Başarı: TEK ATOMİK D1 BATCH (Item 4 — revoke güvenliği). ----
    // ESKİ hâl: device_lists rev-bump SONRA devices-sync + token-delete AYRI sorgulardı
    // → arada-hata = rev-ilerledi-AMA-token-silinmedi → çıkarılan cihazın token'ı KALIR
    // + retry de 409 alır → revoked cihaz erişimi SÜREBİLİR (ciddi revoke-güvenlik açığı).
    // ŞİMDİ: hepsi TEK transaction (`db.batch`, all-or-nothing).
    //
    // Eşzamanlı yazar yarışı: device_lists bump KOŞULLU (`excluded.rev > rev`) → kaybeden
    // bump no-op. Türetilen mutasyonlar (devices upsert / omission-revoke / token-delete)
    // `device_lists.doc_json == BENİM doc'um` KAPISIYLA gated → KAYBEDEN hiçbir şey mutate
    // etmez (stale-liste cihaz diriltemez/yanlış-revoke yapamaz). Bump statement İLK →
    // sonraki statement'lar post-bump doc_json'ı görür (aynı transaction).
    let now_s = now_secs() as i64;
    let now_ms_v = now_ms() as i64;
    let placeholders: String = (0..decoded.len()).map(|_| "?").collect::<Vec<_>>().join(",");

    let mut stmts: Vec<D1PreparedStatement> = Vec::with_capacity(4 + decoded.len());

    // 1) device_lists koşullu rev-bump (İLK — gated derived'lar bunun sonucunu okur).
    stmts.push(
        db.prepare(
            "INSERT INTO device_lists (user_id, rev, doc_json, sig_b64, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET
               rev = excluded.rev, doc_json = excluded.doc_json,
               sig_b64 = excluded.sig_b64, updated_at = excluded.updated_at
             WHERE excluded.rev > device_lists.rev",
        )
        .bind(&[
            d1_text(auth_user),
            d1_int(doc.rev),
            d1_text(doc_json),
            d1_text(sig_b64),
            d1_int(now_s),
        ])?,
    );

    // 2) devices senkronu (her aktif entry insert-or-update, revoked_at=NULL) — yalnız
    //    KAZANAN mutate eder (doc_json-gate: INSERT...SELECT...WHERE).
    for e in &decoded {
        stmts.push(
            db.prepare(
                "INSERT INTO devices
                   (user_id, device_id, role, ed_pub, x_pub, label, added_at, revoked_at)
                 SELECT ?, ?, ?, ?, ?, ?, ?, NULL
                 WHERE (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?
                 ON CONFLICT(user_id, device_id) DO UPDATE SET
                   role = excluded.role, ed_pub = excluded.ed_pub, x_pub = excluded.x_pub,
                   label = excluded.label, added_at = excluded.added_at, revoked_at = NULL",
            )
            .bind(&[
                d1_text(auth_user),
                d1_text(e.device_id),
                d1_text(e.role),
                d1_blob(&e.ed_pub),
                d1_blob(&e.x_pub),
                d1_opt_text(e.label),
                d1_int(e.added_at_ms),
                d1_text(auth_user),
                d1_text(doc_json),
            ])?,
        );
    }

    // 3) omission-revoke: listede OLMAYAN mevcut satırlar → revoked_at=now (gated).
    let revoke_sql = format!(
        "UPDATE devices SET revoked_at = ?
         WHERE user_id = ? AND revoked_at IS NULL AND device_id NOT IN ({placeholders})
           AND (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?"
    );
    let mut revoke_binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(4 + decoded.len());
    revoke_binds.push(d1_int(now_ms_v));
    revoke_binds.push(d1_text(auth_user));
    for e in &decoded {
        revoke_binds.push(d1_text(e.device_id));
    }
    revoke_binds.push(d1_text(auth_user));
    revoke_binds.push(d1_text(doc_json));
    stmts.push(db.prepare(&revoke_sql).bind(&revoke_binds)?);

    // 4) M2-S3.5 B4 (cihaz-çıkar): yeni listede OLMAYAN gerçek-device_id'lerin refresh
    //    token'larını SİL → çıkarılan cihaz token-yenileyemez (15dk access-token TTL
    //    dolunca oturum ölür) + relogin'de revoked-red. Legacy NULL/'' device_id KORUNUR.
    let del_sql = format!(
        "DELETE FROM refresh_tokens
         WHERE user_id = ? AND device_id IS NOT NULL AND device_id != '' AND device_id NOT IN ({placeholders})
           AND (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?"
    );
    let mut del_binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(3 + decoded.len());
    del_binds.push(d1_text(auth_user));
    for e in &decoded {
        del_binds.push(d1_text(e.device_id));
    }
    del_binds.push(d1_text(auth_user));
    del_binds.push(d1_text(doc_json));
    stmts.push(db.prepare(&del_sql).bind(&del_binds)?);

    // 5) Model-B Layer-1 BLOCKER fix: rev HIGH-WATER'ı ilerlet (MAX → monoton; asla
    //    gerilemez). device_lists satırı sonradan kaybolsa bile bu users'ta kalır →
    //    bayat re-PUT reddedilir (yukarıdaki pre-check). Yalnız KAZANAN yazar (doc_json
    //    gate) ilerletir → kaybeden high_water'ı bozamaz.
    stmts.push(
        db.prepare(
            "UPDATE users SET device_list_rev = MAX(device_list_rev, ?)
             WHERE id = ? AND (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?",
        )
        .bind(&[
            d1_int(doc.rev),
            d1_text(auth_user),
            d1_text(auth_user),
            d1_text(doc_json),
        ])?,
    );

    // Atomik çalıştır (all-or-nothing). Tek statement hata verse hepsi rollback.
    db.batch(stmts).await?;

    // KAZANDIM MI? device_lists artık BENİM doc'umu mu tutuyor? (D1 batch+RETURNING
    // davranışına bağımlı olmamak için AYRI oku → sürüm-bağımsız sağlam 409 tespiti.)
    let stored: Option<ListRow> = db
        .prepare("SELECT doc_json, sig_b64, rev FROM device_lists WHERE user_id = ? LIMIT 1")
        .bind(&[d1_text(auth_user)])?
        .first(None)
        .await?;
    match stored {
        Some(r) if r.doc_json == doc_json => Ok(Ok(r.rev)),
        // Bump kaybedildi (eşzamanlı yüksek-rev yazar / eski rev) → derived mutasyonlar
        // da gate'lendiği için ÇALIŞMADI → tutarlı 409. Çağıran 409-retry'da taze GET eder.
        _ => Ok(Err(json_err(409, "rev_conflict")?)),
    }
}

/// `GET /devices/list/:user_id` — kullanıcının güncel imzalı listesi.
/// 200 `{doc_json, sig_b64, rev}` | 404 not_found.
pub async fn get_list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let _ = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let target = match ctx.param("user_id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };

    let db = ctx.env.d1("DB")?;
    let row: Option<ListRow> = db
        .prepare("SELECT doc_json, sig_b64, rev FROM device_lists WHERE user_id = ? LIMIT 1")
        .bind(&[d1_text(&target)])?
        .first(None)
        .await?;
    match row {
        Some(r) => Response::from_json(&serde_json::json!({
            "doc_json": r.doc_json,
            "sig_b64": r.sig_b64,
            "rev": r.rev,
        })),
        None => json_err(404, "not_found"),
    }
}
