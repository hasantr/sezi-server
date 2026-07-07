use crate::auth::middleware::require_auth;
use crate::d1util::{d1_blob, d1_int, d1_prekey_id, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::{json_err, no_content};
use crate::utils::{b64_decode, b64_encode, now_secs};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct UserRow {
    identity_pubkey: Vec<u8>,
}

#[derive(Deserialize)]
struct SpkRow {
    prekey_id: i64,
    prekey_pub: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct OtkRow {
    #[allow(dead_code)] // D1 satır şekli; SELECT'te var, Rust'ta okunmuyor
    id: i64,
    prekey_id: i64,
    prekey_pub: Vec<u8>,
}

/// M2-S2.3 bundle v2: aktif cihaz kaydı (device_lists doğrulamasının server-tarafı
/// izdüşümü; M1 `devices`). Her cihaz için ayrı SPK + OTK claim edilir.
#[derive(Deserialize)]
struct DeviceRow {
    device_id: String,
}

/// GET /keys/:user_id/bundle — bundle v2 (M2-S2.3): her AKTİF cihaz için
/// per-device SPK + bir OTK tüketir. `device_list` (imzalı doc+sig) client'ın
/// kanonik cihaz-listesini doğrulaması için verbatim taşınır. N=1'de `devices[]`
/// tek-eleman (primary) → bugünkü tek-bundle akışıyla birebir.
pub async fn bundle(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // FAZ-1(C): SPK-fallback prekey-DEPLETION DoS bekçisi. SPK-fallback inince (FAZ-1a)
    // bir saldırgan bundle'ı tekrar tekrar çekip bir cihazın OTK'larını tüketip herkesi
    // zayıf-FS SPK'ya zorlayabilir. caller-başına 60/dk tavanı (first-contact nadirdir +
    // session kurulunca bundle hiç çekilmez → 60/dk fazlasıyla bol). Yalnız prod (local
    // dev throttle EDİLMEZ → saha-testi etkilenmez). 429 → client backoff/retry.
    // ŞABLON-DİYETİ: ENV env-yoksa "prod" say (FAIL-SECURE); KV binding OPSİYONEL
    // (yoksa limitsiz devam — bkz. ratelimit::check_rate_limit_env).
    let env_name = crate::utils::var_or(&ctx.env, "ENV", "prod");
    if env_name == "prod"
        && !check_rate_limit_env(&ctx.env, &format!("bundle:fetch:{caller}"), 60, 60).await
    {
        return json_err(429, "rate_limited");
    }
    let target_id = match ctx.param("user_id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };

    let db = ctx.env.d1("DB")?;

    let user: Option<UserRow> = db
        .prepare("SELECT identity_pubkey FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&target_id)])?
        .first(None)
        .await?;
    let user = match user {
        Some(u) => u,
        None => return json_err(404, "not_found"),
    };

    // İmzalı cihaz-listesi (verbatim doc+sig) — client primary Ed25519 ile
    // doğrular (M1 device_lists; zero-trust: server üretemez/değiştiremez).
    #[derive(Deserialize)]
    struct DeviceListRow {
        doc_json: String,
        sig_b64: String,
        rev: i64,
    }
    let device_list: Option<DeviceListRow> = db
        .prepare("SELECT doc_json, sig_b64, rev FROM device_lists WHERE user_id = ? LIMIT 1")
        .bind(&[d1_text(&target_id)])?
        .first(None)
        .await?;
    // M2-S3.5 saha-fix: core `BundleRes.device_list: Option<DeviceListRes{doc_json,
    // sig_b64,rev}>` bekliyor — eski `{doc,sig}` (alan-adı + rev eksik) core'da TÜM
    // bundle decode'unu patlatıyordu. Doğru-şekil + rev (core tarafı da artık tolerant).
    let device_list_json = match device_list {
        Some(dl) => serde_json::json!({
            "doc_json": dl.doc_json,
            "sig_b64": dl.sig_b64,
            "rev": dl.rev,
        }),
        None => serde_json::Value::Null,
    };

    // Aktif cihazlar (revoked_at NULL). Boşsa (M1-öncesi / cihaz-listesi yayınlanmamış)
    // legacy fallback: device_id'siz (NULL) tek "primary" slot — eski tek-cihaz
    // davranışı korunur (SPK+OTK device-filtresiz claim edilir).
    let devices: Vec<DeviceRow> = db
        .prepare(
            "SELECT device_id FROM devices
             WHERE user_id = ? AND revoked_at IS NULL ORDER BY device_id ASC",
        )
        .bind(&[d1_text(&target_id)])?
        .all()
        .await?
        .results()?;

    let mut device_bundles: Vec<serde_json::Value> = Vec::new();
    if devices.is_empty() {
        // Legacy/uyum: cihaz-listesi yok → device-filtresiz tek slot.
        if let Some(b) = build_device_bundle(&db, &target_id, None).await? {
            device_bundles.push(b);
        }
    } else {
        for d in &devices {
            if let Some(b) = build_device_bundle(&db, &target_id, Some(&d.device_id)).await? {
                device_bundles.push(b);
            }
        }
    }

    // FIX-3 (HIGH→MED — bundle sessiz boş): `devices[]` TAMAMEN boşsa (hiçbir cihaz
    // SPK yayınlamamış → `build_device_bundle` hepsinde None döndü) gönderen HİÇBİR
    // cihaza Olm session kuramaz. 200-boş yerine eski tekil-bundle davranışına paralel
    // makine-okunur hata: 503 `no_signed_prekey` (geçici — hedef SPK yayınlayınca
    // çözülür; client retry edebilir). Dolu `devices[]` normal 200 (aşağıda). N=1'de
    // primary SPK yayınladıysa devices tek-eleman dolu → 200 birebir.
    if device_bundles.is_empty() {
        return json_err(503, "no_signed_prekey");
    }

    Response::from_json(&serde_json::json!({
        "user_id": target_id,
        "identity_pubkey_b64": b64_encode(&user.identity_pubkey),
        "device_list": device_list_json,
        "devices": device_bundles,
    }))
}

/// M2-S2.3: tek cihaz için bundle slot'u (per-device SPK + OTK claim). `device`
/// None → legacy device-filtresiz (eski tek-cihaz uyumu). SPK yoksa o cihaz
/// atlanır (None döner — bundle'da yer almaz; tüm cihazlar SPK'sızsa devices boş).
async fn build_device_bundle(
    db: &D1Database,
    target_id: &str,
    device: Option<&str>,
) -> Result<Option<serde_json::Value>> {
    // En-yeni SPK — device-scope'lu (NULL device → eski/legacy SPK da eşleşsin).
    let spk: Option<SpkRow> = match device {
        Some(d) => {
            // device_id eşleşeni TERCİH et; yoksa legacy SPK'ya düş. mig 0015 eski
            // NULL device_id'leri '' yaptı AMA prod ilk-deploy'da kod mig'den ÖNCE
            // inebilir (atomik wire-cut penceresi) → pre-0015 şemada legacy SPK hâlâ
            // NULL. `IS NULL` toleransı (relogin.rs:88 / devices/handlers.rs:205
            // paritesi) deploy-sıra-bağımsızlığı sağlar; yoksa legacy peer 503
            // no_signed_prekey → sunucu-çapında Olm kurulamaz.
            db.prepare(
                "SELECT prekey_id, prekey_pub, signature FROM signed_prekeys
                 WHERE user_id = ? AND (device_id = ? OR device_id IS NULL OR device_id = '')
                 ORDER BY CASE WHEN device_id = ? THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
            )
            .bind(&[d1_text(target_id), d1_text(d), d1_text(d)])?
            .first(None)
            .await?
        }
        None => {
            db.prepare(
                "SELECT prekey_id, prekey_pub, signature FROM signed_prekeys
                 WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&[d1_text(target_id)])?
            .first(None)
            .await?
        }
    };
    let spk = match spk {
        Some(s) => s,
        None => return Ok(None), // bu cihaz henüz SPK yayınlamadı → atla
    };

    // M2-S3.5 SAHA-KRİTİK: core `DeviceBundle.identity_pubkey_b64` ZORUNLU (first-contact
    // Olm peer x_pub/Curve25519). Bu alan EKSİKTİ → peer device-list yayınlayınca
    // (devices[] dolu) core'un BundleRes decode'u TÜMÜYLE patlıyordu ("error decoding
    // response body") → her gönderim ölüyordu. Per-device: `devices.x_pub`; legacy(None):
    // `users.identity_pubkey` (root DH anahtarı). Cihaz/kullanıcı satırı yoksa → atla.
    let identity_pub: Vec<u8> = match device {
        Some(d) => {
            #[derive(Deserialize)]
            struct XRow {
                x_pub: Vec<u8>,
            }
            let row: Option<XRow> = db
                .prepare("SELECT x_pub FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
                .bind(&[d1_text(target_id), d1_text(d)])?
                .first(None)
                .await?;
            match row {
                Some(r) => r.x_pub,
                None => return Ok(None),
            }
        }
        None => {
            #[derive(Deserialize)]
            struct URow {
                identity_pubkey: Vec<u8>,
            }
            let row: Option<URow> = db
                .prepare("SELECT identity_pubkey FROM users WHERE id = ? LIMIT 1")
                .bind(&[d1_text(target_id)])?
                .first(None)
                .await?;
            match row {
                Some(r) => r.identity_pubkey,
                None => return Ok(None),
            }
        }
    };

    // Atomik per-device OTK claim — tek `UPDATE...RETURNING` (SQLite implicit
    // transaction → paralel istekte aynı OTK iki peer'a verilemez). M2-S2.3:
    // claim `AND device_id = ?` (device None → legacy device-filtresiz pool).
    // Subquery NULL → update no-op, RETURNING boş set → OTK null (forward-secret
    // olmayan ama çalışan fallback prekey session; client retry'de OTK gelir).
    let otk: Option<OtkRow> = match device {
        Some(d) => {
            db.prepare(
                "UPDATE one_time_prekeys SET consumed = 1
                 WHERE id = (
                   SELECT id FROM one_time_prekeys
                   WHERE user_id = ? AND device_id = ? AND consumed = 0
                   ORDER BY id ASC LIMIT 1
                 )
                 RETURNING id, prekey_id, prekey_pub",
            )
            .bind(&[d1_text(target_id), d1_text(d)])?
            .first(None)
            .await?
        }
        None => {
            db.prepare(
                "UPDATE one_time_prekeys SET consumed = 1
                 WHERE id = (
                   SELECT id FROM one_time_prekeys
                   WHERE user_id = ? AND consumed = 0
                   ORDER BY id ASC LIMIT 1
                 )
                 RETURNING id, prekey_id, prekey_pub",
            )
            .bind(&[d1_text(target_id)])?
            .first(None)
            .await?
        }
    };

    let otk_json = if let Some(o) = otk {
        serde_json::json!({
            "prekey_id": o.prekey_id,
            "prekey_pub_b64": b64_encode(&o.prekey_pub),
        })
    } else {
        serde_json::Value::Null
    };

    Ok(Some(serde_json::json!({
        "device_id": device,
        "identity_pubkey_b64": b64_encode(&identity_pub),
        "signed_prekey": {
            "prekey_id": spk.prekey_id,
            "prekey_pub_b64": b64_encode(&spk.prekey_pub),
            "signature_b64": b64_encode(&spk.signature),
        },
        "one_time_key": otk_json,
    })))
}

#[derive(Deserialize)]
struct OtkInput {
    // SAHA-FIX (2026-06-27): client `otk_prekey_id` pubkey-türevli u64 (ilk-8-byte LE) üretiyor —
    // u32'ye sığmaz → JSON deserialize FAIL → /keys/otks/replenish 400 → OTK havuzu BOŞ → first-contact
    // Olm session kurulamaz → kripto wedge (self-copy MAC mismatch, okundu-senk bozuk, tek-tik). u64 ŞART.
    prekey_id: u64,
    prekey_pub_b64: String,
}

#[derive(Deserialize)]
struct ReplenishBody {
    otks: Vec<OtkInput>,
    // M2-S1 (opsiyonel): bu cihazın device_id'si. Verilmezse NULL = legacy.
    // S1'de YAZILIR ama claim hâlâ user_id düzeyinde (per-device havuz S2).
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn replenish(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // SAHA-FIX (2026-06-27): `req.json()` = workerd JS `JSON.parse` → 2^53 üstü `prekey_id`
    // (otk_prekey_id pubkey-türevli u64, ~%99 > 2^53) f64'e YUVARLANIR → serde u64 deserialize
    // FAIL → her replenish 400 → OTK havuzu boş → Olm wedge. `req.text()` + Rust `serde_json`
    // büyük u64'ü TAM okur (JS number precision baypas). u32→u64 tek başına ÇÖZMEDİ (kök precision).
    let raw = match req.text().await {
        Ok(t) => t,
        Err(_) => return json_err(400, "bad_request"),
    };
    let body: ReplenishBody = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.otks.is_empty() || body.otks.len() > 100 {
        return json_err(400, "bad_request");
    }
    // Sağlamlaştırma #8: BAŞKA cihazın OTK havuzunu silip-zehirlemesin (aynı-hesap/çalıntı-token
    // cihaz body.device_id=VICTIM yollarsa → kurbanın OTK'larını DELETE + kendininkini onun slotuna
    // yazar = decrypt-DoS). Send-path device-binding paritesi: body.device_id varsa token'la EŞLEŞMELİ
    // + revoked-cihaz yayınlayamaz. (Legacy: device_id None → eski '' tek-havuz, modern cihazları etkilemez.)
    {
        let token_device = crate::auth::middleware::extract_bearer(&req)
            .and_then(|t| crate::auth::jwt::device_id_from_token(&ctx.env, &t).ok().flatten());
        if body.device_id.is_some() && token_device.as_deref() != body.device_id.as_deref() {
            return json_err(403, "device_mismatch");
        }
        if let Some(dev) = body.device_id.as_deref() {
            if crate::auth::middleware::device_revoked(&ctx.env, &user_id, dev).await? {
                return json_err(401, "device_revoked");
            }
        }
    }
    let device_id = body.device_id.as_deref();
    let db = ctx.env.d1("DB")?;
    // KÖK-FIX (stale-OTK temizliği, saha "unknown one-time key"): bu cihazın ESKİ unconsumed
    // OTK'larını sil → fresh batch ile TEMİZ-REPLACE. Eski enumerate-bug'ından (prekey_id 1..N
    // tekrar → INSERT-OR-IGNORE çakışması → yeni-OTK yok sayılıyordu) kalan stale public-key'ler
    // (alıcı-private'ı düşmüş → "unknown") burada temizlenir. consumed=1 (claimed) DOKUNULMAZ.
    // device-scoped (sentinel ''=legacy). best-effort: silme fail ederse fresh insert yine olur.
    // F10 (2026-06-28): DELETE + INSERT'leri TEK atomik `db.batch` ile çalıştır (all-or-nothing).
    // Eskiden best-effort DELETE (ayrı commit, hata yutulur) + ayrı INSERT'ler → DELETE commit +
    // INSERT fail = cihazın OTK havuzu BOŞ kalabilir → yeni ilk-temaslar FS'siz SPK-only fallback'e
    // düşer (FS-degradasyon penceresi). Batch ya hepsi ya hiç → havuz asla yarım-boş kalmaz.
    // ≤1 DELETE + ≤5 INSERT chunk (100 OTK/20) = ≤6 statement, ≤400 bind → D1 batch limiti içinde.
    let device_sentinel = device_id.unwrap_or("");
    let mut stmts: Vec<D1PreparedStatement> = Vec::with_capacity(6);
    // DELETE ilk (fresh-replace): bu cihazın eski unconsumed OTK'larını sil. consumed=1 DOKUNULMAZ.
    stmts.push(
        db.prepare("DELETE FROM one_time_prekeys WHERE user_id = ? AND device_id = ? AND consumed = 0")
            .bind(&[d1_text(&user_id), d1_text(device_sentinel)])?,
    );
    for chunk in body.otks.chunks(20) {
        let mut sql = String::from(
            // INSERT OR IGNORE: idempotent — attach-replenish / retry aynı (user,device,
            // prekey_id)'yi tekrar yayınlarsa UNIQUE-500 yerine sessizce atla (mig 0016).
            "INSERT OR IGNORE INTO one_time_prekeys (user_id, prekey_id, prekey_pub, consumed, device_id) VALUES ",
        );
        let mut binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(chunk.len() * 4);
        let mut pubs: Vec<Vec<u8>> = Vec::with_capacity(chunk.len());
        for k in chunk {
            let p = b64_decode(&k.prekey_pub_b64)
                .map_err(|_| Error::RustError("bad otk pub".into()))?;
            pubs.push(p);
        }
        for (i, (k, p)) in chunk.iter().zip(pubs.iter()).enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str("(?, ?, ?, 0, ?)");
            binds.push(d1_text(&user_id));
            // SAHA-FIX (2026-06-27/28): prekey_id pubkey-türevli u64 → 53-bit maskeli D1 binding
            // (d1util::d1_prekey_id tek-nokta; workerd JS-Number f64 tuzağı + bundle 500 kökü).
            binds.push(d1_prekey_id(k.prekey_id));
            binds.push(d1_blob(p));
            // mig 0016: device_id NOT NULL DEFAULT '' → NULL bind ihlal; legacy '' sentinel.
            binds.push(d1_text(device_sentinel));
        }
        stmts.push(db.prepare(&sql).bind(&binds)?);
    }
    db.batch(stmts).await?;
    Response::from_json(&serde_json::json!({ "count": body.otks.len() }))
}

#[derive(Deserialize)]
struct SignedPrekeyBody {
    // SAHA-FIX (2026-06-27): client prekey_id u64 — u32 parse-fail riskine karşı paritede (OtkInput ile aynı).
    prekey_id: u64,
    prekey_pub_b64: String,
    signature_b64: String,
    // M2-S1 (opsiyonel): bu cihazın device_id'si. Verilmezse NULL = legacy.
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn rotate_signed_prekey(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // SAHA-FIX (2026-06-27): req.json() JS-precision (bkz. replenish) → text+serde_json::from_str.
    let raw = match req.text().await {
        Ok(t) => t,
        Err(_) => return json_err(400, "bad_request"),
    };
    let body: SignedPrekeyBody = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    // Sağlamlaştırma #8 (SPK ikizi): başka cihazın signed-prekey'ini ezmesin → send-path device-binding
    // paritesi (body.device_id varsa token'la eşleşmeli + revoked-cihaz rotate edemez).
    {
        let token_device = crate::auth::middleware::extract_bearer(&req)
            .and_then(|t| crate::auth::jwt::device_id_from_token(&ctx.env, &t).ok().flatten());
        if body.device_id.is_some() && token_device.as_deref() != body.device_id.as_deref() {
            return json_err(403, "device_mismatch");
        }
        if let Some(dev) = body.device_id.as_deref() {
            if crate::auth::middleware::device_revoked(&ctx.env, &user_id, dev).await? {
                return json_err(401, "device_revoked");
            }
        }
    }
    let pub_bytes =
        b64_decode(&body.prekey_pub_b64).map_err(|_| Error::RustError("bad pub".into()))?;
    let sig_bytes =
        b64_decode(&body.signature_b64).map_err(|_| Error::RustError("bad sig".into()))?;
    let now = now_secs();
    let db = ctx.env.d1("DB")?;
    // Idempotent upsert (M2-S3.2c fix): linked-device finalize SPK'sini yayinlarken
    // ayni (user_id, device_id, prekey_id) yeniden gelirse (retry) 500 yerine guncelle.
    // device_id NULL -> '' sentinel (PK kolonu NOT NULL).
    db.prepare(
        "INSERT INTO signed_prekeys (user_id, prekey_id, prekey_pub, signature, created_at, device_id)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, device_id, prekey_id) DO UPDATE SET
           prekey_pub = excluded.prekey_pub,
           signature  = excluded.signature,
           created_at = excluded.created_at",
    )
    .bind(&[
        d1_text(&user_id),
        // SAHA-FIX (2026-06-28): SPK rotate prekey_id de 53-bit maskeli (registration/replenish parite).
        d1_prekey_id(body.prekey_id),
        d1_blob(&pub_bytes),
        d1_blob(&sig_bytes),
        d1_int(now as i64),
        d1_text(body.device_id.as_deref().unwrap_or("")),
    ])?
    .run()
    .await?;
    no_content()
}
