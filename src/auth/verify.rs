use crate::auth::hashing::{sha256_hex, verify_code};
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_blob, d1_int, d1_null, d1_opt_text, d1_prekey_id, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::json_err;
use crate::utils::{b64_decode, b64u_encode, now_secs, random_bytes};
use serde::Deserialize;
use uuid::Uuid;
use worker::*;

#[derive(Deserialize)]
struct PrekeyBundle {
    prekey_id: u64,
    prekey_pub_b64: String,
    signature_b64: String,
}

#[derive(Deserialize)]
struct Otk {
    prekey_id: u64,
    prekey_pub_b64: String,
}

#[derive(Deserialize)]
struct VerifyBody {
    email: String,
    code: String,
    identity_pubkey_b64: String,
    signed_prekey: PrekeyBundle,
    otks: Vec<Otk>,
    display_name: Option<String>,
    // M2-S1 (opsiyonel; eski gövde bunlarsız AYNEN çalışır):
    // device_id = bu kurulumun cihaz kimliği (16 hex); identity_ed_pub_b64 =
    // kullanıcının Ed25519 imza pub'ı (base64). Verilmezse eski davranış.
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    identity_ed_pub_b64: Option<String>,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;

pub async fn verify(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // ŞABLON-DİYETİ: ENV env-yoksa "prod" say (FAIL-SECURE); KV binding OPSİYONEL
    // (yoksa limitsiz devam — bkz. ratelimit::check_rate_limit_env).
    let env_name = crate::utils::var_or(&ctx.env, "ENV", "prod");
    if env_name == "prod" {
        let ip = req
            .headers()
            .get("cf-connecting-ip")
            .ok()
            .flatten()
            .unwrap_or_else(|| "local".into());
        if !check_rate_limit_env(&ctx.env, &format!("auth:verify:{}", ip), 5, 5 * 60).await {
            return json_err(429, "rate_limited");
        }
    }

    // SAHA-FIX (2026-06-27): req.json() = workerd JS JSON.parse → 2^53 üstü u64 prekey_id (OTK)
    // f64'e yuvarlanır → serde u64 FAIL → registration 400. text+Rust serde_json TAM parse eder.
    let raw = match req.text().await {
        Ok(t) => t,
        Err(_) => return json_err(400, "bad_request"),
    };
    let body: VerifyBody = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    if body.code.len() != 6 || !body.code.chars().all(|c| c.is_ascii_digit()) {
        return json_err(400, "bad_request");
    }
    if body.otks.len() > 100 {
        return json_err(400, "bad_request");
    }

    let now = now_secs();
    let db = ctx.env.d1("DB")?;

    #[derive(Deserialize)]
    struct VcRow {
        code_hash: String,
        attempts: i32,
        expires_at: i64,
    }
    let vc: Option<VcRow> = db
        .prepare(
            "SELECT code_hash, attempts, expires_at FROM verification_codes WHERE email = ? LIMIT 1",
        )
        .bind(&[d1_text(&body.email)])?
        .first(None)
        .await?;

    let vc = match vc {
        Some(v) if (v.expires_at as u64) > now => v,
        _ => return json_err(403, "no_code"),
    };
    if vc.attempts >= 5 {
        return json_err(403, "too_many_attempts");
    }
    if !verify_code(&body.code, &vc.code_hash) {
        db.prepare("UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ?")
            .bind(&[d1_text(&body.email)])?
            .run()
            .await?;
        return json_err(403, "wrong_code");
    }

    let user_id = Uuid::new_v4().to_string();
    let identity_pubkey =
        b64_decode(&body.identity_pubkey_b64).map_err(|_| Error::RustError("bad ident".into()))?;
    let spk_pub = b64_decode(&body.signed_prekey.prekey_pub_b64)
        .map_err(|_| Error::RustError("bad spk pub".into()))?;
    let spk_sig = b64_decode(&body.signed_prekey.signature_b64)
        .map_err(|_| Error::RustError("bad spk sig".into()))?;

    // M2-S1: opsiyonel Ed25519 imza pub'ı (verilmezse NULL → eski davranış).
    let identity_ed_pub: Option<Vec<u8>> = match body.identity_ed_pub_b64.as_deref() {
        Some(s) => Some(b64_decode(s).map_err(|_| Error::RustError("bad ed pub".into()))?),
        None => None,
    };
    let device_id = body.device_id.as_deref();

    // SELF-HEAL SIRALAMASI (2026-07-06 sezi-server2 vakası): token imzası TÜM
    // DB-yazımlarından ÖNCE. Eski akış user-INSERT'ten (ve davet/kod
    // mutasyonlarından) SONRA imzalıyordu; JWT-anahtarı bozukken imza patlayınca
    // user-satırı yazılmış kalıyordu → owner-yuvası cihazsız/token'sız "hayalet"
    // kullanıcıyla yanmış oluyordu (/bootstrap 410 → sunucu kalıcı-kilit).
    // İmza + refresh-üretimi yalnız CPU+anahtar işidir (DB'siz) → burada
    // başarısızlık = hiçbir DB-mutasyonu yapılmadan 500 (hayalet OLUŞAMAZ).
    // Başarı yolu bit-aynı: aynı token, aynı yazımlar, aynı göreli sıra.
    let access_token = sign_access_token(&ctx.env, &user_id, device_id)?;
    let refresh = generate_refresh_token();
    let refresh_hash = sha256_hex(&refresh);

    // İlk kayıt olan = owner (sunucu kurucusu, korumalı). Sonrakiler member;
    // owner sonradan set_role ile member'ları admin yapar.
    #[derive(Deserialize)]
    struct UserRow {
        #[allow(dead_code)] // genesis varlık kontrolü; değeri okunmuyor
        id: String,
    }
    let any_user: Option<UserRow> = db
        .prepare("SELECT id FROM users LIMIT 1")
        .first(None)
        .await?;
    let role = if any_user.is_none() {
        "owner"
    } else {
        "member"
    };

    db.prepare(
        "INSERT INTO users (id, email, identity_pubkey, identity_ed_pub, display_name, fcm_token, role, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&user_id),
        d1_text(&body.email),
        d1_blob(&identity_pubkey),
        match &identity_ed_pub {
            Some(b) => d1_blob(b),
            None => d1_null(),
        },
        d1_opt_text(body.display_name.as_deref()),
        d1_text(role),
        d1_int(now as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    db.prepare(
        "INSERT INTO signed_prekeys (user_id, prekey_id, prekey_pub, signature, created_at, device_id)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&[
        d1_text(&user_id),
        // SAHA-FIX (2026-06-28): registration SPK prekey_id de 53-bit maskeli (replenish
        // ile parite; maskesiz workerd-okuma bundle 500 = first-contact wedge).
        d1_prekey_id(body.signed_prekey.prekey_id),
        d1_blob(&spk_pub),
        d1_blob(&spk_sig),
        d1_int(now as i64),
        d1_text(device_id.unwrap_or("")), // device_id NOT NULL DEFAULT '' (mig 0015) -> sentinel
    ])?
    .run()
    .await?;

    // OTK'ları batch insert (D1 placeholder limiti için 20'lik gruplar).
    // M2-S1: device_id kolonu eklendi (verilmezse NULL = legacy/birincil).
    if !body.otks.is_empty() {
        for chunk in body.otks.chunks(20) {
            let mut sql = String::from(
                "INSERT OR IGNORE INTO one_time_prekeys (user_id, prekey_id, prekey_pub, consumed, device_id) VALUES ",
            );
            let mut binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(chunk.len() * 4);
            // pub_bytes'lerin lifetime için önce decode et, sonra binds'e ekle
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
                // SAHA-FIX (2026-06-28): registration OTK prekey_id 53-bit maskeli (replenish parite).
                binds.push(d1_prekey_id(k.prekey_id));
                binds.push(d1_blob(p));
                // mig 0016: one_time_prekeys.device_id NOT NULL DEFAULT '' → NULL bind
                // NOT NULL ihlali; legacy/birincil için '' sentinel (PK device-scope).
                binds.push(d1_text(device_id.unwrap_or("")));
            }
            db.prepare(&sql).bind(&binds)?.run().await?;
        }
    }

    // Davet→kullanıcı izi: redeem'de saklanan invite_token üzerinden used_by doldur.
    // (token yoksa subquery NULL → WHERE token=NULL hiçbir satırı etkilemez; açık modda zararsız.)
    db.prepare(
        "UPDATE invite_tokens SET used_by = ?
         WHERE token = (SELECT invite_token FROM verification_codes WHERE email = ?)",
    )
    .bind(&[d1_text(&user_id), d1_text(&body.email)])?
    .run()
    .await?;

    db.prepare("DELETE FROM verification_codes WHERE email = ?")
        .bind(&[d1_text(&body.email)])?
        .run()
        .await?;

    // Refresh-token'ın DB kaydı imza-SONRASI blokta (kritik olan: USER-satırı
    // imzadan önce yazılmasın; refresh-satırı zaten en son yazılıyordu).
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&refresh_hash),
        d1_text(&user_id),
        d1_int((now + REFRESH_TTL_SEC) as i64),
        d1_int(now as i64),
        d1_opt_text(device_id),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SEC,
    }))
}

fn generate_refresh_token() -> String {
    b64u_encode(&random_bytes(32))
}
