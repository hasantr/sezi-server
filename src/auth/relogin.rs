//! `POST /auth/relogin` — kimlik-imzalı oturum kurtarma (K5c).
//!
//! `refresh_token` öldüğünde (rotate/expire/revoke) oturum normalde kalıcı
//! kaybolurdu (verify YENİ user_id üretir → pairing kopar). Bu endpoint
//! kullanıcının **mevcut** Ed25519 kimlik anahtarına sahip olduğunu kanıtlatıp
//! AYNI `user_id`'ye taze token verir → pairing/identity korunur.
//!
//! Sunucu kullanıcının Ed25519 imza anahtarını AYRI saklamaz (`users.identity_pubkey`
//! = Curve25519/DH). Ama `signed_prekeys` tablosunda kullanıcının SPK pub'ı +
//! Ed25519 imzası kayıtlı (registration/rotation'da `account.sign(spk_pub_bytes)`).
//! Doğrulama iki aşamalı:
//!   1) **Bağlama:** client'ın gönderdiği Ed25519 pub, kayıtlı SPK imzasını
//!      doğruluyor mu? → bu pub, kullanıcının kimlik imza anahtarıdır.
//!   2) **Canlılık:** taze `sezgi-relogin:{user_id}:{ts}` challenge imzası aynı
//!      pub ile doğrulanıyor mu? + `ts` tazelik penceresinde mi (replay sınırı).
//!
//! İkisi de geçerse → taze access + refresh.

use crate::auth::hashing::sha256_hex;
use crate::auth::jwt::sign_access_token;
use crate::d1util::{d1_blob, d1_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{b64_decode, b64u_encode, now_secs, random_bytes};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct ReloginBody {
    user_id: String,
    ed25519_pub_b64: String,
    ts: u64,
    signature_b64: String,
    // M2-S1 (opsiyonel): bu cihazın device_id'si + Ed25519 imza pub'ı. Eski
    // gövde bunlarsız AYNEN çalışır. identity_ed_pub_b64 = ed25519_pub_b64 ile
    // aynı anahtardır (zaten doğrulandı) → users.identity_ed_pub backfill.
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    identity_ed_pub_b64: Option<String>,
}

const REFRESH_TTL_SEC: u64 = 30 * 24 * 60 * 60;
const ACCESS_TTL_SEC: u64 = 15 * 60;
/// Challenge tazelik penceresi (saat kayması toleransı + replay sınırı).
const CHALLENGE_WINDOW_SEC: u64 = 300;

pub async fn relogin(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: ReloginBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    let now = now_secs();
    let skew = now.abs_diff(body.ts);
    if skew > CHALLENGE_WINDOW_SEC {
        return json_err(401, "stale_challenge");
    }

    // Sağlanan Ed25519 pub'ı parse et.
    let ed_bytes = match b64_decode(&body.ed25519_pub_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return json_err(400, "bad_ed25519"),
    };
    let ed_arr: [u8; 32] = ed_bytes.as_slice().try_into().unwrap();
    let verifying = match VerifyingKey::from_bytes(&ed_arr) {
        Ok(v) => v,
        Err(_) => return json_err(400, "bad_ed25519"),
    };

    let db = ctx.env.d1("DB")?;

    // Kullanıcının kayıtlı SPK pub + imzası (en yeni). Ed25519 ile imzalanmış.
    #[derive(Deserialize)]
    struct SpkRow {
        prekey_pub: Vec<u8>,
        signature: Vec<u8>,
    }
    // M2-S3.2 (review HIGH): SPK seçimini CİHAZ-SCOPE'lu yap. Çoklu-cihazda her cihaz
    // KENDİ Account'unun SPK'sını yayınlar (append); device-id'siz "EN YENİ" seçim,
    // bağlı cihaz onboard olunca birincilin relogin proof'unu BAĞLI cihazın SPK'sına
    // karşı doğrulamaya çalışır → identity_mismatch → birincil oturum kurtaramaz. Bu
    // cihazın device_id'siyle eşleşen SPK'yı TERCİH et (yoksa NULL legacy fallback).
    let dev = body.device_id.as_deref();
    let spk: Option<SpkRow> = db
        .prepare(
            "SELECT prekey_pub, signature FROM signed_prekeys
             WHERE user_id = ? AND (device_id = ? OR device_id IS NULL OR device_id = '')
             ORDER BY CASE WHEN device_id = ? THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
        )
        .bind(&[d1_text(&body.user_id), d1_opt_text(dev), d1_opt_text(dev)])?
        .first(None)
        .await?;
    let spk = match spk {
        Some(s) => s,
        None => return json_err(404, "no_identity"),
    };
    if spk.signature.len() != 64 {
        return json_err(500, "bad_spk_sig");
    }

    // 1) Bağlama: sağlanan Ed25519 pub kullanıcının SPK'sını imzalamış kimliğin
    //    anahtarı mı? SPK imzası ham SPK pub bytes'ı imzalar (client:
    //    `account.sign(pub_key.as_bytes())` → ham 32 byte).
    let spk_sig_arr: [u8; 64] = spk.signature.as_slice().try_into().unwrap();
    let spk_sig = ed25519_dalek::Signature::from_bytes(&spk_sig_arr);
    if verifying.verify(&spk.prekey_pub, &spk_sig).is_err() {
        return json_err(401, "identity_mismatch");
    }

    // 2) Canlılık: taze challenge imzası aynı pub ile doğrulanır.
    let challenge = format!("sezgi-relogin:{}:{}", body.user_id, body.ts);
    let chal_bytes = match b64_decode(&body.signature_b64) {
        Ok(b) if b.len() == 64 => b,
        _ => return json_err(400, "bad_sig"),
    };
    let chal_arr: [u8; 64] = chal_bytes.as_slice().try_into().unwrap();
    let chal_sig = ed25519_dalek::Signature::from_bytes(&chal_arr);
    if verifying.verify(challenge.as_bytes(), &chal_sig).is_err() {
        return json_err(401, "bad_challenge");
    }

    // M2-S3.5 B4: ÇIKARILAN cihaz relogin ile geri DÖNEMESİN. body.device_id revoke
    // edilmişse (birincil onu listeden düşürdü → put_list revoked_at=now) 401 → token
    // verilmez (zaman-of-check; SPK-verify geçse bile). device_id'siz/bilinmeyen → eski
    // davranış (N=1 birincil legacy token = device_id NULL → bu kontrolden muaf).
    if let Some(dev) = body.device_id.as_deref() {
        #[derive(Deserialize)]
        struct RevRow {
            revoked_at: Option<i64>,
        }
        let rev: Option<RevRow> = db
            .prepare("SELECT revoked_at FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
            .bind(&[d1_text(&body.user_id), d1_text(dev)])?
            .first(None)
            .await?;
        if rev.and_then(|r| r.revoked_at).is_some() {
            return json_err(401, "device_revoked");
        }
    }

    // M2-S1: opsiyonel Ed25519 imza pub backfill. `verifying` zaten bu pub'ın
    // kullanıcının kimliği olduğunu KRİPTOGRAFİK doğruladı → güvenle yazılır.
    // Yalnız boşsa doldur (mevcut değeri ezme; idempotent).
    if let Some(ed_b64) = body.identity_ed_pub_b64.as_deref() {
        if let Ok(ed_pub) = b64_decode(ed_b64) {
            db.prepare(
                "UPDATE users SET identity_ed_pub = ?
                 WHERE id = ? AND identity_ed_pub IS NULL",
            )
            .bind(&[d1_blob(&ed_pub), d1_text(&body.user_id)])?
            .run()
            .await?;
        }
    }

    // Geçti → mevcut user_id'ye taze token (YENİ kimlik YOK → pairing korunur).
    let device_id = body.device_id.as_deref();
    let access_token = sign_access_token(&ctx.env, &body.user_id, device_id)?;
    let new_refresh = b64u_encode(&random_bytes(32));
    let new_hash = sha256_hex(&new_refresh);
    db.prepare(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at, device_id)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&[
        d1_text(&new_hash),
        d1_text(&body.user_id),
        d1_int((now + REFRESH_TTL_SEC) as i64),
        d1_int(now as i64),
        d1_opt_text(device_id),
    ])?
    .run()
    .await?;

    Response::from_json(&serde_json::json!({
        "user_id": body.user_id,
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SEC,
    }))
}
