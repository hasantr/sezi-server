use crate::auth::hashing::hash_code;
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use crate::email::mailer::send_verification_code;
use crate::ratelimit::check_rate_limit;
use crate::respond::{json_err, no_content};
use crate::utils::{now_secs, random_bytes};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RedeemBody {
    token: Option<String>,
    email: String,
}

const CODE_TTL_SEC: u64 = 10 * 60;

pub async fn redeem(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env_name = ctx.env.var("ENV")?.to_string();
    if env_name == "prod" {
        let ip = req
            .headers()
            .get("cf-connecting-ip")
            .ok()
            .flatten()
            .unwrap_or_else(|| "local".into());
        let kv = ctx.env.kv("RATE_LIMIT")?;
        let key = format!("auth:redeem:{}", ip);
        if !check_rate_limit(&kv, &key, 5, 5 * 60).await? {
            return json_err(429, "rate_limited");
        }
    }

    let body: RedeemBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    if body.email.len() > 254 || !body.email.contains('@') {
        return json_err(400, "bad_request");
    }
    if let Some(t) = &body.token {
        if t.len() < 8 || t.len() > 128 {
            return json_err(400, "bad_request");
        }
    }

    let now = now_secs();
    let db = ctx.env.d1("DB")?;

    // join_mode
    #[derive(Deserialize)]
    struct ModeRow {
        join_mode: String,
    }
    let mode: Option<ModeRow> = db
        .prepare("SELECT join_mode FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await?;
    let join_mode = mode
        .map(|r| r.join_mode)
        .unwrap_or_else(|| "invite_only".into());

    if join_mode == "invite_only" {
        let token = match &body.token {
            Some(t) => t.clone(),
            None => return json_err(403, "invite_required"),
        };
        #[derive(Deserialize)]
        struct InviteRow {
            used: i32,
            expires_at: i64,
        }
        let invite: Option<InviteRow> = db
            .prepare(
                "SELECT used, expires_at FROM invite_tokens WHERE token = ? LIMIT 1",
            )
            .bind(&[d1_text(&token)])?
            .first(None)
            .await?;
        let _invite = match invite {
            Some(i) if i.used == 0 && (i.expires_at as u64) > now => i,
            _ => return json_err(403, "invalid_invite"),
        };
        // NOT: `email_hint` artık kozmetik ETİKET/İSİM (create_invite serbest-metin) →
        // redeem'de e-posta ile EŞLEŞTİRİLMEZ. Eski email-bind KALDIRILDI (sentetik
        // u...@sezgi.local e-postalarıyla zaten işlevsizdi + isim-etiket 400/mismatch
        // veriyordu). Davet kodu = tek sır; kod geçerliyse (used=0 + expiry) redeem olur.
        // M10 (invite TOCTOU): SELECT(`used==0`) ile UPDATE arasında ikinci bir
        // eşzamanlı redeem aynı tek-kullanımlık daveti tüketebiliyordu (iki e-posta
        // aynı daveti redeem). UPDATE'i KOŞULLU-ATOMİK yap (`WHERE used = 0`) +
        // etkilenen-satır=0 ise yarışı KAYBETTİK → "already used". (email_hint/expiry
        // doğrulaması yine yukarıdaki SELECT'te; atomik kapı yalnız used-flag yarışını
        // kapatır.) D1 `changes` = bu UPDATE'in etkilediği satır sayısı.
        let used_changes = db
            .prepare("UPDATE invite_tokens SET used = 1 WHERE token = ? AND used = 0")
            .bind(&[d1_text(&token)])?
            .run()
            .await?
            .meta()?
            .and_then(|m| m.changes)
            .unwrap_or(0);
        if used_changes == 0 {
            return json_err(403, "invalid_invite"); // yarışı kaybettik → zaten kullanıldı
        }
    }

    let code = generate_code();
    let code_hash = hash_code(&code);

    // invite_token: redeem'de doğrulanan davet, verify'da used_by doldurmak için saklanır.
    db.prepare(
        "INSERT INTO verification_codes (email, code_hash, attempts, invite_token, expires_at, created_at)
         VALUES (?, ?, 0, ?, ?, ?)
         ON CONFLICT(email) DO UPDATE SET
            code_hash = excluded.code_hash,
            attempts = 0,
            invite_token = excluded.invite_token,
            expires_at = excluded.expires_at,
            created_at = excluded.created_at",
    )
    .bind(&[
        d1_text(&body.email),
        d1_text(&code_hash),
        d1_opt_text(body.token.as_deref()),
        d1_int((now + CODE_TTL_SEC) as i64),
        d1_int(now as i64),
    ])?
    .run()
    .await?;

    send_verification_code(&ctx.env, &body.email, &code).await?;

    // invite_only modda davet ZATEN kayıt yetkisidir; istemci (onboarding) sahte
    // `@sezgi.local` e-postası kullandığından gerçek gelen-kutusuna kod gönderimi
    // işe yaramaz (kullanıcı kodu asla göremez). Davet doğrulandıysa dev_code'u
    // prod'da da dön — davetsiz kayıt imkânsız olduğu için güvenli. Açık modda
    // (davetsiz) prod e-posta doğrulaması korunur: kod yalnız gerçek e-postaya gider.
    if env_name != "prod" || join_mode == "invite_only" {
        return Response::from_json(&serde_json::json!({
            "ok": true,
            "dev_code": code,
            "join_mode": join_mode,
        }));
    }
    no_content()
}

fn generate_code() -> String {
    let buf = random_bytes(4);
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) % 1_000_000;
    format!("{:06}", n)
}
