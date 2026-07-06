//! TURN kimlik üretimi + bütçe bekçisi (calls Faz 1.5 — internet üstü arama).
//!
//! Aramalar varsayılan P2P (LAN/WiFi doğrudan); aynı ağ dışında NAT araya
//! girince medya **CF Realtime TURN**'den relay edilir. CF Worker'ın KENDİSİ
//! TURN olamaz (ham UDP yok) ama CF'nin yönetilen TURN servisi (`turn.cloudflare.com`)
//! vardır. Worker burada yalnız **kısa-ömürlü TURN kimliği üretir** (CF TURN
//! API'sini çağırır) — ana API token client'a hiç gitmez.
//!
//! **Bütçe bekçisi:** CF'de sert harcama-tavanı YOK → sürpriz faturayı önlemek
//! için worker aylık kimlik-üretim sayacı tutar (`turn_usage`); `TURN_MONTHLY_CAP`
//! aşılınca kimlik ÜRETMEZ (`capped`) → client doğrudan/STUN'a düşer, CF faturası
//! o noktada durur. Secret'lar set değilse TURN devre-dışı (`disabled`).

use crate::auth::middleware::require_auth;
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

/// TURN kimliği TTL (saniye). Aramanın tamamını kapsayacak kadar uzun (6 saat),
/// sızıntı penceresini sınırlayacak kadar kısa.
const TURN_TTL_SECS: u32 = 21_600;

/// Aylık kimlik-üretim tavanı varsayılanı (env `TURN_MONTHLY_CAP` ezebilir).
/// Kişisel kullanımda fazlasıyla yeterli; runaway/suistimal backstop'u. Her
/// kimlik ~bir aramadır; relay'li ses saatte ~30 MB → 5000 kimlik çok düşük risk.
const DEFAULT_MONTHLY_CAP: i64 = 5_000;

#[derive(Deserialize)]
struct CfIceResponse {
    #[serde(rename = "iceServers")]
    ice_servers: serde_json::Value,
}

#[derive(Deserialize)]
struct UsageRow {
    issued: i64,
}

/// `POST /turn/credentials` — oturumlu kullanıcıya kısa-ömürlü CF TURN kimliği
/// üretir (client ICE config'ine ekler). Auth zorunlu (yalnız kayıtlı kullanıcı).
/// Yanıt: `{iceServers:[...], ttl}` · devre-dışı: `{iceServers:[], disabled:true}`
/// · tavan aşıldı: `{iceServers:[], capped:true}`. Hata da olsa client zarar
/// görmez (boş liste = doğrudan/STUN'a düşer).
pub async fn credentials(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = &ctx.env;

    // 1. Auth — yalnız kayıtlı kullanıcı kendi araması için kimlik alır.
    if let Err(resp) = require_auth(&req, env) {
        return Ok(resp);
    }

    // 2. Secret'lar set mi? Değilse TURN devre-dışı (graceful; client STUN'a düşer).
    let key_id = env.secret("TURN_KEY_ID").map(|v| v.to_string()).ok();
    let api_token = env.secret("TURN_API_TOKEN").map(|v| v.to_string()).ok();
    let (key_id, api_token) = match (key_id, api_token) {
        (Some(k), Some(t)) if !k.is_empty() && !t.is_empty() => (k, t),
        _ => {
            return Response::from_json(&serde_json::json!({
                "iceServers": [],
                "disabled": true,
            }));
        }
    };

    // 3. Bütçe bekçisi — aylık tavan. Aşıldıysa ÜRETME (CF faturası durur).
    let cap = monthly_cap(env);
    let month = current_month_utc();
    let db = env.d1("DB")?;
    // Sayaç okuma fail-open: tablo yok (migration uygulanmadı) / D1 hatası →
    // 0 say, üretimi ENGELLEME (bekçi backstop'tur, güvenlik değil). Tavan
    // gerçekten dolduysa zaten sayaç dolu olur.
    let issued: i64 = match db
        .prepare("SELECT issued FROM turn_usage WHERE month = ? LIMIT 1")
        .bind(&[JsValue::from_str(&month)])
    {
        Ok(stmt) => stmt
            .first::<UsageRow>(None)
            .await
            .ok()
            .flatten()
            .map(|r| r.issued)
            .unwrap_or(0),
        Err(_) => 0,
    };
    if issued >= cap {
        return Response::from_json(&serde_json::json!({
            "iceServers": [],
            "capped": true,
        }));
    }

    // 4. CF TURN API'sinden kısa-ömürlü kimlik üret.
    let url = format!(
        "https://rtc.live.cloudflare.com/v1/turn/keys/{}/credentials/generate-ice-servers",
        key_id
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(
        serde_json::json!({ "ttl": TURN_TTL_SECS }).to_string().into(),
    ));
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {}", api_token))?;
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let cf_req = Request::new_with_init(&url, &init)?;
    let mut cf_resp = Fetch::Request(cf_req).send().await?;
    if cf_resp.status_code() >= 300 {
        return json_err(502, "turn_upstream_error");
    }
    let parsed: CfIceResponse = cf_resp.json().await?;

    // 5. Sayaç artır (üretim başarılı). Best-effort: tablo yoksa/hata olursa
    //    kimlik yine döner (sayaç eksik kalır, arama bozulmaz). Aylık upsert.
    if let Ok(stmt) = db
        .prepare(
            "INSERT INTO turn_usage (month, issued) VALUES (?, 1) \
             ON CONFLICT(month) DO UPDATE SET issued = issued + 1",
        )
        .bind(&[JsValue::from_str(&month)])
    {
        let _ = stmt.run().await;
    }

    // 6. iceServers'ı client'a dön (doğrudan WebRTC RTCPeerConnection config'i).
    Response::from_json(&serde_json::json!({
        "iceServers": parsed.ice_servers,
        "ttl": TURN_TTL_SECS,
    }))
}

/// Aylık TURN kimlik-üretim tavanı: env `TURN_MONTHLY_CAP` (parse edilemezse/
/// yoksa `DEFAULT_MONTHLY_CAP`). `pub(crate)`: bütçe bekçisi (buradaki
/// `credentials`) ve /admin/stats raporu (Faz 1c) AYNI tavanı okusun —
/// ilan = davranış tutarlılığı (retention deseni).
pub(crate) fn monthly_cap(env: &Env) -> i64 {
    env.var("TURN_MONTHLY_CAP")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_MONTHLY_CAP)
}

/// epoch saniyesinden "YYYY-MM" (UTC). Howard Hinnant civil-from-days algoritması
/// (chrono'suz; bütçe penceresi anahtarı). Takvim ayına hizalı.
/// `pub(crate)`: /admin/stats (Faz 1c) bu ayın `turn_usage.issued` satırını
/// AYNI anahtarla okur (sayaç yazan ile raporlayan pencere-uyumlu kalır).
pub(crate) fn current_month_utc() -> String {
    let secs = now_secs() as i64;
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}", y, m)
}
