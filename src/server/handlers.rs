use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct ServerSettingsRow {
    name: String,
    join_mode: String,
}

pub async fn info(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = ctx.env.d1("DB")?;
    let row: Option<ServerSettingsRow> = db
        .prepare("SELECT name, join_mode FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await?;
    let (name, join_mode) = row
        .map(|r| (r.name, r.join_mode))
        .unwrap_or_else(|| ("Sezi".into(), "invite_only".into()));
    // owner_exists: onboarding'in "sahipli mi sahipsiz mi" ön-sorusu — TEK
    // yan-etkisiz alan. Aksi halde app /bootstrap 200-vs-410 probe'una düşer;
    // o kapı hayalet-owner denetim SELECT'lerini (+ olası self-heal batch'i)
    // koşar. Owner-tanımı welcome.rs ile TEK-OTORİTE (bit-aynı SELECT), kopya
    // YOK. FAIL-SECURE: sorgu düşerse (None) `true` = "sahipli-say" → sahipsiz
    // sunucuyu yanlışlıkla "sahiplenilebilir" ilan etme (app yine /bootstrap
    // ile KESİN doğrular). Additive alan → eski /server/info tüketicilerinin
    // name/join_mode parse'ı kırılmaz.
    let owner_exists = crate::welcome::owner_exists(&ctx.env).await.unwrap_or(true);
    Response::from_json(&serde_json::json!({
        "name": name,
        "join_mode": join_mode,
        "owner_exists": owner_exists,
    }))
}

/// Sunucunun desteklediği yetenekler. İstemci `/capabilities` çağırır;
/// dönen `p2p.kinds` listesine göre kullanıcı arayüzünde toggle'lar
/// aktif veya pasif gösterilir.
///
/// Şu anki durum (P2P scaffolding modu):
///   - `p2p.supported = true` — istemci UI toggle'larını aktif eder
///     (kullanıcı tercihini kaydedebilir).
///   - `p2p.kinds = ["message", "image", "attachment", "file"]` — tüm
///     türlere izin.
///   - `transport = "iroh-pending"` — sunucu iroh signaling iskeletini
///     bildirir ama henüz gerçek transport köprülemesi aktif değil.
///   - **Davranış**: istemci hâlâ tüm trafiği CF üzerinden gönderir
///     (mobile `shouldUseP2P()` helper `transportAvailable=false`
///     döndüğü için fallback CF). P3 entegrasyonu landing'inde transport
///     otomatik devreye girer; kullanıcı tercihleri zaten kaydedilmiş.
///
/// Versioning: `version` alanı protokol değişikliğinde artar; istemci
/// uyumsuz versionlarla başa çıkmak için kullanır.
pub async fn capabilities(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Sunucu adı (server_settings; /server/info ile aynı kaynak).
    let db = ctx.env.d1("DB")?;
    let row: Option<ServerSettingsRow> = db
        .prepare("SELECT name, join_mode FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await?;
    let name = row.map(|r| r.name).unwrap_or_else(|| "Sezi".into());
    let retention_days = fetch_retention_days(&ctx.env).await;
    let message_retention_days = fetch_message_retention_days(&ctx.env).await;
    let delete_window_hours = fetch_delete_window_hours(&ctx.env).await;
    // Lite kurulum (R2 OPSİYONEL): MEDIA binding'ine bağımlı özellikler DİNAMİK ilan
    // edilir. Owner binding'i sonradan dashboard'dan eklerse (redeploy'suz) bir sonraki
    // /capabilities çağrısı true döner → client kartı kendini günceller.
    // Faz 1: any_available == MEDIA binding VAR MI (eski MediaStore::available ile
    // bit-aynı). Faz 3: router D1 harici depoları da görecek → Lite+B2 kurulumda true.
    let media_ok = crate::storage::StorageRouter::from_env(&ctx.env)
        .await
        .map(|r| r.any_available())
        .unwrap_or(false);
    Response::from_json(&serde_json::json!({
        "version": 1,
        // Self-host güncelleme tespiti (2026-07-12): DERLEME-anı damgası
        // (yyyyMMddHHmm int, monoton). `sync-template.ps1` worker-build ÖNCESİ
        // `SEZI_BUILD` env'ini set eder + şablon köküne aynı değeri `VERSION`
        // dosyasına yazar → damga + prebuilt-WASM AYNI koşudan çıkar (drift yok).
        // Client mevcut-build'i upstream VERSION ile kıyaslar → "güncelleme var".
        // env yoksa (monorepo prod / elle deploy) 0 = "bilinmiyor" (client rozet
        // göstermez). `version` (protokol) AYRI kalır — karıştırma.
        "build": option_env!("SEZI_BUILD").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
        "name": name,
        // M2-S2.3 (WIRE-CUT): protokol yetenek ilanı. device_addressing=1 →
        // server batch-wire (envelopes[]) + per-device OTK/bundle v2 destekler;
        // tekil envelope_b64 form'u artık 400 alır. Client buna göre batch-form
        // gönderir (eski tekil-form sökülür).
        "protocol": {
            "device_addressing": 1
        },
        // Veri saklama ilanı (retention). Relay modeli. Mesaj: DO-fanout teslimde
        // silinir (`on_delivery`); teslim edilmeyen en çok `message_days`.
        // ⚠️ MEDYA DÜRÜSTLÜK (2026-07-10 audit #3): medya ACK-delete zinciri
        // istemcide BAĞLI DEĞİL → medya teslimde SİLİNMEZ, her hâlde en çok
        // `media_days` TTL ile tutulur. Bu yüzden `media: "ttl"` (on_delivery
        // DEĞİL) — ilan fiili davranışla birebir. Gerçek teslim-sonrası-sil
        // recipient/room kaydı gerektirir (audit #2+#3 epic).
        "retention": {
            "model": "relay",
            "messages": "on_delivery",
            "media": "ttl",
            "media_days": retention_days,
            "message_days": message_retention_days,
        },
        // "Herkesten sil" penceresi (2026-07-12): bir mesaj GÖNDERİLDİKTEN sonra
        // en çok kaç SAAT içinde "herkesten sil" yapılabilir (owner-ayarlı,
        // DEFAULT 48). Alıcı-taraf ileride ZORLAR (mesaj-yaşı > pencere → red);
        // server yalnız DEĞERİ ilan eder. retention deseninin ikizi (D1
        // server_settings). Top-level (retention bloğu değil) — client
        // `delete_window_hours` düz-alan bekler.
        "delete_window_hours": delete_window_hours,
        // Sunucu özellik ilanı (C3). true=destekli, false=yapılandırılmamış/henüz yok.
        // R2-bağımlılık haritası (Lite kurulum, kod-kanıtlı 2026-07-06):
        //   - media/files → media/handlers.rs upload/download = R2 blob → media_ok.
        //   - apps → eklenti-kod dağıtımı plugin_blob.rs put/get_code = R2 (8KB üstü VE
        //     tüm bundle'lar DAİMA R2; core plugin_install.rs CODE_INLINE_THRESHOLD).
        //     Plugin-log DO-tabanlı (R2'siz çalışır) ve ≤8KB tek-html inline gider ama
        //     platformun ana dağıtım yolu R2 → dürüst ilan = media_ok.
        //   - backup → SERVER-endpoint'i YOK (yedek core'da yerel-dosya export/import;
        //     worker'da backup rotası hiç yok) → R2'den BAĞIMSIZ, true kalır.
        //   - calls → signaling relay (DO/WS) + TURN (CF Calls API) → R2'siz TAM, true.
        "features": {
            "messaging": true,
            "media": media_ok,
            "files": media_ok,
            "calls": true,
            "backup": true,
            "apps": media_ok
        },
        // ⚠️ P2P DÜRÜSTLÜK (2026-07-10 audit #5): `supported:true` = yetenek VAR
        // + istemci toggle'ları kaydedilebilir; AMA `available:false` = transport
        // HENÜZ AKTİF DEĞİL (iroh-pending) → ham JSON'u doğrudan okuyan (denetçi/
        // 3.taraf-istemci) "çalışıyor" sanmasın. İstemci zaten `transport=='iroh'`
        // olmadıkça CF'ye düşer (p2p_router.shouldUseP2P). `available`/`status`
        // additive → mevcut `supported`/`transport` parse'ı kırılmaz.
        "p2p": {
            "supported": true,
            "available": false,
            "status": "experimental",
            "kinds": ["message", "image", "attachment", "file"],
            "transport": "iroh-pending",
            "note": "scaffolding mode; client preferences saved, transport activates with P3"
        }
    }))
}

/// `server_settings.retention_days` — medya teslim edilmezse kaç gün tutulur
/// (cron fallback penceresi). Tablo/satır yoksa veya hata olursa varsayılan 30.
/// Hem `/capabilities` ilanı hem `media/upload` `expires_at` hesabı bunu okur.
pub async fn fetch_retention_days(env: &Env) -> i64 {
    let Ok(db) = env.d1("DB") else {
        return 30;
    };
    #[derive(Deserialize)]
    struct R {
        retention_days: i64,
    }
    let row: Option<R> = db
        .prepare("SELECT retention_days FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
        .ok()
        .flatten();
    row.map(|r| r.retention_days).unwrap_or(30)
}

/// `server_settings.message_retention_days` — teslim edilmeyen mesaj DO
/// `pending` kuyruğunda kaç gün tutulur (DO alarm temizlik penceresi).
/// Tablo/satır/kolon yoksa veya hata olursa varsayılan 30. Hem `/capabilities`
/// ilanı hem inbox_do alarm temizliği bunu okur.
pub async fn fetch_message_retention_days(env: &Env) -> i64 {
    let Ok(db) = env.d1("DB") else {
        return 30;
    };
    #[derive(Deserialize)]
    struct R {
        message_retention_days: i64,
    }
    let row: Option<R> = db
        .prepare("SELECT message_retention_days FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
        .ok()
        .flatten();
    row.map(|r| r.message_retention_days).unwrap_or(30)
}

/// `server_settings.delete_window_hours` — "herkesten sil" penceresi (owner-ayarlı).
/// Bir mesaj GÖNDERİLDİKTEN sonra en çok kaç SAAT içinde "herkesten sil"
/// yapılabilir. Alıcı taraf ileride bunu ZORLAR; `/capabilities` yalnız DEĞERİ
/// ilan eder. Tablo/satır/kolon yoksa veya hata olursa varsayılan 48
/// (message_retention_days deseninin ikizi).
pub async fn fetch_delete_window_hours(env: &Env) -> i64 {
    let Ok(db) = env.d1("DB") else {
        return 48;
    };
    #[derive(Deserialize)]
    struct R {
        delete_window_hours: i64,
    }
    let row: Option<R> = db
        .prepare("SELECT delete_window_hours FROM server_settings WHERE id = 1 LIMIT 1")
        .first(None)
        .await
        .ok()
        .flatten();
    row.map(|r| r.delete_window_hours).unwrap_or(48)
}
