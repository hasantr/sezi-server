use crate::auth::jwt::{public_jwk, verify_access_token};
use crate::respond::json_err;
use worker::*;

mod admin;
mod auth;
mod cf_analytics;
mod d1util;
mod devices;
mod email;
mod groups;
mod keys;
mod maintenance;
mod media;
mod messages;
mod plugin_blob;
mod plugin_log;
mod plugin_media;
mod push;
mod quota;
mod ratelimit;
mod respond;
mod self_provision;
mod server;
mod sigv4;
mod storage;
mod turn;
mod usage;
mod utils;
mod welcome;

pub use messages::inbox_do::UserInbox;
pub use plugin_log::PluginRoomLog;

#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// Günlük cleanup cron — wrangler.toml [triggers] crons. Günlük gövde
/// `maintenance::run_daily` (cron + lazy-yol ORTAK fonksiyon; gövde oraya
/// saf-taşındı). Cron her koşuşta damgasını tazeler → cron'lu kurulumda
/// lazy-yol uyur (maintenance.rs modül başlığı; cron'suz şablon-kurulumda
/// bakım tamamen lazy-yoldan yürür).
#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Self-host Faz A boot-guard: cron, izolate'i fetch'ten ÖNCE cold-start
    // edebilir (taze fork'ta drain 0021 fanout_retry tablosuna dokunur) →
    // migration + anahtar provisioning burada da garanti. Memoized → sıcak
    // izolate'te no-op; env-secret'lı + wrangler-migrated prod'da tamamen no-op.
    self_provision::ensure_ready(&env).await;
    // W4-b: HER scheduled invocation'da durable-retry drain (Fable#4: cron-string match KIRILGAN
    // → drain'i KOŞULSUZ çalıştır; "*/2 * * * *" sık-drain + "0 4 * * *" günlük ikisinde de koşar).
    crate::messages::handlers::drain_fanout_retry(&env).await;
    // Lazy-maintenance damgası: cron çalışan kurulumda drain-damgası hep taze →
    // fetch-yolu lazy-drain HİÇ uyanmaz (prod bit-aynı).
    maintenance::stamp_drain(&env).await;
    // Takılabilir-depolama Faz 4: draining-depo taşıma tick'i (≤4 blob/koşum;
    // draining depo yokken tek ucuz SELECT ile sessiz çıkar). Fanout-drain gibi HER
    // invocation'da koşar; damga cron'lu kurulumda lazy storage-move'u uyutur.
    if let Err(e) = storage::drain::run_storage_move(&env).await {
        let msg = e.to_string();
        let truncated: String = msg.chars().take(80).collect();
        console_log!("storage move error: {}", truncated);
    }
    maintenance::stamp_move(&env).await;
    // MINOR-2 (Fable+Codex): sık-cron ise erken-çık (cleanup/GC koşma). Günlük "0 4 * * *" VE
    // beklenmedik normalize-sürprizi → cleanup'a DÜŞER (fail-toward-running: gürültülü-ama-GÜVENLİ;
    // eski `!= "0 4"` yönü sürprizde cleanup+GC'yi SESSİZCE hiç koşturmazdı = media-GC+TTL-GC durur).
    // cleanup idempotent → fazladan-koşum zararsız. drain ZATEN koşulsuz (yukarıda) → asla atlanmaz.
    if event.cron() == "*/2 * * * *" {
        return;
    }
    // Günlük set (cleanup + fanout-TTL-GC + kota-reconcile) — lazy-yol ile
    // bit-aynı ortak gövde + günlük-damga (lazy günlük-GC'yi uyutur).
    maintenance::run_daily(&env).await;
    maintenance::stamp_daily(&env).await;
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    // Self-host Faz A boot-guard: D1 self-migration (A2) + anahtar
    // self-provisioning (A1). İzolate-scope memoized → ilk istekte koşar,
    // sonrası no-op (hot-path'e D1-roundtrip SOKULMAZ). env-secret'lı +
    // wrangler-migrated kurulumda (bizim prod) tamamen no-op'a düşer.
    // /sync'ten ÖNCE olmalı: sync_ws token doğrular → anahtar hazır olmalı.
    self_provision::ensure_ready(&env).await;

    // Lazy-maintenance (cron'suz kurulum): istek-sırtında bakım tetikleyicisi.
    // İstek kritik-yoluna maliyeti thread_local zaman-karşılaştırması (D1'siz,
    // await'siz); damga-kontrol + olası iş `ctx.wait_until` arka-planında.
    maintenance::maybe_run_lazy(&env, &ctx);

    // /sync WS upgrade direkt DO'ya geçilir (Router'dan önce ele alalım,
    // çünkü WS upgrade için header passthrough şart).
    let url = req.url()?;
    let path = url.path().to_string();
    if path == "/sync" {
        return sync_ws(req, env).await;
    }

    Router::new()
        // Kök = hoş-geldin sayfası (insan-okur; taze kurulumda 404-güvensizliği
        // yerine "sunucun hazır" + adres-kopyala yönergesi). API'ler dokunulmadı.
        .get_async("/", welcome::welcome)
        .get("/healthz", |_, _| {
            Response::from_json(&serde_json::json!({"ok": true}))
        })
        .get_async("/.well-known/jwks.json", jwks)
        .get_async("/server/info", server::handlers::info)
        .get_async("/capabilities", server::handlers::capabilities)
        .get_async("/bootstrap", auth::bootstrap::bootstrap)
        .post_async("/auth/redeem", auth::invite::redeem)
        .post_async("/auth/verify", auth::verify::verify)
        .post_async("/auth/refresh", auth::refresh::refresh)
        .post_async("/auth/relogin", auth::relogin::relogin)
        .get_async("/auth/me", auth::me::me)
        .post_async("/admin/invites", admin::handlers::create_invite)
        .get_async("/admin/invites", admin::handlers::list_invites)
        .post_async("/admin/revoke-invite", admin::handlers::revoke_invite)
        .get_async("/admin/users", admin::handlers::list_users)
        .post_async("/admin/set-role", admin::handlers::set_role)
        .post_async("/admin/remove-member", admin::handlers::remove_member)
        .post_async(
            "/admin/transfer-ownership",
            admin::handlers::transfer_ownership,
        )
        .patch_async(
            "/admin/server-settings",
            admin::handlers::update_settings,
        )
        // CF Analytics config — owner self-service (YALNIZ owner; WRITE-ONLY:
        // token buradan yalnız yazılır, hiçbir endpoint geri döndürmez).
        .patch_async("/admin/cf-config", admin::cf_config::set_cf_config)
        // FCM push config — owner self-service (YALNIZ owner; WRITE-ONLY:
        // service-account buradan yalnız yazılır, hiçbir endpoint geri döndürmez).
        .patch_async("/admin/fcm-config", admin::fcm_config::set_fcm_config)
        // Kota epic Faz-0: self-report kullanım istatistikleri (admin/owner-gated;
        // SHADOW-MODE — yalnız rapor, hiçbir limit zorlanmaz).
        .get_async("/admin/stats", admin::stats::stats)
        // Server-çapı eklenti politikası. GET = HERHANGİ aktif üye (picker filtreler);
        // POST = require_admin (admin|owner). DISABLED-only saklama (satır = disabled).
        .get_async("/plugin-policy", admin::plugin_policy::get_plugin_policy)
        .post_async("/admin/plugin-policy", admin::plugin_policy::set_plugin_policy)
        // Takılabilir-Depolama (Faz 2+4) — owner harici blob-deposu bağlar/yönetir.
        // GET/probe = require_admin; POST/PATCH/DELETE/drain = require_owner (secret güçlü).
        // config_json (secret) HİÇBİR cevapta dönmez (WRITE-ONLY; cf/fcm-config emsali).
        // drain (Faz 4): depoyu boşaltmaya al — taşıma motoru storage/drain.rs.
        .get_async("/admin/storage", admin::storage::list)
        .post_async("/admin/storage", admin::storage::add)
        .patch_async("/admin/storage/:id", admin::storage::update)
        .delete_async("/admin/storage/:id", admin::storage::remove)
        .post_async("/admin/storage/:id/probe", admin::storage::probe)
        .post_async("/admin/storage/:id/drain", admin::storage::drain)
        // Gruplar (Faz 1 — üyelik; üye-seviyesi, server-admin değil). Fan-out Faz 2.
        .post_async("/groups", groups::create_group)
        .get_async("/groups", groups::list_my_groups)
        .get_async("/groups/:id/members", groups::group_members)
        .post_async("/groups/:id/add-member", groups::add_member)
        .post_async("/groups/:id/remove-member", groups::remove_member)
        .post_async("/groups/:id/set-role", groups::set_role)
        .post_async("/groups/:id/settings", groups::update_settings)
        .post_async("/groups/:id/accept", groups::accept_invite)
        .post_async("/groups/:id/decline", groups::decline_invite)
        .delete_async("/groups/:id", groups::delete_group)
        // Çoklu-cihaz (M1 — imzalı cihaz-listesi sakla/dağıt; additive).
        .put_async("/devices/list", devices::handlers::put_list)
        .get_async("/devices/list/:user_id", devices::handlers::get_list)
        // Çoklu-cihaz (M2-S3.2 — QR-link akışı; hepsi POST, bkz devices/link.rs).
        .post_async("/devices/link-start", devices::link::link_start)
        .post_async("/devices/link-approve", devices::link::link_approve)
        .post_async("/devices/link-status", devices::link::link_status)
        .get_async("/keys/:user_id/bundle", keys::handlers::bundle)
        .post_async("/keys/otks/replenish", keys::handlers::replenish)
        .post_async(
            "/keys/signed-prekey",
            keys::handlers::rotate_signed_prekey,
        )
        .post_async("/messages/send", messages::handlers::send)
        .post_async("/messages/read", messages::handlers::read)
        // Ortak-kök #1: receipt-sync HTTP ikizi (WS-Connected olmayan cihaz kendi tikini
        // cursor-pull eder — WS `receipt_sync` frame'iyle bit-aynı {rows,more}).
        .get_async("/messages/receipt-sync", messages::handlers::receipt_sync)
        // Kardeş-okundu durable cursor (2026-06-28): U'nun cihazı okuduğu msg_uid'leri kendi
        // inbox DO'suna bildirir (self_read_state) + cursor-pull. receipt-sync'in okundu-self ikizi.
        .post_async("/messages/self-read", messages::handlers::self_read)
        .get_async("/messages/self-read-sync", messages::handlers::self_read_sync)
        // Eklenti/feed server-log (Faz-2): per-(room,plugin) append-only şifreli log.
        // append = JWT+aktif-üye+author-binding → DO; sync = cursor-pull. Server KÖR.
        .post_async("/plugin-log/:room/:plugin/append", plugin_log::append)
        .get_async("/plugin-log/:room/:plugin/sync", plugin_log::sync)
        .post_async("/plugin-blob/:room/:id", plugin_blob::put_code)
        .get_async("/plugin-blob/:room/:id", plugin_blob::get_code)
        // Üye-yüklenebilir KALICI eklenti-medya (plugin_blob'un üye-PUT'lu, 50 MiB'lik
        // kardeşi): aktif-üye PUT/GET, room-scope R2, kota+usage media ile ORTAK sayaçlar.
        .post_async("/plugin-media/:room/:id", plugin_media::put_media)
        .get_async("/plugin-media/:room/:id", plugin_media::get_media)
        .post_async("/media/upload", media::handlers::upload)
        .get_async("/media/:id", media::handlers::download)
        .post_async("/media/:id/ack", media::handlers::ack)
        .post_async("/push/register", push::handlers::register)
        .post_async("/push/unregister", push::handlers::unregister)
        // Arama TURN kimliği (calls Faz 1.5 — internet üstü relay; bütçe-bekçili).
        .post_async("/turn/credentials", turn::credentials)
        .run(req, env)
        .await
}

async fn jwks(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let jwk = public_jwk(&ctx.env)?;
    let mut resp = Response::from_json(&serde_json::json!({ "keys": [jwk] }))?;
    let headers = resp.headers_mut();
    headers.set("cache-control", "public, max-age=300")?;
    Ok(resp)
}

/// WS /sync upgrade: token doğrula, kullanıcının DO stub'ına orijinal request'i
/// proxy et (DO içinde header passthrough ile WS pair kurulur).
///
/// Auth pattern: `Sec-WebSocket-Protocol: sezgi.bearer.v1, <access_token>`.
/// İlk subprotocol scheme adı, ikincisi credential. Bu standart "token via
/// subprotocol" yöntemi — token URL query'sinde değil, böylece CF Workers tail
/// debug log'unda görünmez (URL log'lara düşer, header düşmez).
async fn sync_ws(req: Request, env: Env) -> Result<Response> {
    let token = match extract_bearer_subprotocol(&req) {
        Ok(t) => t,
        Err(e) => return json_err(400, e),
    };
    let user_id = match verify_access_token(&env, &token) {
        Ok(uid) => uid,
        Err(_) => return json_err(401, "invalid_token"),
    };
    // İPTAL-KONTROLÜ (checkpoint 3): token-bound cihaz device-list'ten DÜŞÜRÜLMÜŞ ise YENİ
    // WS oturumu AÇMA → çalınan cihaz, 15dk access-token TTL'i içinde bile canlı push/WS-send
    // kanalı kuramaz. Event-driven (upgrade başına BİR sorgu; polling yok). Zaten-açık WS'in
    // anlık kesimi (DO-side WS-1008) ayrı follow-up; bu yeni-oturumu kapatır.
    if let Some(dev) = crate::auth::jwt::device_id_from_token(&env, &token)
        .ok()
        .flatten()
    {
        // FAIL-CLOSED (Codex cp3): DB hatasında `.unwrap_or(false)` WS'i AÇIYORDU → iptal-edilmiş
        // cihaz D1-hatası penceresinde oturum kurabilirdi. Hata → 503 (oturum AÇMA); yalnız
        // kesin Ok(false) geçer. (W1/HTTP send zaten `?` ile fail-closed.)
        match crate::auth::middleware::device_revoked(&env, &user_id, &dev).await {
            Ok(true) => return json_err(401, "device_revoked"),
            Ok(false) => {}
            Err(_) => return json_err(503, "revoke_check_unavailable"),
        }
    }
    let upgrade = req.headers().get("upgrade").ok().flatten();
    if upgrade.as_deref().map(|s| s.to_lowercase()) != Some("websocket".into()) {
        return json_err(426, "expected_websocket");
    }

    let namespace = env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?;
    stub.fetch_with_request(req).await
}

/// `Sec-WebSocket-Protocol: sezgi.bearer.v1, <token>` parse — token döndürür.
/// Eski `?token=` query param desteklenmez (cutover).
pub(crate) fn extract_bearer_subprotocol(req: &Request) -> std::result::Result<String, &'static str> {
    let raw = req
        .headers()
        .get("Sec-WebSocket-Protocol")
        .ok()
        .flatten()
        .ok_or("subprotocol_required")?;
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.len() != 2 || parts[0] != "sezgi.bearer.v1" {
        return Err("expected_subprotocol_sezgi_bearer_v1");
    }
    if parts[1].is_empty() {
        return Err("token_empty");
    }
    Ok(parts[1].to_string())
}
