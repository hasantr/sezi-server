use crate::auth::jwt::device_id_from_token;
use crate::auth::middleware::{extract_bearer, require_auth};
use crate::d1util::{d1_int, d1_opt_text, d1_text};
use sha2::{Digest, Sha256};

/// W4-b (grup fan-out kısmi-fail durable-retry) sabitleri.
const W4B_INITIAL_BACKOFF_SECS: i64 = 30; // enqueue → ilk drain-denemesi gecikmesi
// MINOR-1 (Fable+Codex): lease'i backoff-tabanından AYIR. LEASE = claim in-flight penceresi (10dk):
// drain-crash / yavaş-DO'da satır bu kadar "meşgul" → çakışan cron AYNI satırı re-claim ETMEZ
// (lease >> cron-periyodu 2dk + max-drain-süresi → double-notify penceresi kapanır). Fail'de next_at
// backoff'la EZİLİR (retry gecikmez); yalnız drain-crash'te 10dk sonra kurtulur (self-heal).
const W4B_LEASE_SECS: i64 = 600;
const W4B_BACKOFF_BASE_SECS: i64 = 120; // fail-backoff tabanı (lease'ten AYRI): 120→240→…→3600-cap
const W4B_MAX_BACKOFF_SECS: i64 = 3600; // backoff tavanı — uzun-outage'da 1sa aralıkla döner, SİLİNMEZ (kayıp yok)
const W4B_DRAIN_BATCH: usize = 50; // cron başına drain (D1-yanıt boyutu + sıralı DO-fetch süre tavanı)
use crate::respond::{json_err, no_content};
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

/// M2-S2.3 (WIRE-CUT): batch zarf öğesi. 1:1'de `device_id` = HEDEF alıcı
/// cihazı (gönderen bundle'dan bilir → cihaz-başına ayrı Olm zarfı). GRUPta
/// `device_id` YOK (tek Megolm zarfı; device fan-out WORKER-İÇİ türetilir).
#[derive(Deserialize)]
struct EnvItem {
    #[serde(default)]
    device_id: Option<String>,
    envelope_b64: String,
}

/// M2-S2.3: tekil `envelope_b64` SÖKÜLDÜ → `envelopes:Vec<EnvItem>` batch.
/// HTTP ≡ WS-send batch (bit-aynı gövde). N=1'de tek-eleman envelopes →
/// bugünkü tek-zarf akışıyla birebir.
#[derive(Deserialize)]
struct SendBody {
    /// 1:1 doğrudan mesaj alıcısı. Grup mesajında `None` (bunun yerine `group_id`).
    #[serde(default)]
    recipient_id: Option<String>,
    /// GRUP mesajı (Faz 2): bu grubun üyelerine fan-out. 1:1'de `None`.
    #[serde(default)]
    group_id: Option<String>,
    /// M2-S2.3: GÖNDERENİN cihazı (alıcı doğru Olm cihaz-oturumunu seçer;
    /// grupta tek Megolm zarfı için yine taşınır). Bundle v2 + device-claim ile
    /// uçtan-uca cihaz-adresleme. Eski tekil-form `sender_device_id` taşımaz.
    sender_device_id: String,
    /// M2-S2.3: cihaz-başına zarf listesi. 1:1 N≥1; grup tek-eleman device_id'siz.
    envelopes: Vec<EnvItem>,
}

#[derive(Deserialize)]
struct NotifyResult {
    id: i64,
    #[serde(default)]
    delivered_live: bool,
}

/// Bir kullanıcının DO inbox'ına `/notify` (store + WS push). `group_id` Some ise
/// alıcının frame'i bunu taşır → alıcı Megolm (grup) decrypt yolunu seçer.
/// `recipient_device` Some ise pending o cihaza scope'lanır (per-device kuyruk +
/// ack-izolasyonu; S2.2 notify_inner). Dönen `id` o ALICININ pending sıra-id'si.
/// Hata → `Err` (fan-out'ta per-device GÖRÜNÜR — sessiz-atla KALKAR, red-team #18).
/// notify_inner payload'ı (recipient DO `/notify` gövdesi). `notify_recipient` + W4-b drain
/// AYNI şekli kurar (tutarlılık; tek kaynak).
fn build_notify_payload(
    recipient_id: &str,
    sender_id: &str,
    sender_device_id: &str,
    recipient_device_id: Option<&str>,
    envelope_b64: &str,
    group_id: Option<&str>,
) -> String {
    serde_json::json!({
        "sender_id": sender_id,
        "sender_device_id": sender_device_id,
        "recipient_device_id": recipient_device_id,
        // W1-backstop: ALICI user_id → notify_inner persist eder (DO offline'da kendi user'ını bilmez).
        "recipient_id": recipient_id,
        "envelope_b64": envelope_b64,
        "group_id": group_id,
    })
    .to_string()
}

/// TEK DO `/notify` denemesi (store + WS push). Ok → (pending_id, delivered_live). Hata → Err
/// (id_from_name/stub / fetch-fail / 200-dışı / parse-fail). `notify_recipient` bunu 3× loop'lar
/// (transient retry); W4-b drain TEK-atış çağırır (satır-düzeyi next_at-backoff = retry).
async fn notify_once(
    namespace: &ObjectNamespace,
    recipient_id: &str,
    payload: &str,
) -> Result<(i64, bool)> {
    let stub = namespace.id_from_name(recipient_id)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(payload.to_string().into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let do_req = Request::new_with_init("https://do.sezgi/notify", &init)?;
    let mut resp = stub.fetch_with_request(do_req).await?;
    if resp.status_code() != 200 {
        return Err(Error::RustError(format!("do_notify_status_{}", resp.status_code())));
    }
    resp.json::<NotifyResult>()
        .await
        .map(|r| (r.id, r.delivered_live))
        .map_err(|_| Error::RustError("do_notify_bad_response".into()))
}

async fn notify_recipient(
    namespace: &ObjectNamespace,
    recipient_id: &str,
    sender_id: &str,
    sender_device_id: &str,
    recipient_device_id: Option<&str>,
    envelope_b64: &str,
    group_id: Option<&str>,
) -> Result<(i64, bool)> {
    let payload = build_notify_payload(
        recipient_id,
        sender_id,
        sender_device_id,
        recipient_device_id,
        envelope_b64,
        group_id,
    );
    // W4 BOUNDED in-request retry (3 deneme; transient DO 5xx/overload/routing yakalar). notify_inner
    // dedup'ı (60sn sıcak-DO) "başardı-ama-yanıt-düştü"yü yutar → çift-pending yok. 3'ü de fail → Err
    // → caller görünür sayar → W4-b durable-retry kuyruğuna enqueue (kısmi-fail'de).
    const NOTIFY_ATTEMPTS: usize = 3;
    let mut last_err = Error::RustError("do_notify_failed".into());
    for attempt in 0..NOTIFY_ATTEMPTS {
        match notify_once(namespace, recipient_id, &payload).await {
            Ok(r) => {
                if attempt > 0 {
                    console_log!(
                        "[deliv] W4 notify retry-recovered: {}. denemede OK (recipient={recipient_id})",
                        attempt + 1
                    );
                }
                return Ok(r);
            }
            Err(e) => last_err = e,
        }
    }
    console_log!("[deliv] W4 notify {NOTIFY_ATTEMPTS} deneme FAIL (recipient={recipient_id})");
    Err(last_err)
}

/// W4-b durable-retry drain (cron; HER scheduled invocation'da çağrılır). Atomik-claim
/// (`UPDATE...next_at LEASE-ileri RETURNING` → çakışan cron AYNI satırı re-notify etmez) → TEK-atış
/// re-notify → OK=DELETE+FCM-wake-paritesi, FAIL=exp-backoff UPDATE (SİLMEZ; Codex#4 kayıp-önleme —
/// uzun-outage'da döner, TTL-GC çok-eskiyi toplar). Bounded batch. Best-effort (D1/DO-hatası → satır
/// kalır → sonraki tur; tablo yoksa/migration-yok → sessiz no-op). notify_recipient'ın 3-retry gövdesi
/// DEĞİL `notify_once` tek-atış (satır-düzeyi backoff = retry, Fable#2).
pub(crate) async fn drain_fanout_retry(env: &Env) {
    let Ok(db) = env.d1("DB") else { return };
    let Ok(namespace) = env.durable_object("USER_INBOX") else { return };
    let now = now_secs() as i64;
    #[derive(serde::Deserialize)]
    struct RetryRow {
        id: i64,
        recipient_id: String,
        #[serde(default)]
        recipient_device: Option<String>,
        sender_id: String,
        #[serde(default)]
        sender_device: Option<String>,
        envelope_b64: String,
        group_id: String,
        attempts: i64,
    }
    // Atomik claim: due satırların next_at'ini LEASE-ileri it (in-flight işareti) + döndür.
    let claimed: Vec<RetryRow> = match db
        .prepare(
            "UPDATE fanout_retry SET next_at = ?
             WHERE id IN (SELECT id FROM fanout_retry WHERE next_at <= ? ORDER BY next_at LIMIT ?)
             RETURNING id, recipient_id, recipient_device, sender_id, sender_device, envelope_b64, group_id, attempts",
        )
        .bind(&[
            d1_int(now + W4B_LEASE_SECS),
            d1_int(now),
            d1_int(W4B_DRAIN_BATCH as i64),
        ]) {
        Ok(stmt) => match stmt.all().await {
            Ok(res) => res.results::<RetryRow>().unwrap_or_default(),
            Err(_) => return,
        },
        Err(_) => return,
    };
    if claimed.is_empty() {
        return;
    }
    let total = claimed.len();
    let mut ok = 0usize;
    for r in &claimed {
        let payload = build_notify_payload(
            &r.recipient_id,
            &r.sender_id,
            r.sender_device.as_deref().unwrap_or(""),
            r.recipient_device.as_deref(),
            &r.envelope_b64,
            Some(&r.group_id),
        );
        match notify_once(&namespace, &r.recipient_id, &payload).await {
            Ok((_, delivered_live)) => {
                if let Ok(stmt) = db
                    .prepare("DELETE FROM fanout_retry WHERE id = ?")
                    .bind(&[d1_int(r.id)])
                {
                    let _ = stmt.run().await;
                }
                // FCM-wake paritesi (handlers offline dalı, Codex#6): teslim OK + offline → wake.
                if !delivered_live {
                    crate::push::fcm::maybe_push_wake(
                        env, &db, &r.recipient_id, r.recipient_device.as_deref(),
                    )
                    .await;
                }
                ok += 1;
            }
            Err(_) => {
                // exp-backoff, SİLMEZ (Codex#4): attempts++ + next_at ileri. attempts yalnız DO-hatası
                // sayar (offline≠hata → notify başarılı) → yüksek-attempts = "DO günlerce bozuk"=nadir.
                let shift = r.attempts.clamp(0, 5) as u32;
                let backoff = (W4B_BACKOFF_BASE_SECS << shift).min(W4B_MAX_BACKOFF_SECS);
                if let Ok(stmt) = db
                    .prepare("UPDATE fanout_retry SET attempts = attempts + 1, next_at = ? WHERE id = ?")
                    .bind(&[d1_int(now + backoff), d1_int(r.id)])
                {
                    let _ = stmt.run().await;
                }
            }
        }
    }
    console_log!("[deliv] W4-b drain: {ok}/{total} re-notify OK");
}

/// W4-b TTL-GC (günlük-cron): çok-eski fanout_retry satırlarını topla. MAX-attempts'te SİLMEDİĞİMİZ
/// için tek üst-sınır BU = bounded. RETENTION-PARİTESİ (server-lean audit 2026-07-03): fanout_retry
/// E2E-ciphertext taşır = `pending` gibi teslim-tamponu → owner-ayarlı `message_retention_days`
/// penceresinde tutulur (sabit-TTL DEĞİL). "Server unutur/şişmez" politikası: owner retention'ı ne
/// diyorsa fanout_retry de o kadar (inbox_do/mod.rs:377 pending-cleanup deseninin birebir aynası).
pub(crate) async fn gc_fanout_retry(env: &Env) {
    let Ok(db) = env.d1("DB") else { return };
    let days = crate::server::handlers::fetch_message_retention_days(env).await;
    let cutoff = now_secs() as i64 - days * 24 * 3600;
    if let Ok(stmt) = db
        .prepare("DELETE FROM fanout_retry WHERE created_at < ?")
        .bind(&[d1_int(cutoff)])
    {
        let _ = stmt.run().await;
    }
}

pub async fn send(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let sender_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // S2 (Fable HIGH — kota/DoS): per-user mesaj rate-limit. Farklı-byte zarf 60sn
    // dedup'ı atlatıp UserInbox DO'yu (SQLite) şişiremesin. 300 mesaj / 60sn: en
    // yoğun meşru sohbetin üstü (insan ~<2/sn), otomatik-spam'i keser. KV sliding-
    // window (auth redeem/verify + media/upload ile AYNI altyapı). Grup fan-out
    // bu sınırın İÇİNDE (1 send = N DO-write ama 1 hit) → meşru grup-mesajı serbest.
    // KV binding OPSİYONEL (şablon-diyeti): yoksa limitsiz devam — bkz. ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("msg:send:{sender_id}"), 300, 60).await {
        return json_err(429, "rate_limited");
    }
    let body: SendBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    // M2-S2.3 (WIRE-CUT): batch zarf. Boş-batch → 400. Her zarf len-check
    // TÜMÜ-VEYA-HİÇBİRİ: tek zarf bile sınır-dışıysa tüm istek 400 (kısmi
    // kabul yok → client ya hepsi gönderildi ya hiçbiri, tutarlı durum).
    if body.envelopes.is_empty() || body.envelopes.len() > 100 {
        return json_err(400, "bad_request");
    }
    if body.sender_device_id.is_empty() {
        return json_err(400, "bad_request");
    }
    // M2-S3.1 B1 (token-binding) — TÜM S3 self/echo-dışlamanın GÜVEN-TEMELİ: forged
    // `sender_device_id` ile BAŞKA cihaz adına HTTP send (sahte self-copy / grup-echo
    // enjeksiyonu) önle. body.sender_device_id, JWT'nin `device_id` claim'iyle EŞLEŞMELİ.
    // require_auth DEĞİŞTİRİLMEZ (6 çağıran blast-radius) → ayrı bearer+device çek.
    // token_device==None (eski claim'siz token) → 403 (S3 cihazları device-claim'li
    // token alır; eski token relogin'e zorlanır). WS-send yolu (inbox_do/ws.rs) ZATEN
    // attachment-device=token-bound → bu kapı yalnız HTTP send forgery yüzeyini kapatır.
    let token_device =
        extract_bearer(&req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    if token_device.as_deref() != Some(body.sender_device_id.as_str()) {
        return json_err(403, "device_mismatch");
    }
    // İPTAL-KONTROLÜ (güvenlik denetimi — checkpoint 3): token-bound cihaz device-list'ten
    // DÜŞÜRÜLMÜŞ (revoked) ise 15dk access-token TTL'i dolmadan da gönderimi REDDET → çalınan
    // cihaz iptalden sonra mesaj GÖNDEREMEZ. Event-driven (her send BİR sorgu; polling yok).
    if crate::auth::middleware::device_revoked(&ctx.env, &sender_id, &body.sender_device_id).await? {
        return json_err(401, "device_revoked");
    }
    for e in &body.envelopes {
        if e.envelope_b64.len() < 20 || e.envelope_b64.len() > 64 * 1024 {
            return json_err(400, "bad_request");
        }
    }

    let db = ctx.env.d1("DB")?;
    let namespace = ctx.env.durable_object("USER_INBOX")?;

    // ---- GRUP yolu (Faz 2 fan-out): group_id → üyelere (gönderen hariç) /notify ----
    if let Some(group_id) = body.group_id.as_deref() {
        // Gönderen bu grubun üyesi olmalı (E2E: sunucu içeriği görmez, yalnız
        // üyelik tablosundan dağıtım yapar).
        if crate::groups::group_role(&db, group_id, &sender_id)
            .await?
            .is_none()
        {
            return json_err(403, "not_member");
        }
        // M2-S2.3 (red-team BLOCKER #9): grup tek-Megolm zarfı. EnvItem tek-eleman,
        // device_id'siz olmalı (fan-out worker-içi türetilir). Birden çok zarf veya
        // device_id taşıyan grup gövdesi geçersiz.
        if body.envelopes.len() != 1 || body.envelopes[0].device_id.is_some() {
            return json_err(400, "bad_request");
        }
        let envelope_b64 = body.envelopes[0].envelope_b64.as_str();
        #[derive(Deserialize)]
        struct MemberDevice {
            user_id: String,
            // FIX-1 (BLOCKER): LEFT JOIN → cihaz-listesi YAYINLAMAMIŞ aktif üye için
            // `device_id` NULL döner. Bu yüzden `Option<String>` (eski `String` INNER
            // JOIN'de cihazsız üyeyi DÜŞÜRÜYORDU → grup mesajı kalıcı kayıp).
            device_id: Option<String>,
        }
        // M2-S2.3 grup recipient_device türetme (red-team BLOCKER #9 + FIX-1): AKTİF
        // üye (Faz 6 #3 consent) × o üyenin AKTİF cihazları. `group_members LEFT JOIN
        // devices` → her (üye, cihaz) çiftine TEK Megolm zarfı `recipient_device` ile
        // INSERT (DO dedup recipient_device'a bağımlı → ikinci-cihaz yutulmaz).
        //
        // FIX-1 (BLOCKER — grup üye-düşürme): INNER JOIN → LEFT JOIN. Cihaz-listesi
        // YAYINLAMAMIŞ aktif üye `devices`'ta satıra sahip değil → INNER JOIN onu
        // fan-out'tan DÜŞÜRÜP grup mesajını KALICI kaybediyordu. LEFT JOIN cihazsız
        // üye için `device_id=NULL` döndürür → aşağıdaki döngü onu `recipient_device=
        // None` (device-blind pending) ile kuyruğa yazar → üye sonradan cihaz-listesi
        // yayınlayıp bağlanınca NULL-tolerant flush ile alır (FIX-2). N=1'de her üye
        // tek-primary döner = INNER ile bit-aynı satır. `revoked_at IS NULL` = aktif
        // cihaz. Gönderenin kendi cihazları hariç (user_id != sender).
        let pairs: Vec<MemberDevice> = db
            .prepare(
                "SELECT gm.user_id AS user_id, d.device_id AS device_id
                 FROM group_members gm
                 LEFT JOIN devices d
                   ON d.user_id = gm.user_id AND d.revoked_at IS NULL
                 WHERE gm.group_id = ? AND gm.user_id != ?
                   AND gm.status = 'active'",
            )
            .bind(&[d1_text(group_id), d1_text(&sender_id)])?
            .all()
            .await?
            .results()?;
        // M12 (fan-out amplifikasyon — DoS): bir grup-send `pairs.len()` adet DO-write
        // üretir (üye × cihaz). Baştaki tek-hit `msg:send` guard'ı bunu 1 olay sayıyordu
        // → büyük gruba 300 send/60s = ~300×N DO-write. Fan-out GENİŞLİĞİYLE ağırlıklı
        // İKİNCİ guard: ayrı `msg:grp_fanout:{sender}` kovasında `pairs.len()` birim
        // maliyet. 6000 birim/60s: 256-üyelik tam-gruba ~23 send/dk, küçük gruplara çok
        // daha fazla = meşru kullanım serbest, amplifikasyon-spam kesilir. Üye-tavanı
        // (MAX_GROUP_MEMBERS=256) tek-send maliyetini sınırlar → birlikte sınırlı toplam.
        if !pairs.is_empty()
            && !crate::ratelimit::check_rate_limit_weighted_env(
                &ctx.env,
                &format!("msg:grp_fanout:{sender_id}"),
                6000,
                60,
                pairs.len(),
            )
            .await
        {
            return json_err(429, "rate_limited");
        }
        // Her (üye, cihaz) çiftine fan-out (sıralı; worker WASM tek-thread). Bir
        // cihaz DO'su başarısızsa atla (diğerleri teslim olur); idempotency DO
        // dedup'ta. Grupta tek kanonik id YOK → ilk başarılı çiftinki, hiç yoksa
        // zaman damgası (yalnız gönderenin lokal "Sent" takibi; grup-receipt ayrı).
        // FIX-1: `device_id` Some → somut cihaz hedefi; None (cihaz yayınlamamış üye)
        // → `recipient_device=None` device-blind pending (üye düşmez).
        let mut first_id: Option<i64> = None;
        let mut delivered_count: usize = 0;
        let mut failed_pairs = Vec::new();
        for p in &pairs {
            match notify_recipient(
                &namespace,
                &p.user_id,
                &sender_id,
                &body.sender_device_id,
                p.device_id.as_deref(),
                envelope_b64,
                Some(group_id),
            )
            .await
            {
                Ok((id, delivered_live)) => {
                    if first_id.is_none() {
                        first_id = Some(id);
                    }
                    delivered_count += 1;
                    // Bu üye-cihaz OFFLINE → içeriksiz FCM-wake (grup fan-out per-device).
                    if !delivered_live {
                        crate::push::fcm::maybe_push_wake(
                            &ctx.env, &db, &p.user_id, p.device_id.as_deref(),
                        )
                        .await;
                    }
                }
                Err(_) => failed_pairs.push(p), // W4-b: 3-deneme de fail → durable-retry'e
            }
        }
        // TOPLAM-fail (hiç-teslim) → 502 retryable; enqueue YOK (sender tümünü retry'lar → partial-dup
        // riski yok). Sağlamlaştırma #4: eskiden hiç-teslim olsa bile 200+sentetik-id dönüp gönderen
        // "başarılı" sanıp mesajı KALICI kaybediyordu; 502 = client güvenle yeniden dener (DO-dedup güvenli).
        if !pairs.is_empty() && delivered_count == 0 {
            return json_err(502, "fanout_failed");
        }
        // W4-b: KISMİ-fail (delivered_count>0 ama bazı çift Err) → başarısız (üye,cihaz)'ları DURABLE
        // fanout_retry kuyruğuna yaz → cron drain re-notify eder → o üye grup mesajını KAÇIRMAZ.
        // retry_key = sha256(recipient|device|group|envelope)[..16] + INSERT OR IGNORE = idempotent
        // (sender-retry / çift-enqueue AYNI satırı çift-yazmaz → dup-pending + W2-cap tüketimi önlenir).
        // BEST-EFFORT: INSERT fail (D1-down / migration-yok) → send KIRILMAZ + `failed:n` response'ta
        // görünür (YALAN-garanti yok; mevcut sessiz-loss'tan STRICTLY BETTER). Total-fail buraya gelmez.
        let failed_n = failed_pairs.len();
        if failed_n > 0 {
            let now = now_secs() as i64;
            for p in &failed_pairs {
                let device = p.device_id.as_deref().unwrap_or("");
                let mut hasher = Sha256::new();
                hasher.update(p.user_id.as_bytes());
                hasher.update(b"|");
                hasher.update(device.as_bytes());
                hasher.update(b"|");
                hasher.update(group_id.as_bytes());
                hasher.update(b"|");
                hasher.update(envelope_b64.as_bytes());
                let retry_key: String =
                    hasher.finalize()[..16].iter().map(|b| format!("{:02x}", b)).collect();
                if let Ok(stmt) = db
                    .prepare(
                        "INSERT OR IGNORE INTO fanout_retry
                         (retry_key, recipient_id, recipient_device, sender_id, sender_device,
                          envelope_b64, group_id, attempts, next_at, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                    )
                    .bind(&[
                        d1_text(&retry_key),
                        d1_text(&p.user_id),
                        d1_opt_text(p.device_id.as_deref()),
                        d1_text(&sender_id),
                        d1_text(&body.sender_device_id),
                        d1_text(envelope_b64),
                        d1_text(group_id),
                        d1_int(now + W4B_INITIAL_BACKOFF_SECS),
                        d1_int(now),
                    ])
                {
                    let _ = stmt.run().await;
                }
            }
            console_log!(
                "[deliv] W4-b enqueue: {failed_n}/{} kismi-fail durable-retry'e (group={group_id})",
                pairs.len()
            );
        }
        let id = first_id.unwrap_or_else(|| now_secs() as i64);
        // SAHA-FIX (grup-send "batch ack boş"): client `send_group_message` →
        // `SendBatchRes { ts, acks }` bekliyor (batch-wire-cut M2-S2.4); eski yanıt
        // {id,ts} `acks` taşımadığı için client `res.acks.first()` = None → grup mesajı
        // 8/8 retry'da DÜŞÜYORDU. `acks` ekle (grup tek-kanonik-id → tek eleman,
        // device_id=None). `id` de korunur (eski-client geriye uyumu). M4 DEĞİL — grup
        // 1:1-batch'e geçerken atlanmış.
        return Response::from_json(&serde_json::json!({
            "id": id,
            "ts": now_secs(),
            "acks": [{ "id": id }],
            // W4-b: kaç (üye,cihaz) durable-retry'e düştü (0 = tam-teslim). Client bugün
            // kullanmasa da telemetri + ileride "kısmi-teslim" görünürlük/nudge kapısı.
            "failed": failed_n,
        }));
    }

    // ---- 1:1 yolu (batch device fan-out) ----
    let recipient_id = match body.recipient_id.as_deref() {
        Some(r) => r,
        None => return json_err(400, "bad_request"), // ne recipient ne group
    };
    if recipient_id.len() != 36 {
        return json_err(400, "bad_request");
    }
    // M2-S2.3 self-send device-aware: recipient==sender ise YALNIZCA farklı-cihaz
    // İZİN (OutboundCopy self-copy için wire-yapısı hazır; davranış S3). Aynı-cihaza
    // self-send hâlâ 400. Her EnvItem'in device_id'si sender_device_id'den farklı
    // olmalı.
    if recipient_id == sender_id {
        let any_same = body
            .envelopes
            .iter()
            .any(|e| e.device_id.as_deref() == Some(body.sender_device_id.as_str()));
        // device_id'siz self-send (hangi cihaza belirsiz) de reddedilir.
        let any_missing = body.envelopes.iter().any(|e| e.device_id.is_none());
        if any_same || any_missing {
            return json_err(400, "cannot_send_to_self");
        }
    }
    #[derive(Deserialize)]
    struct Idr {
        #[allow(dead_code)] // varlık kontrolü için fetch; değeri okunmuyor
        id: String,
    }
    let recipient: Option<Idr> = db
        .prepare("SELECT id FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(recipient_id)])?
        .first(None)
        .await?;
    if recipient.is_none() {
        return json_err(404, "recipient_not_found");
    }
    // FIX-2(a) (HIGH — orphan NULL): 1:1 yolunda her EnvItem.device_id ZORUNLU.
    // 1:1 gönderen, bundle v2'den alıcının cihazlarını bilir → her zarf SOMUT bir
    // cihaza hedeflenir (cihaz-başına ayrı Olm session). device_id=None taşıyan
    // 1:1 gövdesi = buggy/eski client → orphan-NULL pending üretir (çok-cihaz
    // belirsizliği). Burada erken 400 ile engellenir. (NULL pending YALNIZCA grup
    // fallback'inden [cihaz yayınlamamış üye, FIX-1] veya S1-token device-blind
    // yolundan MEŞRU olarak oluşur — 1:1'den ASLA.)
    if body.envelopes.iter().any(|e| e.device_id.is_none()) {
        return json_err(400, "bad_request");
    }
    // M2-S2.3 batch 1:1 fan-out: her EnvItem → /notify(recipient_device). PER-DEVICE
    // başarı/hata GÖRÜNÜR (mevcut `if let Ok(Some)` sessiz-atla KALKAR, red-team #18):
    // başarılı cihazlar acks'e girer, başarısız cihazlar DÜŞER → eksik device_id
    // client'a görünür. N=1'de tek-eleman → tek ack = bugünkü tek-zarf akışı.
    let mut acks: Vec<serde_json::Value> = Vec::with_capacity(body.envelopes.len());
    for e in &body.envelopes {
        match notify_recipient(
            &namespace,
            recipient_id,
            &sender_id,
            &body.sender_device_id,
            e.device_id.as_deref(),
            &e.envelope_b64,
            None,
        )
        .await
        {
            Ok((id, delivered_live)) => {
                acks.push(serde_json::json!({
                    "device_id": e.device_id,
                    "id": id,
                }));
                // Alıcı o cihazda OFFLINE → içeriksiz FCM-wake (1:1 HTTP yolu).
                if !delivered_live {
                    crate::push::fcm::maybe_push_wake(
                        &ctx.env, &db, recipient_id, e.device_id.as_deref(),
                    )
                    .await;
                }
            }
            Err(_) => { /* per-device fail → ack listesinden düşer (görünür) */ }
        }
    }
    // Hiçbir cihaz başaramadıysa 502 (eski tek-zarf "do_notify_failed" paritesi).
    if acks.is_empty() {
        return json_err(502, "do_notify_failed");
    }
    Response::from_json(&serde_json::json!({ "ts": now_secs(), "acks": acks }))
}

#[derive(Deserialize)]
struct ReadBody {
    peer_id: String,
    ids: Vec<i64>,
    /// #11 Layer-4b (Codex Q7): `ids`'e PARALEL msg_uid'ler — WS-read fallback'i HTTP'ye
    /// düşse de kardeş-yakınsama uid'i kaybetmesin. Eski client / WS yolu → boş Vec.
    #[serde(default)]
    uids: Vec<String>,
}

pub async fn read(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let recipient_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // FIX-3 (CONCERN H2 — WS-read DoS bypass): WS-read'e rate-limit eklendi ama HTTP
    // `/messages/read` guard'sızdı → WS sınırı HTTP üzerinden atlanıp peer DO'ya
    // sınırsız forward-read push edilebiliyordu (DoS). send() (line ~94) ile TUTARLI
    // guard: per-user `msg:read:{recipient_id}` kovasında 300/60s, fail-closed 429.
    // (Ayrı kova → meşru read trafiği send kotasını yemez; read başına yine 1 hit.)
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("msg:read:{recipient_id}"), 300, 60)
        .await
    {
        return json_err(429, "rate_limited");
    }
    let body: ReadBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.ids.is_empty() || body.ids.len() > 500 {
        return json_err(400, "bad_request");
    }
    if body.peer_id == recipient_id {
        return json_err(400, "cannot_read_self");
    }
    if body.peer_id.len() != 36 {
        return json_err(400, "bad_request");
    }
    // Sağlamlaştırma #9: revoked-cihaz read-receipt FORGE edemesin (send-path revoke paritesi —
    // ws.rs:325 send-yolunda var, read-yolunda eksikti). Token-bound cihaz device-list'ten düşürülmüş
    // (revoked) ise 15dk TTL dolmadan da read-forward'ı REDDET. (Legacy claim'siz token → check yok.)
    {
        let token_device = crate::auth::middleware::extract_bearer(&req)
            .and_then(|t| crate::auth::jwt::device_id_from_token(&ctx.env, &t).ok().flatten());
        if let Some(dev) = token_device.as_deref() {
            if crate::auth::middleware::device_revoked(&ctx.env, &recipient_id, dev).await? {
                return json_err(401, "device_revoked");
            }
        }
    }

    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&body.peer_id)?.get_stub()?;
    let payload = serde_json::json!({
        "from": recipient_id,
        "ids": body.ids,
        "uids": body.uids,
    })
    .to_string();
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(payload.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let do_req = Request::new_with_init("https://do.sezgi/forward-read", &init)?;
    stub.fetch_with_request(do_req).await?;
    no_content()
}

/// `GET /messages/receipt-sync?since=` — Ortak-kök #1: çağıranın KENDİ UserInbox DO'sundaki
/// durable `receipt_state`'ini cursor-pull (WS `receipt_sync` frame'inin HTTP ikizi). WS-Connected
/// OLMAYAN (HTTP-send fallback'teki) cihaz, kendi giden mesajının stuck tikini buradan yakınsatır.
/// receipt_state caller'ın kendi inbox'unda yaşar → `id_from_name(&user_id)` (kendi DO'm).
pub async fn receipt_sync(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    // İptal-paritesi (send handlers.rs:125): iptal-edilmiş cihaza tik-state vermek düşük-risk
    // (içerik yok, yalnız kendi-hesap tik durumu) ama parite en ucuz + tutarlı. Eski claim'siz
    // token (token_device==None) → kontrol atlanır (read/send'deki gibi legacy-tolerans).
    let token_device =
        extract_bearer(&req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    if let Some(dev) = token_device.as_deref() {
        if crate::auth::middleware::device_revoked(&ctx.env, &user_id, dev).await? {
            return json_err(401, "device_revoked");
        }
    }
    // `since` client query'sinden (plugin_log::sync deseni — DO URL'ine güvenli i64 enjeksiyonu).
    let mut since: i64 = 0;
    let url = req.url()?;
    for (k, v) in url.query_pairs() {
        if k.as_ref() == "since" {
            since = v.parse().unwrap_or(0);
        }
    }
    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?; // KENDİ inbox'um
    let do_req = Request::new(
        &format!("https://do.sezgi/receipt-sync?since={since}"),
        Method::Get,
    )?;
    stub.fetch_with_request(do_req).await
}

/// `POST /messages/self-read` (2026-06-28 kardeş-okundu epic): U'nun bir cihazı okuduğu incoming
/// mesajların `msg_uid`'lerini KENDİ inbox DO'suna bildirir → `self_read_state` set-once + diğer
/// U-cihazlarına self_read_update/delta. receipt `read`'in okundu-self ikizi; ama PEER'a değil
/// kendi DO'ma gider (kardeş yakınsama). Body {uids:[...]} DO'da parse edilir (opak forward).
pub async fn self_read(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let token_device =
        extract_bearer(&req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    if let Some(dev) = token_device.as_deref() {
        if crate::auth::middleware::device_revoked(&ctx.env, &user_id, dev).await? {
            return json_err(401, "device_revoked");
        }
    }
    // W3 (self-read DoS-hardening, 2026-07-02): rate-limit (send/read desenine paralel — ayrı kova,
    // 300/60s, KV-hatasında fail-open). `self_read_state` full-pull için PURGE EDİLMEZ (Codex Q8) →
    // sınırsız-büyümeye karşı rate-limit + body-cap tek savunma. 300/60s = legit-TAVANIN ÇOK üstünde:
    // client mark-read'i dwell-controller ile BATCH'ler (istek≠mesaj; pratik tavan ~30-60/dk) →
    // meşru kullanıcı bu limite ULAŞMAZ, yalnız runaway/abuse keser. NOT (Codex-flag): client
    // send_self_read_durable hata'da retry'siz DROP eder (pre-existing) → 429 teorik okuma-kaybı;
    // ama limit legit-üstü olduğundan yalnız abuse'un KENDİ sahte-read'i düşer. Client-retry ayrı
    // robustness follow-up'ı (bu değişiklik legit yol için hatasız).
    if !crate::ratelimit::check_rate_limit_env(&ctx.env, &format!("msg:selfread:{user_id}"), 300, 60).await {
        return json_err(429, "rate_limited");
    }
    let body = req.text().await.unwrap_or_default();
    // W3: body-boyut tavanı — 500 uid × ~40B ≈ 20KB → 32KB cömert. Aşan = anomali/abuse → 400.
    if body.len() > 32 * 1024 {
        return json_err(400, "payload_too_large");
    }
    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?; // KENDİ inbox'um
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let do_req = Request::new_with_init("https://do.sezgi/self-read", &init)?;
    stub.fetch_with_request(do_req).await
}

/// `GET /messages/self-read-sync?since=` — kardeş-okundu cursor-pull (WS `self_read_sync` frame'in
/// HTTP ikizi). Yeni cihaz cursor=0'dan tüm okundu-durumu çeker → backlog yakınsar. receipt_sync aynası.
pub async fn self_read_sync(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
        Err(resp) => return Ok(resp),
    };
    let token_device =
        extract_bearer(&req).and_then(|t| device_id_from_token(&ctx.env, &t).ok().flatten());
    if let Some(dev) = token_device.as_deref() {
        if crate::auth::middleware::device_revoked(&ctx.env, &user_id, dev).await? {
            return json_err(401, "device_revoked");
        }
    }
    let mut since: i64 = 0;
    let url = req.url()?;
    for (k, v) in url.query_pairs() {
        if k.as_ref() == "since" {
            since = v.parse().unwrap_or(0);
        }
    }
    let namespace = ctx.env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(&user_id)?.get_stub()?; // KENDİ inbox'um
    let do_req = Request::new(
        &format!("https://do.sezgi/self-read-sync?since={since}"),
        Method::Get,
    )?;
    stub.fetch_with_request(do_req).await
}
