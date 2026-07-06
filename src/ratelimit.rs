use crate::utils::now_secs;
use worker::{console_log, kv::KvStore, Result};

/// KV-tabanlı sliding window rate-limit. Mevcut TS implementasyonun birebir kopyası.
pub async fn check_rate_limit(
    kv: &KvStore,
    key: &str,
    max_hits: usize,
    window_sec: u64,
) -> Result<bool> {
    check_rate_limit_weighted(kv, key, max_hits, window_sec, 1).await
}

/// M12 (fan-out amplifikasyon): AĞIRLIKLI sliding-window. `weight` = bu olayın
/// "maliyeti" (örn. grup-send fan-out genişliği = N DO-write). Pencerede biriken
/// toplam ağırlık `max_hits`'i aşarsa reddeder; aksi halde `weight` adet zaman
/// damgası ekler (her biri pencere boyunca sayılır). `weight=1` → `check_rate_limit`
/// ile birebir aynı davranış. Maliyet KV-friendly: tek get + tek put (vektör
/// `weight` kadar büyür, makul üye-tavanı [MAX_GROUP_MEMBERS] altında sınırlı).
pub async fn check_rate_limit_weighted(
    kv: &KvStore,
    key: &str,
    max_hits: usize,
    window_sec: u64,
    weight: usize,
) -> Result<bool> {
    let now = now_secs();
    let cutoff = now.saturating_sub(window_sec);
    // FAIL-OPEN (Tier-2 #13 — 2026-06-28): KV OKUMA hatası (günlük KV-limiti aşımı / geçici KV
    // arızası) → rate-limit'i BYPASS et (İZİN VER), eski `?` propagasyonu gibi TÜM trafiği
    // 500/429 ile KİLİTLEME. 2026-06-27 saha-wedge'i tam buydu: rate-limiter her-istekte KV-put
    // → retry-storm günlük 1000-PUT limitini aştı → fail-closed → messages/ws/keys/auth route'ları
    // 429/500 → MESAJLAŞMA DURDU. Self-hosted kapalı-üye modelinde abuse-riski düşük; fail-closed
    // maliyeti (tüm akış durur) kıyaslanamaz ağır. Limit-aşımı geçici gevşeme << tam kesinti.
    let raw = match kv.get(key).text().await {
        Ok(v) => v,
        Err(e) => {
            console_log!("ratelimit: KV get FAIL → fail-open (izin ver) key={key}: {e:?}");
            return Ok(true);
        }
    };
    let mut hits: Vec<u64> = raw
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    hits.retain(|&t| t > cutoff);
    let w = weight.max(1);
    // Biriken toplam + bu olayın ağırlığı tavanı aşıyorsa reddet (kısmi kabul yok).
    if hits.len() + w > max_hits {
        return Ok(false);
    }
    for _ in 0..w {
        hits.push(now);
    }
    let payload = serde_json::to_string(&hits).unwrap_or_else(|_| "[]".into());
    // FAIL-OPEN: KV YAZMA hatası (günlük PUT limiti) → kaydı atla ama İZİN VER. Bu hit sayılmaz
    // (sayaç biraz gevşer) ama mesajlaşma DURMAZ. Ayrıca: yazma başarısızsa zaten KV-limit-modu
    // → put'u tekrar zorlamak limiti daha da yer.
    match kv.put(key, payload) {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(window_sec + 60).execute().await {
                console_log!("ratelimit: KV put FAIL → fail-open (izin) key={key}: {e:?}");
            }
        }
        Err(e) => {
            console_log!("ratelimit: KV put-builder FAIL → fail-open (izin) key={key}: {e:?}");
        }
    }
    Ok(true)
}
