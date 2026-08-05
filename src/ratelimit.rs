use crate::utils::now_secs;
use worker::{console_log, kv::KvStore, Env, Result};

/// A MISSING BINDING FAILS OPEN. `env.kv("RATE_LIMIT")` erroring is read as "allow",
/// so a deployment without the namespace silently has no rate limiting anywhere. All
/// callers go through these env helpers, so no handler is left with a `?`-propagating
/// `env.kv("RATE_LIMIT")?` that would turn a missing binding into a 500.
///
/// This used to say the self-host template ships WITHOUT the binding, to keep the
/// Deploy-to-Cloudflare screen short. **That is no longer true** — `sezi-server`'s
/// `wrangler.toml` declares the `RATE_LIMIT` namespace with a placeholder id the
/// deployer fills in, the same as prod. The stale note mattered: it was read as
/// "every rate limit in this file is decorative on a self-host install", which made
/// each new limit look pointless to add. They are real on both.
///
/// The fail-open behaviour stays anyway, because a hand-rolled deployment can still
/// omit the namespace, and losing a rate limit is a better failure than losing the
/// endpoint. It does mean a limit is never a BOUND — anything that must actually be
/// bounded needs a D1 count beside it, the way `groups::create_group` pairs its brake
/// with `MAX_OWNED_GROUPS`.
pub async fn check_rate_limit_env(env: &Env, key: &str, max_hits: usize, window_sec: u64) -> bool {
    check_rate_limit_weighted_env(env, key, max_hits, window_sec, 1).await
}

/// Weighted variant of [check_rate_limit_env] (used by the M12 fan-out guard).
pub async fn check_rate_limit_weighted_env(
    env: &Env,
    key: &str,
    max_hits: usize,
    window_sec: u64,
    weight: usize,
) -> bool {
    let kv = match env.kv("RATE_LIMIT") {
        Ok(kv) => kv,
        // No binding (self-host template) → continue unlimited.
        Err(_) => return true,
    };
    // check_rate_limit_weighted is already fail-open internally (a KV get/put error
    // yields Ok(true)); it should never return Err, but if it does we fail open too.
    check_rate_limit_weighted(&kv, key, max_hits, window_sec, weight)
        .await
        .unwrap_or(true)
}

/// M12 (fan-out amplification): a WEIGHTED sliding window. `weight` is the "cost" of
/// this event — e.g. the fan-out width of a group send equals N DO writes. If the
/// total weight accumulated in the window would exceed `max_hits` the event is
/// rejected; otherwise `weight` timestamps are appended (each counts for the rest of
/// the window). `weight = 1` behaves exactly like the old unweighted
/// `check_rate_limit`. Cost stays KV-friendly: one get + one put (the vector grows by
/// `weight`, bounded by the member ceiling). This is the module-internal core;
/// everything outside calls the env helpers, where the binding is optional.
async fn check_rate_limit_weighted(
    kv: &KvStore,
    key: &str,
    max_hits: usize,
    window_sec: u64,
    weight: usize,
) -> Result<bool> {
    let now = now_secs();
    let cutoff = now.saturating_sub(window_sec);
    // FAIL-OPEN (Tier-2 #13 — 2026-06-28): on a KV READ error (daily KV limit exceeded,
    // or a transient KV outage) BYPASS the rate limit and ALLOW the request, rather than
    // locking ALL traffic behind 500/429 the way the old `?` propagation did. That was
    // exactly the 2026-06-27 field wedge: the rate limiter did a KV put on every request
    // → a retry storm blew past the daily 1000-PUT limit → fail-closed → the
    // messages/ws/keys/auth routes all returned 429/500 → MESSAGING STOPPED. In a
    // self-hosted closed-membership model the abuse risk is low, while the cost of
    // failing closed (the whole flow halts) is incomparably worse. Temporarily loose
    // limits during a KV outage beat a total outage.
    let raw = match kv.get(key).text().await {
        Ok(v) => v,
        Err(e) => {
            console_log!("ratelimit: KV get FAIL → fail-open (allow) key={key}: {e:?}");
            return Ok(true);
        }
    };
    let mut hits: Vec<u64> = raw
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    hits.retain(|&t| t > cutoff);
    let w = weight.max(1);
    // Reject if the accumulated total plus this event's weight exceeds the ceiling
    // (no partial admission).
    if hits.len() + w > max_hits {
        return Ok(false);
    }
    for _ in 0..w {
        hits.push(now);
    }
    let payload = serde_json::to_string(&hits).unwrap_or_else(|_| "[]".into());
    // FAIL-OPEN: on a KV WRITE error (daily PUT limit) skip the record but ALLOW the
    // request. This hit goes uncounted — the counter loosens slightly — but messaging
    // does NOT stop. And if the write failed we are already in KV-limit mode, so
    // retrying the put would only eat further into the limit.
    match kv.put(key, payload) {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(window_sec + 60).execute().await {
                console_log!("ratelimit: KV put FAIL → fail-open (allow) key={key}: {e:?}");
            }
        }
        Err(e) => {
            console_log!("ratelimit: KV put-builder FAIL → fail-open (allow) key={key}: {e:?}");
        }
    }
    Ok(true)
}
