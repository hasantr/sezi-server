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

/// What a sliding-window check decided — and, when it said no, how long the caller has to wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    /// Over the limit. `retry_after_s` is the moment enough of the window's hits will have aged
    /// out for this request to fit: what `Retry-After` carries, so a client can count down to it
    /// instead of telling a person to try again "in a few minutes".
    Refused { retry_after_s: u64 },
}

// ── The door: redeem and verify (campus plan Wave F) ────────────────────────────────────────
//
// A lecture hall of 120 shares one NAT address, and before Wave F redeem and verify allowed 5 per
// 5 minutes per ADDRESS — the sixth student waited, the thirtieth waited half an hour. The limits
// are now keyed per INVITE, scaled to its seats, with a much looser per-address CEILING beside them
// that only a script reaches. What a per-address limit used to guard against — guessing — is
// guarded by counting MISSES per address instead: a student who mistypes a code once costs one
// miss, an enumerator costs thousands.

/// Window of every door limit below.
pub(crate) const DOOR_WINDOW_SECS: u64 = 5 * 60;
/// Redeem or verify calls one address may make per window, whatever the invite. Twice a full
/// lecture hall plus retries; only a script gets here.
pub(crate) const DOOR_IP_CEILING: usize = 300;
/// Refused redeems (an unknown code or token, a spent invite) one address may collect per window
/// before redeem stops answering it. This is what bounds guessing a 39-bit code
/// (`auth::invite_code`). Counted in D1, not KV, by `door_bucket` — reserved before the lookup.
pub(crate) const DOOR_MISS_LIMIT: usize = 30;

/// Refused redeems one IPv6 /48 may collect per window, across all its /64s — see
/// [`door_miss_buckets`].
pub(crate) const DOOR_PREFIX_MISS_LIMIT: usize = 4 * DOOR_MISS_LIMIT;

/// The address a door's miss budget belongs to: an IPv4 address as it is, an IPv6 address as its
/// /64 (adversarial review 2026-10-14, F6). One IPv6 host is handed a whole /64 — SLAAC, privacy
/// addresses, a VPS's routed prefix — and can send from any of its 2^64 addresses, so a budget per
/// full IPv6 address was no budget at all. An IPv4-mapped IPv6 address is its IPv4 address.
/// Anything that is not an address (`"local"`) is kept as it is.
pub(crate) fn door_address(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        Ok(std::net::IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => ip.to_string(),
    }
}

/// The miss counter's key for one address ([`door_address`]). ONE bucket for every door that can
/// tell a live invite from a dead one — redeem, and the invite page (`invite_page`) — so a second
/// door adds no guesses: an address gets [`DOOR_MISS_LIMIT`] misses per window across both
/// together.
pub(crate) fn door_miss_key(ip: &str) -> String {
    format!("auth:redeem:miss:{}", door_address(ip))
}

/// Every miss bucket a request reserves from, with its limit, most specific first: the address's
/// own ([`door_miss_key`]), and for an IPv6 address also its /48 at [`DOOR_PREFIX_MISS_LIMIT`].
///
/// Why the /48 too: a /48 is one site's allocation (a home, a company, a free tunnel-broker
/// account) and holds 65,536 /64s, so the /64 bucket alone still lets one person holding a /48
/// guess 65,536 times as fast. The /48 bucket bounds that at four /64s' worth, while one /64 can
/// still spend only its own 30 of it.
///
/// Why no server-wide ceiling: whatever bounds the whole server is a lever that lets one attacker
/// lock every joiner out for as long as they keep pulling it, and the people a server most needs
/// to admit — a class at the start of term — are exactly who would be locked out. The bound per
/// /64 and per /48 makes guessing cost addresses; a code's expiry and the per-invite limits do the
/// rest. Each guess costs the server one D1 write (template README, "The door").
pub(crate) fn door_miss_buckets(ip: &str) -> Vec<(String, usize)> {
    let mut buckets = vec![(door_miss_key(ip), DOOR_MISS_LIMIT)];
    if let Ok(std::net::IpAddr::V6(v6)) = ip.parse::<std::net::IpAddr>() {
        if v6.to_ipv4_mapped().is_none() {
            let s = v6.segments();
            buckets.push((
                format!("auth:redeem:miss48:{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]),
                DOOR_PREFIX_MISS_LIMIT,
            ));
        }
    }
    buckets
}

/// Redeems or verifies one invite may see per window: a personal invite is one person (today's
/// five), a class invite scales with its seats — two calls a seat plus slack — so the whole class
/// gets in during the first minutes of a lecture. Capped, so a 1000-seat invite cannot open an
/// unbounded window.
pub(crate) fn per_invite_limit(seats: i64) -> usize {
    if seats <= 1 {
        return 5;
    }
    (seats.saturating_mul(2).saturating_add(10)).clamp(10, 2_000) as usize
}

/// The client address the door's buckets are keyed by.
///
/// - `SEZI_TRUSTED_PROXY_HEADER` set (a self-hosted relay behind its own reverse proxy): that
///   header and NOTHING else. For `x-forwarded-for` the LAST entry is read — the one the proxy in
///   front of us appended; earlier entries are whatever the client sent. A missing or malformed
///   value falls into the shared `"local"` bucket rather than to `cf-connecting-ip`, which a client
///   can simply send to a relay that is not behind Cloudflare.
/// - `none`: no header can be trusted — a relay clients reach DIRECTLY, with nothing in front.
///   `wrangler dev` fills `cf-connecting-ip` from the socket only when the client sent none and
///   passes a client's own value through (measured 2026-10-14), so every caller shares `"local"`:
///   one budget for the network, never a fresh one per request. Since the review of 2026-10-14
///   (F7) only a FALLBACK: the app's "this network" install runs behind the LAN front
///   (`template/deploy/sezi-lan-front.mjs`), which sets `x-real-ip` from the socket, and trusts
///   that (`SEZI_TRUSTED_PROXY_HEADER=x-real-ip`). `none` is left for a relay whose folder the
///   front could not be written to, where one shared budget beats a forgeable one.
/// - Unset: `cf-connecting-ip`, which Cloudflare sets on every request, else `"local"` — today's
///   behaviour, and the reason self-hosted installs need the variable.
pub(crate) fn pick_client_ip(
    trusted_header: Option<&str>,
    header: impl Fn(&str) -> Option<String>,
) -> String {
    const SHARED: &str = "local";
    let valid = |v: &str| {
        !v.is_empty()
            && v.len() <= 64
            && v.bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':')
    };
    match trusted_header.map(str::trim).filter(|h| !h.is_empty()) {
        // No header is trustworthy (a relay with no proxy in front): one bucket for everyone.
        Some(name) if name.eq_ignore_ascii_case("none") => SHARED.into(),
        Some(name) => {
            let raw = header(name).unwrap_or_default();
            let value = if name.eq_ignore_ascii_case("x-forwarded-for") {
                raw.rsplit(',').next().unwrap_or("").trim().to_string()
            } else {
                raw.trim().to_string()
            };
            if valid(&value) {
                value
            } else {
                SHARED.into()
            }
        }
        None => header("cf-connecting-ip")
            .map(|v| v.trim().to_string())
            .filter(|v| valid(v))
            .unwrap_or_else(|| SHARED.into()),
    }
}

/// The address part of a socket peer as workerd reports it in `request.cf.clientIp`: `ip:port`,
/// `[v6]:port`, or a bare address. `None` for anything that is not an address.
pub(crate) fn peer_address_ip(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let ip = if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if raw.matches(':').count() == 1 {
        raw.split(':').next().unwrap_or("")
    } else {
        raw
    };
    let valid = !ip.is_empty()
        && ip.len() <= 64
        && ip.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':');
    valid.then(|| ip.to_string())
}

/// The TCP peer workerd hands a worker (`request.cf.clientIp`). Absent on Cloudflare, which has no
/// such field; there the caller comes from `cf-connecting-ip`.
fn socket_peer(req: &worker::Request) -> Option<String> {
    let cf = js_sys::Reflect::get(req.inner(), &wasm_bindgen::JsValue::from_str("cf")).ok()?;
    if cf.is_null() || cf.is_undefined() {
        return None;
    }
    js_sys::Reflect::get(&cf, &wasm_bindgen::JsValue::from_str("clientIp"))
        .ok()?
        .as_string()
}

/// [pick_client_ip] for a live request.
///
/// `socket` (a relay on bare workerd that clients reach directly, the app's "this network"
/// install since 2026-10-15): the TCP peer itself, so no header is trusted at all and no LAN front
/// is needed — the front existed because `wrangler dev` gave the worker no peer address. A peer
/// that cannot be read shares the `"local"` bucket, the same fail-closed answer as a bad header.
pub(crate) fn client_ip(req: &worker::Request, env: &Env) -> String {
    let configured = crate::utils::var_or(env, "SEZI_TRUSTED_PROXY_HEADER", "");
    if configured.trim().eq_ignore_ascii_case("socket") {
        return socket_peer(req)
            .and_then(|raw| peer_address_ip(&raw))
            .unwrap_or_else(|| "local".into());
    }
    pick_client_ip(Some(configured.as_str()), |name| {
        req.headers().get(name).ok().flatten()
    })
}

/// [check_rate_limit_env] for an endpoint that tells a refused caller when to come back. Fails
/// open exactly as the bool form does.
pub async fn admit_env(env: &Env, key: &str, max_hits: usize, window_sec: u64) -> Admission {
    admit_weighted_env(env, key, max_hits, window_sec, 1).await
}

/// Weighted variant of [check_rate_limit_env] (used by the M12 fan-out guard).
pub async fn check_rate_limit_weighted_env(
    env: &Env,
    key: &str,
    max_hits: usize,
    window_sec: u64,
    weight: usize,
) -> bool {
    admit_weighted_env(env, key, max_hits, window_sec, weight).await == Admission::Allowed
}

async fn admit_weighted_env(
    env: &Env,
    key: &str,
    max_hits: usize,
    window_sec: u64,
    weight: usize,
) -> Admission {
    let kv = match env.kv("RATE_LIMIT") {
        Ok(kv) => kv,
        // No binding (self-host template) → continue unlimited.
        Err(_) => return Admission::Allowed,
    };
    // check_rate_limit_weighted is already fail-open internally (a KV get/put error
    // yields Ok(Allowed)); it should never return Err, but if it does we fail open too.
    check_rate_limit_weighted(&kv, key, max_hits, window_sec, weight)
        .await
        .unwrap_or(Admission::Allowed)
}

/// How long until `weight` more hits fit under `max_hits` in a window of `window_sec`.
///
/// A hit at `t` counts while `t > now - window_sec`, so it leaves the window at `t + window_sec`.
/// To admit `weight` more, the `hits.len() + weight - max_hits` oldest have to leave; the wait is
/// until the last of those does. At least one second — `Retry-After: 0` reads as "now", which is
/// the answer that was just refused. A weight that can never fit waits out the whole window.
pub(crate) fn retry_after_s(
    hits: &[u64],
    max_hits: usize,
    weight: usize,
    window_sec: u64,
    now: u64,
) -> u64 {
    let w = weight.max(1);
    let must_leave = (hits.len() + w).saturating_sub(max_hits);
    if must_leave == 0 {
        return 1;
    }
    if w > max_hits || must_leave > hits.len() {
        return window_sec.max(1);
    }
    let mut sorted = hits.to_vec();
    sorted.sort_unstable();
    (sorted[must_leave - 1] + window_sec).saturating_sub(now).max(1)
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
) -> Result<Admission> {
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
            return Ok(Admission::Allowed);
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
        return Ok(Admission::Refused {
            retry_after_s: retry_after_s(&hits, max_hits, w, window_sec, now),
        });
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
    Ok(Admission::Allowed)
}

#[cfg(test)]
#[path = "ratelimit_tests.rs"]
mod tests;
