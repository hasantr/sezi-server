//! A brake on wrong keys, per sender address (docs/BOTS_BUILD.md §2.5).
//!
//! A well-formed key that opens no bot costs the server a D1 read (the lookup), and nothing
//! bounded how often an address could send one: the per-bot budget (`inbox_do/bot/api_budget.rs`)
//! is counted only for a key that opened a bot. Guessing is hopeless — a key carries 256 random
//! bits — but a loop spends the D1 reads the whole server shares. So an address (an IPv4 address,
//! or an IPv6 /64, `ratelimit::door_address`) that has sent [`MISSES_PER_MINUTE`] refused keys in
//! a minute is answered `bot/rate-limited` before any lookup, until its minute is over. A missing
//! or malformed key is refused without a lookup, costs nothing, and is not counted.
//!
//! **A key this isolate has seen open a bot is never braked** (for [`GOOD_FOR_S`] after it last
//! did; it is still looked up every time, so a renewed key stops at once). Several programs can
//! share one address: every caller of a relay that trusts no proxy header is `"local"`
//! (`ratelimit::client_ip`), and so is every caller behind a tunnel that is not configured to
//! pass the caller's address on. Without this, one program retrying an old key would hold every
//! other bot on that address.
//!
//! It is the isolate's memory, not D1 or KV: it costs no write anywhere, which is the point — a
//! counter in D1 would turn each wrong key into a write, and the KV limiter spends the namespace's
//! daily puts. The cost is that it is per isolate: exact on a self-hosted relay (one workerd
//! process), approximate on Cloudflare, where the optional edge rule (template README) is the
//! bound. Both tables are bounded; a full one drops entries that have ended first, then the
//! oldest.

use std::cell::RefCell;
use std::collections::HashMap;

/// Refused keys an address may send in a minute.
pub(crate) const MISSES_PER_MINUTE: u32 = 20;
/// The window (seconds).
pub(crate) const WINDOW_S: i64 = 60;
/// Addresses remembered at once.
pub(crate) const MAX_ADDRESSES: usize = 4_096;
/// How long a key that opened a bot passes the brake after it last did (seconds).
pub(crate) const GOOD_FOR_S: i64 = 600;
/// Good keys remembered at once.
pub(crate) const MAX_GOOD: usize = 1_024;

#[derive(Default)]
pub(crate) struct Brake {
    /// Address → (when its window began, s; refused keys in it).
    windows: HashMap<String, (i64, u32)>,
    /// A good key's hash → until when it passes (s).
    good: HashMap<String, i64>,
}

/// Make room for one more entry in `map`: drop what has ended, then, if still full, the entry
/// that ends first.
fn make_room<V>(map: &mut HashMap<String, V>, max: usize, ends: impl Fn(&V) -> i64, now_s: i64) {
    if map.len() < max {
        return;
    }
    map.retain(|_, v| ends(v) > now_s);
    if map.len() >= max {
        if let Some(k) = map.iter().min_by_key(|(_, v)| ends(v)).map(|(k, _)| k.clone()) {
            map.remove(&k);
        }
    }
}

impl Brake {
    /// May `addr` have `key_hash` looked up at `now_s`? `Err(retry_after_s)` while its window is
    /// spent and the key is not one this isolate saw open a bot.
    pub(crate) fn check(&self, addr: &str, key_hash: &str, now_s: i64) -> Result<(), u64> {
        if self.good.get(key_hash).is_some_and(|&until| until > now_s) {
            return Ok(());
        }
        match self.windows.get(addr) {
            Some(&(start, misses)) if start + WINDOW_S > now_s && misses >= MISSES_PER_MINUTE => {
                Err((start + WINDOW_S - now_s).max(1) as u64)
            }
            _ => Ok(()),
        }
    }

    /// `addr` sent `key_hash`, which opened no bot.
    pub(crate) fn miss(&mut self, addr: &str, key_hash: &str, now_s: i64) {
        self.good.remove(key_hash);
        if !self.windows.contains_key(addr) {
            make_room(&mut self.windows, MAX_ADDRESSES, |&(start, _)| start + WINDOW_S, now_s);
        }
        let w = self.windows.entry(addr.to_string()).or_insert((now_s, 0));
        if w.0 + WINDOW_S <= now_s {
            *w = (now_s, 0);
        }
        w.1 = w.1.saturating_add(1);
    }

    /// `key_hash` opened a bot.
    pub(crate) fn good(&mut self, key_hash: &str, now_s: i64) {
        if !self.good.contains_key(key_hash) {
            make_room(&mut self.good, MAX_GOOD, |&until| until, now_s);
        }
        self.good.insert(key_hash.to_string(), now_s + GOOD_FOR_S);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> (usize, usize) {
        (self.windows.len(), self.good.len())
    }
}

thread_local! {
    /// One per isolate (a WASM isolate is single-threaded, so a thread_local is an isolate memo).
    static BRAKE: RefCell<Brake> = RefCell::new(Brake::default());
}

pub(crate) fn check(addr: &str, key_hash: &str, now_s: i64) -> Result<(), u64> {
    BRAKE.with(|b| b.borrow().check(addr, key_hash, now_s))
}

pub(crate) fn miss(addr: &str, key_hash: &str, now_s: i64) {
    BRAKE.with(|b| b.borrow_mut().miss(addr, key_hash, now_s));
}

pub(crate) fn good(key_hash: &str, now_s: i64) {
    BRAKE.with(|b| b.borrow_mut().good(key_hash, now_s));
}

#[cfg(test)]
#[path = "key_brake_tests.rs"]
mod tests;
