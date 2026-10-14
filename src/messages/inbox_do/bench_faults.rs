//! Injected failures for `bench/notify-fanout` ONLY — compiled with `--features bench-faults`,
//! never in a deployed build. They let the bench drive the paths a healthy local run never takes:
//! the in-request retry, the close that queues a member, the drain, and a hop whose answer is
//! lost after it reached its members.
//!
//! - `BENCH_FAIL_MEMBERS = "<user-id prefix>:<n>"`: an inbox whose owner starts with the prefix
//!   fails its first `n` `/notify-member` calls, before storing anything.
//! - `BENCH_FAIL_HOPS = "<n>"`: the first `n` `/fanout` calls an inbox serves reach their members
//!   and then answer 500, as if the answer were lost.
//!
//! The counts live in the inbox's storage, so they survive between the bench's runs; the bench
//! uses a fresh state directory per scenario.

use super::UserInbox;

impl UserInbox {
    pub(crate) async fn bench_member_fault(&self, recipient_id: &str) -> bool {
        let Some(spec) = self.env.var("BENCH_FAIL_MEMBERS").ok().map(|v| v.to_string()) else {
            return false;
        };
        let Some((prefix, n)) = spec.split_once(':') else { return false };
        let Ok(n) = n.parse::<u32>() else { return false };
        recipient_id.starts_with(prefix) && self.bench_count("bench_member_faults", n).await
    }

    pub(crate) async fn bench_hop_fault(&self) -> bool {
        let Some(n) = self.env.var("BENCH_FAIL_HOPS").ok().and_then(|v| v.to_string().parse::<u32>().ok())
        else {
            return false;
        };
        self.bench_count("bench_hop_faults", n).await
    }

    /// True (and counted) while fewer than `limit` faults have been injected here.
    async fn bench_count(&self, key: &str, limit: u32) -> bool {
        let storage = self.state.storage();
        let done: u32 = storage.get(key).await.ok().flatten().unwrap_or(0);
        if done >= limit {
            return false;
        }
        let _ = storage.put(key, done + 1).await;
        true
    }
}
